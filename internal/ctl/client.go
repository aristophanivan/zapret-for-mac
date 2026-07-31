package ctl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrNotRunning means nothing is listening on the control socket: either the
// daemon is stopped or it was never installed. zaprctl turns this into exit
// code 3.
var ErrNotRunning = errors.New("ctl: the zapret-mac daemon is not running")

// ErrPermissionDenied means the socket exists but this user may not talk to it
// (not a member of the admin group). zaprctl turns this into exit code 4 and
// prints the sudo command to retry with.
var ErrPermissionDenied = errors.New("ctl: permission denied on the control socket")

// Client talks to the daemon. It is stateless: every call opens its own
// connection, which keeps a hung streaming command from blocking status polls
// and means there is no session to resynchronise after an error.
type Client struct {
	path    string
	timeout time.Duration
	maxLine int
}

// NewClient returns a client for the socket at path; an empty path means
// DefaultSocketPath.
func NewClient(path string) *Client {
	if path == "" {
		path = DefaultSocketPath
	}
	return &Client{path: path, timeout: DefaultTimeout, maxLine: MaxLine}
}

// WithTimeout returns a copy of c whose exchanges are bounded by d.
func (c *Client) WithTimeout(d time.Duration) *Client {
	cp := *c
	if d > 0 {
		cp.timeout = d
	}
	return &cp
}

// Path returns the socket path the client talks to.
func (c *Client) Path() string { return c.path }

// dial opens the control socket, classifying the failures a user can act on.
func (c *Client) dial(ctx context.Context) (*net.UnixConn, error) {
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.DialContext(ctx, "unix", c.path)
	if err != nil {
		switch {
		case errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.ECONNREFUSED):
			return nil, fmt.Errorf("%w (socket %s)", ErrNotRunning, c.path)
		case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
			return nil, fmt.Errorf("%w (socket %s)", ErrPermissionDenied, c.path)
		case errors.Is(err, syscall.EINVAL) && len(c.path) > MaxSocketPath:
			// connect(2) answers EINVAL for a path too long for sun_path, which
			// Go reports as "invalid argument". Say what is actually wrong.
			return nil, fmt.Errorf("ctl: socket path is %d bytes, but Darwin connects to at most %d: %s",
				len(c.path), MaxSocketPath, c.path)
		}
		return nil, fmt.Errorf("ctl: connect to %s: %w", c.path, err)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("ctl: %s is not a unix socket", c.path)
	}
	return uc, nil
}

// Do performs one request/response exchange.
func (c *Client) Do(ctx context.Context, req Request) (Response, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()

	// A cancelled context must abort a blocking read, and unix sockets have no
	// other way to interrupt one: closing the fd does it.
	stop := watchContext(ctx, conn)
	defer stop()

	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return Response{}, fmt.Errorf("ctl: set deadline: %w", err)
	}
	if err := writeRequest(conn, req); err != nil {
		return Response{}, err
	}
	br := bufio.NewReaderSize(conn, 4096)
	line, err := readLine(br, c.maxLine)
	if err != nil {
		return Response{}, readError(err, req.Cmd, c.path)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, fmt.Errorf("ctl: malformed response to %q: %w", req.Cmd, err)
	}
	return resp, nil
}

// call is Do plus the OK check and payload decode.
func (c *Client) call(ctx context.Context, req Request, out any) error {
	resp, err := c.Do(ctx, req)
	if err != nil {
		return err
	}
	if err := resp.Err(); err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if len(resp.Data) == 0 {
		// A mutating command may legitimately answer with a bare OK.
		return nil
	}
	return resp.Decode(out)
}

func writeRequest(conn *net.UnixConn, req Request) error {
	b, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("ctl: encode request: %w", err)
	}
	b = append(b, '\n')
	if len(b) > MaxLine {
		return fmt.Errorf("ctl: request of %d bytes exceeds the %d byte line limit", len(b), MaxLine)
	}
	if _, err := conn.Write(b); err != nil {
		if errors.Is(err, syscall.EPIPE) {
			return fmt.Errorf("%w (it closed the connection while we were sending %q)", ErrNotRunning, req.Cmd)
		}
		return fmt.Errorf("ctl: send %q: %w", req.Cmd, err)
	}
	return nil
}

// readError turns a read failure into a message that says what to do.
func readError(err error, cmd, path string) error {
	switch {
	case errors.Is(err, ErrLineTooLong):
		return fmt.Errorf("ctl: response to %q exceeded %d bytes", cmd, MaxLine)
	case errors.Is(err, os.ErrDeadlineExceeded):
		return fmt.Errorf("ctl: %q timed out; the daemon is alive but not answering (check `zaprctl logs`)", cmd)
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return fmt.Errorf("%w (it closed the connection during %q; see the daemon log)", ErrNotRunning, cmd)
	}
	if errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("ctl: %q was cancelled", cmd)
	}
	if strings.Contains(err.Error(), "EOF") {
		return fmt.Errorf("ctl: the daemon closed the connection without answering %q (socket %s); see the daemon log", cmd, path)
	}
	return fmt.Errorf("ctl: read response to %q: %w", cmd, err)
}

// watchContext closes conn when ctx is done, so a blocking read unblocks. The
// returned function stops the watcher.
func watchContext(ctx context.Context, conn *net.UnixConn) func() {
	if ctx == nil || ctx.Done() == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

// ---------------------------------------------------------------------------
// typed helpers
// ---------------------------------------------------------------------------

// Ping reports whether the daemon answers at all.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.Version(ctx)
	return err
}

// Version asks which daemon build is running.
func (c *Client) Version(ctx context.Context) (VersionData, error) {
	var v VersionData
	err := c.call(ctx, Request{Cmd: CmdVersion}, &v)
	return v, err
}

// Status fetches the full state.
func (c *Client) Status(ctx context.Context) (StatusData, error) {
	var v StatusData
	err := c.call(ctx, Request{Cmd: CmdStatus}, &v)
	return v, err
}

// Stats fetches the counters.
func (c *Client) Stats(ctx context.Context) (StatsData, error) {
	var v StatsData
	err := c.call(ctx, Request{Cmd: CmdStats}, &v)
	return v, err
}

// Caps fetches the capability matrix of the running transport.
func (c *Client) Caps(ctx context.Context) (CapsData, error) {
	var v CapsData
	err := c.call(ctx, Request{Cmd: CmdCaps}, &v)
	return v, err
}

// Start brings the datapath up. The returned status is the state afterwards; it
// is zero when the daemon answered with a bare OK.
func (c *Client) Start(ctx context.Context) (StatusData, error) {
	return c.StartOn(ctx, "")
}

// StartOn brings the datapath up on a specific transport ("auto", "divert" or
// "proxy"). An empty string keeps whatever the daemon was configured with.
//
// The override is honoured for real: if the datapath is already running on a
// different transport the daemon takes it down and brings it back up on the
// requested one, so the returned StatusData always reports what is actually
// running. A transport that cannot start reports why instead of silently
// falling back.
func (c *Client) StartOn(ctx context.Context, transport string) (StatusData, error) {
	var v StatusData
	req := Request{Cmd: CmdStart}
	if transport != "" {
		req.Args = map[string]string{"transport": transport}
	}
	err := c.call(ctx, req, &v)
	return v, err
}

// VPN inspects or stops VPN software that holds a tunnel default route.
// action is "status", "stop" or "start"; force permits signalling processes
// when the graceful path was not enough.
func (c *Client) VPN(ctx context.Context, action string, force bool) (VPNData, error) {
	var v VPNData
	args := map[string]string{"action": action}
	if force {
		args["force"] = "1"
	}
	err := c.call(ctx, Request{Cmd: CmdVPN, Args: args}, &v)
	return v, err
}

// Stop takes the datapath down.
func (c *Client) Stop(ctx context.Context) (StatusData, error) {
	var v StatusData
	err := c.call(ctx, Request{Cmd: CmdStop}, &v)
	return v, err
}

// Reload re-reads the active strategy from disk.
func (c *Client) Reload(ctx context.Context) (StatusData, error) {
	var v StatusData
	err := c.call(ctx, Request{Cmd: CmdReload}, &v)
	return v, err
}

// Use switches strategy.
func (c *Client) Use(ctx context.Context, name string) (UseData, error) {
	var v UseData
	err := c.call(ctx, Request{Cmd: CmdUse, Args: map[string]string{"name": name}}, &v)
	return v, err
}

// List enumerates installed strategies.
func (c *Client) List(ctx context.Context) (ListData, error) {
	var v ListData
	err := c.call(ctx, Request{Cmd: CmdList}, &v)
	return v, err
}

// Doctor runs diagnostics, optionally repairing.
func (c *Client) Doctor(ctx context.Context, repair bool) (DoctorData, error) {
	var v DoctorData
	args := map[string]string{}
	if repair {
		args["repair"] = "1"
	}
	err := c.call(ctx, Request{Cmd: CmdDoctor, Args: args}, &v)
	return v, err
}

// Selftest runs the connectivity test. targets may be nil for the defaults.
func (c *Client) Selftest(ctx context.Context, targets []string, strategy string) (SelftestData, error) {
	args := map[string]string{}
	if len(targets) > 0 {
		args["targets"] = strings.Join(targets, ",")
	}
	if strategy != "" {
		args["strategy"] = strategy
	}
	var v SelftestData
	err := c.WithTimeout(SelftestTimeout).call(ctx, Request{Cmd: CmdSelftest, Args: args}, &v)
	return v, err
}

// HostsApply installs the /etc/hosts pinning block.
func (c *Client) HostsApply(ctx context.Context) (HostsData, error) {
	var v HostsData
	err := c.call(ctx, Request{Cmd: CmdHostsApply}, &v)
	return v, err
}

// HostsRemove removes it.
func (c *Client) HostsRemove(ctx context.Context) (HostsData, error) {
	var v HostsData
	err := c.call(ctx, Request{Cmd: CmdHostsRemove}, &v)
	return v, err
}

// IPSet queries (mode == "") or sets the tri-state ipset switch.
func (c *Client) IPSet(ctx context.Context, mode string) (IPSetData, error) {
	args := map[string]string{}
	if mode != "" {
		args["mode"] = mode
	}
	var v IPSetData
	err := c.call(ctx, Request{Cmd: CmdIPSet, Args: args}, &v)
	return v, err
}

// LogTail streams log lines to fn until the stream ends, fn returns an error or
// ctx is cancelled. With follow set the call only returns on cancellation.
func (c *Client) LogTail(ctx context.Context, opt LogTailOpts, fn func(line string) error) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := watchContext(ctx, conn)
	defer stop()

	args := map[string]string{}
	if opt.Lines > 0 {
		args["lines"] = strconv.Itoa(opt.Lines)
	}
	if opt.Follow {
		args["follow"] = "1"
	}
	// Sending must not block forever, but a follower legitimately waits with
	// nothing to read, so only the write half gets a deadline.
	if err := conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return fmt.Errorf("ctl: set write deadline: %w", err)
	}
	if err := writeRequest(conn, Request{Cmd: CmdLogtail, Args: args}); err != nil {
		return err
	}
	// Half-closing tells the server we will not send more. It must NOT be done
	// for a follower: the server treats our FIN as "the client hung up" and ends
	// the stream, which is exactly what keeps a `logs -f` alive.
	if !opt.Follow {
		if err := conn.CloseWrite(); err != nil && !errors.Is(err, syscall.ENOTCONN) {
			// ENOTCONN means the server answered and closed before we got round to
			// half-closing. The request is already on the wire and the response is
			// already in our receive buffer, so this is a benign race, not a
			// failure — reporting it made `logs` flake under concurrency.
			return fmt.Errorf("ctl: close write half: %w", err)
		}
	}

	br := bufio.NewReaderSize(conn, 64*1024)
	for {
		if !opt.Follow {
			if err := conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
				return fmt.Errorf("ctl: set read deadline: %w", err)
			}
		} else {
			_ = conn.SetReadDeadline(time.Time{})
		}
		line, err := readLine(br, c.maxLine)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil // cancelled on purpose (^C on `zaprctl logs -f`)
			}
			if strings.Contains(err.Error(), "EOF") {
				return nil
			}
			return readError(err, CmdLogtail, c.path)
		}
		var resp Response
		if err := json.Unmarshal(line, &resp); err != nil {
			return fmt.Errorf("ctl: malformed logtail chunk: %w", err)
		}
		if err := resp.Err(); err != nil {
			return err
		}
		if len(resp.Data) > 0 {
			var chunk LogChunk
			if err := resp.Decode(&chunk); err != nil {
				return err
			}
			for _, l := range chunk.Lines {
				if err := fn(l); err != nil {
					return err
				}
			}
		}
		if !resp.More {
			return nil
		}
	}
}

// IsNotRunning reports whether err means "no daemon".
func IsNotRunning(err error) bool { return errors.Is(err, ErrNotRunning) }

// IsPermissionDenied reports whether err means "you are not allowed to ask".
func IsPermissionDenied(err error) bool { return errors.Is(err, ErrPermissionDenied) }
