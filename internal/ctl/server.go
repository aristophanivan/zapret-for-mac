package ctl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ErrAlreadyRunning is returned by Listen when something is already listening on
// the socket path. It is never returned for a stale socket file left behind by a
// killed daemon: that one is removed and the listen proceeds.
var ErrAlreadyRunning = errors.New("ctl: another daemon is already listening on the control socket")

// ErrLineTooLong is reported when a peer sends a line longer than MaxLine.
var ErrLineTooLong = errors.New("ctl: request line too long")

// LogTailOpts is the parameter block of the logtail command.
type LogTailOpts struct {
	// Lines is how much history to send first; 0 means the server default.
	Lines int
	// Follow keeps the response open and streams new lines as they appear.
	Follow bool
}

// Handler is what the daemon implements. Every method maps to one command.
//
// Methods must be safe for concurrent use: the server handles each connection in
// its own goroutine and a status poll must never be blocked by a slow selftest.
type Handler interface {
	// Version identifies the running daemon.
	Version() (VersionData, error)
	// Status is the full one-screen state.
	Status() (StatusData, error)
	// Stats is the counter block on its own, for scripts and graphing.
	Stats() (StatsData, error)
	// Caps is the capability matrix of the active transport plus the ops the
	// active strategy needs and cannot get.
	Caps() (CapsData, error)
	// VPN reports detected VPN software (action "status") or stops what holds a
	// tunnel default route (action "stop", with force), or restores what a
	// previous stop unloaded (action "start").
	VPN(action string, force bool) (VPNData, error)
	// Start brings the datapath up (idempotent). transport is "" to keep the
	// daemon's configured choice, or one of auto|divert|proxy to override it;
	// an override that differs from the running datapath restarts it.
	Start(transport string) error
	// Stop takes the datapath down and reverts its pf rules (idempotent).
	Stop() error
	// Reload re-reads the active strategy and its lists from disk.
	Reload() error
	// Use switches to another strategy by name or path.
	Use(name string) (UseData, error)
	// List enumerates the installed strategies.
	List() (ListData, error)
	// Doctor runs diagnostics; repair asks it to fix what it can.
	Doctor(repair bool) (DoctorData, error)
	// Selftest performs a connectivity test. Recognised args: "targets"
	// (comma separated host:port list) and "strategy".
	Selftest(args map[string]string) (SelftestData, error)
	// HostsApply installs the /etc/hosts pinning block.
	HostsApply() (HostsData, error)
	// HostsRemove removes it.
	HostsRemove() (HostsData, error)
	// IPSet reads (mode == "") or sets flowseal's tri-state ipset switch.
	IPSet(mode string) (IPSetData, error)
	// LogTail sends log history and, with Follow, keeps streaming. It must
	// return as soon as ctx is done or emit returns an error (the client hung
	// up).
	LogTail(ctx context.Context, opt LogTailOpts, emit func(LogChunk) error) error
}

// ServerOpts configures a Server.
type ServerOpts struct {
	// Path is the socket path; empty means DefaultSocketPath.
	Path string
	// Group is the group name given rw access; empty means SocketGroup.
	// Set to "-" to skip the chown entirely (tests).
	Group string
	// Mode is the socket's permission bits; 0 means SocketMode.
	Mode os.FileMode
	// ReadTimeout bounds how long a connection may take to deliver its request
	// line; WriteTimeout bounds a single response write. Zero means
	// DefaultTimeout.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// HandlerTimeout bounds a non-streaming handler call. Zero means
	// SelftestTimeout, which is the slowest command.
	HandlerTimeout time.Duration
	// MaxLine overrides MaxLine.
	MaxLine int
	// Logf receives accept/dispatch diagnostics; nil discards them.
	Logf func(format string, args ...any)
}

func (o ServerOpts) path() string {
	if o.Path == "" {
		return DefaultSocketPath
	}
	return o.Path
}

func (o ServerOpts) mode() os.FileMode {
	if o.Mode == 0 {
		return SocketMode
	}
	return o.Mode
}

func (o ServerOpts) readTimeout() time.Duration {
	if o.ReadTimeout <= 0 {
		return DefaultTimeout
	}
	return o.ReadTimeout
}

func (o ServerOpts) writeTimeout() time.Duration {
	if o.WriteTimeout <= 0 {
		return DefaultTimeout
	}
	return o.WriteTimeout
}

func (o ServerOpts) handlerTimeout() time.Duration {
	if o.HandlerTimeout <= 0 {
		return SelftestTimeout
	}
	return o.HandlerTimeout
}

func (o ServerOpts) maxLine() int {
	if o.MaxLine <= 0 {
		return MaxLine
	}
	return o.MaxLine
}

// Server serves the control socket. One connection carries one request, except
// logtail, whose response is a stream of chunks.
type Server struct {
	h    Handler
	opts ServerOpts

	mu     sync.Mutex
	ln     *net.UnixListener
	path   string
	closed bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewServer returns a server for h. Nothing is created until Listen.
func NewServer(h Handler, o ServerOpts) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{h: h, opts: o, ctx: ctx, cancel: cancel}
}

func (s *Server) logf(format string, args ...any) {
	if s.opts.Logf != nil {
		s.opts.Logf(format, args...)
	}
}

// Path returns the socket path in use.
func (s *Server) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path != "" {
		return s.path
	}
	return s.opts.path()
}

// Listen creates the socket with the right owner and mode.
//
// The socket is bound at a temporary name in the same directory, has its mode
// and group set there, and is then renamed into place. Binding directly at the
// final path would leave a window in which the socket exists with the process
// umask's permissions, and on a multi-user machine that window is enough for
// anybody to connect.
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("ctl: server is closed")
	}
	if s.ln != nil {
		return errors.New("ctl: server is already listening")
	}

	path := s.opts.path()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("ctl: create socket directory %s: %w", dir, err)
	}
	if err := checkSocketDir(dir, s.opts.Logf); err != nil {
		return err
	}
	if err := clearStaleSocket(path); err != nil {
		return err
	}
	// After clearStaleSocket, so that "exists and is not a socket" — which is
	// true whatever the length — keeps its own, more actionable message.
	if err := checkSocketPathLen(path); err != nil {
		return err
	}

	tmp := path + ".tmp"
	// A leftover temp socket from a killed daemon would make bind fail with
	// EADDRINUSE, so drop it first; nobody can be listening on it, because we
	// rename it away immediately after binding.
	_ = os.Remove(tmp)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: tmp, Net: "unix"})
	if err != nil {
		return fmt.Errorf("ctl: listen on %s: %w", tmp, err)
	}
	// We manage the socket file's lifetime ourselves: the listener's address is
	// the temp name, so its own unlink-on-close would remove the wrong path.
	ln.SetUnlinkOnClose(false)

	cleanup := func() {
		_ = ln.Close()
		_ = os.Remove(tmp)
	}

	if err := os.Chmod(tmp, s.opts.mode()); err != nil {
		cleanup()
		return fmt.Errorf("ctl: chmod %s to %#o: %w", tmp, s.opts.mode(), err)
	}
	if err := chownGroup(tmp, s.opts.Group); err != nil {
		// Without the group the socket is root-only, which silently breaks
		// unprivileged `zaprctl status`. That is a real failure for a daemon;
		// for an unprivileged test run it is unavoidable, so only root treats
		// it as fatal.
		if os.Geteuid() == 0 {
			cleanup()
			return err
		}
		s.logf("ctl: %v (running unprivileged, continuing with owner-only access)", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return fmt.Errorf("ctl: rename %s -> %s: %w", tmp, path, err)
	}

	s.ln = ln
	s.path = path
	s.logf("ctl: listening on %s (mode %#o, group %s)", path, s.opts.mode(), groupLabel(s.opts.Group))
	return nil
}

// Serve accepts connections until Close. It returns nil on a clean Close,
// including the race where Close wins against a just-started Serve goroutine.
func (s *Server) Serve() error {
	s.mu.Lock()
	ln, closed := s.ln, s.closed
	s.mu.Unlock()
	if closed {
		return nil
	}
	if ln == nil {
		return errors.New("ctl: Serve called before Listen")
	}
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// A transient accept error (EMFILE under fd pressure) must not kill
			// the control plane: back off briefly and keep going.
			s.logf("ctl: accept: %v", err)
			select {
			case <-s.ctx.Done():
				return nil
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(conn)
		}()
	}
}

// ListenAndServe is Listen followed by Serve.
func (s *Server) ListenAndServe() error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve()
}

// Close stops accepting, cancels in-flight streaming responses, waits for
// handlers to finish and removes the socket file.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln, path := s.ln, s.path
	s.ln = nil
	s.mu.Unlock()

	s.cancel()
	var err error
	if ln != nil {
		err = ln.Close()
	}
	s.wg.Wait()
	if path != "" {
		if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) && err == nil {
			err = fmt.Errorf("ctl: remove %s: %w", path, rerr)
		}
	}
	return err
}

// serveConn reads one request, dispatches it and writes the response(s).
func (s *Server) serveConn(conn *net.UnixConn) {
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(s.opts.readTimeout()))
	br := bufio.NewReaderSize(conn, 4096)
	line, err := readLine(br, s.opts.maxLine())
	if err != nil {
		switch {
		case errors.Is(err, ErrLineTooLong):
			// Answer before closing: a client that overshot deserves a reason
			// rather than a bare EOF. We do not try to resynchronise — the rest
			// of that line is discarded with the connection.
			s.write(conn, errResponse(fmt.Errorf("%w: limit is %d bytes", ErrLineTooLong, s.opts.maxLine())))
		case errors.Is(err, io.EOF):
			// Client connected and went away: nothing to say.
		case errors.Is(err, os.ErrDeadlineExceeded):
			s.logf("ctl: client sent no request within %s, closing", s.opts.readTimeout())
		default:
			s.logf("ctl: read request: %v", err)
		}
		return
	}

	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		s.write(conn, errResponse(fmt.Errorf("ctl: malformed request: %w", err)))
		return
	}
	req.Cmd = strings.ToLower(strings.TrimSpace(req.Cmd))
	if req.Cmd == "" {
		s.write(conn, errResponse(errors.New("ctl: empty command; known commands: "+strings.Join(Commands, ", "))))
		return
	}

	if req.Cmd == CmdLogtail {
		s.serveLogtail(conn, req)
		return
	}
	s.write(conn, s.dispatch(req))
}

// dispatch runs a non-streaming command under a timeout, so a wedged handler
// cannot hold a connection (and its deadline-less side effects) forever.
func (s *Server) dispatch(req Request) (resp Response) {
	type result struct{ r Response }
	done := make(chan result, 1)
	go func() {
		defer func() {
			// A handler panic must not take the daemon down: the control plane
			// is the only way left to diagnose it.
			if p := recover(); p != nil {
				done <- result{errResponse(fmt.Errorf("ctl: handler for %q panicked: %v", req.Cmd, p))}
			}
		}()
		done <- result{s.call(req)}
	}()
	timeout := s.opts.handlerTimeout()
	select {
	case r := <-done:
		return r.r
	case <-time.After(timeout):
		return errResponse(fmt.Errorf("ctl: command %q did not finish within %s", req.Cmd, timeout))
	case <-s.ctx.Done():
		return errResponse(errors.New("ctl: daemon is shutting down"))
	}
}

// call performs the actual handler invocation.
func (s *Server) call(req Request) Response {
	h := s.h
	if h == nil {
		return errResponse(errors.New("ctl: server has no handler"))
	}
	switch req.Cmd {
	case CmdVersion:
		v, err := h.Version()
		if err != nil {
			return errResponse(err)
		}
		return newResponse(v)
	case CmdStatus:
		v, err := h.Status()
		if err != nil {
			return errResponse(err)
		}
		return newResponse(v)
	case CmdStats:
		v, err := h.Stats()
		if err != nil {
			return errResponse(err)
		}
		return newResponse(v)
	case CmdCaps:
		v, err := h.Caps()
		if err != nil {
			return errResponse(err)
		}
		return newResponse(v)
	case CmdVPN:
		v, err := h.VPN(req.Args["action"], req.Args["force"] == "1")
		if err != nil {
			return errResponse(err)
		}
		return newResponse(v)
	case CmdStart:
		if err := h.Start(req.Args["transport"]); err != nil {
			return errResponse(err)
		}
		return s.statusOrEmpty(h)
	case CmdStop:
		if err := h.Stop(); err != nil {
			return errResponse(err)
		}
		return s.statusOrEmpty(h)
	case CmdReload:
		if err := h.Reload(); err != nil {
			return errResponse(err)
		}
		return s.statusOrEmpty(h)
	case CmdUse:
		name := strings.TrimSpace(req.Arg("name"))
		if name == "" {
			return errResponse(errors.New(`ctl: use needs a strategy name: {"cmd":"use","args":{"name":"general"}}`))
		}
		v, err := h.Use(name)
		if err != nil {
			return errResponse(err)
		}
		return newResponse(v)
	case CmdList:
		v, err := h.List()
		if err != nil {
			return errResponse(err)
		}
		return newResponse(v)
	case CmdDoctor:
		v, err := h.Doctor(req.Bool("repair"))
		if err != nil {
			return errResponse(err)
		}
		return newResponse(v)
	case CmdSelftest:
		v, err := h.Selftest(req.Args)
		if err != nil {
			return errResponse(err)
		}
		return newResponse(v)
	case CmdHostsApply:
		v, err := h.HostsApply()
		if err != nil {
			return errResponse(err)
		}
		return newResponse(v)
	case CmdHostsRemove:
		v, err := h.HostsRemove()
		if err != nil {
			return errResponse(err)
		}
		return newResponse(v)
	case CmdIPSet:
		mode := strings.ToLower(strings.TrimSpace(req.Arg("mode")))
		switch mode {
		case "", IPSetLoaded, IPSetNone, IPSetAny:
		default:
			return errResponse(fmt.Errorf("ctl: ipset mode %q is unknown; use %q, %q or %q (or omit it to query)",
				mode, IPSetLoaded, IPSetNone, IPSetAny))
		}
		v, err := h.IPSet(mode)
		if err != nil {
			return errResponse(err)
		}
		return newResponse(v)
	default:
		return errResponse(fmt.Errorf("ctl: unknown command %q; known commands: %s", req.Cmd, strings.Join(Commands, ", ")))
	}
}

// statusOrEmpty answers a mutating command with the new status when it can, so
// the CLI can print the result of `start` without a second round trip. A status
// failure is not the command's failure, so it degrades to a bare OK.
func (s *Server) statusOrEmpty(h Handler) Response {
	v, err := h.Status()
	if err != nil {
		return Response{OK: true}
	}
	return newResponse(v)
}

// serveLogtail streams log chunks until the client hangs up, the handler is
// done, or the server closes.
func (s *Server) serveLogtail(conn *net.UnixConn, req Request) {
	opt := LogTailOpts{Follow: req.Bool("follow")}
	if n := strings.TrimSpace(req.Arg("lines")); n != "" {
		v, err := strconv.Atoi(n)
		if err != nil || v < 0 {
			s.write(conn, errResponse(fmt.Errorf("ctl: logtail lines=%q is not a non-negative number", n)))
			return
		}
		opt.Lines = v
	}
	if s.h == nil {
		s.write(conn, errResponse(errors.New("ctl: server has no handler")))
		return
	}

	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	// A follower stops reading only by disconnecting, and a unix socket only
	// reports that on write. Watching for EOF in parallel turns "the user hit
	// ^C" into an immediate cancel instead of a stalled goroutine.
	//
	// Only for a follower: a one-shot client half-closes its write side as soon
	// as the request is sent, and treating that FIN as "hung up" would cancel
	// the handler before it had emitted the history the client asked for.
	if opt.Follow {
		go func() {
			_ = conn.SetReadDeadline(time.Time{})
			buf := make([]byte, 1)
			for {
				if _, err := conn.Read(buf); err != nil {
					cancel()
					return
				}
				select {
				case <-ctx.Done():
					return
				default:
				}
			}
		}()
	}

	emit := func(c LogChunk) error {
		if len(c.Lines) == 0 {
			return nil
		}
		resp := newResponse(c)
		resp.More = true
		return s.writeErr(conn, resp)
	}

	err := func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("ctl: logtail handler panicked: %v", p)
			}
		}()
		return s.h.LogTail(ctx, opt, emit)
	}()

	if err != nil && !errors.Is(err, context.Canceled) && !isBrokenPipe(err) {
		s.write(conn, errResponse(err))
		return
	}
	// Terminate the stream so a client that is still reading knows it is over.
	s.write(conn, Response{OK: true})
}

// write sends one response line, ignoring write errors (the peer may be gone).
func (s *Server) write(conn *net.UnixConn, resp Response) {
	if err := s.writeErr(conn, resp); err != nil && !isBrokenPipe(err) {
		s.logf("ctl: write response: %v", err)
	}
}

// writeErr sends one response line and reports failures.
func (s *Server) writeErr(conn *net.UnixConn, resp Response) error {
	b, err := json.Marshal(resp)
	if err != nil {
		b, err = json.Marshal(Response{OK: false, Error: fmt.Sprintf("ctl: cannot encode response: %v", err)})
		if err != nil {
			return err
		}
	}
	if len(b)+1 > s.opts.maxLine() {
		b, err = json.Marshal(Response{OK: false, Error: fmt.Sprintf(
			"ctl: response of %d bytes exceeds the %d byte line limit; ask for less (fewer log lines, --json off)",
			len(b), s.opts.maxLine())})
		if err != nil {
			return err
		}
	}
	b = append(b, '\n')
	if err := conn.SetWriteDeadline(time.Now().Add(s.opts.writeTimeout())); err != nil {
		return err
	}
	_, err = conn.Write(b)
	return err
}

// ---------------------------------------------------------------------------
// socket plumbing
// ---------------------------------------------------------------------------

// MaxSocketPath is the longest usable unix-socket path on Darwin.
//
// struct sockaddr_un carries sun_path[104], and the kernel needs room for the
// terminating NUL, so 103 bytes is the last length that binds. Measured on
// Darwin 25.5.0: 103 succeeds, 104 fails with EINVAL.
const MaxSocketPath = 103

// socketTmpSuffix is what Listen appends while it binds at a temporary name.
// It comes out of the same 103-byte budget, so the caller-visible limit for a
// socket path is MaxSocketPath-len(socketTmpSuffix).
const socketTmpSuffix = ".tmp"

// checkSocketPathLen rejects an over-long socket path with an explanation.
//
// bind(2) answers EINVAL for a path that does not fit sun_path, which Go
// surfaces as the uninformative "bind: invalid argument". A daemon that refuses
// to start with that message tells the operator nothing, and the path is
// operator-supplied (--socket), so diagnose it before binding.
func checkSocketPathLen(path string) error {
	if budget := MaxSocketPath - len(socketTmpSuffix); len(path) > budget {
		return fmt.Errorf("ctl: socket path is %d bytes, but Darwin binds at most %d "+
			"(sun_path is %d bytes incl. NUL, and %d are reserved for the %q suffix "+
			"Listen binds under): %s",
			len(path), budget, MaxSocketPath+1, len(socketTmpSuffix), socketTmpSuffix, path)
	}
	return nil
}

// checkSocketDir inspects the directory the control socket is bound in.
//
// THE EXPOSURE. macOS ships /var/run as drwxrwxr-x root:daemon — group-writable
// and NOT sticky. Socket creation itself is safe (clearStaleSocket refuses a
// non-socket, and we bind at a temp name and rename, so there is no umask window),
// but the DIRECTORY is the hole: a process running as group `daemon` can
// pre-create our path so the daemon refuses to start, or replace the socket file
// after our rename so unprivileged clients talk to an impostor.
//
// The line drawn here: a WORLD-writable non-sticky directory is refused, because
// any local user could exploit it. A group-writable one is a loud warning instead
// of a refusal — the exposure is limited to processes already running as that
// system group, and refusing would make the stock /var/run default unusable on
// every Mac. Point --socket at a root-owned 0755 directory to close it entirely.
//
// A non-root process gets a pass: it cannot fix a system directory's permissions
// and its socket is not a privilege boundary.
func checkSocketDir(dir string, logf func(string, ...any)) error {
	if os.Geteuid() != 0 {
		return nil
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("ctl: stat socket directory %s: %w", dir, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return nil
	}
	perm := fi.Mode().Perm()
	sticky := fi.Mode()&os.ModeSticky != 0
	if st.Uid == 0 && perm&0o022 == 0 {
		return nil // root-owned and only root can write: nothing to say
	}
	if perm&0o002 != 0 && !sticky {
		return fmt.Errorf("ctl: refusing to bind the control socket in %s: it is world-writable and not "+
			"sticky (uid %d, mode %s), so any local user can pre-create or replace the socket file and "+
			"impersonate the daemon. Point --socket at a root-owned directory with mode 0755",
			dir, st.Uid, perm)
	}
	if logf != nil && !sticky {
		logf("ctl: WARNING: %s is uid %d mode %s (group-writable, not sticky): a process in that group can "+
			"pre-create %s to stop the daemon starting, or replace the socket after we bind it. "+
			"Pass --socket <root-owned 0755 dir>/zapret-mac.sock to close that off.",
			dir, st.Uid, perm, dir)
	}
	return nil
}

// clearStaleSocket removes a socket file nobody is listening on.
//
// The only safe way to tell a stale socket from a live one is to connect: a
// stale one refuses (ECONNREFUSED) because no process holds it. A successful
// connect, or a timeout (a live daemon that is busy accepting), means somebody
// is there and we must not unlink it.
func clearStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("ctl: stat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("ctl: %s exists and is not a socket (mode %s); move it out of the way", path, fi.Mode())
	}
	conn, derr := net.DialTimeout("unix", path, 500*time.Millisecond)
	if derr == nil {
		_ = conn.Close()
		return fmt.Errorf("%w: %s", ErrAlreadyRunning, path)
	}
	if errors.Is(derr, os.ErrDeadlineExceeded) || os.IsTimeout(derr) {
		return fmt.Errorf("%w: %s did not answer within 500ms but is bound", ErrAlreadyRunning, path)
	}
	if !errors.Is(derr, syscall.ECONNREFUSED) && !errors.Is(derr, syscall.ENOENT) {
		return fmt.Errorf("ctl: %s exists and cannot be probed: %w; remove it by hand if no daemon is running", path, derr)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ctl: remove stale socket %s: %w", path, err)
	}
	return nil
}

// chownGroup sets the socket's group. group == "-" skips the change; an empty
// group means SocketGroup.
func chownGroup(path, group string) error {
	if group == "-" {
		return nil
	}
	if group == "" {
		group = SocketGroup
	}
	gid := -1
	if g, err := user.LookupGroup(group); err == nil {
		if v, cerr := strconv.Atoi(g.Gid); cerr == nil {
			gid = v
		}
	}
	if gid < 0 && group == SocketGroup {
		// The group database is unreadable (a stripped-down system, or a
		// sandbox): fall back to the fixed gid macOS assigns to admin.
		gid = SocketGroupGID
	}
	if gid < 0 {
		return fmt.Errorf("ctl: group %q not found; cannot set the owner group of %s", group, path)
	}
	if err := os.Chown(path, -1, gid); err != nil {
		return fmt.Errorf("ctl: chown %s to group %s (gid %d): %w", path, group, gid, err)
	}
	return nil
}

func groupLabel(group string) string {
	switch group {
	case "":
		return SocketGroup
	case "-":
		return "(unchanged)"
	default:
		return group
	}
}

// readLine reads one newline-terminated line, refusing anything longer than max.
// The newline is not returned.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > max {
			return nil, ErrLineTooLong
		}
		buf = append(buf, chunk...)
		if err == nil {
			return trimEOL(buf), nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(buf) > 0 {
			// A final line without a newline is still a complete request.
			return trimEOL(buf), nil
		}
		return nil, err
	}
}

func trimEOL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// isBrokenPipe reports whether err is the peer having closed the connection,
// which is normal for a streaming response and not worth logging.
func isBrokenPipe(err error) bool {
	return errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, net.ErrClosed)
}
