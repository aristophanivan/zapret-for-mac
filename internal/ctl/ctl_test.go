package ctl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// test scaffolding
// ---------------------------------------------------------------------------

// fakeHandler is a Handler that records what it was asked and can be told to
// fail or to block.
type fakeHandler struct {
	mu sync.Mutex

	calls []string

	failWith       error
	blockFor       time.Duration
	panicOn        string
	usedName       string
	ipsetMode      string
	repair         bool
	testArgs       map[string]string
	startTransport string
	vpnAction      string
	vpnForce       bool

	logHistory []string
	logFollow  bool
}

func (f *fakeHandler) note(name string) error {
	f.mu.Lock()
	f.calls = append(f.calls, name)
	fail, block, panicOn := f.failWith, f.blockFor, f.panicOn
	f.mu.Unlock()
	if panicOn == name {
		panic("boom in " + name)
	}
	if block > 0 {
		time.Sleep(block)
	}
	return fail
}

func (f *fakeHandler) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeHandler) Version() (VersionData, error) {
	if err := f.note(CmdVersion); err != nil {
		return VersionData{}, err
	}
	return VersionData{Version: "test", Go: "go1.x", PID: 4242, Started: "2026-07-27T00:00:00Z", Binary: "/x/zapretd"}, nil
}

func (f *fakeHandler) Status() (StatusData, error) {
	if err := f.note(CmdStatus); err != nil {
		return StatusData{}, err
	}
	return StatusData{
		Version: "test", PID: 4242, Running: true, Transport: "divert",
		TransportReason: "auto", Strategy: "general", StrategyPath: "/x/general.toml",
		Profiles: 9, WindowTCP: []string{"80", "443"}, WindowUDP: []string{"443"},
		UptimeSec: 61, DatapathUptimeSec: 60,
		Caps:        CapsData{Transport: "divert", Inject: true, Segment: true, TLSRec: true},
		Unsupported: []string{"fake (needs inject)"},
		Stats:       StatsData{Transport: "divert", PktsIn: 7, FlowsActive: 2},
		PF:          PFData{Anchor: "zapret-mac", Enabled: true, AnchorReferenced: true, RuleLines: 12, Token: "3"},
		IPSet:       IPSetLoaded, HostsEntries: 241, LogPath: "/var/log/zapretd.log",
		Warnings: []string{"a VPN is active"},
	}, nil
}

func (f *fakeHandler) Stats() (StatsData, error) {
	if err := f.note(CmdStats); err != nil {
		return StatsData{}, err
	}
	return StatsData{Transport: "divert", PktsIn: 7, PktsOut: 6, Desyncs: 3}, nil
}

func (f *fakeHandler) Caps() (CapsData, error) {
	if err := f.note(CmdCaps); err != nil {
		return CapsData{}, err
	}
	return CapsData{Transport: "proxy", Reason: "fallback", Strategy: "general",
		Segment: true, TLSRec: true, DropOriginal: true,
		Unsupported: []string{"fake (needs inject, per-packet-ttl)"}}, nil
}

// VPN records the action so a test can assert the argument reached the handler.
func (f *fakeHandler) VPN(action string, force bool) (VPNData, error) {
	f.mu.Lock()
	f.vpnAction, f.vpnForce = action, force
	f.mu.Unlock()
	if err := f.note(CmdVPN); err != nil {
		return VPNData{}, err
	}
	return VPNData{
		Providers:      []VPNProvider{{Name: "AmneziaVPN", Jobs: []string{"system/AmneziaVPN"}, PIDs: []int{589}}},
		TunnelDefaults: []string{"utun4"},
		Blocking:       true,
	}, nil
}

// startTransport records the transport the server passed through, so a test can
// assert that `zaprctl start --transport X` really reaches the handler.
func (f *fakeHandler) Start(transport string) error {
	f.mu.Lock()
	f.startTransport = transport
	f.mu.Unlock()
	return f.note(CmdStart)
}
func (f *fakeHandler) Stop() error   { return f.note(CmdStop) }
func (f *fakeHandler) Reload() error { return f.note(CmdReload) }

func (f *fakeHandler) Use(name string) (UseData, error) {
	if err := f.note(CmdUse); err != nil {
		return UseData{}, err
	}
	f.mu.Lock()
	f.usedName = name
	f.mu.Unlock()
	return UseData{Strategy: name, Path: "/x/" + name + ".toml", Restarted: true}, nil
}

func (f *fakeHandler) List() (ListData, error) {
	if err := f.note(CmdList); err != nil {
		return ListData{}, err
	}
	return ListData{Active: "general", Transport: "divert", Dir: "/x",
		Strategies: []StrategyInfo{
			{Name: "general", Summary: "general: 9 profiles, ops: fake", Profiles: 9, Active: true},
			{Name: "general-alt", Summary: "general-alt: 8 profiles, ops: multisplit", Profiles: 8,
				Unsupported: []string{"fake (needs inject)"}},
		}}, nil
}

func (f *fakeHandler) Doctor(repair bool) (DoctorData, error) {
	if err := f.note(CmdDoctor); err != nil {
		return DoctorData{}, err
	}
	f.mu.Lock()
	f.repair = repair
	f.mu.Unlock()
	d := DoctorData{Version: "test", UID: 0, Root: true, DaemonRunning: true, Transport: "divert",
		Checks: []Check{
			{Name: "pf enabled", OK: true, Severity: SevInfo, Detail: "token 3"},
			{Name: "datapath", OK: false, Severity: SevError, Detail: "not running", Fix: "zaprctl start"},
			{Name: "vpn", OK: false, Severity: SevWarn, Detail: "utun4"},
		},
		JournalPath: "/x/journal.jsonl", JournalPending: 2}
	if repair {
		d.Repaired = []string{"restarted the datapath"}
	}
	return d, nil
}

func (f *fakeHandler) Selftest(args map[string]string) (SelftestData, error) {
	if err := f.note(CmdSelftest); err != nil {
		return SelftestData{}, err
	}
	f.mu.Lock()
	f.testArgs = args
	f.mu.Unlock()
	return SelftestData{Strategy: "general", Transport: "divert", OK: true,
		Targets: []TestTarget{{Target: "a:443", SNI: "a", OK: true, MS: 12, Detail: "TLS 1.3", Desynced: true}}}, nil
}

func (f *fakeHandler) HostsApply() (HostsData, error) {
	if err := f.note(CmdHostsApply); err != nil {
		return HostsData{}, err
	}
	return HostsData{Path: "/etc/hosts", SourcePath: "/x/hosts", Applied: true, Entries: 3, Names: 7, DNSFlushed: true}, nil
}

func (f *fakeHandler) HostsRemove() (HostsData, error) {
	if err := f.note(CmdHostsRemove); err != nil {
		return HostsData{}, err
	}
	return HostsData{Path: "/etc/hosts", DNSFlushed: true}, nil
}

func (f *fakeHandler) IPSet(mode string) (IPSetData, error) {
	if err := f.note(CmdIPSet); err != nil {
		return IPSetData{}, err
	}
	f.mu.Lock()
	f.ipsetMode = mode
	f.mu.Unlock()
	out := IPSetData{Mode: IPSetLoaded, Path: "/x/ipset-all.txt", Entries: 5, Backup: true}
	if mode != "" {
		out.Mode, out.Previous, out.Reloaded = mode, IPSetLoaded, true
	}
	return out, nil
}

func (f *fakeHandler) LogTail(ctx context.Context, opt LogTailOpts, emit func(LogChunk) error) error {
	if err := f.note(CmdLogtail); err != nil {
		return err
	}
	hist := f.logHistory
	if opt.Lines > 0 && opt.Lines < len(hist) {
		hist = hist[len(hist)-opt.Lines:]
	}
	if len(hist) > 0 {
		if err := emit(LogChunk{Lines: hist}); err != nil {
			return err
		}
	}
	if !opt.Follow {
		return nil
	}
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
		if err := emit(LogChunk{Lines: []string{fmt.Sprintf("live-%d", i)}}); err != nil {
			return err
		}
	}
}

// sockPath returns a short-enough socket path.
//
// sun_path is 104 bytes on Darwin and bind(2) fails with EINVAL past that.
// t.TempDir() already spends ~50 bytes on /var/folders/..., and a long test name
// plus the ".tmp" suffix Listen binds at first can blow the limit, so anything
// close to it falls back to a short directory of its own.
func sockPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	if len(p) <= 80 {
		return p
	}
	dir, err := os.MkdirTemp("", "z")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s")
}

// serve starts a server on a private socket and returns it with a client.
func serve(t *testing.T, h Handler, o ServerOpts) (*Server, *Client) {
	t.Helper()
	if o.Path == "" {
		o.Path = sockPath(t)
	}
	// The test user is not necessarily in the admin group, and chowning to it
	// would fail; "-" means "leave the group alone".
	if o.Group == "" {
		o.Group = "-"
	}
	s := NewServer(h, o)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen(%s): %v", o.Path, err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
		if _, err := os.Lstat(o.Path); !os.IsNotExist(err) {
			t.Errorf("socket %s still exists after Close (err %v)", o.Path, err)
		}
	})
	c := NewClient(o.Path).WithTimeout(5 * time.Second)
	return s, c
}

// ---------------------------------------------------------------------------
// every command
// ---------------------------------------------------------------------------

func TestEveryCommandRoundTrips(t *testing.T) {
	h := &fakeHandler{logHistory: []string{"one", "two", "three"}}
	_, c := serve(t, h, ServerOpts{})
	ctx := context.Background()

	if v, err := c.Version(ctx); err != nil || v.PID != 4242 || v.Version != "test" {
		t.Fatalf("Version = %+v, %v", v, err)
	}
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Transport != "divert" || st.Strategy != "general" || st.Stats.PktsIn != 7 ||
		!st.PF.Enabled || st.IPSet != IPSetLoaded || len(st.Unsupported) != 1 {
		t.Fatalf("Status = %+v", st)
	}
	if s, err := c.Stats(ctx); err != nil || s.PktsOut != 6 || s.Desyncs != 3 {
		t.Fatalf("Stats = %+v, %v", s, err)
	}
	caps, err := c.Caps(ctx)
	if err != nil || caps.Transport != "proxy" || caps.Inject || !caps.Segment {
		t.Fatalf("Caps = %+v, %v", caps, err)
	}
	if rows := caps.Rows(); len(rows) != 11 || rows[0].Name != "inject" {
		t.Fatalf("Caps.Rows() = %+v", rows)
	}
	// start/stop/reload answer with the new status.
	if st, err := c.Start(ctx); err != nil || !st.Running {
		t.Fatalf("Start = %+v, %v", st, err)
	}
	if _, err := c.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := c.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	u, err := c.Use(ctx, "general (ALT2)")
	if err != nil || u.Strategy != "general (ALT2)" || !u.Restarted {
		t.Fatalf("Use = %+v, %v", u, err)
	}
	l, err := c.List(ctx)
	if err != nil || len(l.Strategies) != 2 || l.Active != "general" {
		t.Fatalf("List = %+v, %v", l, err)
	}
	d, err := c.Doctor(ctx, true)
	if err != nil || len(d.Checks) != 3 || len(d.Repaired) != 1 || d.JournalPending != 2 {
		t.Fatalf("Doctor = %+v, %v", d, err)
	}
	if errs, warns := d.Problems(); errs != 1 || warns != 1 {
		t.Fatalf("Problems = %d, %d", errs, warns)
	}
	ts, err := c.Selftest(ctx, []string{"a:443", "b:80"}, "general")
	if err != nil || !ts.OK || len(ts.Targets) != 1 {
		t.Fatalf("Selftest = %+v, %v", ts, err)
	}
	if ha, err := c.HostsApply(ctx); err != nil || !ha.Applied || ha.Names != 7 {
		t.Fatalf("HostsApply = %+v, %v", ha, err)
	}
	if hr, err := c.HostsRemove(ctx); err != nil || hr.Applied {
		t.Fatalf("HostsRemove = %+v, %v", hr, err)
	}
	if is, err := c.IPSet(ctx, ""); err != nil || is.Mode != IPSetLoaded || is.Previous != "" {
		t.Fatalf("IPSet(query) = %+v, %v", is, err)
	}
	if is, err := c.IPSet(ctx, IPSetNone); err != nil || is.Mode != IPSetNone || !is.Reloaded {
		t.Fatalf("IPSet(none) = %+v, %v", is, err)
	}
	// The vpn command carries both of its arguments through to the handler.
	if v, err := c.VPN(ctx, "stop", true); err != nil || !v.Blocking || len(v.Providers) != 1 {
		t.Fatalf("VPN = %+v, %v", v, err)
	}
	h.mu.Lock()
	gotAction, gotForce := h.vpnAction, h.vpnForce
	h.mu.Unlock()
	if gotAction != "stop" || !gotForce {
		t.Fatalf("handler saw action=%q force=%v, want stop/true", gotAction, gotForce)
	}

	var got []string
	if err := c.LogTail(ctx, LogTailOpts{Lines: 2}, func(l string) error {
		got = append(got, l)
		return nil
	}); err != nil {
		t.Fatalf("LogTail: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"two", "three"}) {
		t.Fatalf("LogTail lines = %q", got)
	}

	// Every command in the exported list must have been exercised.
	seen := map[string]bool{}
	for _, c := range h.called() {
		seen[c] = true
	}
	for _, cmd := range Commands {
		if !seen[cmd] {
			t.Errorf("command %q was never dispatched by this test", cmd)
		}
	}
	// And the arguments must have arrived.
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.usedName != "general (ALT2)" {
		t.Errorf("Use got name %q", h.usedName)
	}
	if !h.repair {
		t.Errorf("Doctor got repair=false")
	}
	if h.ipsetMode != IPSetNone {
		t.Errorf("IPSet got mode %q", h.ipsetMode)
	}
	if h.testArgs["targets"] != "a:443,b:80" || h.testArgs["strategy"] != "general" {
		t.Errorf("Selftest got args %v", h.testArgs)
	}
}

func TestHandlerErrorIsReported(t *testing.T) {
	h := &fakeHandler{failWith: errors.New("pf is on fire")}
	_, c := serve(t, h, ServerOpts{})
	_, err := c.Status(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pf is on fire") {
		t.Fatalf("err = %v, want the handler's message", err)
	}
}

func TestHandlerPanicBecomesAnError(t *testing.T) {
	h := &fakeHandler{panicOn: CmdStatus}
	_, c := serve(t, h, ServerOpts{})
	_, err := c.Status(context.Background())
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("err = %v, want a panic report", err)
	}
	// The server must still be alive.
	if _, err := c.Version(context.Background()); err != nil {
		t.Fatalf("Version after a handler panic: %v", err)
	}
}

func TestUnknownAndMalformedRequests(t *testing.T) {
	h := &fakeHandler{}
	s, c := serve(t, h, ServerOpts{})

	resp, err := c.Do(context.Background(), Request{Cmd: "frobnicate"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.OK || !strings.Contains(resp.Error, "unknown command") {
		t.Fatalf("resp = %+v", resp)
	}
	resp, err = c.Do(context.Background(), Request{Cmd: "  "})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.OK || !strings.Contains(resp.Error, "empty command") {
		t.Fatalf("resp = %+v", resp)
	}
	// Case and whitespace are normalised.
	resp, err = c.Do(context.Background(), Request{Cmd: " STATUS "})
	if err != nil || !resp.OK {
		t.Fatalf("resp = %+v, %v", resp, err)
	}

	// Raw garbage must be answered, not crash the server.
	line := rawExchange(t, s.Path(), "this is not json\n")
	if !strings.Contains(line, "malformed request") {
		t.Fatalf("raw response = %q", line)
	}
	if len(h.called()) == 0 {
		t.Fatalf("handler was never called")
	}
}

func TestUseWithoutNameIsRejectedBeforeTheHandler(t *testing.T) {
	h := &fakeHandler{}
	_, c := serve(t, h, ServerOpts{})
	resp, err := c.Do(context.Background(), Request{Cmd: CmdUse})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.OK || !strings.Contains(resp.Error, "needs a strategy name") {
		t.Fatalf("resp = %+v", resp)
	}
	for _, c := range h.called() {
		if c == CmdUse {
			t.Fatalf("the handler was called despite a missing name")
		}
	}
}

func TestIPSetModeIsValidatedBeforeTheHandler(t *testing.T) {
	h := &fakeHandler{}
	_, c := serve(t, h, ServerOpts{})
	resp, err := c.Do(context.Background(), Request{Cmd: CmdIPSet, Args: map[string]string{"mode": "sometimes"}})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.OK || !strings.Contains(resp.Error, "unknown") {
		t.Fatalf("resp = %+v", resp)
	}
	if len(h.called()) != 0 {
		t.Fatalf("handler was called with an invalid mode: %v", h.called())
	}
}

// ---------------------------------------------------------------------------
// framing
// ---------------------------------------------------------------------------

func TestOversizedRequestLineIsRejected(t *testing.T) {
	h := &fakeHandler{}
	s, _ := serve(t, h, ServerOpts{MaxLine: 512})
	// 4 KiB with no newline: well past the limit, still small enough to fit in
	// the socket buffer so the write cannot block.
	line := rawExchange(t, s.Path(), strings.Repeat("x", 4096))
	if !strings.Contains(line, "too long") {
		t.Fatalf("response = %q, want a line-too-long error", line)
	}
	if len(h.called()) != 0 {
		t.Fatalf("handler ran on an oversized line: %v", h.called())
	}
}

func TestOversizedResponseIsReplacedByAnError(t *testing.T) {
	// The status payload is far bigger than this limit, so the server must
	// answer with an explanation instead of a truncated line.
	h := &fakeHandler{}
	_, c := serve(t, h, ServerOpts{MaxLine: 200})
	_, err := c.Status(context.Background())
	if err == nil || !strings.Contains(err.Error(), "line limit") {
		t.Fatalf("err = %v, want the response-too-large error", err)
	}
}

func TestRequestWithoutTrailingNewlineStillWorks(t *testing.T) {
	h := &fakeHandler{}
	s, _ := serve(t, h, ServerOpts{})
	line := rawExchangeHalfClose(t, s.Path(), `{"cmd":"version"}`)
	var resp Response
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("unmarshal %q: %v", line, err)
	}
	if !resp.OK {
		t.Fatalf("resp = %+v", resp)
	}
}

// ---------------------------------------------------------------------------
// deadlines and concurrency
// ---------------------------------------------------------------------------

func TestServerClosesIdleConnectionAfterReadTimeout(t *testing.T) {
	h := &fakeHandler{}
	s, _ := serve(t, h, ServerOpts{ReadTimeout: 150 * time.Millisecond})
	conn, err := net.Dial("unix", s.Path())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	// Send nothing at all. The server must not wait forever.
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	start := time.Now()
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatalf("read returned data on an idle connection")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("the server held an idle connection for %s", el)
	}
}

func TestSlowHandlerHitsTheDispatchTimeout(t *testing.T) {
	h := &fakeHandler{blockFor: 2 * time.Second}
	_, c := serve(t, h, ServerOpts{HandlerTimeout: 100 * time.Millisecond})
	start := time.Now()
	_, err := c.Status(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("err = %v, want the handler timeout", err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("the dispatch timeout took %s to fire", el)
	}
}

func TestClientDeadlineOnAWedgedHandler(t *testing.T) {
	h := &fakeHandler{blockFor: 3 * time.Second}
	_, c := serve(t, h, ServerOpts{HandlerTimeout: 10 * time.Second})
	start := time.Now()
	_, err := c.WithTimeout(200 * time.Millisecond).Status(context.Background())
	if err == nil {
		t.Fatalf("a wedged handler produced no client error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want a client timeout", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("the client waited %s despite a 200ms timeout", el)
	}
}

func TestCancelledContextAbortsTheCall(t *testing.T) {
	h := &fakeHandler{blockFor: 2 * time.Second}
	_, c := serve(t, h, ServerOpts{HandlerTimeout: 10 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if _, err := c.Status(ctx); err == nil {
		t.Fatalf("a cancelled context produced no error")
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("cancellation took %s", el)
	}
}

func TestConcurrentClients(t *testing.T) {
	h := &fakeHandler{logHistory: []string{"a", "b"}}
	_, c := serve(t, h, ServerOpts{})
	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n*3)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := context.Background()
			if _, err := c.Status(ctx); err != nil {
				errs <- fmt.Errorf("status %d: %w", i, err)
			}
			if _, err := c.Stats(ctx); err != nil {
				errs <- fmt.Errorf("stats %d: %w", i, err)
			}
			if err := c.LogTail(ctx, LogTailOpts{Lines: 2}, func(string) error { return nil }); err != nil {
				errs <- fmt.Errorf("logtail %d: %w", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := len(h.called()); got != n*3 {
		t.Fatalf("handler saw %d calls, want %d", got, n*3)
	}
}

// ---------------------------------------------------------------------------
// logtail streaming
// ---------------------------------------------------------------------------

func TestLogTailFollowStreamsAndStopsOnClientError(t *testing.T) {
	h := &fakeHandler{logHistory: []string{"h1", "h2"}}
	_, c := serve(t, h, ServerOpts{})
	stop := errors.New("enough")
	var got []string
	err := c.LogTail(context.Background(), LogTailOpts{Follow: true}, func(l string) error {
		got = append(got, l)
		if len(got) >= 5 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) {
		t.Fatalf("LogTail err = %v, want the callback's error", err)
	}
	if len(got) < 5 || got[0] != "h1" || got[1] != "h2" {
		t.Fatalf("lines = %q", got)
	}
	if !strings.HasPrefix(got[2], "live-") {
		t.Fatalf("expected live lines after the history, got %q", got)
	}
}

func TestLogTailFollowStopsWhenTheClientDisconnects(t *testing.T) {
	h := &fakeHandler{}
	_, c := serve(t, h, ServerOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- c.LogTail(ctx, LogTailOpts{Follow: true}, func(string) error { return nil })
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("LogTail after cancel = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("LogTail did not return after the context was cancelled")
	}
}

func TestLogTailRejectsABadLineCount(t *testing.T) {
	h := &fakeHandler{}
	_, c := serve(t, h, ServerOpts{})
	resp, err := c.Do(context.Background(), Request{Cmd: CmdLogtail, Args: map[string]string{"lines": "-4"}})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.OK || !strings.Contains(resp.Error, "non-negative") {
		t.Fatalf("resp = %+v", resp)
	}
}

// ---------------------------------------------------------------------------
// socket lifecycle
// ---------------------------------------------------------------------------

func TestSocketPermissions(t *testing.T) {
	s, _ := serve(t, &fakeHandler{}, ServerOpts{})
	fi, err := os.Lstat(s.Path())
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket (mode %s)", s.Path(), fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm != SocketMode {
		t.Fatalf("mode = %#o, want %#o", perm, SocketMode)
	}
}

func TestStaleSocketIsRemoved(t *testing.T) {
	path := sockPath(t)
	// Leave a bound-then-abandoned socket file behind, exactly what a SIGKILLed
	// daemon leaves.
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	ln.SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the stale socket did not survive: %v", err)
	}
	_, c := serve(t, &fakeHandler{}, ServerOpts{Path: path})
	if _, err := c.Version(context.Background()); err != nil {
		t.Fatalf("Version over the reclaimed socket: %v", err)
	}
}

func TestSecondServerRefusesALiveSocket(t *testing.T) {
	s, _ := serve(t, &fakeHandler{}, ServerOpts{})
	other := NewServer(&fakeHandler{}, ServerOpts{Path: s.Path(), Group: "-"})
	err := other.Listen()
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("Listen on a live socket = %v, want ErrAlreadyRunning", err)
	}
	// The live socket must still work.
	c := NewClient(s.Path())
	if _, err := c.Version(context.Background()); err != nil {
		t.Fatalf("Version after the refused Listen: %v", err)
	}
}

func TestListenRefusesANonSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s := NewServer(&fakeHandler{}, ServerOpts{Path: path, Group: "-"})
	err := s.Listen()
	if err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("Listen = %v, want a refusal", err)
	}
}

func TestServeBeforeListen(t *testing.T) {
	s := NewServer(&fakeHandler{}, ServerOpts{Path: sockPath(t), Group: "-"})
	if err := s.Serve(); err == nil {
		t.Fatalf("Serve before Listen returned nil")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestClientAgainstNothing(t *testing.T) {
	c := NewClient(filepath.Join(t.TempDir(), "absent")).WithTimeout(time.Second)
	_, err := c.Status(context.Background())
	if !IsNotRunning(err) {
		t.Fatalf("err = %v, want ErrNotRunning", err)
	}
	if IsPermissionDenied(err) {
		t.Fatalf("a missing socket must not look like a permission problem")
	}
}

func TestClientAfterServerClose(t *testing.T) {
	path := sockPath(t)
	s := NewServer(&fakeHandler{}, ServerOpts{Path: path, Group: "-"})
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	c := NewClient(path).WithTimeout(time.Second)
	if _, err := c.Version(context.Background()); err != nil {
		t.Fatalf("Version: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if _, err := c.Version(context.Background()); !IsNotRunning(err) {
		t.Fatalf("err after Close = %v, want ErrNotRunning", err)
	}
}

// ---------------------------------------------------------------------------
// JSON shape stability
// ---------------------------------------------------------------------------

// TestJSONShapeStability pins the wire format. zaprctl --json output is consumed
// by scripts, so a renamed or dropped key is a breaking change and has to be a
// deliberate edit of this test.
func TestJSONShapeStability(t *testing.T) {
	cases := []struct {
		name string
		v    any
		keys []string
	}{
		{"Request", Request{Cmd: "x", Args: map[string]string{"a": "b"}}, []string{"args", "cmd"}},
		{"Response", Response{OK: true, Error: "e", Data: json.RawMessage(`1`), More: true},
			[]string{"data", "error", "more", "ok"}},
		{"VersionData", VersionData{Version: "v", Go: "g", PID: 1, Started: "s", Binary: "b"},
			[]string{"binary", "go", "pid", "started", "version"}},
		{"StatsData", StatsData{Transport: "t"}, []string{
			"bytes_in", "bytes_out", "degraded", "desyncs", "errors", "flows_active", "flows_total",
			"matched", "pkts_dropped", "pkts_in", "pkts_inject", "pkts_out", "queue_drop", "restarts", "transport"}},
		{"CapsData", CapsData{Transport: "t", Reason: "r", Strategy: "s", Unsupported: []string{"u"}}, []string{
			"drop_original", "fooling", "frag", "inject", "ip_id", "ipv6_exthdr", "per_packet_ttl",
			"reason", "segment", "seq", "strategy", "tlsrec", "transport", "udp", "unsupported"}},
		{"PFData", PFData{Anchor: "a", Token: "1", Drift: "d", LastVerify: "l"},
			[]string{"anchor", "anchor_referenced", "drift", "enabled", "last_verify", "rule_lines", "token"}},
		{"StatusData", StatusData{
			Version: "v", Strategy: "s", StrategyPath: "p", Transport: "t", TransportReason: "r",
			WindowTCP: []string{"1"}, WindowUDP: []string{"2"}, Unsupported: []string{"u"},
			IPSet: "loaded", LogPath: "l", DataDir: "d", Warnings: []string{"w"},
		}, []string{
			"block_quic", "caps", "data_dir", "datapath_uptime_sec", "hosts_entries", "ipset", "log_path",
			"pf", "pid", "profiles", "running", "stats", "strategy", "strategy_path", "transport",
			"transport_reason", "unsupported", "uptime_sec", "version", "warnings", "window_tcp", "window_udp"}},
		{"StrategyInfo", StrategyInfo{Name: "n", Path: "p", Description: "d", Summary: "s",
			Ops: []string{"o"}, Unsupported: []string{"u"}},
			[]string{"active", "description", "name", "ops", "path", "profiles", "summary", "unsupported"}},
		{"ListData", ListData{Active: "a", Transport: "t", Dir: "d", Strategies: []StrategyInfo{}},
			[]string{"active", "dir", "strategies", "transport"}},
		{"UseData", UseData{Strategy: "s", Path: "p", Unsupported: []string{"u"}, Warnings: []string{"w"}},
			[]string{"path", "restarted", "strategy", "unsupported", "warnings"}},
		{"Check", Check{Name: "n", Severity: "info", Detail: "d", Fix: "f"},
			[]string{"detail", "fix", "name", "ok", "severity"}},
		{"DoctorData", DoctorData{Version: "v", Transport: "t", Checks: []Check{}, Repaired: []string{"r"},
			JournalPath: "j"}, []string{
			"checks", "daemon_running", "journal_path", "journal_pending", "repaired", "root", "transport", "uid", "version"}},
		{"TestTarget", TestTarget{Target: "t", SNI: "s", Detail: "d"},
			[]string{"desynced", "detail", "ms", "ok", "sni", "target"}},
		{"SelftestData", SelftestData{Strategy: "s", Transport: "t", Targets: []TestTarget{}, Warnings: []string{"w"}},
			[]string{"ok", "strategy", "targets", "transport", "warnings"}},
		{"HostsData", HostsData{Path: "p", SourcePath: "s", Warnings: []string{"w"}},
			[]string{"applied", "dns_flushed", "entries", "names", "path", "source_path", "warnings"}},
		{"IPSetData", IPSetData{Mode: "m", Previous: "p", Path: "x"},
			[]string{"backup_present", "entries", "mode", "path", "previous", "reloaded"}},
		{"LogChunk", LogChunk{Lines: []string{"l"}}, []string{"lines"}},
	}
	for _, tc := range cases {
		b, err := json.Marshal(tc.v)
		if err != nil {
			t.Fatalf("%s: marshal: %v", tc.name, err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.name, err)
		}
		var got []string
		for k := range m {
			got = append(got, k)
		}
		sort.Strings(got)
		want := append([]string(nil), tc.keys...)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s keys = %v, want %v", tc.name, got, want)
		}
	}
}

func TestResponseHelpers(t *testing.T) {
	if err := (Response{OK: true}).Err(); err != nil {
		t.Fatalf("Err on an OK response = %v", err)
	}
	if err := (Response{}).Err(); err == nil || !strings.Contains(err.Error(), "without a reason") {
		t.Fatalf("Err on a bare failure = %v", err)
	}
	if err := (Response{Error: "nope"}).Err(); err == nil || err.Error() != "nope" {
		t.Fatalf("Err = %v", err)
	}
	var v StatsData
	if err := (Response{OK: true}).Decode(&v); err == nil {
		t.Fatalf("Decode of an empty payload succeeded")
	}
	if err := (Response{OK: true, Data: json.RawMessage(`{"pkts_in":5}`)}).Decode(&v); err != nil || v.PktsIn != 5 {
		t.Fatalf("Decode = %+v, %v", v, err)
	}
	if err := (Response{OK: true, Data: json.RawMessage(`{`)}).Decode(&v); err == nil {
		t.Fatalf("Decode of broken JSON succeeded")
	}
}

func TestRequestArgHelpers(t *testing.T) {
	r := Request{Args: map[string]string{"repair": "YES", "follow": "0", "name": " x "}}
	if !r.Bool("repair") {
		t.Errorf("Bool(repair) = false")
	}
	if r.Bool("follow") || r.Bool("absent") {
		t.Errorf("Bool returned true for %q / absent", r.Arg("follow"))
	}
	if got := r.Arg("name"); got != " x " {
		t.Errorf("Arg(name) = %q", got)
	}
	if got := (Request{}).Arg("x"); got != "" {
		t.Errorf("Arg on a nil map = %q", got)
	}
}

func TestSortedUnique(t *testing.T) {
	got := SortedUnique([]string{"b", "a", "b", "", "c"})
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("SortedUnique = %q", got)
	}
	if SortedUnique(nil) != nil {
		t.Fatalf("SortedUnique(nil) must stay nil")
	}
}

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{-time.Second, "0.0s"},
		{1500 * time.Millisecond, "1.5s"},
		{90 * time.Second, "1m30s"},
		{3*time.Hour + 4*time.Minute, "3h04m"},
		{50*time.Hour + 30*time.Minute, "2d02h30m"},
	}
	for _, tc := range cases {
		if got := FormatDuration(tc.d); got != tc.want {
			t.Errorf("FormatDuration(%s) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// raw helpers
// ---------------------------------------------------------------------------

// rawExchange writes payload verbatim and returns the first response line.
func rawExchange(t *testing.T, path, payload string) string {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	// A rejected oversized line makes the server close early, so a short write
	// is expected and must not fail the test.
	_, _ = conn.Write([]byte(payload))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		t.Fatalf("read response: %v", err)
	}
	return strings.TrimSpace(line)
}

// rawExchangeHalfClose sends payload without a newline and half-closes, which is
// how a client signals "that is the whole request".
func rawExchangeHalfClose(t *testing.T, path, payload string) string {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatalf("not a unix conn")
	}
	if err := uc.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := uc.Write([]byte(payload)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := uc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	line, err := bufio.NewReader(uc).ReadString('\n')
	if err != nil && line == "" {
		t.Fatalf("read response: %v", err)
	}
	return strings.TrimSpace(line)
}
