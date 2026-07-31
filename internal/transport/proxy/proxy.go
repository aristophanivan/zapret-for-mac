// Package proxy implements the socket-level transport: pf `rdr pass` redirects
// the TCP port window to a local listener, the listener recovers the original
// destination with ioctl(DIOCNATLOOK) on /dev/pf, dials the real server itself
// and relays the bytes — cutting the request into segments on the way, the way
// zapret's tpws does on macOS.
//
// It is the degraded fallback of the two transports, and the one a cautious user
// can pick deliberately: it needs no packet injection, no BPF write, no tunnel
// interface, and it cannot desync anything below the byte stream. Caps() is
// desync.ProxyCaps() — Segment, TLSRec and DropOriginal only.
//
// # WHY THE RULESET LOOKS THE WAY IT DOES
//
// macOS pf cannot redirect an outbound packet, so a locally originated
// connection is first forced onto lo0 with `route-to (lo0 127.0.0.1)` and then
// `rdr`-ed on lo0 to the listener. netcfg.RedirectRules renders both rules; the
// only thing this package insists on is `user { > root }` on the route-to rule.
// That clause is not an option here but a hard requirement: without it the
// proxy's own upstream connections match the same rule and are redirected back
// into the proxy, which accepts them, dials again, and so on until the process
// runs out of descriptors.
//
// # WHAT IS NOT PROXIED
//
// UDP. A `rdr` to a local listener plus DIOCNATLOOK recovers a TCP connection's
// destination; QUIC, Discord voice and the STUN family need the divert transport.
// The strategy's UDP window is therefore ignored here, and Start says so once.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/engine"
	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
	"github.com/naladwepo/zapret-for-mac/internal/transport"
)

// Defaults for everything transport.Config does not carry.
const (
	// DefaultAnchor is the pf anchor the ruleset is loaded into.
	DefaultAnchor = "zapret-mac"
	// DefaultStateDir holds the pf token, the rollback journal and the
	// byte-exact backups of the files netcfg patches.
	DefaultStateDir = "/var/db/zapret-mac"
	// DefaultProxyPort is the local listener port used when Config.ProxyPort is
	// zero. It matches zapret's own tpws default.
	DefaultProxyPort = 10800
	// DefaultMaxConns bounds the number of connections being relayed at once.
	// Each one costs two descriptors and two goroutines, so the pool is what
	// keeps a burst of connections from exhausting the process' fd limit.
	DefaultMaxConns = 512
)

// Timeouts. All of them are deliberately short: this transport sits in the
// middle of every browser connection in the port window, so a stall here is
// indistinguishable from a broken network.
const (
	// firstPayloadTimeout is how long to wait for the client's first bytes
	// before giving up on desyncing and just splicing. It must not stall a
	// protocol where the server speaks first (SMTP, some IMAP setups, any
	// server-hello-first protocol running on a port in the window).
	firstPayloadTimeout = 1500 * time.Millisecond
	// firstPayloadMax bounds the first read. A TLS ClientHello is a few
	// kilobytes; nothing the desync ops look at lives beyond this, and anything
	// past it is relayed by the splice loop anyway.
	firstPayloadMax = 32 * 1024
	// dialTimeout bounds the upstream connect.
	dialTimeout = 10 * time.Second
	// relayBuf is the size of each direction's copy buffer.
	relayBuf = 32 * 1024
	// closeWait bounds how long Close waits for in-flight relays to finish
	// before returning; the pf teardown must not be held up by a stuck peer.
	closeWait = 3 * time.Second
	// relayIdleTimeout is the default Options.RelayIdleTimeout: how long a
	// spliced connection may move no bytes at all before it is torn down. It has
	// to be well above any legitimate think time (a keep-alive connection between
	// two page loads, a long-polling request) and well below "forever".
	relayIdleTimeout = 120 * time.Second
	// acceptBackoff is how long the accept loop pauses after a transient
	// failure (EMFILE, ENFILE, ECONNABORTED) so it does not spin.
	acceptBackoff = 20 * time.Millisecond
)

// Options carries what transport.Config does not: which pf anchor and state
// directory to use, where to log, and the seams the tests and `zaprctl` need.
// The zero value is valid and means "all defaults".
type Options struct {
	// Anchor is the pf anchor name. Empty means DefaultAnchor.
	Anchor string
	// StateDir is where the pf token, journal and backups live. Empty means
	// DefaultStateDir.
	StateDir string
	// Logf receives progress and diagnostics. Nil discards them.
	Logf func(format string, args ...any)
	// DryRun validates the pf ruleset and logs what would happen without
	// changing the packet filter. The listener is still opened, so a dry run
	// still proves the port is free.
	DryRun bool

	// PF, when non-nil, is used instead of one built from Anchor/StateDir. The
	// daemon passes its own so that both transports and `zaprctl doctor` share
	// one pf reference and one journal.
	PF *netcfg.PF
	// NoPF disables all pf wiring. Nothing is redirected, so the listener only
	// serves connections something else steered to it; it is how the datapath
	// is exercised without root.
	NoPF bool
	// KeepAnchorStatements leaves the `anchor`/`rdr-anchor` lines in
	// /etc/pf.conf on stop. Removing them means reloading the main ruleset,
	// which flushes anchors other services installed at runtime; a daemon that
	// restarts often may prefer to leave the (empty, harmless) statements in
	// place and let `zaprctl doctor --repair` remove them.
	KeepAnchorStatements bool

	// Lookup overrides the /dev/pf original-destination recovery. The tests use
	// it; in production it stays nil and OpenPFLookup is used.
	Lookup DestLookup

	// ExcludeTable and TargetTable are pf tables constraining which
	// destinations are redirected (zapret's <nozapret> and its ipset mode).
	// Empty means unconstrained.
	ExcludeTable string
	TargetTable  string
	// Ifaces optionally restricts the route-to rule to these outbound
	// interfaces (zapret's IFACE_WAN).
	Ifaces []string
	// IPv6 also installs the inet6 ruleset and binds the link-local
	// fe80::1%lo0 that zapret's pf.sh redirects to. It is off by default
	// because the inet6 redirect could not be exercised end to end here (that
	// needs root and a v6 uplink); the listener on [::1] is opened either way,
	// so switching it on is the only change needed once it has been.
	IPv6 bool

	// MaxConns bounds concurrent relays. Zero means DefaultMaxConns.
	MaxConns int
	// FirstPayloadTimeout overrides how long a connection waits for the
	// client's first bytes before being relayed without a desync. Zero means
	// firstPayloadTimeout. It is tunable because the cost is asymmetric: too
	// long delays every protocol whose server speaks first by that much, too
	// short misses the request a strategy was written for.
	FirstPayloadTimeout time.Duration
	// RelayIdleTimeout bounds how long a spliced connection may sit with no
	// bytes moving in either direction before both sockets are closed. Zero means
	// relayIdleTimeout. Without a bound, a peer that completes the handshake and
	// then goes silent forever holds two descriptors, two goroutines and a slot in
	// the MaxConns pool for the rest of the process' life; MaxConns such peers
	// make every subsequent connection on the redirected ports fail.
	RelayIdleTimeout time.Duration
}

// Transport is the socket-level transport. It implements transport.Transport.
type Transport struct {
	cfg  transport.Config
	opts Options
	logf func(string, ...any)

	eng  *engine.Engine
	port int

	mu    sync.Mutex
	strat *strategy.Strategy
	lns   []*net.TCPListener
	undo  []undoStep
	// lookup recovers original destinations. One supplied through
	// Options.Lookup belongs to the caller and is never closed here; one this
	// Transport opened itself has its Close on the undo stack.
	lookup DestLookup
	pf     *netcfg.PF
	// v6Target is the IPv6 loopback address the listener actually bound, and so
	// the address the inet6 rdr rule must point at: "fe80::1", "::1" or "" when
	// no IPv6 loopback could be bound at all.
	v6Target string
	started  bool
	closed   bool

	closing atomic.Bool
	sem     chan struct{}
	wg      sync.WaitGroup

	st counters
}

// undoStep is one reversible side effect, named so teardown can log what it is
// undoing even when the daemon was killed and restarted.
type undoStep struct {
	what string
	fn   func() error
}

// counters are the Stats fields, kept as atomics because every relay goroutine
// updates them.
type counters struct {
	flowsActive atomic.Int64
	flowsTotal  atomic.Int64
	payloads    atomic.Int64
	writes      atomic.Int64
	blocked     atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
	matched     atomic.Int64
	desyncs     atomic.Int64
	errs        atomic.Int64
	refused     atomic.Int64
	// idleClosed counts relays torn down by the idle watchdog, so an operator can
	// tell "the pool is full because of stalled peers" from "the pool is full
	// because the machine is busy".
	idleClosed atomic.Int64
}

// compile-time proof that the contract is satisfied.
var _ transport.Transport = (*Transport)(nil)

// New builds a proxy transport with default options.
func New(cfg transport.Config) (*Transport, error) {
	return NewWithOptions(cfg, Options{})
}

// NewWithOptions builds a proxy transport.
//
// It validates everything that can be validated without touching the system, so
// a misconfiguration is reported before any privileged side effect happens.
func NewWithOptions(cfg transport.Config, opts Options) (*Transport, error) {
	if cfg.Engine == nil {
		return nil, errors.New("proxy: Config.Engine is required")
	}
	if cfg.Strategy == nil {
		return nil, errors.New("proxy: Config.Strategy is required")
	}
	port := cfg.ProxyPort
	if port == 0 {
		port = DefaultProxyPort
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("proxy: invalid listener port %d", cfg.ProxyPort)
	}
	if opts.Anchor == "" {
		opts.Anchor = DefaultAnchor
	}
	if opts.StateDir == "" {
		opts.StateDir = DefaultStateDir
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = DefaultMaxConns
	}
	if opts.FirstPayloadTimeout <= 0 {
		opts.FirstPayloadTimeout = firstPayloadTimeout
	}
	if opts.RelayIdleTimeout <= 0 {
		opts.RelayIdleTimeout = relayIdleTimeout
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	t := &Transport{
		cfg:    cfg,
		opts:   opts,
		logf:   logf,
		eng:    cfg.Engine,
		port:   port,
		strat:  cfg.Strategy,
		lookup: opts.Lookup,
		sem:    make(chan struct{}, opts.MaxConns),
	}
	if _, err := t.rulesFor(cfg.Strategy); err != nil {
		return nil, err
	}
	return t, nil
}

// Name implements transport.Transport.
func (t *Transport) Name() string { return "proxy" }

// Caps implements transport.Transport: byte-level tricks only.
func (t *Transport) Caps() desync.Caps { return desync.ProxyCaps() }

// Port reports the local listener port actually in use.
func (t *Transport) Port() int { return t.port }

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

// Start opens the listener, installs the pf ruleset and serves until ctx is
// cancelled or the accept loop fails.
//
// Setup order is listener -> /dev/pf -> pf.conf anchor statements -> pfctl -E ->
// anchor ruleset, and every step pushes its inverse onto an undo stack that Close
// (or a failed Start) unwinds in reverse. Nothing here is left behind on a clean
// stop, and everything that could be left behind by a SIGKILL is in the netcfg
// journal for `zaprctl doctor --repair`.
func (t *Transport) Start(ctx context.Context) error {
	if err := t.setup(); err != nil {
		// Undo whatever setup managed before failing: Close may never be called
		// if Start returned an error.
		if uerr := t.unwind(); uerr != nil {
			return errors.Join(err, uerr)
		}
		return err
	}
	return t.serve(ctx)
}

// setup performs every privileged step, in order.
func (t *Transport) setup() error {
	t.mu.Lock()
	if t.started {
		t.mu.Unlock()
		return errors.New("proxy: already started")
	}
	if t.closed {
		t.mu.Unlock()
		return errors.New("proxy: transport is closed")
	}
	t.started = true
	strat := t.strat
	t.mu.Unlock()

	t.warnEnvironment(strat)

	if err := t.listen(); err != nil {
		return err
	}
	if err := t.openLookup(); err != nil {
		return err
	}
	if err := t.wirePF(strat); err != nil {
		return err
	}
	return nil
}

// warnEnvironment reports the conditions that make this transport pointless
// before it silently fails to help.
func (t *Transport) warnEnvironment(strat *strategy.Strategy) {
	if len(strat.WindowUDP) > 0 {
		t.logf("proxy: the strategy's UDP window (%d range(s)) is ignored: a userspace "+
			"relay cannot proxy UDP; use the divert transport for QUIC, Discord voice and STUN",
			len(strat.WindowUDP))
	}
	if t.cfg.BlockQUIC {
		t.logf("proxy: BlockQUIC is set but this transport installs no UDP rules; QUIC will " +
			"NOT be blocked, so a browser may keep using it and bypass the relay entirely")
	}
	if !t.cfg.ExemptRoot {
		t.logf("proxy: Config.ExemptRoot is false, but `user { > root }` is installed anyway: " +
			"without it the relay's own upstream connections are redirected back into itself")
	}
	iface, gw, _, _, err := netcfg.DefaultRoute()
	if err != nil {
		t.logf("proxy: cannot read the IPv4 default route: %v", err)
		return
	}
	if netcfg.IsTunnelInterface(iface) {
		t.logf("proxy: WARNING: the IPv4 default route points at tunnel interface %s (gateway %v) — "+
			"a VPN owns the uplink. Everything already travels inside the tunnel, so redirecting "+
			"the port window through this relay changes nothing the DPI on the other side of the "+
			"tunnel can see. Disconnect the VPN, or use its split-tunnel mode, before judging "+
			"whether a strategy works.", iface, gw)
	}
}

// listen binds the loopback listeners.
//
// 127.0.0.1 is required: it is the inet rdr target. [::1] is opened when it is
// available, and its absence is not fatal — a machine with IPv6 disabled must
// still get a working IPv4 relay.
//
// With Options.IPv6 the link-local fe80::1%lo0 is bound as well, because that,
// not ::1, is where zapret's own pf.sh points its inet6 redirect:
//
//	rdr on lo0 inet6 proto tcp from !::1 to any port $port -> fe80::1 port $1
//
// Whichever of the two actually bound becomes the rdr target, so the rule always
// points at an address something is listening on.
func (t *Transport) listen() error {
	v4, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: t.port})
	if err != nil {
		return fmt.Errorf("proxy: listening on 127.0.0.1:%d: %w", t.port, err)
	}
	t.addListener(v4)
	t.logf("proxy: listening on %s", v4.Addr())

	target := ""
	if t.opts.IPv6 {
		// fe80::1 needs its scope: a link-local address is only meaningful
		// together with the interface it lives on.
		if ln, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("fe80::1"), Zone: "lo0", Port: t.port}); err != nil {
			t.logf("proxy: not listening on [fe80::1%%lo0]:%d (%v); falling back to [::1]", t.port, err)
		} else {
			t.addListener(ln)
			t.logf("proxy: listening on %s", ln.Addr())
			target = "fe80::1"
		}
	}
	if ln, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback, Port: t.port}); err != nil {
		t.logf("proxy: not listening on [::1]:%d (%v)", t.port, err)
	} else {
		t.addListener(ln)
		t.logf("proxy: listening on %s", ln.Addr())
		if target == "" {
			target = "::1"
		}
	}

	t.mu.Lock()
	t.v6Target = target
	t.mu.Unlock()
	if t.opts.IPv6 && target == "" {
		t.logf("proxy: Options.IPv6 is set but no IPv6 loopback address could be bound; " +
			"the inet6 redirect will not be installed")
	}
	return nil
}

// addListener records a listener and its teardown step.
//
// The teardown step tolerates an already-closed listener: serve closes them on
// context cancellation and Close closes them again, and neither wants to hear
// about the other having got there first.
func (t *Transport) addListener(ln *net.TCPListener) {
	closeOnce := func() error {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
		return nil
	}
	t.mu.Lock()
	t.lns = append(t.lns, ln)
	t.undo = append(t.undo, undoStep{what: "close listener " + ln.Addr().String(), fn: closeOnce})
	t.mu.Unlock()
}

// openLookup opens /dev/pf unless a lookup was injected.
func (t *Transport) openLookup() error {
	t.mu.Lock()
	have := t.lookup != nil
	t.mu.Unlock()
	if have {
		return nil
	}
	if t.opts.NoPF {
		return errors.New("proxy: NoPF is set but no Options.Lookup was supplied; " +
			"without pf there is nothing to recover an original destination from")
	}
	l, err := OpenPFLookup()
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.lookup = l
	t.undo = append(t.undo, undoStep{what: "close " + netcfg.PfDevicePath, fn: l.Close})
	t.mu.Unlock()
	return nil
}

// wirePF patches the main ruleset, takes a pf reference and loads the anchor's
// rules, pushing each inverse onto the undo stack as it goes.
func (t *Transport) wirePF(strat *strategy.Strategy) error {
	if t.opts.NoPF {
		t.logf("proxy: pf wiring disabled (Options.NoPF); nothing will be redirected to the listener")
		return nil
	}
	rules, err := t.rulesFor(strat)
	if err != nil {
		return err
	}

	pf := t.opts.PF
	if pf == nil {
		pf = netcfg.NewPF(t.opts.Anchor, netcfg.PFOpts{
			StateDir: t.opts.StateDir,
			DryRun:   t.opts.DryRun,
			Logf:     t.logf,
		})
	}
	t.mu.Lock()
	t.pf = pf
	t.mu.Unlock()

	if err := pf.Preflight(); err != nil {
		return fmt.Errorf("proxy: pf preflight failed: %w", err)
	}

	patched, err := pf.EnsureAnchorStatements()
	if err != nil {
		return fmt.Errorf("proxy: making pf evaluate anchor %q: %w", t.opts.Anchor, err)
	}
	if !t.opts.KeepAnchorStatements {
		t.push("remove the anchor statements from "+pf.PfConfPath(), pf.RemoveAnchorStatements)
	} else if patched {
		t.logf("proxy: leaving the anchor statements in %s (Options.KeepAnchorStatements); "+
			"`zaprctl doctor --repair` removes them", pf.PfConfPath())
	}

	if err := pf.Enable(); err != nil {
		return fmt.Errorf("proxy: enabling pf: %w", err)
	}
	t.push("release the pf reference", pf.Release)

	if err := t.loadRules(pf, rules); err != nil {
		return err
	}
	t.push("flush anchor "+t.opts.Anchor, pf.FlushRules)
	return nil
}

// loadRules installs the ruleset, falling back to the IPv4-only half if the
// combined one does not parse.
//
// The fallback exists because the inet6 redirect is the one rule that could not
// be verified on the development machine: a v6 `rdr` to ::1 on lo0 is accepted
// by pfctl in principle, but if this kernel disagrees the IPv4 relay must still
// come up rather than the whole transport failing.
func (t *Transport) loadRules(pf *netcfg.PF, rules ruleSet) error {
	if rules.both != rules.v4 {
		if err := pf.LoadRules(rules.both); err == nil {
			return nil
		} else {
			t.logf("proxy: the combined inet/inet6 ruleset was rejected (%v); retrying with IPv4 only", err)
		}
	}
	if err := pf.LoadRules(rules.v4); err != nil {
		return fmt.Errorf("proxy: loading the redirect ruleset into anchor %q: %w", t.opts.Anchor, err)
	}
	return nil
}

// push adds an undo step.
func (t *Transport) push(what string, fn func() error) {
	t.mu.Lock()
	t.undo = append(t.undo, undoStep{what: what, fn: fn})
	t.mu.Unlock()
}

// unwind runs the undo stack in reverse, keeping going after a failure so one
// stuck step cannot strand the rest.
func (t *Transport) unwind() error {
	t.mu.Lock()
	steps := t.undo
	t.undo = nil
	t.mu.Unlock()

	var errs []error
	for i := len(steps) - 1; i >= 0; i-- {
		s := steps[i]
		if err := s.fn(); err != nil {
			// pf.conf drift is reported by netcfg as an error even though the
			// removal succeeded; keep it visible but do not treat it as a
			// failure to clean up.
			if errors.Is(err, netcfg.ErrPfConfDrift) {
				t.logf("proxy: %s: %v", s.what, err)
				continue
			}
			errs = append(errs, fmt.Errorf("proxy: %s: %w", s.what, err))
			continue
		}
		t.logf("proxy: undone: %s", s.what)
	}
	return errors.Join(errs...)
}

// ruleSet holds the anchor ruleset in its two forms.
type ruleSet struct {
	// v4 is the inet-only ruleset, always usable.
	v4 string
	// both is v4 plus the inet6 rules, equal to v4 when IPv6 is off.
	both string
}

// rulesFor renders the anchor ruleset for a strategy. It is also the validation
// New performs, which is why it returns a descriptive error for an empty window
// instead of an empty ruleset: an empty port list in pf means "no rule", i.e. a
// transport that silently relays nothing.
func (t *Transport) rulesFor(s *strategy.Strategy) (ruleSet, error) {
	if s == nil {
		return ruleSet{}, errors.New("proxy: no strategy")
	}
	ports := portRanges(s.WindowTCP)
	if len(ports) == 0 {
		return ruleSet{}, fmt.Errorf("proxy: strategy %q has an empty TCP port window; "+
			"there would be nothing to redirect (the UDP window cannot be proxied)", s.Name)
	}
	base := netcfg.RedirOpts{
		ListenAddr:   "127.0.0.1",
		ListenPort:   t.port,
		TCPPorts:     ports,
		ExcludeTable: t.opts.ExcludeTable,
		TargetTable:  t.opts.TargetTable,
		Ifaces:       t.opts.Ifaces,
		// Forced on, not taken from Config.ExemptRoot: see the package comment.
		ExemptRoot: true,
	}
	v4 := netcfg.RedirectRules(base)
	out := ruleSet{v4: v4, both: v4}
	if t.opts.IPv6 {
		// Before listen() has run there is no bound address yet; use zapret's
		// own choice so New can still validate the ruleset.
		t.mu.Lock()
		target := t.v6Target
		t.mu.Unlock()
		if target == "" && t.started {
			// listen() ran and bound no IPv6 loopback: no inet6 rules at all.
			return out, nil
		}
		if target == "" {
			target = "fe80::1"
		}
		v6opts := base
		v6opts.IPv6 = true
		v6opts.ListenAddr = target
		out.both = mergeRulesets(v4, netcfg.RedirectRules(v6opts))
	}
	return out, nil
}

// portRanges converts a strategy port set into netcfg's shape.
func portRanges(ps strategy.PortSet) []netcfg.PortRange {
	out := make([]netcfg.PortRange, 0, len(ps))
	for _, r := range ps {
		out = append(out, netcfg.PortRange{r.Lo, r.Hi})
	}
	return out
}

// mergeRulesets concatenates two rulesets, dropping a repeated `table <x>
// persist` declaration. Both halves declare the same tables, and pfctl rejects a
// second declaration of one it already has in the same anchor.
func mergeRulesets(a, b string) string {
	seen := make(map[string]bool)
	var out []string
	for _, chunk := range []string{a, b} {
		for _, line := range strings.Split(chunk, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(line), "table ") {
				if seen[strings.TrimSpace(line)] {
					continue
				}
				seen[strings.TrimSpace(line)] = true
			}
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

// Reload swaps the active strategy. Established relays keep running: their
// desync decision was already made when their first payload was written, and the
// engine keeps each flow's cached profile until the flow expires.
//
// When the TCP window changed, the anchor ruleset is reloaded so newly opened
// connections on the new ports are redirected too.
func (t *Transport) Reload(s *strategy.Strategy) error {
	if s == nil {
		return errors.New("proxy: Reload needs a strategy")
	}
	rules, err := t.rulesFor(s)
	if err != nil {
		return err
	}

	t.mu.Lock()
	old := t.strat
	t.strat = s
	pf := t.pf
	started := t.started && !t.closed
	t.mu.Unlock()

	// The engine holds the profile chain the datapath executes; swapping it is
	// what actually changes behaviour. It is idempotent, so a daemon that also
	// calls engine.Reload itself is fine.
	t.eng.Reload(s)

	if pf == nil || !started || t.opts.NoPF {
		t.logf("proxy: strategy reloaded to %q (no pf ruleset to update)", s.Name)
		return nil
	}
	oldRules, oerr := t.rulesFor(old)
	if oerr == nil && oldRules.both == rules.both {
		t.logf("proxy: strategy reloaded to %q; the pf ruleset is unchanged", s.Name)
		return nil
	}
	if err := t.loadRules(pf, rules); err != nil {
		return err
	}
	t.logf("proxy: strategy reloaded to %q and the pf ruleset updated", s.Name)
	return nil
}

// Stats implements transport.Transport.
//
// The packet-level fields are mapped onto what a socket relay can count, and the
// mapping is deliberately conservative rather than flattering:
//
//	PktsIn      first client payloads intercepted (one per connection)
//	PktsOut     Write calls made while applying plans, i.e. TCP segments the
//	            request was cut into
//	PktsInject  always 0: this transport injects nothing
//	PktsDropped connections the `block` op closed without forwarding
//	QueueDrop   connections refused because the relay pool was full
//	BytesIn     bytes relayed client -> server
//	BytesOut    bytes relayed server -> client
func (t *Transport) Stats() transport.Stats {
	return transport.Stats{
		Transport:   t.Name(),
		FlowsActive: t.st.flowsActive.Load(),
		FlowsTotal:  t.st.flowsTotal.Load(),
		PktsIn:      t.st.payloads.Load(),
		PktsOut:     t.st.writes.Load(),
		PktsInject:  0,
		PktsDropped: t.st.blocked.Load(),
		BytesIn:     t.st.bytesIn.Load(),
		BytesOut:    t.st.bytesOut.Load(),
		Desyncs:     t.st.desyncs.Load(),
		Matched:     t.st.matched.Load(),
		Errors:      t.st.errs.Load(),
		// Both numbers describe the same pressure: a connection refused because
		// the pool was full, and a stalled relay the watchdog had to reclaim to
		// free a slot.
		QueueDrop: t.st.refused.Load() + t.st.idleClosed.Load(),
	}
}

// Close stops accepting, waits briefly for in-flight relays and unwinds every
// privileged change in reverse order. It is safe to call twice and safe to call
// without a preceding Start.
func (t *Transport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	lns := t.lns
	t.lns = nil
	t.mu.Unlock()

	t.closing.Store(true)
	for _, ln := range lns {
		_ = ln.Close()
	}

	// Wait for the relays, but not forever: a peer that never closes must not
	// keep the pf ruleset installed.
	done := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(closeWait):
		t.logf("proxy: %d relay(s) still running after %v; tearing down pf anyway",
			t.st.flowsActive.Load(), closeWait)
	}

	return t.unwind()
}

// ---------------------------------------------------------------------------
// accept / relay
// ---------------------------------------------------------------------------

// serve runs the accept loops and blocks until ctx is cancelled, Close is called
// or an accept fails unrecoverably.
func (t *Transport) serve(ctx context.Context) error {
	t.mu.Lock()
	lns := make([]*net.TCPListener, len(t.lns))
	copy(lns, t.lns)
	t.mu.Unlock()
	if len(lns) == 0 {
		return errors.New("proxy: no listener")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Closing the listeners is what unblocks Accept; ctx cancellation cannot.
	go func() {
		<-ctx.Done()
		t.mu.Lock()
		cur := make([]*net.TCPListener, len(t.lns))
		copy(cur, t.lns)
		t.mu.Unlock()
		for _, ln := range cur {
			_ = ln.Close()
		}
	}()

	errCh := make(chan error, len(lns))
	var loops sync.WaitGroup
	for _, ln := range lns {
		loops.Add(1)
		go func(ln *net.TCPListener) {
			defer loops.Done()
			if err := t.acceptLoop(ctx, ln); err != nil {
				errCh <- err
				cancel()
			}
		}(ln)
	}
	loops.Wait()
	close(errCh)

	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// acceptLoop accepts connections on one listener until it is closed.
func (t *Transport) acceptLoop(ctx context.Context, ln *net.TCPListener) error {
	for {
		c, err := ln.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil || t.closing.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if isTransientAccept(err) {
				t.st.errs.Add(1)
				t.logf("proxy: accept on %s: %v (retrying)", ln.Addr(), err)
				select {
				case <-time.After(acceptBackoff):
					continue
				case <-ctx.Done():
					return nil
				}
			}
			return fmt.Errorf("proxy: accept on %s: %w", ln.Addr(), err)
		}
		select {
		case t.sem <- struct{}{}:
		default:
			// The pool is full. Refusing is better than queueing: a queued
			// connection stalls the browser with no diagnostic, a refused one
			// fails fast and is retried.
			t.st.refused.Add(1)
			t.logf("proxy: relay pool full (%d); refusing %v", t.opts.MaxConns, c.RemoteAddr())
			_ = c.Close()
			continue
		}
		t.wg.Add(1)
		go func() {
			defer func() {
				<-t.sem
				t.wg.Done()
			}()
			t.handle(ctx, c)
		}()
	}
}

// isTransientAccept reports whether an accept error is worth retrying: running
// out of descriptors or a client that vanished mid-handshake is not a reason to
// stop serving the rest of the machine's traffic.
func isTransientAccept(err error) bool {
	for _, e := range []error{unix.EMFILE, unix.ENFILE, unix.ENOMEM, unix.ENOBUFS, unix.ECONNABORTED, unix.EINTR} {
		if errors.Is(err, e) {
			return true
		}
	}
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// handle relays one redirected connection.
//
// Every exit path closes both sockets and forgets the flow: a leaked descriptor
// here is a leak per connection, which on a busy browser session is minutes to
// exhaustion.
func (t *Transport) handle(ctx context.Context, client *net.TCPConn) {
	t.st.flowsActive.Add(1)
	t.st.flowsTotal.Add(1)
	defer t.st.flowsActive.Add(-1)
	defer client.Close()

	from, to, err := endpoints(client)
	if err != nil {
		t.st.errs.Add(1)
		t.logf("proxy: %v", err)
		return
	}

	t.mu.Lock()
	lookup := t.lookup
	t.mu.Unlock()
	if lookup == nil {
		t.st.errs.Add(1)
		t.logf("proxy: no original-destination lookup available; dropping %v", from)
		return
	}

	dst, err := lookup.OrigDst(from, to)
	if err != nil {
		t.st.errs.Add(1)
		if errors.Is(err, ErrNotRedirected) {
			// Somebody connected to the listener directly. Nothing useful can
			// be done: we do not know where they wanted to go.
			t.logf("proxy: %v connected to the listener without a pf redirect; dropping", from)
			return
		}
		t.logf("proxy: recovering the original destination for %v -> %v: %v", from, to, err)
		return
	}
	if t.isSelf(dst) {
		// The loop breaker. It cannot normally trigger, because the route-to
		// rule carries `user { > root }`, but if it ever does the connection
		// must die here rather than recurse.
		t.st.errs.Add(1)
		t.logf("proxy: refusing to relay %v to our own listener %v: pf handed us a loop "+
			"(is `user { > root }` missing from the route-to rule?)", from, dst)
		return
	}

	key := desync.FlowKey{
		Src:     from.Addr().Unmap(),
		Dst:     dst.Addr().Unmap(),
		SrcPort: from.Port(),
		DstPort: dst.Port(),
		Proto:   proto.IPProtoTCP,
	}
	defer t.eng.Forget(key)

	// The upstream connection is opened before the client's first bytes are
	// read, so a protocol whose server speaks first can be relayed at all. The
	// cost is that the `block` op still completes a TCP handshake with the
	// server before closing it: at packet level nfqws can suppress the SYN, a
	// socket-level relay cannot.
	up, err := t.dial(ctx, dst)
	if err != nil {
		t.st.errs.Add(1)
		t.logf("proxy: dialling %v for %v: %v", dst, from, err)
		return
	}
	defer up.Close()

	if err := client.SetNoDelay(true); err != nil {
		t.logf("proxy: TCP_NODELAY on the client socket %v: %v", from, err)
	}
	w, err := NewConnWriter(up)
	if err != nil {
		t.st.errs.Add(1)
		t.logf("proxy: preparing the upstream socket to %v: %v", dst, err)
		return
	}

	payload, readErr := readFirst(client, t.opts.FirstPayloadTimeout)
	if len(payload) > 0 {
		t.st.payloads.Add(1)
		t.st.bytesIn.Add(int64(len(payload)))
		if stop := t.applyPlan(w, key, payload, from, dst); stop {
			return
		}
	} else if readErr != nil && !isTimeout(readErr) {
		// The client went away (or reset) before saying anything.
		if !errors.Is(readErr, io.EOF) {
			t.logf("proxy: reading the first request bytes from %v: %v", from, readErr)
		}
		return
	} else if len(payload) == 0 {
		t.logf("proxy: %v -> %v sent nothing within %v; relaying without a desync "+
			"(the server speaks first)", from, dst, t.opts.FirstPayloadTimeout)
	}

	// Clear the read deadline the first read installed, then splice.
	if err := client.SetReadDeadline(time.Time{}); err != nil {
		t.logf("proxy: clearing the read deadline for %v: %v", from, err)
		return
	}
	t.splice(ctx, client, up, from, dst)
}

// applyPlan asks the engine what to do with the first payload and writes it.
// It returns true when the connection must be closed instead of spliced, either
// because the plan blocked it or because the write failed.
func (t *Transport) applyPlan(w *ConnWriter, key desync.FlowKey, payload []byte, from, dst netip.AddrPort) (stop bool) {
	plan, err := t.eng.PlanStream(key, payload)
	switch {
	case errors.Is(err, engine.ErrNoProfile):
		// No profile matched: forward untouched.
		plan = nil
	case err != nil:
		t.st.errs.Add(1)
		t.logf("proxy: planning %v -> %v (%d bytes): %v; forwarding unchanged", from, dst, len(payload), err)
		plan = nil
	default:
		t.st.matched.Add(1)
	}

	res, err := ApplyPlan(w, plan, payload)
	t.st.writes.Add(int64(res.Writes))
	if t.cfg.Verbose > 0 {
		for _, n := range res.Notes {
			t.logf("proxy: %v -> %v: %s", from, dst, n)
		}
		if plan != nil {
			for _, d := range plan.Degraded {
				t.logf("proxy: %v -> %v: engine degraded: %s", from, dst, d)
			}
		}
	}
	if err != nil {
		t.st.errs.Add(1)
		t.logf("proxy: writing the request to %v: %v", dst, err)
		return true
	}
	if res.Blocked {
		t.st.blocked.Add(1)
		t.st.desyncs.Add(1)
		t.logf("proxy: blocked %v -> %v (%d bytes dropped)", from, dst, len(payload))
		return true
	}
	// A desync happened when the request did not go out as one untouched write.
	if !res.Verbatim && (res.Writes > 1 || res.Rewritten != 0 || res.LowTTL > 0) {
		t.st.desyncs.Add(1)
	}
	if t.cfg.Verbose > 1 {
		t.logf("proxy: %v -> %v: %d byte(s) in %d segment(s), %d low-TTL, %+d rewritten",
			from, dst, res.Bytes, res.Writes, res.LowTTL, res.Rewritten)
	}
	return false
}

// dial connects to the original destination.
//
// The network is pinned to the client's address family ("tcp4"/"tcp6") for two
// reasons: the server must be reached over the same family the application chose,
// and ConnWriter needs to know the family up front so it can pick IP_TTL or
// IPV6_UNICAST_HOPS without guessing.
func (t *Transport) dial(ctx context.Context, dst netip.AddrPort) (*net.TCPConn, error) {
	network := "tcp4"
	if dst.Addr().Unmap().Is6() {
		network = "tcp6"
	}
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.DialContext(ctx, network, dst.String())
	if err != nil {
		return nil, err
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("dialling %s gave a %T, not a *net.TCPConn", network, c)
	}
	return tc, nil
}

// isSelf reports whether dst is this listener, which would make the relay talk
// to itself.
//
// Link-local addresses count as well as loopback ones: with Options.IPv6 the
// inet6 redirect target is fe80::1, which netip does not classify as loopback.
func (t *Transport) isSelf(dst netip.AddrPort) bool {
	if int(dst.Port()) != t.port {
		return false
	}
	a := dst.Addr().Unmap()
	return a.IsLoopback() || a.IsLinkLocalUnicast()
}

// endpoints extracts the connection's peer and local address as AddrPorts.
//
// Both are unmapped: an IPv4 connection accepted on a dual-stack socket is
// reported by the runtime as ::ffff:a.b.c.d, and pf keeps IPv4 state for it, so a
// 4-in-6 address would look up a tuple that has no state.
func endpoints(c *net.TCPConn) (from, to netip.AddrPort, err error) {
	ra, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return from, to, fmt.Errorf("unexpected remote address type %T", c.RemoteAddr())
	}
	la, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		return from, to, fmt.Errorf("unexpected local address type %T", c.LocalAddr())
	}
	rip, ok := netip.AddrFromSlice(ra.IP)
	if !ok {
		return from, to, fmt.Errorf("unparsable remote address %v", ra.IP)
	}
	lip, ok := netip.AddrFromSlice(la.IP)
	if !ok {
		return from, to, fmt.Errorf("unparsable local address %v", la.IP)
	}
	from = netip.AddrPortFrom(rip.Unmap(), uint16(ra.Port))
	to = netip.AddrPortFrom(lip.Unmap(), uint16(la.Port))
	return from, to, nil
}

// readFirst reads the client's first bytes, bounded by firstPayloadTimeout so a
// protocol where the server speaks first is not stalled.
//
// One read is deliberate: it is the first segment the client sent, which is
// exactly what a DPI inspects and what nfqws/tpws act on. Waiting for more would
// merge the client's own segment boundaries and change what the desync sees.
func readFirst(c *net.TCPConn, wait time.Duration) ([]byte, error) {
	if err := c.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return nil, err
	}
	buf := make([]byte, firstPayloadMax)
	n, err := c.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

// isTimeout reports whether err is a deadline expiry.
func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// splice copies both directions until each side closes, propagating the
// half-close so a protocol that shuts down one direction (HTTP/1.0, some
// upload flows) keeps working.
//
// Two bounds make it impossible for one peer to pin resources for ever:
//
//   - an idle deadline, refreshed by either direction on every chunk it moves,
//     so a connection that is genuinely in use is never cut while a silent one
//     is;
//   - ctx, which Close and a cancelled Start propagate, so shutdown does not
//     depend on the peers cooperating.
//
// Both are enforced by closing the sockets: that is what unblocks a goroutine
// parked in read(2), which neither a context nor a WaitGroup can do.
func (t *Transport) splice(ctx context.Context, client, upstream *net.TCPConn, from, dst netip.AddrPort) {
	idle := t.opts.RelayIdleTimeout

	// active is bumped by whichever direction last moved bytes; the watchdog
	// compares it against its own last observation instead of resetting socket
	// deadlines from two goroutines at once.
	var active atomic.Int64
	active.Store(time.Now().UnixNano())

	var wg sync.WaitGroup
	wg.Add(2)
	copyDir := func(dstConn, srcConn *net.TCPConn, count func(int64)) {
		defer wg.Done()
		buf := make([]byte, relayBuf)
		for {
			n, rerr := srcConn.Read(buf)
			if n > 0 {
				active.Store(time.Now().UnixNano())
				count(int64(n))
				if _, werr := dstConn.Write(buf[:n]); werr != nil {
					break
				}
				active.Store(time.Now().UnixNano())
			}
			if rerr != nil {
				break
			}
		}
		// Tell the peer there is no more data in this direction; do not close the
		// socket, the other direction may still be running.
		_ = dstConn.CloseWrite()
	}

	go copyDir(upstream, client, func(n int64) { t.st.bytesIn.Add(n) })
	go copyDir(client, upstream, func(n int64) { t.st.bytesOut.Add(n) })

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	tick := idle / 4
	if tick < time.Second {
		tick = time.Second
	}
	timer := time.NewTicker(tick)
	defer timer.Stop()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			_ = client.SetDeadline(time.Now())
			_ = upstream.SetDeadline(time.Now())
			<-done
			return
		case <-timer.C:
			last := time.Unix(0, active.Load())
			if time.Since(last) < idle {
				continue
			}
			t.st.idleClosed.Add(1)
			t.logf("proxy: %v -> %v moved no bytes for %v; closing the relay", from, dst, idle)
			// A deadline in the past makes every parked read/write return
			// immediately, which is the only way to unblock read(2).
			_ = client.SetDeadline(time.Now())
			_ = upstream.SetDeadline(time.Now())
			<-done
			return
		}
	}
}
