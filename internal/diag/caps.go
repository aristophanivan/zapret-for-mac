// Package diag implements zapret-mac's diagnostics: runtime capability
// detection, the `zaprctl doctor` health checks and their repair actions, the
// `zaprctl test` connectivity probes, and the strategy auto-picker.
//
// It exists so that using this tool does not require the Windows original's
// trial-and-error ritual ("try general.bat, then general (ALT).bat, then …").
// Three questions are answered mechanically instead:
//
//   - Detect: what can this machine actually do? (which transport, which
//     desync.Caps)
//   - Doctor / Repair: what is wrong with this machine or with our own leftover
//     state, and what exactly fixes it?
//   - Run / Pick: does the bypass work right now, and which strategy works best?
//
// Two design rules run through the whole package:
//
//   - Everything that reads the machine is separated from everything that
//     decides. The deciding half (Analyze, ClassifyError, ClassifyDNS,
//     ScoreResults, RankCandidates, RulesDrift) is pure and takes its input as
//     data, so it is unit-testable without root and without a network.
//   - Nothing here is allowed to leave a trace. Detect creates a utun, loads one
//     narrow pf rule and unwinds both; it never writes /etc/pf.conf, never
//     changes a route, never touches DNS. Repair only ever removes things this
//     daemon itself created, identified by our own anchor name, our own marker
//     blocks and our own rollback journal.
package diag

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
	"github.com/naladwepo/zapret-for-mac/internal/pfvar"
)

// Transport names Detect can conclude. They are the two implementations under
// internal/transport plus "none" for a machine that can run neither.
const (
	// TransportDivert is the packet-level transport: pf route-to into a utun we
	// own (interception + drop verdict) plus a BPF Ethernet write for
	// re-emission and injection. Full winws-class capabilities.
	TransportDivert = "divert"
	// TransportProxy is the socket-level fallback: pf rdr to a local listener
	// plus ioctl(DIOCNATLOOK) to recover the original destination. TCP only,
	// byte-level tricks only.
	TransportProxy = "proxy"
	// TransportNone means neither transport can run here.
	TransportNone = "none"
)

// DefaultProbeAnchor is the pf anchor Detect and Doctor assume the daemon owns.
const DefaultProbeAnchor = "zapret-mac"

// Detect's defaults. The probe target is in TEST-NET-2 (RFC 5737): it routes to
// the default gateway like any other public address, so pf's `pass out` rule
// fires on it, but nothing answers and no real service is contacted.
const (
	defaultProbeTarget  = "198.51.100.7"
	defaultProbePort    = 443
	defaultDetectBudget = 6 * time.Second
	defaultSteerWait    = 2500 * time.Millisecond
)

// utunAFPrefixLen is the length of the framing header on every utun read and
// write: the address family in network byte order, i.e. {0,0,0,2} for AF_INET.
const utunAFPrefixLen = 4

// Capabilities is the answer to "what can this machine do". Every field is
// filled in on a best-effort basis: a failure to determine one capability never
// prevents the others from being reported, and running unprivileged degrades the
// whole structure to "Root: false" plus explanatory Notes rather than an error.
type Capabilities struct {
	// Root is euid == 0. Nothing else in this struct can be true without it.
	Root bool

	// UtunOK reports that a utun interface could be created, addressed and
	// brought up entirely through ioctls, and UtunName is the kernel-assigned
	// name it got (the interface is destroyed again before Detect returns).
	UtunOK   bool
	UtunName string

	// PfOK reports that /sbin/pfctl is usable and /dev/pf could be opened
	// O_RDWR, i.e. that pf can be driven at all.
	PfOK bool
	// PfEnabled is pf's status as found, before Detect took any reference.
	PfEnabled bool

	// AnchorReachable reports whether the main pf ruleset currently names our
	// anchor. When false, nothing loaded into the anchor is ever evaluated and
	// AnchorLine holds the exact statements the daemon would add to
	// /etc/pf.conf. Detect never performs that edit itself.
	AnchorReachable bool
	// WildcardAnchor is non-empty when the anchor is reachable through a
	// wildcard anchor point the stock ruleset already declares (typically
	// "com.apple/zapret-mac"). In that case rules become live with NO edit to
	// /etc/pf.conf, which is the mode the daemon prefers.
	WildcardAnchor string
	// AnchorLine is the /etc/pf.conf addition needed when AnchorReachable is
	// false, verbatim.
	AnchorLine string

	// SteerOK reports the decisive experiment: with a narrow `pass out quick
	// route-to (utunN …)` rule loaded, one TCP connect to the probe target
	// produced a packet on the utun file descriptor. That is what makes
	// intercept-mangle-reinject possible on macOS.
	SteerOK bool
	// SteerTested is false when the experiment could not be run at all (not
	// root, no utun, the anchor is unreachable, or the anchor already holds the
	// running daemon's rules). SteerOK == false with SteerTested == false means
	// "unknown", not "impossible"; the Notes say which.
	SteerTested bool

	// BpfWriteOK reports that a /dev/bpfN descriptor could be bound to the
	// uplink with BIOCSHDRCMPLT and that a frame could actually be written.
	BpfWriteOK bool
	// RawOK reports that an AF_INET SOCK_RAW socket with IP_HDRINCL could be
	// created. The divert transport does not use it (BPF bypasses pf, a raw
	// socket does not), but its availability is worth knowing.
	RawOK bool
	// NatlookOK reports that ioctl(DIOCNATLOOK) on /dev/pf is reachable with
	// the struct layout this build assumes — the lookup the proxy transport
	// needs to recover a redirected connection's original destination.
	NatlookOK bool

	// TunnelDefaultRoute is the name of the tunnel interface that currently
	// owns the default route ("utun4" with AmneziaVPN up), or "" when the
	// default route is a physical link. A full-tunnel VPN makes desync
	// pointless and points the BPF write at the wrong link.
	TunnelDefaultRoute string

	// Iface, Gateway, Local and GatewayMAC describe the uplink the divert
	// transport would attach to: the interface to write frames on, its own
	// address, the next hop and the next hop's link-layer address (the Ethernet
	// destination of every re-emitted frame).
	Iface      string
	Gateway    netip.Addr
	Local      netip.Addr
	GatewayMAC string
	// MTU is the uplink's MTU, 0 when it could not be read.
	MTU int

	// OSVersion, Darwin and Arch identify the machine; SIP is "enabled",
	// "partially-disabled", "disabled" or "unknown".
	OSVersion string
	Darwin    string
	Arch      string
	SIP       string

	// Notes explains every degraded or skipped conclusion above, in the order
	// the checks ran. It is the field to print when a user asks "why proxy?".
	Notes []string
}

// DetectOpts configures Detect. The zero value is valid and does the safest
// useful thing: probe everything reversibly against 198.51.100.7:443 using the
// default anchor name.
type DetectOpts struct {
	// Anchor is the pf anchor the daemon owns. Defaults to
	// DefaultProbeAnchor. Detect loads its probe rule into this anchor only
	// when the anchor is currently empty, so a running daemon's rules are never
	// overwritten.
	Anchor string
	// PfctlPath and PfConfPath override /sbin/pfctl and /etc/pf.conf.
	PfctlPath  string
	PfConfPath string

	// Target and Port are the destination of the steering experiment. Defaults
	// to 198.51.100.7:443 (TEST-NET-2, RFC 5737).
	Target netip.Addr
	Port   int

	// Iface pins the uplink instead of taking it from the default route.
	Iface string
	// UtunUnit is the requested utun unit; 0 asks the kernel for the first free
	// one.
	UtunUnit int

	// Timeout bounds the whole run. Defaults to 6s.
	Timeout time.Duration

	// SkipSteer suppresses the pf half of the steering experiment: no rule is
	// loaded and no connect is attempted, so pf is left completely alone. The
	// utun is still created and destroyed, because that is what UtunOK reports
	// and it touches nothing outside this process. Use it when the daemon is
	// running and you want the facts without going near its anchor.
	SkipSteer bool
	// SkipBPFWrite stops short of actually writing a frame: the descriptor is
	// still opened and configured, but BpfWriteOK then only proves the setup
	// path.
	SkipBPFWrite bool
	// NoPfEnable forbids taking a `pfctl -E` reference. Without it the steering
	// experiment cannot run on a machine where pf is currently disabled.
	NoPfEnable bool

	// Logf receives progress lines. nil discards them.
	Logf func(format string, args ...any)
}

// withDefaults returns a copy of o with every unset field filled in.
func (o DetectOpts) withDefaults() DetectOpts {
	if o.Anchor == "" {
		o.Anchor = DefaultProbeAnchor
	}
	if o.PfctlPath == "" {
		o.PfctlPath = netcfg.DefaultPfctlPath
	}
	if o.PfConfPath == "" {
		o.PfConfPath = netcfg.DefaultPfConfPath
	}
	if !o.Target.IsValid() {
		o.Target = netip.MustParseAddr(defaultProbeTarget)
	}
	if o.Port <= 0 || o.Port > 65535 {
		o.Port = defaultProbePort
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultDetectBudget
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return o
}

// Transport reports which transport this machine can run.
//
// "divert" needs root, a usable pf, a utun and a working BPF write. Steering is
// required not to have been DISPROVEN rather than to have been proven, because
// the common reason it cannot be proven is that /etc/pf.conf does not name our
// anchor yet — which the daemon fixes on startup, and Detect deliberately does
// not.
//
// "proxy" needs root, a usable pf and a reachable DIOCNATLOOK. Everything else
// is "none".
func (c Capabilities) Transport() string {
	if !c.Root || !c.PfOK {
		return TransportNone
	}
	if c.UtunOK && c.BpfWriteOK && (c.SteerOK || !c.SteerTested) {
		return TransportDivert
	}
	if c.NatlookOK {
		return TransportProxy
	}
	return TransportNone
}

// DesyncCaps is what the engine may assume on this machine. It is the Caps of
// the transport Transport() selected: desync.FullCaps for divert,
// desync.ProxyCaps for proxy, and the zero Caps (which every op fails against)
// for none.
func (c Capabilities) DesyncCaps() desync.Caps {
	switch c.Transport() {
	case TransportDivert:
		return desync.FullCaps()
	case TransportProxy:
		return desync.ProxyCaps()
	default:
		return desync.Caps{}
	}
}

// Summary is a one-line rendering for `zaprctl doctor` headers.
func (c Capabilities) Summary() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "transport=%s root=%v pf=%v anchor=%v utun=%v steer=%s bpf=%v natlook=%v",
		c.Transport(), c.Root, c.PfOK, c.AnchorReachable, c.UtunOK, c.steerText(), c.BpfWriteOK, c.NatlookOK)
	if c.Iface != "" {
		fmt.Fprintf(&sb, " iface=%s", c.Iface)
	}
	if c.TunnelDefaultRoute != "" {
		fmt.Fprintf(&sb, " VPN=%s", c.TunnelDefaultRoute)
	}
	return sb.String()
}

// steerText renders the tri-state of the steering experiment.
func (c Capabilities) steerText() string {
	switch {
	case !c.SteerTested:
		return "untested"
	case c.SteerOK:
		return "ok"
	default:
		return "failed"
	}
}

// AnchorStatementLines returns the exact /etc/pf.conf addition a top-level pf
// anchor needs in order to be evaluated at all. A stock macOS /etc/pf.conf only
// anchors "com.apple/*", so without these two statements everything loaded into
// our anchor is dead weight.
//
// They cannot be one contiguous block: macOS pf enforces the section order
// options, normalization, queueing, translation, filtering, and rejects a file
// where a translation statement follows a filter one.
func AnchorStatementLines(anchor string) string {
	return fmt.Sprintf(`rdr-anchor %q   # at the head of the translation section, above rdr-anchor "com.apple/*"`+"\n"+
		`anchor %q       # at the head of the filter section, above anchor "com.apple/*"`, anchor, anchor)
}

// Detect probes this machine's capabilities. It is non-destructive and fully
// reversible:
//
//  1. Read-only facts: uid, macOS/Darwin version, SIP, the default route, the
//     uplink's MAC and MTU, the next hop's MAC (from the ARP cache, primed with
//     at most one UDP datagram to the gateway's discard port).
//  2. pf reachability: pfctl is executable, /dev/pf opens O_RDWR, pf's status,
//     and whether the main ruleset names our anchor.
//  3. ioctl(DIOCNATLOOK) with a tuple that cannot exist. ENOENT is the pass
//     condition: it proves the ioctl number and struct layout are right and we
//     have permission, without needing a redirected connection.
//  4. An AF_INET SOCK_RAW socket with IP_HDRINCL, created and closed.
//  5. A /dev/bpfN descriptor bound to the uplink with BIOCSHDRCMPLT, plus one
//     60-byte frame with EtherType 0x88B5 (IEEE local experimental) addressed
//     from and to our own MAC. That exercises the exact write path the
//     transport uses while putting nothing routable on the network.
//  6. A utun, created and configured entirely through ioctls.
//  7. The steering experiment: load one narrow route-to rule for the probe
//     target into our anchor, make one TCP connect, and watch the utun file
//     descriptor for the segment pf was asked to hand over.
//
// Steps 6 and 7 are unwound in reverse before returning, including on context
// cancellation and on panic: the anchor is flushed back to empty, any pf
// reference taken is released with `pfctl -X`, and the utun disappears the moment
// its control socket is closed.
//
// Detect never writes /etc/pf.conf. When the anchor turns out to be unreachable
// the steering experiment is skipped, AnchorReachable is false and AnchorLine
// carries the statements the daemon would add. It also never overwrites a
// non-empty anchor, so running it while the daemon is active is safe — and in
// that case SteerTested stays false, which Transport() reads as "unproven, not
// impossible".
//
// The returned error is non-nil for a failure that invalidates the whole report
// (currently: an unreadable interface table) and for a cancelled or expired
// context. In the latter case the returned Capabilities still holds everything
// that was established before the deadline. Every individual capability that
// could not be determined is reported as false with a Note explaining why, so an
// unprivileged run degrades to a report rather than an error.
func Detect(ctx context.Context, o DetectOpts) (Capabilities, error) {
	o = o.withDefaults()
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	var (
		c  Capabilities
		cl cleanupStack
	)
	defer cl.run(&c)

	c.Root = os.Geteuid() == 0
	c.OSVersion = sysctlString("kern.osproductversion")
	c.Darwin = sysctlString("kern.osrelease")
	c.Arch = sysctlString("hw.machine")
	c.SIP = sipStatus()
	c.AnchorLine = AnchorStatementLines(o.Anchor)
	if !c.Root {
		c.note("running as uid %d, not root: pf cannot be driven, /dev/pf and /dev/bpfN cannot be opened, "+
			"and no utun can be created. Re-run with sudo for a complete answer.", os.Geteuid())
	}

	// ---- step 1: read-only network facts -----------------------------------
	if err := c.detectUplink(o); err != nil {
		return c, err
	}

	// ---- step 2: pf reachability -------------------------------------------
	c.detectPf(ctx, o)

	// ---- steps 3 and 4: cheap privileged capabilities ----------------------
	c.detectNatlook()
	c.detectRawSocket()

	// ---- step 5: BPF -------------------------------------------------------
	c.detectBPF(o)

	// ---- step 6: the utun -------------------------------------------------
	// It is created even when the steering experiment is skipped: it is the only
	// way UtunOK can be answered honestly, and it touches nothing outside our own
	// process (closing the control socket destroys the interface).
	utun := c.detectUtun(o, &cl)

	// ---- step 7: the steering experiment -----------------------------------
	if o.SkipSteer {
		c.note("steering experiment skipped by request (SkipSteer): pf was left completely alone, so SteerTested " +
			"stays false and Transport() treats steering as unproven rather than impossible")
	} else {
		c.detectSteering(ctx, o, &cl, utun)
	}
	return c, ctx.Err()
}

// note appends an explanatory line.
func (c *Capabilities) note(format string, args ...any) {
	c.Notes = append(c.Notes, fmt.Sprintf(format, args...))
}

// ---------------------------------------------------------------------------
// step 1: uplink
// ---------------------------------------------------------------------------

// detectUplink fills in Iface, Local, Gateway, GatewayMAC, MTU and
// TunnelDefaultRoute. It reads the kernel routing table and, when the gateway's
// link-layer address is not cached yet, sends at most one UDP datagram to its
// discard port to make the kernel resolve it.
func (c *Capabilities) detectUplink(o DetectOpts) error {
	ifaces, err := netcfg.Interfaces()
	if err != nil {
		return fmt.Errorf("diag: cannot read the interface table: %w", err)
	}

	// Which interface would the kernel actually use for a public destination?
	// A connect(2) on a UDP socket performs the route lookup and nothing else —
	// no packet leaves the machine — so this is the cheapest honest answer, and
	// unlike the routing table it resolves the ambiguity of a VPN and a physical
	// link both advertising a default route.
	egress := egressInterface(ifaces)
	if egress != "" && netcfg.IsTunnelInterface(egress) {
		c.TunnelDefaultRoute = egress
	}

	var route netcfg.Route
	switch {
	case o.Iface != "":
		route, err = netcfg.RouteForIface(o.Iface)
		if err != nil {
			c.note("no usable IPv4 gateway route on the pinned interface %s: %v", o.Iface, err)
			return nil
		}
	default:
		routes, rerr := netcfg.DefaultRoutes4()
		if rerr != nil {
			c.note("cannot read the IPv4 default route: %v", rerr)
			return nil
		}
		if len(routes) == 0 {
			c.note("no IPv4 default route at all: this machine has no uplink to desync")
			return nil
		}
		// DefaultRoutes4 sorts non-tunnel routes first, so routes[0] is the
		// physical uplink the BPF write must target even when a VPN owns the
		// default route.
		route = routes[0]
		if c.TunnelDefaultRoute == "" {
			for _, r := range routes {
				if r.IsTunnel {
					c.TunnelDefaultRoute = r.Iface
					break
				}
			}
		}
	}

	c.Iface = route.Iface
	c.Gateway = route.Gateway
	c.Local = route.Local
	c.MTU = route.MTU
	if route.IsTunnel {
		c.note("the only uplink we found is tunnel interface %s: a BPF Ethernet write needs a real link layer, "+
			"so the divert transport cannot re-emit there", route.Iface)
	}
	if c.TunnelDefaultRoute != "" {
		c.note("the default route currently goes through tunnel interface %s (a VPN is active): traffic never "+
			"reaches the DPI we are trying to fool, and a BPF write on %s would target the wrong link",
			c.TunnelDefaultRoute, c.Iface)
	}
	if len(route.MAC) == 0 {
		c.note("interface %s has no link-layer address: the Ethernet source of a re-emitted frame is unknown", c.Iface)
	}
	switch {
	case len(route.GatewayMAC) == 6:
		// A directly attached next hop: the routing table already gave us the
		// link-layer address.
		c.GatewayMAC = route.GatewayMAC.String()
	case route.Gateway.IsValid() && route.Gateway.Is4():
		if mac, err := netcfg.ResolveGatewayMAC(route.Gateway); err == nil {
			c.GatewayMAC = mac.String()
		} else {
			c.note("cannot resolve the next hop's link-layer address (%v): the divert transport has no Ethernet "+
				"destination to write to", err)
		}
	default:
		c.note("the default route has no IPv4 next hop, so there is no gateway MAC to write frames to")
	}
	return nil
}

// egressInterface reports the interface the kernel would use to reach a public
// address, by connecting a UDP socket and looking at the local address it binds.
// It returns "" when the lookup fails (no route, no network).
func egressInterface(ifaces map[string]netcfg.Interface) string {
	conn, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return ""
	}
	defer conn.Close()
	ua, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || ua.IP == nil {
		return ""
	}
	local, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return ""
	}
	local = local.Unmap()
	for name, inf := range ifaces {
		for _, a := range inf.Addrs {
			if a.Unmap() == local {
				return name
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// step 2: pf
// ---------------------------------------------------------------------------

// detectPf establishes PfOK, PfEnabled and AnchorReachable.
func (c *Capabilities) detectPf(ctx context.Context, o DetectOpts) {
	st, err := os.Stat(o.PfctlPath)
	switch {
	case err != nil:
		c.note("%s is missing (%v): pf cannot be driven", o.PfctlPath, err)
		return
	case st.IsDir() || st.Mode().Perm()&0o111 == 0:
		c.note("%s is not executable: pf cannot be driven", o.PfctlPath)
		return
	}

	fd, err := pfvar.Open()
	if err != nil {
		// pfvar's message already names the device and its mode.
		c.note("pf cannot be driven: %v", err)
		return
	}
	_ = pfvar.Close(fd)
	c.PfOK = true

	info, _, err := runPfctl(ctx, o.PfctlPath, "", "-s", "info")
	if err != nil {
		c.note("cannot query pf status: %v", err)
	} else {
		c.PfEnabled = strings.Contains(info, "Status: Enabled")
		if !c.PfEnabled {
			c.note("pf is currently disabled; the daemon enables it with `pfctl -E` (reference counted) " +
				"and releases it with `pfctl -X`, never `pfctl -d`")
		}
	}

	// An anchor is only evaluated if the ruleset the kernel is running names it.
	// Check the live ruleset first (that is what decides), then the file (which
	// is what survives a reboot).
	live := c.anchorReachableLive(ctx, o)
	inFile := false
	if conf, err := os.ReadFile(o.PfConfPath); err == nil {
		inFile = netcfg.AnchorStatementsPresent(conf, o.Anchor)
	} else {
		c.note("cannot read %s: %v", o.PfConfPath, err)
	}
	c.AnchorReachable = live
	switch {
	case live && c.WildcardAnchor != "":
		c.note("rules reach pf through the wildcard sub-anchor %q, which the stock ruleset already evaluates, "+
			"so %s needs no edit at all. The trade-off: anything that flushes com.apple/* wholesale takes our "+
			"rules with it, which the daemon detects as drift and reloads.", c.WildcardAnchor, o.PfConfPath)
	case live && !inFile:
		c.note("anchor %q is referenced by the running ruleset but not by %s, so it will be gone after a reboot "+
			"or after anything runs `pfctl -f %s`", o.Anchor, o.PfConfPath, o.PfConfPath)
	case !live:
		c.note("anchor %q is NOT referenced by the running pf ruleset, so nothing loaded into it is evaluated. "+
			"Detect never edits %s; the daemon adds exactly these lines:\n%s",
			o.Anchor, o.PfConfPath, c.AnchorLine)
	}
}

// anchorReachableLive reports whether the kernel's main ruleset contains an
// anchor statement naming our anchor, in either the filter or the translation
// section.
func (c *Capabilities) anchorReachableLive(ctx context.Context, o DetectOpts) bool {
	// Two ways to be reachable. Either the ruleset names our top-level anchor
	// (which only happens after /etc/pf.conf was patched), or it declares a
	// wildcard anchor point covering "com.apple/<anchor>" — in which case
	// loading rules into that sub-anchor is enough and no file is ever touched.
	// A stock macOS ruleset always provides the second, which is why the daemon
	// prefers it.
	sub := "com.apple/" + o.Anchor
	wildFilter, wildNat := false, false
	for _, what := range []string{"rules", "nat"} {
		out, _, err := runPfctl(ctx, o.PfctlPath, "", "-s", what)
		if err != nil {
			continue
		}
		if rulesetReferencesAnchor(out, o.Anchor) {
			return true
		}
		if netcfg.WildcardAnchorCovers(out, sub) {
			if what == "rules" {
				wildFilter = true
			} else {
				wildNat = true
			}
		}
	}
	if wildFilter && wildNat {
		c.WildcardAnchor = sub
		return true
	}
	return false
}

// rulesetReferencesAnchor scans `pfctl -s rules|nat` output for an anchor
// statement naming anchor. pfctl prints them as `anchor "name" all`, so the
// name is matched as a quoted token or as the first path element of one.
func rulesetReferencesAnchor(ruleset, anchor string) bool {
	for _, line := range strings.Split(ruleset, "\n") {
		l := strings.TrimSpace(line)
		if !strings.Contains(l, "anchor") {
			continue
		}
		for _, tok := range strings.Fields(l) {
			name := strings.Trim(tok, `"`)
			if name == anchor || strings.HasPrefix(name, anchor+"/") {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// step 3: DIOCNATLOOK
// ---------------------------------------------------------------------------

// detectNatlook probes ioctl(DIOCNATLOOK) with a tuple that cannot have state.
//
// pfvar.ErrNoState (the kernel's ENOENT) is the success condition: it proves the
// kernel understood the request number and the 84-byte struct, looked in its
// state table and found nothing. ENOTTY or EINVAL would mean the layout this
// build assumes is wrong — exactly what the proxy transport must not discover at
// runtime, when it has an accepted connection in hand and no way to learn where
// it was going.
//
// The ABI itself lives in internal/pfvar, so there is one transcription of
// Apple's pfvar.h in the tree rather than two that can drift apart.
func (c *Capabilities) detectNatlook() {
	fd, err := pfvar.Open()
	if err != nil {
		if c.Root {
			c.note("DIOCNATLOOK not probed: %v", err)
		}
		return
	}
	defer pfvar.Close(fd)

	// 127.0.0.1:0 -> 127.0.0.1:0 cannot be in a state table (port 0 never is),
	// so the lookup is guaranteed to miss without our having to create anything.
	lo := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0)
	_, err = pfvar.Natlook(fd, unix.AF_INET, unix.IPPROTO_TCP, lo, lo)
	switch {
	case err == nil:
		c.NatlookOK = true
		c.note("DIOCNATLOOK unexpectedly found state for 127.0.0.1:0; the ioctl works, which is all the proxy " +
			"transport needs to know")
	case errors.Is(err, pfvar.ErrNoState):
		// The expected answer: the ABI is right, there is simply no such state.
		c.NatlookOK = true
	default:
		c.note("ioctl(DIOCNATLOOK) failed with something other than the expected ENOENT, so the proxy transport "+
			"cannot recover original destinations on this kernel: %v", err)
	}
}

// ---------------------------------------------------------------------------
// step 4: raw socket
// ---------------------------------------------------------------------------

// detectRawSocket creates and immediately closes an AF_INET SOCK_RAW socket with
// IP_HDRINCL. Nothing is sent: Darwin's rip_output() expects ip_len and ip_off
// in HOST byte order, and exercising that quirk would put a real packet on the
// network for no diagnostic gain.
func (c *Capabilities) detectRawSocket() {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		if c.Root {
			c.note("socket(AF_INET, SOCK_RAW, IPPROTO_RAW) failed: %s", errnoName(err))
		}
		return
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		c.note("setsockopt(IP_HDRINCL) failed: %s", errnoName(err))
		return
	}
	c.RawOK = true
}

// ---------------------------------------------------------------------------
// step 5: BPF
// ---------------------------------------------------------------------------

// etherTypeLocalExperimental is IEEE 802 "local experimental EtherType 1"
// (0x88B5). A frame carrying it is not IP, is not routed, and is discarded by
// anything that receives it — which is why it is what the write probe emits.
const etherTypeLocalExperimental = 0x88b5

// detectBPF opens a /dev/bpfN descriptor, binds it to the uplink with
// BIOCSHDRCMPLT and (unless SkipBPFWrite) writes one harmless frame.
func (c *Capabilities) detectBPF(o DetectOpts) {
	if c.Iface == "" {
		c.note("BPF not probed: no uplink interface was determined")
		return
	}
	if netcfg.IsTunnelInterface(c.Iface) {
		c.note("BPF not probed on %s: it is a tunnel interface and has no Ethernet link layer to write", c.Iface)
		return
	}
	h, err := openBPF(c.Iface)
	if err != nil {
		if c.Root {
			c.note("cannot open a BPF descriptor for %s: %v", c.Iface, err)
		}
		return
	}
	defer h.Close()

	if h.Datalink != dltEN10MB {
		c.note("BPF on %s reports datalink type %d, not DLT_EN10MB (%d): the transport's 14-byte Ethernet header "+
			"would be wrong on this link", c.Iface, h.Datalink, dltEN10MB)
		return
	}
	if o.SkipBPFWrite {
		c.BpfWriteOK = true
		c.note("BPF descriptor for %s opened and configured (BIOCSHDRCMPLT, DLT_EN10MB) but no frame was written "+
			"(SkipBPFWrite), so the write path itself is unproven", c.Iface)
		return
	}

	mac, err := net.ParseMAC(macOfIface(c.Iface))
	if err != nil || len(mac) != 6 {
		c.note("cannot determine %s's own MAC, so no probe frame could be written", c.Iface)
		return
	}
	// 60 bytes total: 14-byte header plus 46 bytes of zeroes, the Ethernet
	// minimum. Source == destination == our own MAC, so even a switch that does
	// forward it sends it nowhere useful.
	frame := make([]byte, 60)
	copy(frame[0:6], mac)
	copy(frame[6:12], mac)
	frame[12] = etherTypeLocalExperimental >> 8
	frame[13] = etherTypeLocalExperimental & 0xff
	if _, err := h.write(frame); err != nil {
		c.note("write(/dev/bpf) on %s failed: %v; the divert transport cannot inject or re-emit packets", c.Iface, err)
		return
	}
	c.BpfWriteOK = true
}

// macOfIface returns the named interface's link-layer address as a string, or
// "" when it has none.
func macOfIface(name string) string {
	ifaces, err := netcfg.Interfaces()
	if err != nil {
		return ""
	}
	inf, ok := ifaces[name]
	if !ok || len(inf.MAC) != 6 {
		return ""
	}
	return inf.MAC.String()
}

// ---------------------------------------------------------------------------
// step 6: steering
// ---------------------------------------------------------------------------

// detectUtun creates the point-to-point tunnel the divert transport would use,
// records the result, and registers its destruction.
//
// It is a step of its own rather than part of the steering experiment because
// UtunOK decides which transport can run, and a caller that suppresses the
// steering experiment (SkipSteer, e.g. while the daemon is running and owns the
// anchor) must not thereby be told that the divert transport is unavailable.
//
// Creating a utun touches nothing but this process: the interface exists exactly
// as long as its control socket is open, so closing that socket is a complete
// and unfailable rollback.
func (c *Capabilities) detectUtun(o DetectOpts, cl *cleanupStack) *utunHandle {
	if !c.Root {
		c.note("utun not created: it needs root")
		return nil
	}
	local, peer, substituted := pickTunnelPair()
	utun, err := createUTUN(o.UtunUnit, local, peer, 1500)
	if err != nil {
		c.note("cannot create a utun, so the divert transport cannot intercept anything: %v", err)
		return nil
	}
	cl.push("close the probe utun "+utun.Name+" (destroys the interface)", utun.Close)
	c.UtunOK = true
	c.UtunName = utun.Name
	if substituted {
		c.note("198.18.0.1/198.18.0.2 were already in use, so the probe utun used %s -> %s instead", local, peer)
	}
	if len(utun.ConfigErrors) > 0 {
		c.note("utun %s configured with warnings: %s", utun.Name, strings.Join(utun.ConfigErrors, "; "))
	}
	return utun
}

// detectSteering runs the experiment the whole design rests on and unwinds it.
func (c *Capabilities) detectSteering(ctx context.Context, o DetectOpts, cl *cleanupStack, utun *utunHandle) {
	if !c.Root {
		c.note("steering experiment skipped: it needs root")
		return
	}
	if !c.PfOK {
		c.note("steering experiment skipped: pf is not usable")
		return
	}
	if utun == nil {
		c.note("steering experiment skipped: no utun could be created to steer into")
		return
	}
	if !c.AnchorReachable {
		c.note("steering experiment skipped: anchor %q is not referenced by the running ruleset, so a rule loaded "+
			"into it could not fire. Add the lines above to %s (the daemon does this itself) and re-run.",
			o.Anchor, o.PfConfPath)
		return
	}

	pf := netcfg.NewPF(o.Anchor, netcfg.PFOpts{
		PfConfPath: o.PfConfPath,
		PfctlPath:  o.PfctlPath,
		// No StateDir on purpose: a probe must not append rollback-journal
		// entries describing rules it is about to remove itself.
		Logf: o.Logf,
	})

	// Never clobber a running daemon's rules.
	existing, err := pf.Rules()
	if err != nil {
		c.note("cannot read anchor %q: %v", o.Anchor, err)
		return
	}
	existingNat, _ := pf.NatRules()
	if strings.TrimSpace(existing) != "" || strings.TrimSpace(existingNat) != "" {
		c.note("steering experiment skipped: anchor %q already holds %d rule line(s) — the daemon is running, and "+
			"overwriting them would break it. Stop the daemon and re-run, or trust the running configuration.",
			o.Anchor, countNonEmptyLines(existing)+countNonEmptyLines(existingNat))
		return
	}

	if !c.PfEnabled {
		if o.NoPfEnable {
			c.note("steering experiment skipped: pf is disabled and NoPfEnable was set")
			return
		}
		if err := pf.Enable(); err != nil {
			c.note("cannot take a pf reference with `pfctl -E`: %v", err)
			return
		}
		cl.push("release the pf reference (pfctl -X)", func() error { return pf.Release() })
	}

	// The narrow probe rule. It deliberately omits the daemon's `user { > root }`
	// clause: that clause exists to keep the daemon's own root-owned traffic out
	// of the window, but the connect below IS root-owned, so with it the
	// experiment could never succeed.
	rule := fmt.Sprintf("pass out quick route-to (%s %s) inet proto tcp from any to %s port %d no state\n",
		utun.Name, utun.Peer, o.Target, o.Port)
	if err := pf.LoadRules(rule); err != nil {
		c.note("cannot load the probe rule into anchor %q: %v", o.Anchor, err)
		return
	}
	cl.push("flush anchor "+o.Anchor+" back to empty", pf.FlushRules)
	c.SteerTested = true
	o.Logf("diag: probe rule loaded into anchor %q: %s", o.Anchor, strings.TrimSpace(rule))

	// Read the utun while one connect is attempted. Nothing answers 198.51.100.7,
	// so the dial always fails; the only thing that matters is whether its SYN
	// materialises on the file descriptor.
	wait := defaultSteerWait
	if dl, ok := ctx.Deadline(); ok {
		if remain := time.Until(dl) - 300*time.Millisecond; remain < wait {
			wait = remain
		}
	}
	if wait <= 0 {
		c.note("steering experiment skipped: the time budget was already exhausted")
		return
	}

	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		d := net.Dialer{Timeout: wait}
		conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(o.Target.String(), fmt.Sprint(o.Port)))
		if err == nil {
			_ = conn.Close()
		}
	}()

	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		_, pkt, err := utun.read(time.Until(deadline))
		if err != nil {
			c.note("reading the probe utun failed: %v", err)
			break
		}
		if len(pkt) < 20 {
			continue
		}
		dst, ok := ipv4Dst(pkt)
		if !ok {
			continue
		}
		if dst == o.Target {
			c.SteerOK = true
			break
		}
	}
	<-dialDone

	if !c.SteerOK {
		c.note("pf route-to did NOT hand the outbound segment to %s within %s: intercept-mangle-reinject is not "+
			"available on this machine, so only the socket-level proxy transport can run", utun.Name, wait)
	}
}

// ipv4Dst extracts the destination address of an IPv4 packet, defensively.
func ipv4Dst(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}), true
}

// pickTunnelPair chooses the point-to-point pair for the probe utun. It prefers
// 198.18.0.1 -> 198.18.0.2 (RFC 2544 benchmarking space, which never appears in
// real traffic) and substitutes a free pair when a VPN already owns those.
func pickTunnelPair() (local, peer netip.Addr, substituted bool) {
	inUse := map[netip.Addr]bool{}
	if ifaces, err := netcfg.Interfaces(); err == nil {
		for _, inf := range ifaces {
			for _, a := range inf.Addrs {
				inUse[a.Unmap()] = true
			}
		}
	}
	try := func(a, b [4]byte) (netip.Addr, netip.Addr, bool) {
		x, y := netip.AddrFrom4(a), netip.AddrFrom4(b)
		return x, y, !inUse[x] && !inUse[y]
	}
	if l, r, ok := try([4]byte{198, 18, 0, 1}, [4]byte{198, 18, 0, 2}); ok {
		return l, r, false
	}
	for _, second := range []byte{18, 19} {
		for third := 1; third < 256; third++ {
			if l, r, ok := try([4]byte{198, second, byte(third), 1}, [4]byte{198, second, byte(third), 2}); ok {
				return l, r, true
			}
		}
	}
	return netip.AddrFrom4([4]byte{198, 18, 0, 1}), netip.AddrFrom4([4]byte{198, 18, 0, 2}), false
}

// countNonEmptyLines counts lines with content.
func countNonEmptyLines(s string) int {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// cleanup stack
// ---------------------------------------------------------------------------

// cleanupStack unwinds Detect's side effects in reverse order. It runs from a
// deferred call so cancellation, an early return and a panic all reach it.
type cleanupStack struct {
	steps []cleanupStep
}

type cleanupStep struct {
	name string
	fn   func() error
}

// push registers an undo action. Actions run last-registered-first.
func (s *cleanupStack) push(name string, fn func() error) {
	s.steps = append(s.steps, cleanupStep{name: name, fn: fn})
}

// run executes every registered action, recording failures as Notes. A failure
// is never fatal: the remaining actions still run, because the alternative is
// leaving more behind than necessary.
func (s *cleanupStack) run(c *Capabilities) {
	for i := len(s.steps) - 1; i >= 0; i-- {
		st := s.steps[i]
		if err := st.fn(); err != nil && c != nil {
			c.note("cleanup step %q failed: %v — run `zaprctl doctor --repair`", st.name, err)
		}
	}
	s.steps = nil
}

// ---------------------------------------------------------------------------
// pfctl runner
// ---------------------------------------------------------------------------

// pfctlTimeout bounds one pfctl invocation.
const pfctlTimeout = 15 * time.Second

// runPfctl executes pfctl and returns stdout and stderr separately. pfctl writes
// rules to stdout but tokens and warnings to stderr, so callers routinely need
// both.
func runPfctl(ctx context.Context, pfctlPath, stdin string, args ...string) (stdout, stderr string, err error) {
	if pfctlPath == "" {
		pfctlPath = netcfg.DefaultPfctlPath
	}
	ctx, cancel := context.WithTimeout(ctx, pfctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, pfctlPath, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	runErr := cmd.Run()
	if runErr != nil {
		return out.String(), errb.String(), fmt.Errorf("pfctl %s: %w: %s",
			strings.Join(args, " "), runErr, strings.TrimSpace(errb.String()))
	}
	return out.String(), errb.String(), nil
}

// ---------------------------------------------------------------------------
// sysctl helpers
// ---------------------------------------------------------------------------

// sysctlString reads a string sysctl, returning "?" when it does not exist.
func sysctlString(name string) string {
	v, err := unix.Sysctl(name)
	if err != nil {
		return "?"
	}
	return v
}

// sysctlIntOK reads an integer sysctl, reporting whether it exists.
func sysctlIntOK(name string) (int, bool) {
	v, err := unix.SysctlUint32(name)
	if err != nil {
		return 0, false
	}
	return int(v), true
}

// csrctl(2) constants. Op 1 is CSR_SYSCALL_GET_ACTIVE_CONFIG in xnu's
// bsd/kern/kern_csr.c; it copies out one uint32 csr_config_t and the kernel
// rejects any other size.
const (
	csrSyscallGetActiveConfig = 1
	csrConfigSize             = 4
)

// sipStatus reports System Integrity Protection's state. csrctl(2) is asked
// first because it needs no subprocess; csrutil(1) is the fallback.
func sipStatus() string {
	var cfg uint32
	_, _, errno := unix.Syscall(unix.SYS_CSRCTL, csrSyscallGetActiveConfig,
		uintptr(unsafe.Pointer(&cfg)), csrConfigSize)
	if errno == 0 {
		if cfg == 0 {
			return "enabled"
		}
		return fmt.Sprintf("partially-disabled (csr_active_config=%#x)", cfg)
	}
	out, err := exec.Command("/usr/bin/csrutil", "status").CombinedOutput()
	if err != nil {
		return "unknown"
	}
	line := strings.ToLower(strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0]))
	switch {
	case strings.Contains(line, "enabled"):
		return "enabled"
	case strings.Contains(line, "disabled"):
		return "disabled"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------------------
// utun — copied from cmd/zapret-probe, which verified every constant against
// this machine's SDK. cmd/ cannot be imported, so the plumbing is duplicated.
// ---------------------------------------------------------------------------

// sysprotoControl is SYSPROTO_CONTROL from <sys/sys_domain.h>; utunOptIfname is
// UTUN_OPT_IFNAME from <net/if_utun.h>. x/sys/unix exports neither.
const (
	sysprotoControl = 2
	utunOptIfname   = 2
)

// Interface-configuration ioctl request numbers from <sys/sockio.h>:
//
//	SIOCAIFADDR  _IOW ('i', 26, struct ifaliasreq) == 0x8040691a (sizeof 64)
//	SIOCSIFMTU   _IOW ('i', 52, struct ifreq)      == 0x80206934 (sizeof 32)
//	SIOCSIFFLAGS _IOW ('i', 16, struct ifreq)      == 0x80206910
//	SIOCGIFFLAGS _IOWR('i', 17, struct ifreq)      == 0xc0206911
const (
	siocAIfAddr  = 0x8040691a
	siocSIfMTU   = 0x80206934
	siocSIfFlags = 0x80206910
	siocGIfFlags = 0xc0206911
)

// ifAliasReq mirrors "struct ifaliasreq" from <net/if.h>: a 16-byte interface
// name plus three sockaddrs (addr, broadaddr, mask), 64 bytes total. On a
// point-to-point interface the kernel treats ifra_broadaddr as the peer address,
// which is how "ifconfig utunN A B" works.
type ifAliasReq struct {
	Name      [unix.IFNAMSIZ]byte
	Addr      unix.RawSockaddrInet4
	Broadaddr unix.RawSockaddrInet4
	Mask      unix.RawSockaddrInet4
}

// ifReqInt mirrors "struct ifreq" when the union member in use is an int.
type ifReqInt struct {
	Name [unix.IFNAMSIZ]byte
	Val  int32
	_    [12]byte
}

// ifReqFlags mirrors "struct ifreq" when the union member is "short ifru_flags".
type ifReqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags int16
	_     [14]byte
}

// Compile-time guards on the struct sizes the request numbers above encode. A
// mismatch would make the kernel answer ENOTTY at runtime; each pair of unsigned
// subtractions fails to compile unless the two sides are equal.
const (
	_ = uint(unsafe.Sizeof(ifAliasReq{}) - 64)
	_ = uint(64 - unsafe.Sizeof(ifAliasReq{}))
	_ = uint(unsafe.Sizeof(ifReqInt{}) - 32)
	_ = uint(32 - unsafe.Sizeof(ifReqInt{}))
	_ = uint(unsafe.Sizeof(ifReqFlags{}) - 32)
	_ = uint(32 - unsafe.Sizeof(ifReqFlags{}))
)

// sockaddrInet4Raw builds a filled-in sockaddr_in for the ifaliasreq slots.
func sockaddrInet4Raw(ip netip.Addr) unix.RawSockaddrInet4 {
	return unix.RawSockaddrInet4{
		Len:    unix.SizeofSockaddrInet4,
		Family: unix.AF_INET,
		Addr:   ip.As4(),
	}
}

// utunHandle owns a utun control socket and therefore the interface itself:
// closing the socket destroys utunN, which is what makes cleanup complete.
type utunHandle struct {
	fd int
	// Name is the kernel-assigned interface name ("utun9").
	Name string
	// Local and Peer are the point-to-point addresses; Peer is what pf's
	// route-to option names as the next hop on this interface.
	Local netip.Addr
	Peer  netip.Addr
	// MTU is the interface MTU that was requested.
	MTU int
	// ConfigErrors records non-fatal configuration failures.
	ConfigErrors []string
}

// createUTUN opens a utun control socket, attaches it to a unit, reads back the
// kernel-assigned name and configures addresses, MTU and flags with ioctls only.
//
// The kernel's sc_unit numbering is 1-based: sc_unit == unit+1 selects utun<unit>
// and sc_unit == 0 asks for the lowest free unit.
func createUTUN(unit int, local, peer netip.Addr, mtu int) (*utunHandle, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL): %s", errnoName(err))
	}
	h := &utunHandle{fd: fd, MTU: mtu, Local: local, Peer: peer}

	var ci unix.CtlInfo
	copy(ci.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, &ci); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf(`ioctl(CTLIOCGINFO, "com.apple.net.utun_control"): %s`, errnoName(err))
	}
	if cerr := unix.Connect(fd, &unix.SockaddrCtl{ID: ci.Id, Unit: uint32(unit) + 1}); cerr != nil {
		// The requested unit is taken; ask the kernel to pick one.
		if err2 := unix.Connect(fd, &unix.SockaddrCtl{ID: ci.Id, Unit: 0}); err2 != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("connect(utun unit %d): %s; auto unit also failed: %s",
				unit, errnoName(cerr), errnoName(err2))
		}
	}
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME): %s", errnoName(err))
	}
	h.Name = name
	if err := h.configure(local, peer); err != nil {
		unix.Close(fd)
		h.fd = -1
		return nil, err
	}
	return h, nil
}

// configure assigns the point-to-point addresses, sets the MTU and brings the
// interface up, all through ioctls on a scratch AF_INET datagram socket.
func (h *utunHandle) configure(local, peer netip.Addr) error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket(AF_INET, SOCK_DGRAM) for ioctl: %s", errnoName(err))
	}
	defer unix.Close(s)

	var aif ifAliasReq
	copy(aif.Name[:], h.Name)
	aif.Addr = sockaddrInet4Raw(local)
	aif.Broadaddr = sockaddrInet4Raw(peer)
	aif.Mask = sockaddrInet4Raw(netip.AddrFrom4([4]byte{255, 255, 255, 255}))
	if err := ioctlPtr(s, siocAIfAddr, unsafe.Pointer(&aif)); err != nil {
		return fmt.Errorf("ioctl(SIOCAIFADDR, %s %s->%s/32): %s", h.Name, local, peer, errnoName(err))
	}

	var mtu ifReqInt
	copy(mtu.Name[:], h.Name)
	mtu.Val = int32(h.MTU)
	if err := ioctlPtr(s, siocSIfMTU, unsafe.Pointer(&mtu)); err != nil {
		// A wrong MTU does not invalidate the experiment; record and continue.
		h.ConfigErrors = append(h.ConfigErrors,
			fmt.Sprintf("ioctl(SIOCSIFMTU, %s, %d): %s", h.Name, h.MTU, errnoName(err)))
	}

	var fl ifReqFlags
	copy(fl.Name[:], h.Name)
	if err := ioctlPtr(s, siocGIfFlags, unsafe.Pointer(&fl)); err != nil {
		return fmt.Errorf("ioctl(SIOCGIFFLAGS, %s): %s", h.Name, errnoName(err))
	}
	// The bit pf's route-to needs is IFF_UP; IFF_RUNNING is set alongside it
	// because utun honours it.
	fl.Flags |= int16(unix.IFF_UP | unix.IFF_RUNNING)
	if err := ioctlPtr(s, siocSIfFlags, unsafe.Pointer(&fl)); err != nil {
		return fmt.Errorf("ioctl(SIOCSIFFLAGS, %s, UP): %s", h.Name, errnoName(err))
	}
	return nil
}

// read waits up to timeout for one datagram and returns the IP packet with the
// 4-byte address-family framing stripped, plus the prefix that was present.
func (h *utunHandle) read(timeout time.Duration) (prefix, pkt []byte, err error) {
	if h == nil || h.fd < 0 {
		return nil, nil, unix.EBADF
	}
	ready, err := waitReadable(h.fd, timeout)
	if err != nil {
		return nil, nil, err
	}
	if !ready {
		return nil, nil, nil
	}
	buf := make([]byte, h.MTU+utunAFPrefixLen+512)
	n, err := unix.Read(h.fd, buf)
	if err != nil {
		return nil, nil, fmt.Errorf("read(utun): %s", errnoName(err))
	}
	if n < utunAFPrefixLen {
		return buf[:n], nil, fmt.Errorf("short utun read: %d bytes", n)
	}
	return buf[:utunAFPrefixLen], buf[utunAFPrefixLen:n], nil
}

// Close destroys the interface by closing its control socket.
func (h *utunHandle) Close() error {
	if h == nil || h.fd < 0 {
		return nil
	}
	err := unix.Close(h.fd)
	h.fd = -1
	if err != nil {
		return fmt.Errorf("close(utun %s): %s", h.Name, errnoName(err))
	}
	return nil
}

// ---------------------------------------------------------------------------
// BPF — request numbers from <net/bpf.h>, cross-checked against x/sys/unix's
// generated darwin/arm64 constants.
// ---------------------------------------------------------------------------

const (
	biocSBlen     = 0xc0044266 // BIOCSBLEN     _IOWR('B', 102, u_int)
	biocSetIf     = 0x8020426c // BIOCSETIF     _IOW ('B', 108, struct ifreq)
	biocGDLT      = 0x4004426a // BIOCGDLT      _IOR ('B', 106, u_int)
	biocImmediate = 0x80044270 // BIOCIMMEDIATE _IOW ('B', 112, u_int)
	biocSHdrCmplt = 0x80044275 // BIOCSHDRCMPLT _IOW ('B', 117, u_int)
	biocSSeeSent  = 0x80044277 // BIOCSSEESENT  _IOW ('B', 119, u_int)
)

// dltEN10MB is DLT_EN10MB: frames written to the descriptor must start with a
// 14-byte Ethernet header.
const dltEN10MB = 1

// bpfProbeBufLen is the kernel read buffer requested via BIOCSBLEN. The probe
// never reads, so the smallest sane value keeps the allocation trivial.
const bpfProbeBufLen = 32 * 1024

// bpfHandle is an open /dev/bpfN descriptor bound to one interface.
type bpfHandle struct {
	fd       int
	Device   string
	Iface    string
	Datalink int
}

// openBPF finds the first usable /dev/bpfN, binds it to iface and configures it
// for a header-complete write: with BIOCSHDRCMPLT the kernel transmits the frame
// verbatim, bypassing pf entirely, which is what keeps re-emission from looping
// back into our own route-to rule.
func openBPF(iface string) (*bpfHandle, error) {
	var lastErr error
	for i := 0; i < 256; i++ {
		dev := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := unix.Open(dev, unix.O_RDWR, 0)
		if err != nil {
			lastErr = fmt.Errorf("open(%s): %s", dev, errnoName(err))
			switch {
			case errors.Is(err, unix.EBUSY):
				continue // in use by another process; try the next node
			case errors.Is(err, unix.ENOENT):
				// No more cloned nodes exist.
				i = 256
			case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
				return nil, lastErr
			}
			continue
		}
		h := &bpfHandle{fd: fd, Device: dev, Iface: iface}
		if err := h.setup(); err != nil {
			_ = unix.Close(fd)
			h.fd = -1
			return nil, err
		}
		return h, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no /dev/bpfN nodes exist")
	}
	return nil, fmt.Errorf("no usable BPF device: %w", lastErr)
}

// setup applies the descriptor options in the order the kernel requires: the
// buffer length must be set before the interface is attached.
func (h *bpfHandle) setup() error {
	blen := int32(bpfProbeBufLen)
	if err := ioctlPtr(h.fd, biocSBlen, unsafe.Pointer(&blen)); err != nil {
		return fmt.Errorf("ioctl(BIOCSBLEN): %s", errnoName(err))
	}
	var req ifReqInt
	copy(req.Name[:], h.Iface)
	if err := ioctlPtr(h.fd, biocSetIf, unsafe.Pointer(&req)); err != nil {
		return fmt.Errorf("ioctl(BIOCSETIF, %s): %s", h.Iface, errnoName(err))
	}
	one := int32(1)
	zero := int32(0)
	if err := ioctlPtr(h.fd, biocSHdrCmplt, unsafe.Pointer(&one)); err != nil {
		return fmt.Errorf("ioctl(BIOCSHDRCMPLT, 1): %s", errnoName(err))
	}
	if err := ioctlPtr(h.fd, biocImmediate, unsafe.Pointer(&one)); err != nil {
		return fmt.Errorf("ioctl(BIOCIMMEDIATE, 1): %s", errnoName(err))
	}
	// Do not capture our own transmissions: the probe only writes.
	if err := ioctlPtr(h.fd, biocSSeeSent, unsafe.Pointer(&zero)); err != nil {
		return fmt.Errorf("ioctl(BIOCSSEESENT, 0): %s", errnoName(err))
	}
	var dlt int32
	if err := ioctlPtr(h.fd, biocGDLT, unsafe.Pointer(&dlt)); err != nil {
		return fmt.Errorf("ioctl(BIOCGDLT): %s", errnoName(err))
	}
	h.Datalink = int(dlt)
	return nil
}

// write transmits one complete link-layer frame.
func (h *bpfHandle) write(frame []byte) (int, error) {
	if h == nil || h.fd < 0 {
		return 0, unix.EBADF
	}
	n, err := unix.Write(h.fd, frame)
	if err != nil {
		return n, fmt.Errorf("write(%s): %s", h.Device, errnoName(err))
	}
	return n, nil
}

// Close releases the BPF descriptor.
func (h *bpfHandle) Close() error {
	if h == nil || h.fd < 0 {
		return nil
	}
	err := unix.Close(h.fd)
	h.fd = -1
	return err
}

// ---------------------------------------------------------------------------
// shared syscall plumbing
// ---------------------------------------------------------------------------

// ioctlPtr issues ioctl(fd, req, arg). It mirrors the unexported helper in
// x/sys/unix. arg must come from unsafe.Pointer(&x) so escape analysis
// heap-allocates x: heap objects do not move, so handing the kernel a uintptr of
// one is safe.
func ioctlPtr(fd int, req uint32, arg unsafe.Pointer) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

// waitReadable blocks until fd is readable or timeout expires, retrying on
// EINTR. poll(2) is used instead of SO_RCVTIMEO because the utun control socket
// is an AF_SYSTEM socket and BPF descriptors are character devices.
func waitReadable(fd int, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return false, nil
		}
		ms := int(remain / time.Millisecond)
		if ms < 1 {
			ms = 1
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, ms)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return false, fmt.Errorf("poll: %s", errnoName(err))
		}
		if n == 0 {
			return false, nil
		}
		if fds[0].Revents&(unix.POLLIN|unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return true, nil
		}
	}
}

// errnoNames maps the errnos this package can observe to their symbolic names.
// It is a slice, not a map literal, because Darwin aliases some values
// (EWOULDBLOCK == EAGAIN) and duplicate constant map keys do not compile.
var errnoNames = []struct {
	e    unix.Errno
	name string
}{
	{unix.EPERM, "EPERM"}, {unix.ENOENT, "ENOENT"}, {unix.ESRCH, "ESRCH"},
	{unix.EINTR, "EINTR"}, {unix.EIO, "EIO"}, {unix.ENXIO, "ENXIO"},
	{unix.EBADF, "EBADF"}, {unix.EACCES, "EACCES"}, {unix.EFAULT, "EFAULT"},
	{unix.EBUSY, "EBUSY"}, {unix.EEXIST, "EEXIST"}, {unix.ENODEV, "ENODEV"},
	{unix.EINVAL, "EINVAL"}, {unix.ENFILE, "ENFILE"}, {unix.EMFILE, "EMFILE"},
	{unix.ENOTTY, "ENOTTY"}, {unix.ENOSPC, "ENOSPC"}, {unix.EROFS, "EROFS"},
	{unix.EPIPE, "EPIPE"}, {unix.EAGAIN, "EAGAIN"}, {unix.EINPROGRESS, "EINPROGRESS"},
	{unix.ENOTSOCK, "ENOTSOCK"}, {unix.EMSGSIZE, "EMSGSIZE"},
	{unix.EPROTOTYPE, "EPROTOTYPE"}, {unix.ENOPROTOOPT, "ENOPROTOOPT"},
	{unix.EPROTONOSUPPORT, "EPROTONOSUPPORT"}, {unix.ENOTSUP, "ENOTSUP"},
	{unix.EAFNOSUPPORT, "EAFNOSUPPORT"}, {unix.EADDRINUSE, "EADDRINUSE"},
	{unix.EADDRNOTAVAIL, "EADDRNOTAVAIL"}, {unix.ENETDOWN, "ENETDOWN"},
	{unix.ENETUNREACH, "ENETUNREACH"}, {unix.ECONNABORTED, "ECONNABORTED"},
	{unix.ECONNRESET, "ECONNRESET"}, {unix.ENOBUFS, "ENOBUFS"},
	{unix.EISCONN, "EISCONN"}, {unix.ENOTCONN, "ENOTCONN"},
	{unix.ETIMEDOUT, "ETIMEDOUT"}, {unix.ECONNREFUSED, "ECONNREFUSED"},
	{unix.EHOSTDOWN, "EHOSTDOWN"}, {unix.EHOSTUNREACH, "EHOSTUNREACH"},
	{unix.ENOSYS, "ENOSYS"}, {unix.ECANCELED, "ECANCELED"},
	{unix.EOPNOTSUPP, "EOPNOTSUPP"}, {unix.ENOMEM, "ENOMEM"},
}

// errnoNameByValue indexes errnoNames, keeping the first name for aliases.
var errnoNameByValue = func() map[unix.Errno]string {
	m := make(map[unix.Errno]string, len(errnoNames))
	for _, en := range errnoNames {
		if _, dup := m[en.e]; !dup {
			m[en.e] = en.name
		}
	}
	return m
}()

// errnoName renders err as "ENAME (message)" when it carries an errno, and as
// the plain message otherwise. Every syscall failure this package reports goes
// through it, so the operator always sees the symbolic errno.
func errnoName(err error) string {
	if err == nil {
		return "OK"
	}
	var e unix.Errno
	if errors.As(err, &e) {
		if name, ok := errnoNameByValue[e]; ok {
			return fmt.Sprintf("%s (%v)", name, e)
		}
		return fmt.Sprintf("errno %d (%v)", int(e), e)
	}
	return err.Error()
}
