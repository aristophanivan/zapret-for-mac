package diag

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
)

// Finding severities. They are plain strings so the CLI can colour them and the
// RPC layer can ship them without a conversion table.
const (
	// SeverityInfo is context the operator should see but need not act on.
	SeverityInfo = "info"
	// SeverityWarn is something that degrades the bypass or will bite later.
	SeverityWarn = "warn"
	// SeverityError is something that makes the bypass not work at all, or
	// leftover state that must be cleaned up.
	SeverityError = "error"
)

// Finding is one diagnostic result. Fix is the concrete action that resolves it,
// phrased as a command or an instruction the operator can follow verbatim; an
// empty Fix means there is nothing to do.
type Finding struct {
	Severity string
	Title    string
	Detail   string
	Fix      string
}

// OK reports whether the finding is informational, i.e. requires no action. It
// exists so translating a Finding into the control protocol's per-check boolean
// is mechanical rather than a judgement call at the call site.
func (f Finding) OK() bool { return f.Severity == SeverityInfo }

// String renders a finding on one line plus its fix, for a terminal.
func (f Finding) String() string {
	s := fmt.Sprintf("[%s] %s: %s", strings.ToUpper(f.Severity), f.Title, f.Detail)
	if f.Fix != "" {
		s += "\n    fix: " + f.Fix
	}
	return s
}

// ProcessInfo is one process the conflict scan matched.
type ProcessInfo struct {
	PID int
	// Path is the executable path `ps -axo comm=` reported.
	Path string
	// Tool is the human name of the product it was recognised as.
	Tool string
	// Why explains how it conflicts with us.
	Why string
	// Fix is the suggested resolution.
	Fix string
}

// IPSetInfo is the tri-state of one loaded ipset, as `zaprctl` sees it. It is
// passed into DoctorOpts rather than read from disk because the authoritative
// copy is the one the running strategy compiled, not the file on disk.
type IPSetInfo struct {
	// Name is the list's file name or logical name.
	Name string
	// Any is lists.CIDRSet.Any: the file was empty, so the set matches every
	// address.
	Any bool
	// None is lists.CIDRSet.IsNone(): the set holds only the 203.0.113.113/32
	// sentinel, so it matches nothing.
	None bool
	// Count is lists.CIDRSet.Len().
	Count int
}

// State reports the tri-state as one of "any", "none" or "loaded".
func (s IPSetInfo) State() string {
	switch {
	case s.Any:
		return "any"
	case s.None:
		return "none"
	default:
		return "loaded"
	}
}

// DNSObservation is one name looked up through both the system resolver and a
// DNS-over-HTTPS resolver.
type DNSObservation struct {
	Name      string
	System    []netip.Addr
	DoH       []netip.Addr
	SystemErr string
	DoHErr    string
	// DoHServer names the resolver the DoH answer came from.
	DoHServer string
}

// HostsState is what the /etc/hosts check needs.
type HostsState struct {
	// Path is the hosts file inspected.
	Path string
	// Applied are the entries currently inside our marker block.
	Applied []netcfg.HostEntry
	// UpstreamPath is flowseal's .upstream/service/hosts, and Upstream the
	// entries parsed from it. An empty UpstreamPath means the comparison could
	// not be made.
	UpstreamPath string
	Upstream     []netcfg.HostEntry
	// Err is a collection failure, if any.
	Err string
}

// SystemState is the complete input to Analyze.
//
// Everything Doctor learns about the machine lands here first, and Analyze then
// turns it into findings without touching the machine again. That split is the
// whole reason the checks are testable: a test constructs a SystemState by hand,
// passes it in through DoctorOpts.State, and asserts on the findings — no root,
// no pf, no network.
type SystemState struct {
	// Caps is the capability probe's verdict (possibly a passive-only one).
	Caps Capabilities
	// CapsProbeSkipped says that Caps was never filled in, so its zero value
	// must not be read as "this machine can do nothing". A caller that already
	// knows its transport (the running daemon does) sets Caps itself and leaves
	// this false.
	CapsProbeSkipped bool
	// UID is the effective uid Doctor ran as.
	UID int

	// Anchor is the pf anchor we own; PfConfPath the main ruleset.
	Anchor     string
	PfConfPath string
	// PfEnabled is pf's status, PfEnabledKnown false when it could not be read.
	PfEnabled      bool
	PfEnabledKnown bool
	// AnchorInPfConf reports whether the main configuration FILE names our
	// anchor (survives a reboot); AnchorReferencedLive whether the RUNNING
	// ruleset does (decides whether our rules are evaluated right now).
	AnchorInPfConf       bool
	AnchorReferencedLive bool
	// WildcardAnchorLive reports that the running ruleset declares a wildcard
	// anchor point covering "com.apple/<anchor>", both for filter and for
	// translation rules. That makes our rules evaluated without any edit to the
	// main configuration file, which is the daemon's preferred mode — so an
	// unpatched pf.conf is then correct rather than broken.
	WildcardAnchorLive bool
	// EffectiveAnchor is the anchor path that actually answered with our rules:
	// "com.apple/<anchor>" in wildcard mode, the plain name otherwise.
	EffectiveAnchor string
	// ForeignAnchors are anchors in the main ruleset that are neither ours nor
	// Apple's.
	ForeignAnchors []string

	// AnchorRules and AnchorNat are `pfctl -a <anchor> -s rules|nat` output.
	AnchorRules string
	AnchorNat   string
	// WantRules is the ruleset the running strategy needs (netcfg.SteerRules or
	// netcfg.RedirectRules output). Empty disables the drift check.
	WantRules string

	// Journal are the rollback records still on disk; JournalPath where they
	// live.
	Journal     []netcfg.Entry
	JournalPath string
	// PfToken is the `pfctl -E` token found in the state directory, "" when
	// none.
	PfToken string
	// PfTokenPath is where that token file lives.
	PfTokenPath string
	// DaemonRunning tells the journal, token and anchor checks whether the
	// leftovers they see belong to a live daemon. DaemonRunningKnown is false
	// when the caller could not determine it, in which case those checks report
	// conditionally.
	DaemonRunning      bool
	DaemonRunningKnown bool

	// OrphanUtuns are utun interfaces carrying an address from our
	// point-to-point pool (198.18.0.0/15) — a tunnel a crashed daemon created.
	OrphanUtuns []string

	// Competing are processes recognised as other packet filters or bypass
	// tools; BusyPorts are the usual local-proxy ports something is already
	// listening on.
	Competing []ProcessInfo
	BusyPorts []int

	// Hosts is the /etc/hosts pinning state.
	Hosts HostsState

	// IPSets is the tri-state of every ipset the running strategy uses.
	IPSets []IPSetInfo

	// DNS holds the system-vs-DoH comparisons.
	DNS []DNSObservation

	// Iface and MTU describe the uplink; TSO is net.inet.tcp.tso and
	// TSOKnown whether that sysctl exists.
	Iface    string
	MTU      int
	TSO      int
	TSOKnown bool

	// Strategy is the active strategy's name and StrategyUnsupported the ops
	// the active transport cannot honour (strategy.Strategy.Unsupported).
	Strategy            string
	StrategyUnsupported []string

	// CollectErrors records checks that could not be performed, so a missing
	// finding is never mistaken for a passing one.
	CollectErrors []string
}

// DoctorOpts configures Doctor, CollectState and Repair.
type DoctorOpts struct {
	// State, when non-nil, is used verbatim instead of reading the machine.
	// This is the seam the tests use, and it is also how `zaprctl` re-analyses a
	// state it captured earlier.
	State *SystemState

	// Anchor, PfConfPath, PfctlPath, HostsPath and StateDir locate everything we
	// own. Empty fields take the netcfg defaults.
	Anchor     string
	PfConfPath string
	PfctlPath  string
	HostsPath  string
	StateDir   string
	// HostsMarker overrides the /etc/hosts block marker (default "zapret-mac").
	HostsMarker string
	// UpstreamHostsPath is flowseal's service/hosts, used for the staleness
	// comparison. Empty disables it.
	UpstreamHostsPath string

	// WantRules is the ruleset the running strategy needs; Strategy and
	// StrategyUnsupported describe it. All three are supplied by the caller
	// because Doctor does not load strategies itself.
	WantRules           string
	Strategy            string
	StrategyUnsupported []string
	// IPSets is the tri-state of the running strategy's ipsets.
	IPSets []IPSetInfo

	// DaemonRunning, when non-nil, tells the leftover checks whether a daemon
	// is live.
	DaemonRunning *bool

	// Detect configures the capability probe CollectState runs. SkipDetect
	// suppresses it entirely (Caps is then left zero and reported as unknown).
	Detect     DetectOpts
	SkipDetect bool

	// SkipDNS suppresses the resolver comparison, which is the only check that
	// needs the network. DNSNames overrides the names compared.
	SkipDNS  bool
	DNSNames []string
	// SystemResolver and DoHResolver override the resolvers, which is how the
	// comparison is tested without a network.
	SystemResolver Resolver
	DoHResolver    Resolver

	// DryRun makes Repair report what it would do without doing it.
	DryRun bool

	// Timeout bounds CollectState. Defaults to 20s.
	Timeout time.Duration
	// Logf receives progress lines.
	Logf func(format string, args ...any)
}

// withDefaults fills in the unset fields.
func (o DoctorOpts) withDefaults() DoctorOpts {
	if o.Anchor == "" {
		o.Anchor = DefaultProbeAnchor
	}
	if o.PfConfPath == "" {
		o.PfConfPath = netcfg.DefaultPfConfPath
	}
	if o.PfctlPath == "" {
		o.PfctlPath = netcfg.DefaultPfctlPath
	}
	if o.HostsPath == "" {
		o.HostsPath = netcfg.DefaultHostsPath
	}
	if o.HostsMarker == "" {
		o.HostsMarker = "zapret-mac"
	}
	if len(o.DNSNames) == 0 {
		o.DNSNames = DefaultDNSCheckNames()
	}
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return o
}

// DefaultDNSCheckNames are the names the resolver comparison uses: names this
// tool exists to unblock, whose DNS answers are therefore the ones a censor has
// a motive to forge.
func DefaultDNSCheckNames() []string {
	return []string{"discord.com", "cdn.discordapp.com", "www.youtube.com"}
}

// Doctor collects the machine's state and analyses it, returning findings
// ordered most-actionable first (errors, then warnings, then info; stable within
// each group).
//
// It reads and probes but changes nothing: the only mutation any check performs
// is Detect's fully reversible capability probe, and even that is skippable with
// DoctorOpts.SkipDetect. An unprivileged run still produces a useful report.
func Doctor(ctx context.Context, o DoctorOpts) ([]Finding, error) {
	o = o.withDefaults()
	if o.State != nil {
		return Analyze(*o.State), nil
	}
	st, err := CollectState(ctx, o)
	if err != nil {
		return nil, err
	}
	return Analyze(st), nil
}

// CollectState reads everything Analyze needs off the machine. It is exported so
// `zaprctl doctor --json` can dump the raw state, and so a caller can collect
// once and analyse repeatedly.
func CollectState(ctx context.Context, o DoctorOpts) (SystemState, error) {
	o = o.withDefaults()
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	st := SystemState{
		UID:                 os.Geteuid(),
		Anchor:              o.Anchor,
		PfConfPath:          o.PfConfPath,
		WantRules:           o.WantRules,
		Strategy:            o.Strategy,
		StrategyUnsupported: o.StrategyUnsupported,
		IPSets:              o.IPSets,
	}
	if o.DaemonRunning != nil {
		st.DaemonRunning = *o.DaemonRunning
		st.DaemonRunningKnown = true
	}
	fail := func(what string, err error) {
		st.CollectErrors = append(st.CollectErrors, what+": "+err.Error())
	}

	// --- capabilities -------------------------------------------------------
	st.CapsProbeSkipped = o.SkipDetect
	if !o.SkipDetect {
		d := o.Detect
		d.Anchor = o.Anchor
		d.PfConfPath = o.PfConfPath
		d.PfctlPath = o.PfctlPath
		caps, err := Detect(ctx, d)
		if err != nil {
			fail("capability probe", err)
		}
		st.Caps = caps
	}
	st.Iface = st.Caps.Iface
	st.MTU = st.Caps.MTU
	if st.Iface == "" {
		if r, err := netcfg.DefaultRoute4(); err == nil {
			st.Iface, st.MTU = r.Iface, r.MTU
		}
	}
	// TCP segmentation offload: with it on, a segment read from the utun can be
	// larger than the MTU and carry a checksum the NIC was going to fill in, so
	// the transport must recompute checksums rather than trust them.
	if v, ok := sysctlIntOK("net.inet.tcp.tso"); ok {
		st.TSO, st.TSOKnown = v, true
	}

	// --- pf state -----------------------------------------------------------
	if out, _, err := runPfctl(ctx, o.PfctlPath, "", "-s", "info"); err == nil {
		st.PfEnabled = strings.Contains(out, "Status: Enabled")
		st.PfEnabledKnown = true
	} else {
		fail("pfctl -s info", err)
	}
	if conf, err := os.ReadFile(o.PfConfPath); err == nil {
		st.AnchorInPfConf = netcfg.AnchorStatementsPresent(conf, o.Anchor)
		for _, name := range netcfg.AnchorNames(conf) {
			if name == o.Anchor || strings.HasPrefix(name, "com.apple") {
				continue
			}
			st.ForeignAnchors = appendUnique(st.ForeignAnchors, name)
		}
	} else {
		fail("read "+o.PfConfPath, err)
	}
	wildFilter, wildNat := false, false
	for _, what := range []string{"rules", "nat"} {
		out, _, err := runPfctl(ctx, o.PfctlPath, "", "-s", what)
		if err != nil {
			fail("pfctl -s "+what, err)
			continue
		}
		if rulesetReferencesAnchor(out, o.Anchor) {
			st.AnchorReferencedLive = true
		}
		if netcfg.WildcardAnchorCovers(out, "com.apple/"+o.Anchor) {
			if what == "rules" {
				wildFilter = true
			} else {
				wildNat = true
			}
		}
		for _, name := range liveAnchorNames(out) {
			if name == o.Anchor || strings.HasPrefix(name, "com.apple") {
				continue
			}
			st.ForeignAnchors = appendUnique(st.ForeignAnchors, name)
		}
	}
	// Both halves are required: filter rules ride the `anchor "com.apple/*"`
	// point and rdr rules the `rdr-anchor "com.apple/*"` one.
	st.WildcardAnchorLive = wildFilter && wildNat
	// The daemon loads rules into the wildcard sub-anchor "com.apple/<anchor>"
	// whenever the stock ruleset provides that anchor point, and only falls back
	// to a top-level anchor otherwise. Asking the top-level name alone reported
	// an empty anchor while the datapath was steering happily through the
	// sub-anchor — a false alarm that pointed the user at a non-existent
	// problem. Ask the effective name, and remember which one answered.
	st.EffectiveAnchor = o.Anchor
	if st.WildcardAnchorLive {
		sub := "com.apple/" + o.Anchor
		subRules, _, subErr := runPfctl(ctx, o.PfctlPath, "", "-a", sub, "-s", "rules")
		subNat, _, _ := runPfctl(ctx, o.PfctlPath, "", "-a", sub, "-s", "nat")
		if subErr == nil && (strings.TrimSpace(subRules) != "" || strings.TrimSpace(subNat) != "") {
			st.EffectiveAnchor = sub
			st.AnchorRules, st.AnchorNat = subRules, subNat
		}
	}
	if st.EffectiveAnchor == o.Anchor {
		if out, _, err := runPfctl(ctx, o.PfctlPath, "", "-a", o.Anchor, "-s", "rules"); err == nil {
			st.AnchorRules = out
		} else {
			fail("pfctl -a "+o.Anchor+" -s rules", err)
		}
		if out, _, err := runPfctl(ctx, o.PfctlPath, "", "-a", o.Anchor, "-s", "nat"); err == nil {
			st.AnchorNat = out
		}
	}

	// --- our own leftovers --------------------------------------------------
	if o.StateDir != "" {
		st.JournalPath = filepath.Join(o.StateDir, netcfg.JournalName)
		entries, err := readJournalFile(st.JournalPath)
		if err != nil {
			fail("read "+st.JournalPath, err)
		}
		st.Journal = entries

		st.PfTokenPath = filepath.Join(o.StateDir, netcfg.PfTokenName)
		if tok, err := readTokenFile(st.PfTokenPath); err == nil {
			st.PfToken = tok
		} else if !os.IsNotExist(err) {
			fail("read "+st.PfTokenPath, err)
		}
	}
	// Only interfaces the journal says we created count; see findOrphanUtuns.
	st.OrphanUtuns = findOrphanUtuns(st.Journal)

	// --- competing owners ---------------------------------------------------
	procs, err := scanProcesses(ctx)
	if err != nil {
		fail("process scan", err)
	}
	st.Competing = procs
	st.BusyPorts = busyLocalPorts(usualProxyPorts())

	// --- hosts --------------------------------------------------------------
	st.Hosts = collectHosts(o)

	// --- DNS ----------------------------------------------------------------
	if !o.SkipDNS {
		st.DNS = compareResolvers(ctx, o)
	}
	return st, nil
}

// appendUnique appends s when it is not already present.
func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

// liveAnchorNames extracts anchor names from `pfctl -s rules|nat` output, which
// renders them as `anchor "name" all`.
func liveAnchorNames(ruleset string) []string {
	var out []string
	for _, line := range strings.Split(ruleset, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 {
			continue
		}
		if !strings.HasSuffix(f[0], "anchor") {
			continue
		}
		name := strings.Trim(f[1], `"`)
		if name == "" {
			continue
		}
		out = appendUnique(out, strings.TrimSuffix(strings.TrimSuffix(name, "/*"), "/"))
	}
	return out
}

// readJournalFile parses netcfg's append-only JSON-lines journal without opening
// it for append, so a read-only doctor run cannot truncate a torn tail or create
// the state directory. Malformed lines are skipped, exactly as netcfg does.
func readJournalFile(path string) ([]netcfg.Entry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []netcfg.Entry
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e netcfg.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil || e.Step == "" {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

// readTokenFile reads a persisted `pfctl -E` token, rejecting anything that is
// not all digits.
func readTokenFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", nil
	}
	for _, c := range t {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("token file %s does not contain a number: %q", path, t)
		}
	}
	return t, nil
}

// ourTunnelPool is the point-to-point address space the divert transport prefers
// for its utun: RFC 2544 benchmarking space, which never appears in real traffic.
//
// It is emphatically NOT proof of ownership. AmneziaVPN — the VPN this machine
// runs — addresses its own tunnel 198.18.0.1, the very address we would pick
// first. Treating an address from this range as "ours" would make the doctor tell
// a user to go kill their VPN, so ownership is established from the rollback
// journal instead and this prefix only narrows the candidates.
var ourTunnelPool = netip.MustParsePrefix("198.18.0.0/15")

// findOrphanUtuns lists the tunnel interfaces this daemon is known to have
// created and that still exist.
//
// Ownership comes from journal (netcfg.StepUtun records the interface name a
// daemon created), never from the address alone. With no journal entry naming an
// interface, nothing is reported: a false claim here is worse than a missed one,
// because the suggested action is "find the process holding it and kill it".
func findOrphanUtuns(journal []netcfg.Entry) []string {
	claimed := map[string]bool{}
	for _, e := range journal {
		if e.Step != netcfg.StepUtun {
			continue
		}
		if name := e.Data["iface"]; name != "" {
			claimed[name] = true
		}
	}
	if len(claimed) == 0 {
		return nil
	}
	ifaces, err := netcfg.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for name := range claimed {
		inf, ok := ifaces[name]
		if !ok {
			// Already gone: the process holding it exited, which is the normal
			// outcome and needs no report.
			continue
		}
		// Confirm it still looks like ours before naming it. A recycled utun
		// number belonging to something else must not be reported.
		for _, a := range inf.Addrs {
			if a.Is4() && ourTunnelPool.Contains(a.Unmap()) {
				out = append(out, name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// knownConflicts are the products whose presence changes how our own filtering
// behaves. Match is compared case-insensitively against the executable path.
var knownConflicts = []struct {
	Match string
	Tool  string
	Why   string
	Fix   string
}{
	{"littlesnitch", "Little Snitch",
		"it installs a NetworkExtension content filter that sees connections before pf does and can block the daemon's own sockets",
		"allow the zapret-mac daemon in Little Snitch, or quit Little Snitch while testing"},
	{"obdev", "Little Snitch (Objective Development helper)",
		"a Little Snitch helper is running, so a NetworkExtension filter is active alongside pf",
		"allow the zapret-mac daemon in Little Snitch's rules"},
	{"lulu", "LuLu",
		"LuLu is a NetworkExtension firewall: it can silently block the daemon's outbound sockets and its DoH lookups",
		"add an allow rule for the zapret-mac daemon in LuLu, or quit LuLu while testing"},
	{"radiosilence", "Radio Silence",
		"another NetworkExtension firewall is filtering connections independently of pf",
		"allow the zapret-mac daemon there, or quit it while testing"},
	{"tpws", "zapret tpws",
		"another zapret component is running and will own overlapping pf rdr rules and local ports",
		"stop it before starting this daemon: they cannot both redirect the same port window"},
	{"nfqws", "zapret nfqws",
		"an nfqws process is running, which means a second zapret installation is active",
		"stop it before starting this daemon"},
	{"zapret", "another zapret installation",
		"a second zapret installation is running and may own pf anchors and rules of its own",
		"stop it, then run `zaprctl doctor --repair` to clear anything it left behind"},
	{"byedpi", "ByeDPI",
		"ByeDPI is a local SOCKS proxy doing its own DPI bypass: applications pointed at it never reach our port window",
		"stop ByeDPI, or point your applications away from its SOCKS port"},
	{"ciadpi", "ByeDPI (ciadpi)",
		"a ByeDPI binary is running as a local proxy doing its own bypass",
		"stop it, or point your applications away from its SOCKS port"},
	{"sing-box", "sing-box",
		"sing-box usually creates a tun interface and takes the default route, so our desync never sees the traffic",
		"stop sing-box, or configure it not to take the default route"},
	{"xray", "Xray",
		"Xray proxies traffic before it reaches our port window",
		"stop Xray while testing the bypass"},
	{"v2ray", "V2Ray",
		"V2Ray proxies traffic before it reaches our port window",
		"stop V2Ray while testing the bypass"},
	{"clash", "Clash / Mihomo",
		"Clash usually installs a tun device and a default route, so our desync never sees the traffic",
		"stop Clash, or switch it out of tun mode"},
	{"tun2socks", "tun2socks",
		"tun2socks takes the default route into a userspace stack, bypassing our steering entirely",
		"stop it while testing the bypass"},
	{"amnezia", "AmneziaVPN",
		"AmneziaVPN routes everything through its own tunnel, so there is no DPI on the path left to fool",
		"disconnect the VPN, or accept that desync is a no-op while it is up"},
	{"openvpn", "OpenVPN",
		"OpenVPN routes traffic through a tunnel; if it holds the default route, desync is pointless",
		"disconnect it, or restrict it to split tunnelling"},
	{"wireguard", "WireGuard",
		"WireGuard routes traffic through a tunnel; if it holds the default route, desync is pointless",
		"disconnect it, or restrict AllowedIPs so it does not take the default route"},
	{"tailscale", "Tailscale",
		"Tailscale can take the default route when an exit node is selected, which bypasses our steering",
		"disable the exit node while testing the bypass"},
}

// scanProcesses lists running processes and returns the ones recognised as
// conflicting. It uses `ps -axo pid=,comm=` rather than reading kinfo_proc: the
// struct layout is version-dependent and undocumented, while this output format
// has been stable for decades. `ps` needs no privileges to list other users'
// processes on macOS.
func scanProcesses(ctx context.Context) ([]ProcessInfo, error) {
	cmd := exec.CommandContext(ctx, "/bin/ps", "-axo", "pid=,comm=")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("/bin/ps -axo pid=,comm=: %w", err)
	}
	return matchProcesses(string(out)), nil
}

// matchProcesses is the pure half of scanProcesses: it turns `ps` output into
// conflict findings. Split out so it can be tested against captured output.
func matchProcesses(psOutput string) []ProcessInfo {
	var out []ProcessInfo
	seen := map[string]bool{}
	self := os.Getpid()
	for _, line := range strings.Split(psOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		sp := strings.IndexAny(line, " \t")
		if sp < 0 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(line[:sp]))
		if err != nil {
			continue
		}
		path := strings.TrimSpace(line[sp+1:])
		if path == "" || pid == self {
			continue
		}
		lower := strings.ToLower(path)
		for _, k := range knownConflicts {
			if !strings.Contains(lower, k.Match) {
				continue
			}
			// One finding per product, not per process: a firewall spawns
			// several helpers and listing them all buries the report.
			if seen[k.Tool] {
				break
			}
			seen[k.Tool] = true
			out = append(out, ProcessInfo{PID: pid, Path: path, Tool: k.Tool, Why: k.Why, Fix: k.Fix})
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}

// usualProxyPorts are the loopback ports the bypass tools in this space use by
// default. Something already listening there is either another such tool or a
// previous instance of ours.
func usualProxyPorts() []int {
	return []int{
		988,   // zapret tpws default
		1080,  // SOCKS: ByeDPI/ciadpi default
		1081,  // ByeDPI alternate
		8881,  // spoofdpi default
		10800, // our proxy transport's default listener
		10801, // our proxy transport's second listener
	}
}

// busyLocalPorts reports which of ports already has a listener on 127.0.0.1. It
// tests by binding: a successful bind is released immediately, so nothing is
// taken away from anyone.
func busyLocalPorts(ports []int) []int {
	var busy []int
	for _, p := range ports {
		l, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			// EADDRINUSE is the only failure that means "someone is there";
			// EACCES on a privileged port means we simply may not look.
			if errors.Is(err, unix.EADDRINUSE) {
				busy = append(busy, p)
			}
			continue
		}
		_ = l.Close()
	}
	return busy
}

// collectHosts reads our /etc/hosts block and flowseal's upstream list.
func collectHosts(o DoctorOpts) HostsState {
	hs := HostsState{Path: o.HostsPath, UpstreamPath: o.UpstreamHostsPath}
	h := netcfg.NewHosts(o.HostsPath, "")
	h.SetMarker(o.HostsMarker)
	applied, err := h.Applied()
	if err != nil {
		// A parse complaint still yields usable entries; record it and go on.
		hs.Err = err.Error()
	}
	hs.Applied = applied
	if o.UpstreamHostsPath != "" {
		if b, rerr := os.ReadFile(o.UpstreamHostsPath); rerr == nil {
			up, perr := netcfg.ParseHostsFile(b)
			hs.Upstream = up
			if perr != nil && hs.Err == "" {
				hs.Err = perr.Error()
			}
		} else {
			hs.UpstreamPath = ""
			if hs.Err == "" {
				hs.Err = rerr.Error()
			}
		}
	}
	return hs
}

// ---------------------------------------------------------------------------
// Analyze — pure
// ---------------------------------------------------------------------------

// Analyze turns a collected SystemState into findings. It is pure: no syscalls,
// no subprocesses, no clock. Every check is exercised by the tests through a
// hand-built SystemState, which is why DoctorOpts carries a State field at all.
//
// Findings come back ordered by severity (error, warn, info) and, within a
// severity, in the order the checks are written here, which is roughly "most
// likely to be the actual problem" first.
func Analyze(st SystemState) []Finding {
	var f []Finding
	add := func(sev, title, detail, fix string) {
		f = append(f, Finding{Severity: sev, Title: title, Detail: detail, Fix: fix})
	}

	// ---- 1. a VPN owns the default route ---------------------------------
	if st.Caps.TunnelDefaultRoute != "" {
		add(SeverityError, "A VPN holds the default route",
			fmt.Sprintf("the IPv4 default route goes through tunnel interface %s. Two things break at once: the "+
				"traffic we would desync is encapsulated and never passes the DPI we are fooling, and the divert "+
				"transport's BPF re-emit writes Ethernet frames on the physical uplink (%s), which is not where "+
				"those packets are supposed to go.",
				st.Caps.TunnelDefaultRoute, orUnknown(st.Iface)),
			"disconnect the VPN (AmneziaVPN/OpenVPN/WireGuard) before using zapret-mac, or configure it for split "+
				"tunnelling so the hosts you want unblocked stay off the tunnel. If you keep the VPN, you do not "+
				"need this tool for those hosts at all.")
	}

	// ---- 2. what can this machine do -------------------------------------
	switch {
	case st.CapsProbeSkipped:
		// The zero Capabilities must never be read as "this machine can do
		// nothing"; say plainly that nothing was measured.
		add(SeverityInfo, "Capability probe was not run",
			"the transport verdict below is whatever the caller supplied, not something this run measured.",
			"")
	default:
		f = append(f, transportFindings(st)...)
	}

	// ---- 3. competing pf owners and filters ------------------------------
	if len(st.ForeignAnchors) > 0 {
		add(SeverityWarn, "Foreign pf anchors in the main ruleset",
			fmt.Sprintf("the main pf ruleset references anchors that are neither ours (%q) nor Apple's: %s. Another "+
				"filtering tool or VPN owns rules that are evaluated alongside ours, and pf's filter rules are "+
				"last-match-wins, so one of theirs can silently override our steering.",
				st.Anchor, strings.Join(st.ForeignAnchors, ", ")),
			"inspect them with `sudo pfctl -a <name> -s rules`. If they belong to a tool you no longer use, remove "+
				"its anchor statement from "+orDefault(st.PfConfPath, netcfg.DefaultPfConfPath)+
				" yourself — zapret-mac never edits foreign rules.")
	}
	for _, p := range st.Competing {
		add(SeverityWarn, "Competing tool running: "+p.Tool,
			fmt.Sprintf("pid %d (%s): %s", p.PID, p.Path, p.Why), p.Fix)
	}
	if len(st.BusyPorts) > 0 {
		add(SeverityWarn, "Another local proxy is listening",
			fmt.Sprintf("something already holds %s on 127.0.0.1. Those are the default ports of tpws, ByeDPI and "+
				"our own proxy transport, so either a second bypass tool is running or a previous instance of this "+
				"daemon did not exit cleanly.", joinInts(st.BusyPorts)),
			"find the owner with `sudo lsof -nP -iTCP:"+strconv.Itoa(st.BusyPorts[0])+" -sTCP:LISTEN` and stop it, "+
				"or configure our proxy transport onto a different port.")
	}

	f = append(f, ourStateFindings(st)...)
	f = append(f, environmentFindings(st)...)
	return sortFindings(f)
}

// transportFindings reports what the capability probe concluded and why.
func transportFindings(st SystemState) []Finding {
	var f []Finding
	add := func(sev, title, detail, fix string) {
		f = append(f, Finding{Severity: sev, Title: title, Detail: detail, Fix: fix})
	}
	switch st.Caps.Transport() {
	case TransportDivert:
		add(SeverityInfo, "Transport: divert (full capabilities)",
			fmt.Sprintf("pf route-to into a utun plus a BPF Ethernet write on %s: every winws-class technique is "+
				"available (%s).", orUnknown(st.Iface), st.Caps.Summary()), "")
	case TransportProxy:
		add(SeverityWarn, "Transport: proxy (degraded)",
			fmt.Sprintf("packet-level interception is unavailable, so only the socket-level transport can run: TCP "+
				"only, and only byte-level tricks — no fake packets, no seqovl, no UDP/QUIC. (%s)", st.Caps.Summary()),
			"read the Notes from the capability probe: usually either the BPF write or the route-to steering "+
				"failed. Run `zaprctl doctor` as root, and check that no VPN owns the default route.")
	default:
		detail := st.Caps.Summary()
		fix := "run as root (`sudo zaprctl doctor`): /dev/pf, /dev/bpfN and utun creation all require it."
		if st.Caps.Root {
			fix = "check the capability probe's Notes: pf itself could not be driven, which usually means pfctl is " +
				"missing or /dev/pf could not be opened."
		}
		add(SeverityError, "No transport can run on this machine", detail, fix)
	}
	for _, n := range st.Caps.Notes {
		add(SeverityInfo, "Capability note", n, "")
	}
	return f
}

// ourStateFindings reports on the state this daemon itself owns: pf, our anchor,
// the rules inside it, the leftovers of a previous run, the resolver answers we
// depend on, our /etc/hosts pins and the ipsets the running strategy filters by.
func ourStateFindings(st SystemState) []Finding {
	var f []Finding
	add := func(sev, title, detail, fix string) {
		f = append(f, Finding{Severity: sev, Title: title, Detail: detail, Fix: fix})
	}

	// ---- 4. our own state -------------------------------------------------
	if st.PfEnabledKnown && !st.PfEnabled {
		add(SeverityError, "pf is disabled",
			"packet filtering is off, so no steering or redirect rule of ours can fire.",
			"the daemon enables pf itself with `sudo pfctl -E` (a reference-counted enable it releases with "+
				"`pfctl -X`). If you want it on now: `sudo pfctl -E`. Never use `pfctl -d` to turn it off again — "+
				"that would break every other component that took a reference.")
	}
	switch {
	case !st.AnchorInPfConf && !st.AnchorReferencedLive && st.WildcardAnchorLive:
		// The healthy default on a stock machine: nothing to fix, and saying so
		// matters, because the older advice ("patch pf.conf") is now the worse
		// option — it edits a system file for no gain.
		add(SeverityInfo, "Rules reach pf without touching any system file",
			fmt.Sprintf("the running ruleset declares the wildcard anchor points \"com.apple/*\" for both filter and "+
				"translation rules, so everything we load into the sub-anchor %q is evaluated. %s is therefore left "+
				"exactly as macOS shipped it.", "com.apple/"+st.Anchor, st.PfConfPath),
			"nothing to do. If something ever flushes com.apple/* wholesale, the daemon sees the drift and reloads "+
				"its rules; `sudo zaprctl status` shows the last verification.")
	case !st.AnchorInPfConf && st.AnchorReferencedLive:
		add(SeverityWarn, "Our anchor is live but not persisted",
			fmt.Sprintf("the running ruleset references anchor %q, but %s does not. The reference disappears at the "+
				"next reboot, and sooner if anything runs `pfctl -f %s` — a macOS update, a VPN client, or Internet "+
				"Sharing all do.", st.Anchor, st.PfConfPath, st.PfConfPath),
			"let the daemon persist it (it patches "+st.PfConfPath+" inside marker comments, with a byte-exact "+
				"backup and a journal entry), or add these lines yourself:\n"+AnchorStatementLines(st.Anchor))
	case !st.AnchorInPfConf && !st.AnchorReferencedLive && !st.WildcardAnchorLive:
		add(SeverityError, "Our anchor is not referenced anywhere",
			fmt.Sprintf("neither the running ruleset nor %s names anchor %q. A stock macOS %s only anchors "+
				"\"com.apple/*\", so everything we load into our anchor is never evaluated: the daemon would appear "+
				"to start fine and do nothing at all.", st.PfConfPath, st.Anchor, st.PfConfPath),
			"start the daemon (it performs this one edit itself, reversibly), or add by hand:\n"+
				AnchorStatementLines(st.Anchor))
	case st.AnchorInPfConf && !st.AnchorReferencedLive:
		add(SeverityError, "Our anchor statement is in the file but not loaded",
			fmt.Sprintf("%s names anchor %q, but the kernel's running ruleset does not — the file has been patched "+
				"and never loaded, or something reloaded a different ruleset afterwards.", st.PfConfPath, st.Anchor),
			"reload the main ruleset: `sudo pfctl -f "+st.PfConfPath+"`. (This flushes anchors other services "+
				"inserted at runtime; that is inherent to pf on macOS and is what "+st.PfConfPath+"'s own comment "+
				"warns about.)")
	}

	if strings.TrimSpace(st.WantRules) != "" {
		missing, extra := RulesDrift(st.WantRules, st.AnchorRules+"\n"+st.AnchorNat)
		if len(missing) > 0 {
			add(SeverityError, "Loaded pf rules do not match the running strategy",
				fmt.Sprintf("anchor %q is missing %d rule(s) the active strategy needs: %s. Anything that runs "+
					"`pfctl -f /etc/pf.conf` wipes an anchor's contents, so this is what a macOS update or a VPN "+
					"client leaves behind.", st.Anchor, len(missing), describeFeatures(missing)),
				"re-apply the strategy (`zaprctl reload`), which reloads the anchor from scratch.")
		}
		if len(extra) > 0 {
			add(SeverityWarn, "Unexpected rules in our anchor",
				fmt.Sprintf("anchor %q holds %d rule(s) the active strategy did not ask for: %s. They are most "+
					"likely left over from a previous strategy that was replaced without a flush.",
					st.Anchor, len(extra), describeFeatures(extra)),
				"`zaprctl reload` rewrites the anchor from the active strategy; `sudo pfctl -a "+st.Anchor+
					" -F all` empties it.")
		}
	} else if strings.TrimSpace(st.AnchorRules) == "" && strings.TrimSpace(st.AnchorNat) == "" && st.Strategy != "" {
		add(SeverityError, "Our anchor is empty while a strategy is active",
			fmt.Sprintf("strategy %q is supposed to be running, but anchor %q holds no rules at all, so no traffic "+
				"is being steered.", st.Strategy, orString(st.EffectiveAnchor, st.Anchor)),
			"`zaprctl reload` to re-apply the strategy.")
	}

	if len(st.Journal) > 0 {
		live := st.DaemonRunningKnown && st.DaemonRunning
		sev := SeverityError
		lead := "a previous daemon exited without unwinding its changes"
		if live {
			sev = SeverityInfo
			lead = "the running daemon has changes recorded that it will unwind on exit"
		}
		add(sev, "Rollback journal is not empty",
			fmt.Sprintf("%s: %s in %s (%s).", lead, countOf(len(st.Journal), "entry", "entries"), st.JournalPath,
				summariseJournal(st.Journal)),
			ifElse(live, "nothing to do while the daemon is running.",
				"`sudo zaprctl doctor --repair` replays the journal in reverse: it releases the pf reference, "+
					"removes our marker block from /etc/pf.conf and /etc/hosts, and flushes our anchor. It never "+
					"touches a line it did not write."))
	}
	if st.PfToken != "" {
		live := st.DaemonRunningKnown && st.DaemonRunning
		if live {
			add(SeverityInfo, "pf reference held",
				fmt.Sprintf("the daemon holds pf enable token %s (recorded in %s) and releases it on exit.",
					st.PfToken, st.PfTokenPath), "")
		} else {
			add(SeverityWarn, "Stale pf enable reference",
				fmt.Sprintf("token %s is recorded in %s but no daemon is running. pf's enable count is "+
					"reference-counted, so this leaked reference keeps pf enabled for the rest of the uptime.",
					st.PfToken, st.PfTokenPath),
				"`sudo zaprctl doctor --repair`, or release it directly with `sudo pfctl -X "+st.PfToken+"`.")
		}
	}
	if len(st.OrphanUtuns) > 0 && !(st.DaemonRunningKnown && st.DaemonRunning) {
		add(SeverityWarn, "Orphaned tunnel interface",
			fmt.Sprintf("%s %s recorded in our rollback journal as created by this daemon and still %s, "+
				"addressed out of our point-to-point pool (%s), while no daemon is running. A utun exists only as "+
				"long as some process holds its control socket, so a process is still alive holding ours.",
				strings.Join(st.OrphanUtuns, ", "),
				plural(len(st.OrphanUtuns), "is", "are"),
				plural(len(st.OrphanUtuns), "exists", "exist"),
				ourTunnelPool),
			"find the holder with `sudo lsof -nP | grep -i utun` and stop it. The interface disappears by itself "+
				"the moment that process exits — it cannot be destroyed from outside.")
	}

	// ---- 5. DNS -----------------------------------------------------------
	for _, obs := range st.DNS {
		f = append(f, dnsFinding(obs))
	}

	// ---- 6. /etc/hosts pinning -------------------------------------------
	f = append(f, hostsFindings(st.Hosts)...)

	// ---- 7. ipset tri-state ----------------------------------------------
	for _, s := range st.IPSets {
		switch s.State() {
		case "any":
			add(SeverityWarn, "ipset "+s.Name+" is in the \"any\" state",
				fmt.Sprintf("%s parsed to zero entries, which zapret treats as \"match every address\". Every "+
					"connection in the port window is then desynced, including to sites that were never blocked — "+
					"which is the usual cause of \"some unrelated site broke after I installed this\".", s.Name),
				"put real prefixes in the list, or switch the strategy's filter to a hostlist. If you meant "+
					"\"match nothing\", the marker is a single line `203.0.113.113/32`.")
		case "none":
			add(SeverityInfo, "ipset "+s.Name+" is in the \"none\" state",
				fmt.Sprintf("%s contains only the 203.0.113.113/32 sentinel, so the profile guarding on it can "+
					"never match. That is the deliberate way to disable an ipset-filtered profile.", s.Name), "")
		default:
			add(SeverityInfo, "ipset "+s.Name+" loaded",
				fmt.Sprintf("%d prefix(es).", s.Count), "")
		}
	}

	return f
}

// environmentFindings reports the machine-level context: link characteristics
// that change how split positions behave, the OS and SIP versions, how well the
// active strategy fits the active transport, and every check that could not run.
func environmentFindings(st SystemState) []Finding {
	var f []Finding
	add := func(sev, title, detail, fix string) {
		f = append(f, Finding{Severity: sev, Title: title, Detail: detail, Fix: fix})
	}

	// ---- 8. MTU / offload -------------------------------------------------
	if st.Iface != "" && st.MTU > 0 && st.MTU != 1500 {
		sev := SeverityWarn
		detail := fmt.Sprintf("%s has an MTU of %d, not the usual 1500.", st.Iface, st.MTU)
		if st.MTU < 1500 {
			detail += " A smaller MTU means the client's own segments are smaller, so absolute split positions " +
				"tuned for a 1500-byte path (flowseal's `--dpi-desync-split-pos` values) can land past the end of " +
				"a segment and silently do nothing."
		} else {
			detail += " A jumbo MTU means a single intercepted segment can exceed what the far side's path will " +
				"carry, and our re-emitted frames inherit that size."
		}
		add(sev, "Unusual uplink MTU", detail,
			"prefer marker-relative split positions (`sni+1`, `host+2`, `midsld`) over absolute byte offsets, and "+
				"check `ifconfig "+st.Iface+"` if the value is unexpected (PPPoE gives 1492, some VPN profiles less).")
	}
	if st.TSOKnown && st.TSO != 0 {
		add(SeverityInfo, "TCP segmentation offload is enabled",
			fmt.Sprintf("net.inet.tcp.tso = %d. A segment handed to us can therefore be larger than the interface "+
				"MTU, and its TCP checksum is whatever the NIC was going to overwrite — usually wrong. The "+
				"transport recomputes both checksums on every packet it emits, so this is informational.", st.TSO),
			"")
	}

	// ---- 9. environment ---------------------------------------------------
	add(SeverityInfo, "Machine",
		fmt.Sprintf("macOS %s (Darwin %s, %s), SIP %s, euid %d.",
			orUnknown(st.Caps.OSVersion), orUnknown(st.Caps.Darwin), orUnknown(st.Caps.Arch),
			orUnknown(st.Caps.SIP), st.UID),
		"")

	// ---- 10. strategy fit -------------------------------------------------
	if len(st.StrategyUnsupported) > 0 {
		add(SeverityWarn, "Active strategy uses techniques this transport cannot honour",
			fmt.Sprintf("strategy %q needs: %s.", orUnknown(st.Strategy), strings.Join(st.StrategyUnsupported, "; ")),
			"pick a strategy without those ops (`zaprctl test --pick --dry-run` lists the ones that are fully "+
				"supported), or fix whatever forced the degraded transport.")
	}

	// ---- 11. anything we could not check ---------------------------------
	for _, e := range st.CollectErrors {
		add(SeverityWarn, "A check could not be performed", e,
			"most of these mean the check needed root; re-run with sudo. A missing finding is not a passing one.")
	}
	return f
}

// severityRank orders findings for display.
func severityRank(s string) int {
	switch s {
	case SeverityError:
		return 0
	case SeverityWarn:
		return 1
	default:
		return 2
	}
}

// sortFindings sorts by severity, keeping the original order inside each group.
func sortFindings(f []Finding) []Finding {
	sort.SliceStable(f, func(i, j int) bool {
		return severityRank(f[i].Severity) < severityRank(f[j].Severity)
	})
	return f
}

// summariseJournal renders a journal as "pf.token x1, hosts x1".
func summariseJournal(entries []netcfg.Entry) string {
	counts := map[string]int{}
	var order []string
	for _, e := range entries {
		if counts[e.Step] == 0 {
			order = append(order, e.Step)
		}
		counts[e.Step]++
	}
	parts := make([]string, 0, len(order))
	for _, s := range order {
		parts = append(parts, fmt.Sprintf("%s x%d", s, counts[s]))
	}
	return strings.Join(parts, ", ")
}

// joinInts renders a port list.
func joinInts(v []int) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ", ")
}

// orUnknown substitutes a placeholder for an empty string.
func orUnknown(s string) string { return orDefault(s, "unknown") }

// orDefault returns s, or def when s is empty.
func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// ifElse picks between two strings.
func ifElse(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// plural picks the singular or plural form for n. It exists so findings read as
// English rather than as "entr(y/ies)".
func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}

// countOf renders "1 entry" / "3 entries".
func countOf(n int, singular, pluralForm string) string {
	return strconv.Itoa(n) + " " + plural(n, singular, pluralForm)
}

// ---------------------------------------------------------------------------
// /etc/hosts
// ---------------------------------------------------------------------------

// hostsFindings compares our applied hosts block against the upstream list.
func hostsFindings(hs HostsState) []Finding {
	var out []Finding
	path := orDefault(hs.Path, netcfg.DefaultHostsPath)
	switch {
	case len(hs.Applied) == 0 && hs.UpstreamPath == "":
		out = append(out, Finding{Severity: SeverityInfo,
			Title:  "Host pinning not applied",
			Detail: fmt.Sprintf("%s contains no zapret-mac block, and no upstream list was supplied to compare against.", path),
		})
	case len(hs.Applied) == 0:
		out = append(out, Finding{Severity: SeverityWarn,
			Title: "Host pinning not applied",
			Detail: fmt.Sprintf("%s contains no zapret-mac block, but %s offers %d pinned entries. Upstream pins "+
				"Discord voice and githubusercontent addresses precisely because DNS answers for them are forged; "+
				"without the pins those connections can be redirected before any desync applies.",
				path, hs.UpstreamPath, len(hs.Upstream)),
			Fix: "`sudo zaprctl hosts --apply` writes the block (byte-exact backup, journalled, removable), then " +
				"flushes the DNS cache.",
		})
	default:
		added, removed := diffHostEntries(hs.Applied, hs.Upstream)
		if hs.UpstreamPath == "" {
			out = append(out, Finding{Severity: SeverityInfo,
				Title:  "Host pinning applied",
				Detail: fmt.Sprintf("%d entries in our block in %s; no upstream list to compare against.", len(hs.Applied), path),
			})
		} else if len(added) == 0 && len(removed) == 0 {
			out = append(out, Finding{Severity: SeverityInfo,
				Title:  "Host pinning applied and current",
				Detail: fmt.Sprintf("%d entries in %s, identical to %s.", len(hs.Applied), path, hs.UpstreamPath),
			})
		} else {
			out = append(out, Finding{Severity: SeverityWarn,
				Title: "Host pinning is stale",
				Detail: fmt.Sprintf("our block in %s differs from %s: %s upstream has that we do not, %s we have "+
					"that upstream no longer does. Upstream changes these addresses when Discord moves a voice "+
					"region, so a stale block pins traffic at an address that no longer serves it.",
					path, hs.UpstreamPath,
					countOf(len(added), "entry", "entries"), countOf(len(removed), "entry", "entries")),
				Fix: "`sudo zaprctl hosts --apply` rewrites the block from the current upstream list; " +
					"`sudo zaprctl hosts --remove` takes it out entirely.",
			})
		}
	}
	if hs.Err != "" {
		out = append(out, Finding{Severity: SeverityWarn,
			Title:  "Hosts file could not be fully parsed",
			Detail: hs.Err,
			Fix:    "the unparseable lines are left alone; fix them by hand if they are yours.",
		})
	}
	return out
}

// diffHostEntries compares two entry lists by (address, name) pairs and reports
// what upstream has that we do not, and what we have that upstream does not.
func diffHostEntries(applied, upstream []netcfg.HostEntry) (added, removed []string) {
	key := func(e netcfg.HostEntry) []string {
		out := make([]string, 0, len(e.Names))
		for _, n := range e.Names {
			out = append(out, e.IP.String()+" "+strings.ToLower(n))
		}
		return out
	}
	have := map[string]bool{}
	for _, e := range applied {
		for _, k := range key(e) {
			have[k] = true
		}
	}
	want := map[string]bool{}
	for _, e := range upstream {
		for _, k := range key(e) {
			want[k] = true
		}
	}
	for k := range want {
		if !have[k] {
			added = append(added, k)
		}
	}
	for k := range have {
		if !want[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// ---------------------------------------------------------------------------
// DNS: system resolver versus DoH
// ---------------------------------------------------------------------------

// DNS verdicts returned by ClassifyDNS.
const (
	// DNSOk means the two resolvers agree, at least at /24 granularity.
	DNSOk = "ok"
	// DNSPoisoned means the system resolver returned an address that cannot
	// serve the name: unspecified, loopback, private or link-local.
	DNSPoisoned = "poisoned"
	// DNSMissing means the system resolver returned nothing while DoH did.
	DNSMissing = "system-empty"
	// DNSDiffers means both answered with routable addresses that do not
	// overlap. For a CDN name that is normal, so it is informational.
	DNSDiffers = "differs"
	// DNSUnknown means there was not enough data to compare.
	DNSUnknown = "unknown"
)

// ClassifyDNS compares a system-resolver answer against a DoH answer.
//
// The checks are ordered by how conclusive they are. A forged answer pointing at
// 0.0.0.0/127.0.0.1/an RFC 1918 address is unambiguous and is reported as
// poisoning even if DoH could not be reached. A plain disagreement between two
// sets of routable addresses is NOT evidence of anything: every large CDN answers
// differently depending on which resolver asks, so that case is DNSDiffers and
// carries informational weight only.
func ClassifyDNS(system, doh []netip.Addr) string {
	if len(system) == 0 && len(doh) == 0 {
		return DNSUnknown
	}
	for _, a := range system {
		if isImpossibleAnswer(a) {
			return DNSPoisoned
		}
	}
	if len(doh) == 0 {
		return DNSUnknown
	}
	if len(system) == 0 {
		return DNSMissing
	}
	for _, a := range system {
		for _, b := range doh {
			if a.Unmap() == b.Unmap() {
				return DNSOk
			}
			if sameSlash24(a, b) {
				return DNSOk
			}
		}
	}
	return DNSDiffers
}

// isImpossibleAnswer reports whether a public hostname could never legitimately
// resolve to a: the unspecified address, loopback, an RFC 1918 private address,
// a link-local address or multicast. Those are what a censor's resolver hands
// back when it wants a connection to fail or to land on its own notice page.
func isImpossibleAnswer(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() {
		return false
	}
	return a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast()
}

// sameSlash24 reports whether two IPv4 addresses share a /24, or two IPv6
// addresses share a /48. Anycast front ends are routinely spread over a few
// addresses inside one prefix, so this keeps the comparison from crying wolf.
func sameSlash24(a, b netip.Addr) bool {
	a, b = a.Unmap(), b.Unmap()
	if a.Is4() != b.Is4() {
		return false
	}
	bits := 24
	if !a.Is4() {
		bits = 48
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return false
	}
	return p.Contains(b)
}

// dnsFinding renders one observation.
func dnsFinding(obs DNSObservation) Finding {
	verdict := ClassifyDNS(obs.System, obs.DoH)
	detail := fmt.Sprintf("%s: system resolver -> %s%s; DoH (%s) -> %s%s",
		obs.Name, addrsText(obs.System), errSuffix(obs.SystemErr),
		orDefault(obs.DoHServer, "unknown"), addrsText(obs.DoH), errSuffix(obs.DoHErr))

	const dohFix = "turn on Secure DNS / DNS-over-HTTPS in the browser — that is what flowseal's README asks for, " +
		"and it is the only fix that survives a resolver you do not control. In Chrome: Settings > Privacy and " +
		"security > Security > Use secure DNS. In Firefox: Settings > Privacy & Security > DNS over HTTPS > Max " +
		"Protection. System-wide, install a DoH profile or point the resolver at 1.1.1.1/8.8.8.8."

	switch verdict {
	case DNSPoisoned:
		return Finding{Severity: SeverityError,
			Title: "DNS answer for " + obs.Name + " is forged",
			Detail: detail + ". The system resolver returned an address that cannot serve this name " +
				"(unspecified, loopback, private or link-local), which is DNS-level blocking: no amount of " +
				"packet desync helps, because the connection never goes to the real server.",
			Fix: dohFix}
	case DNSMissing:
		return Finding{Severity: SeverityWarn,
			Title: "System resolver has no answer for " + obs.Name,
			Detail: detail + ". DoH resolves the name, so it exists; the local resolver is either returning " +
				"NXDOMAIN or being blocked.",
			Fix: dohFix}
	case DNSDiffers:
		return Finding{Severity: SeverityInfo,
			Title: "DNS answers for " + obs.Name + " differ between resolvers",
			Detail: detail + ". Both answers are routable and they do not overlap. For a CDN name this is normal " +
				"— geo-DNS gives every resolver a different front end — so treat it as information, not a fault.",
			Fix: ""}
	case DNSUnknown:
		return Finding{Severity: SeverityInfo,
			Title:  "DNS comparison for " + obs.Name + " was inconclusive",
			Detail: detail + ". Not enough data to compare; the DoH lookup itself may be blocked.",
			Fix: "if the DoH lookup failed, that is itself worth knowing: try `curl -sv " +
				"'https://1.1.1.1/dns-query?name=" + obs.Name + "' -H 'accept: application/dns-json'`."}
	default:
		return Finding{Severity: SeverityInfo,
			Title:  "DNS for " + obs.Name + " looks clean",
			Detail: detail + ". The resolvers agree, so nothing is being forged at the DNS layer.",
			Fix:    ""}
	}
}

// addrsText renders an address list compactly.
func addrsText(a []netip.Addr) string {
	if len(a) == 0 {
		return "(none)"
	}
	parts := make([]string, len(a))
	for i, x := range a {
		parts[i] = x.String()
	}
	return strings.Join(parts, " ")
}

// errSuffix renders a non-empty error in brackets.
func errSuffix(s string) string {
	if s == "" {
		return ""
	}
	return " [" + s + "]"
}

// Resolver is the minimal lookup interface the DNS check needs. Both the system
// resolver and the DoH client implement it, and a test supplies a stub.
//
// Implementations must be safe for concurrent use: compareResolvers looks every
// name up in its own goroutine so one hanging resolver costs a single timeout
// rather than one per name.
type Resolver interface {
	// LookupA returns the A/AAAA addresses for name.
	LookupA(ctx context.Context, name string) ([]netip.Addr, error)
	// Describe names the resolver for the report ("system", "DoH 1.1.1.1").
	Describe() string
}

// systemResolver asks the OS resolver, i.e. whatever mDNSResponder is configured
// to use — the answer a browser without Secure DNS would get.
type systemResolver struct{}

// NewSystemResolver returns a Resolver backed by the system resolver.
func NewSystemResolver() Resolver { return systemResolver{} }

// Describe implements Resolver.
func (systemResolver) Describe() string { return "system" }

// LookupA implements Resolver.
func (systemResolver) LookupA(ctx context.Context, name string) ([]netip.Addr, error) {
	var r net.Resolver
	addrs, err := r.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// DefaultDoHServers are the two resolvers whose certificates carry their own IP
// address as a SAN, so they can be reached over TLS with no prior DNS lookup —
// which is exactly what a poisoned resolver must not be able to influence.
func DefaultDoHServers() []string { return []string{"1.1.1.1", "8.8.8.8"} }

// defaultDoHTimeout bounds one DoH lookup. It is generous because the lookups
// run concurrently over a link that may itself be congested or tunnelled, and a
// timeout here is indistinguishable in the report from "DoH is blocked" — the
// most misleading outcome this check can produce.
const defaultDoHTimeout = 8 * time.Second

// NewDefaultDoHResolver returns a Resolver that tries DefaultDoHServers in
// order, which is what the doctor uses when the caller supplies none.
func NewDefaultDoHResolver() Resolver {
	servers := DefaultDoHServers()
	rs := make([]Resolver, 0, len(servers))
	for _, s := range servers {
		rs = append(rs, NewDoHResolver(s, defaultDoHTimeout))
	}
	return FallbackResolver(rs...)
}

// sourcedResolver is optionally implemented by a Resolver that can name which
// backend produced a particular answer. compareResolvers uses it so the report
// cites the resolver that actually answered for that name, rather than the whole
// chain — and so no per-call state has to be shared between goroutines.
type sourcedResolver interface {
	LookupAFrom(ctx context.Context, name string) (addrs []netip.Addr, source string, err error)
}

// fallbackResolver tries each resolver in order until one answers.
type fallbackResolver struct {
	resolvers []Resolver
}

// FallbackResolver chains resolvers: the first one that returns without error
// wins. It exists because a censor blocking 1.1.1.1 is itself common, and
// reporting "inconclusive" in that case would hide the very poisoning the check
// was built to find — 8.8.8.8 is usually still reachable.
//
// A resolver that answers with an empty list counts as having answered: that is a
// legitimate NXDOMAIN, not a failure to reach the resolver.
func FallbackResolver(rs ...Resolver) Resolver {
	return &fallbackResolver{resolvers: rs}
}

// Describe implements Resolver, naming the whole chain. Use LookupAFrom to learn
// which member answered a given lookup.
func (f *fallbackResolver) Describe() string {
	names := make([]string, 0, len(f.resolvers))
	for _, r := range f.resolvers {
		names = append(names, r.Describe())
	}
	if len(names) == 0 {
		return "no resolver"
	}
	return strings.Join(names, " then ")
}

// LookupA implements Resolver.
func (f *fallbackResolver) LookupA(ctx context.Context, name string) ([]netip.Addr, error) {
	addrs, _, err := f.LookupAFrom(ctx, name)
	return addrs, err
}

// LookupAFrom implements sourcedResolver: it also reports which member answered.
func (f *fallbackResolver) LookupAFrom(ctx context.Context, name string) ([]netip.Addr, string, error) {
	var errs []error
	for _, r := range f.resolvers {
		addrs, err := r.LookupA(ctx, name)
		if err == nil {
			return addrs, r.Describe(), nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", r.Describe(), err))
		// A cancelled context will fail every remaining member the same way.
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == 0 {
		return nil, f.Describe(), errors.New("diag: no resolvers configured")
	}
	return nil, f.Describe(), errors.Join(errs...)
}

// dohResolver performs RFC 8484 DNS-over-HTTPS against a fixed IP literal.
type dohResolver struct {
	server  string
	timeout time.Duration
	client  *http.Client
}

// NewDoHResolver returns a Resolver that queries server (an IP literal such as
// "1.1.1.1") over HTTPS.
//
// The URL is built from the literal, never from a hostname, so no DNS lookup
// happens before the lookup — otherwise the resolver we are auditing would get to
// answer the question first. TLS still verifies the certificate: both 1.1.1.1 and
// 8.8.8.8 carry their address in a SAN, so an interception would fail the
// handshake rather than pass silently.
func NewDoHResolver(server string, timeout time.Duration) Resolver {
	if timeout <= 0 {
		timeout = defaultDoHTimeout
	}
	tr := &http.Transport{
		// Pin the connection to the literal, and force HTTP/1.1 over TCP: a
		// blocked QUIC path must not make this look like a DNS failure.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "tcp", net.JoinHostPort(server, "443"))
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}
	return &dohResolver{
		server:  server,
		timeout: timeout,
		client:  &http.Client{Transport: tr, Timeout: timeout},
	}
}

// Describe implements Resolver.
func (d *dohResolver) Describe() string { return "DoH " + d.server }

// LookupA implements Resolver via RFC 8484 GET, whose query is the base64url
// (unpadded) DNS wire message.
func (d *dohResolver) LookupA(ctx context.Context, name string) ([]netip.Addr, error) {
	q, err := buildDNSQuery(name, dnsTypeA)
	if err != nil {
		return nil, err
	}
	url := "https://" + d.server + "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(q)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH %s returned HTTP %d", d.server, resp.StatusCode)
	}
	// 64 KiB is the maximum a DNS message can be; anything larger is not a
	// DNS answer and must not be buffered.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}
	return parseDNSAnswers(body)
}

// DNS wire constants.
const (
	dnsTypeA     = 1
	dnsTypeAAAA  = 28
	dnsClassIN   = 1
	dnsHeaderLen = 12
)

// buildDNSQuery encodes a standard recursive query for one name and type.
//
// The transaction id is random even though a DoH response arrives on the same
// TLS connection: an id of 0 is a fingerprint, and some resolvers reject it.
func buildDNSQuery(name string, qtype uint16) ([]byte, error) {
	labels, err := encodeDNSName(name)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, dnsHeaderLen, dnsHeaderLen+len(labels)+4)
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, fmt.Errorf("diag: cannot generate a DNS transaction id: %w", err)
	}
	msg[0], msg[1] = idb[0], idb[1]
	msg[2] = 0x01 // QR=0 (query), Opcode=0, RD=1 (recursion desired)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, labels...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	return msg, nil
}

// encodeDNSName converts "www.youtube.com" into the length-prefixed label form,
// rejecting anything that cannot be encoded rather than truncating it.
func encodeDNSName(name string) ([]byte, error) {
	n := strings.TrimSuffix(strings.TrimSpace(name), ".")
	if n == "" {
		return nil, errors.New("diag: empty DNS name")
	}
	if len(n) > 253 {
		return nil, fmt.Errorf("diag: DNS name longer than 253 bytes (%d)", len(n))
	}
	var out []byte
	for _, label := range strings.Split(n, ".") {
		if label == "" {
			return nil, fmt.Errorf("diag: DNS name %q has an empty label", name)
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("diag: DNS label %q longer than 63 bytes", label)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// parseDNSAnswers extracts the A and AAAA records from a DNS response message.
//
// Every offset is bounds-checked and name decoding never follows a compression
// pointer (it only needs to know how long the name is, and a pointer always
// terminates it), so a hostile or truncated response yields an error rather than
// a panic or a loop.
func parseDNSAnswers(msg []byte) ([]netip.Addr, error) {
	if len(msg) < dnsHeaderLen {
		return nil, fmt.Errorf("diag: DNS response is %d bytes, shorter than a header", len(msg))
	}
	if rcode := msg[3] & 0x0f; rcode != 0 {
		if rcode == 3 {
			// NXDOMAIN is a valid answer meaning "no such name", not a failure
			// to parse.
			return nil, nil
		}
		return nil, fmt.Errorf("diag: DNS response rcode %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := dnsHeaderLen
	for i := 0; i < qd; i++ {
		n, err := skipDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		off = n + 4 // QTYPE + QCLASS
		if off > len(msg) {
			return nil, errors.New("diag: DNS response truncated inside the question section")
		}
	}
	var out []netip.Addr
	for i := 0; i < an; i++ {
		n, err := skipDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		off = n
		if off+10 > len(msg) {
			return nil, errors.New("diag: DNS response truncated inside an answer header")
		}
		rtype := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, errors.New("diag: DNS response truncated inside answer data")
		}
		switch {
		case rtype == dnsTypeA && rdlen == 4:
			out = append(out, netip.AddrFrom4([4]byte(msg[off:off+4])))
		case rtype == dnsTypeAAAA && rdlen == 16:
			out = append(out, netip.AddrFrom16([16]byte(msg[off:off+16])))
		}
		off += rdlen
	}
	return out, nil
}

// skipDNSName returns the offset just past the name starting at off. A
// compression pointer terminates the name, so no jump is ever taken and the
// function cannot loop.
func skipDNSName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errors.New("diag: DNS name runs past the end of the message")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			if off+2 > len(msg) {
				return 0, errors.New("diag: truncated DNS compression pointer")
			}
			return off + 2, nil
		case l&0xc0 != 0:
			return 0, fmt.Errorf("diag: reserved DNS label type %#02x", msg[off])
		default:
			off += 1 + l
		}
	}
}

// compareResolvers looks every name up through both resolvers, concurrently per
// name so a hanging resolver costs one timeout rather than N.
func compareResolvers(ctx context.Context, o DoctorOpts) []DNSObservation {
	sys := o.SystemResolver
	if sys == nil {
		sys = NewSystemResolver()
	}
	doh := o.DoHResolver
	if doh == nil {
		doh = NewDefaultDoHResolver()
	}
	out := make([]DNSObservation, len(o.DNSNames))
	done := make(chan int, len(o.DNSNames))
	for i, name := range o.DNSNames {
		go func(i int, name string) {
			obs := DNSObservation{Name: name, DoHServer: doh.Describe()}
			if a, err := sys.LookupA(ctx, name); err != nil {
				obs.SystemErr = err.Error()
			} else {
				obs.System = a
			}
			// Prefer the sourced form so a fallback chain names the resolver
			// that answered this particular name.
			if sr, ok := doh.(sourcedResolver); ok {
				a, source, err := sr.LookupAFrom(ctx, name)
				if source != "" {
					obs.DoHServer = source
				}
				if err != nil {
					obs.DoHErr = err.Error()
				} else {
					obs.DoH = a
				}
			} else if a, err := doh.LookupA(ctx, name); err != nil {
				obs.DoHErr = err.Error()
			} else {
				obs.DoH = a
			}
			out[i] = obs
			done <- i
		}(i, name)
	}
	for range o.DNSNames {
		select {
		case <-done:
		case <-ctx.Done():
			return out
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// pf rule drift
// ---------------------------------------------------------------------------

// RuleFeature is the comparable essence of one pf rule: what it does, to which
// protocol, through which route/redirect target, on which ports.
//
// It exists because pf rules cannot be compared as text. pfctl normalises what it
// is given — it prints `port = 443` for `port 443`, and it EXPANDS a port list
// into one rule per port — so `pfctl -a X -s rules` never matches the text that
// was loaded. Comparing features instead makes the drift check honest about what
// it can and cannot detect: it sees a rule that is gone, a target that changed
// and a port that is no longer covered, and it deliberately ignores clause order
// and cosmetic rewriting.
type RuleFeature struct {
	// Action is "pass", "block", "rdr" or "match".
	Action string
	// Proto is "tcp", "udp" or "" when the rule names no protocol.
	Proto string
	// Via is the route-to/rdr-to target as written, e.g. "utun9 198.18.0.2" or
	// "127.0.0.1 port 10800". Empty for a plain filter rule.
	Via string
	// Ports are the port tokens the rule matches, normalised: "443",
	// "19294:19344". A rule with no port clause has none.
	Ports []string
}

// key is the identity a feature is matched on; ports are compared separately
// because pfctl splits port lists across rules.
func (r RuleFeature) key() string { return r.Action + "|" + r.Proto + "|" + r.Via }

// String renders a feature for a diagnostic message.
func (r RuleFeature) String() string {
	s := r.Action
	if r.Proto != "" {
		s += " " + r.Proto
	}
	if r.Via != "" {
		s += " -> " + r.Via
	}
	if len(r.Ports) > 0 {
		s += " port " + strings.Join(r.Ports, ",")
	}
	return s
}

// RuleFeatures extracts one feature per non-empty, non-comment rule line.
func RuleFeatures(ruleset string) []RuleFeature {
	var out []RuleFeature
	for _, line := range strings.Split(ruleset, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "table ") {
			continue
		}
		if f, ok := parseRuleFeature(l); ok {
			out = append(out, f)
		}
	}
	return out
}

// parseRuleFeature decodes one rule line.
func parseRuleFeature(line string) (RuleFeature, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return RuleFeature{}, false
	}
	var f RuleFeature
	switch fields[0] {
	case "pass", "block", "rdr", "match", "nat", "binat":
		f.Action = fields[0]
	default:
		return RuleFeature{}, false
	}

	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "proto":
			if i+1 < len(fields) {
				f.Proto = strings.Trim(fields[i+1], "{}")
			}
		case "route-to", "reply-to", "dup-to":
			// The target is parenthesised: `route-to (utun9 198.18.0.2)`.
			f.Via = strings.Trim(collectParens(fields[i+1:]), "()")
		case "->":
			// A translation rule's target: `-> 127.0.0.1 port 10800`.
			f.Via = strings.Join(fields[i+1:], " ")
			i = len(fields)
		case "port":
			f.Ports = append(f.Ports, collectPortTokens(fields[i+1:])...)
		}
	}
	f.Via = strings.Join(strings.Fields(f.Via), " ")
	sort.Strings(f.Ports)
	return f, true
}

// collectParens joins fields until the one containing the closing parenthesis.
func collectParens(fields []string) string {
	var parts []string
	for _, t := range fields {
		parts = append(parts, t)
		if strings.Contains(t, ")") {
			break
		}
	}
	return strings.Join(parts, " ")
}

// collectPortTokens reads the operand of a `port` clause: a bare port, a
// `= port` form, a `lo:hi` range or a braced list. Anything that is not a port
// terminates the scan, so the clauses that follow are not swallowed.
func collectPortTokens(fields []string) []string {
	var out []string
	brace := false
	for _, t := range fields {
		t = strings.TrimSuffix(strings.TrimPrefix(t, "{"), "}")
		if strings.HasPrefix(t, "{") || t == "" {
			brace = true
			continue
		}
		switch t {
		case "=", "{":
			brace = brace || t == "{"
			continue
		case "}":
			return out
		}
		if isPortToken(t) {
			out = append(out, t)
			continue
		}
		if brace {
			// Inside a list an unrecognised token means the list ended.
			return out
		}
		return out
	}
	return out
}

// isPortToken reports whether t is a decimal port or a lo:hi range.
func isPortToken(t string) bool {
	if t == "" {
		return false
	}
	parts := strings.SplitN(t, ":", 2)
	for _, p := range parts {
		if p == "" {
			return false
		}
		if _, err := strconv.ParseUint(p, 10, 16); err != nil {
			return false
		}
	}
	return true
}

// RulesDrift compares the ruleset a strategy needs against the one pf currently
// holds and reports what is missing and what is unexpected.
//
// Matching is by RuleFeature key (action, protocol, route/redirect target), with
// ports unioned across every loaded rule sharing that key — because pfctl expands
// `port { 80 443 }` into two rules and the union is the only faithful comparison.
// A want-feature is satisfied when a key with the same identity exists and covers
// every port it asks for.
//
// This is deliberately an approximation: it will not notice a changed `user`
// clause, a reordered ruleset or a swapped table reference. It exists to catch
// the failure that actually happens in the field — something ran
// `pfctl -f /etc/pf.conf` and emptied our anchor.
func RulesDrift(want, have string) (missing, extra []RuleFeature) {
	wantF := RuleFeatures(want)
	haveF := RuleFeatures(have)

	haveByKey := map[string]map[string]bool{}
	for _, f := range haveF {
		set := haveByKey[f.key()]
		if set == nil {
			set = map[string]bool{}
			haveByKey[f.key()] = set
		}
		for _, p := range f.Ports {
			set[p] = true
		}
	}
	wantKeys := map[string]bool{}
	for _, f := range wantF {
		wantKeys[f.key()] = true
		set, ok := haveByKey[f.key()]
		if !ok {
			missing = append(missing, f)
			continue
		}
		for _, p := range f.Ports {
			if !set[p] && !portCoveredByRange(p, set) {
				missing = append(missing, f)
				break
			}
		}
	}
	seen := map[string]bool{}
	for _, f := range haveF {
		if wantKeys[f.key()] || seen[f.key()] {
			continue
		}
		seen[f.key()] = true
		extra = append(extra, f)
	}
	return missing, extra
}

// portCoveredByRange reports whether a single port token falls inside one of the
// lo:hi range tokens present in set. pfctl keeps ranges intact but expands
// lists, so a wanted single port can legitimately be covered by a loaded range.
func portCoveredByRange(token string, set map[string]bool) bool {
	p, err := strconv.Atoi(token)
	if err != nil {
		return false
	}
	for t := range set {
		lo, hi, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		l, err1 := strconv.Atoi(lo)
		h, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil {
			continue
		}
		if p >= l && p <= h {
			return true
		}
	}
	return false
}

// describeFeatures renders up to four features for a message.
func describeFeatures(f []RuleFeature) string {
	const max = 4
	parts := make([]string, 0, max)
	for i, x := range f {
		if i == max {
			parts = append(parts, fmt.Sprintf("and %d more", len(f)-max))
			break
		}
		parts = append(parts, x.String())
	}
	return strings.Join(parts, "; ")
}

// ---------------------------------------------------------------------------
// Repair
// ---------------------------------------------------------------------------

// Repair undoes what this daemon left behind, and nothing else.
//
// It performs exactly four classes of action, in this order:
//
//  1. Replay the rollback journal in reverse. Each entry names one change and
//     how to reverse it; entries that cannot be reversed stay in the journal so
//     a later run can retry, which is netcfg.Journal.Rollback's contract.
//  2. Release a stale `pfctl -E` token, so a leaked reference does not keep pf
//     enabled for the rest of the machine's uptime.
//  3. Flush our own pf anchor, which orphans nothing else: the anchor name is
//     ours and only ever holds rules we generated.
//  4. Remove our marker block from /etc/hosts and flush the DNS cache.
//
// Every one of those targets something identified by OUR anchor name, OUR marker
// comments or OUR journal. Foreign anchors, foreign rules and foreign hosts
// entries are never touched, even when they look wrong: this function's job is to
// undo our own mess, not to tidy the machine.
//
// It refuses to act when a daemon is known to be running (DoctorOpts.DaemonRunning
// true), because everything it would remove is then in active use. With DryRun it
// reports what it would do.
func Repair(ctx context.Context, o DoctorOpts) ([]Finding, error) {
	o = o.withDefaults()
	var out []Finding
	add := func(sev, title, detail, fix string) {
		out = append(out, Finding{Severity: sev, Title: title, Detail: detail, Fix: fix})
	}

	if o.DaemonRunning != nil && *o.DaemonRunning {
		add(SeverityError, "Refusing to repair while the daemon is running",
			"everything Repair removes — the pf reference, our anchor's rules, our hosts block — is in active use "+
				"by the running daemon.",
			"stop the daemon first (`sudo zaprctl stop` or `sudo launchctl bootout system/<label>`), then re-run.")
		return out, nil
	}
	if os.Geteuid() != 0 && !o.DryRun {
		add(SeverityError, "Repair needs root",
			fmt.Sprintf("running as uid %d: /dev/pf cannot be opened, and %s and %s cannot be written.",
				os.Geteuid(), o.PfConfPath, o.HostsPath),
			"re-run as `sudo zaprctl doctor --repair`.")
		return out, nil
	}

	pf := netcfg.NewPF(o.Anchor, netcfg.PFOpts{
		PfConfPath: o.PfConfPath,
		PfctlPath:  o.PfctlPath,
		StateDir:   o.StateDir,
		DryRun:     o.DryRun,
		Logf:       o.Logf,
	})
	defer pf.Close()

	hosts := netcfg.NewHosts(o.HostsPath, o.StateDir)
	hosts.SetMarker(o.HostsMarker)
	hosts.SetDryRun(o.DryRun)
	hosts.SetLogf(o.Logf)
	defer hosts.Close()

	// ---- 1. the journal ---------------------------------------------------
	// The entries are read once, before the rollback consumes them, because the
	// tunnel-interface check at the end needs to know which interfaces we claimed.
	var (
		entries []netcfg.Entry
		jerr    error
	)
	if o.StateDir != "" {
		entries, jerr = readJournalFile(filepath.Join(o.StateDir, netcfg.JournalName))
	}
	if o.StateDir == "" {
		add(SeverityWarn, "No state directory configured",
			"without it there is no rollback journal to replay, so anything a crashed daemon changed cannot be "+
				"identified automatically.",
			"pass --state-dir (the daemon's default is /var/db/zapret-mac) so the journal can be found.")
	} else if jerr != nil {
		add(SeverityWarn, "Rollback journal could not be read", jerr.Error(),
			"check permissions on "+filepath.Join(o.StateDir, netcfg.JournalName)+".")
	} else if len(entries) == 0 {
		add(SeverityInfo, "Rollback journal is empty", "nothing was left behind by a previous run.", "")
	} else if o.DryRun {
		add(SeverityInfo, "Would replay the rollback journal",
			fmt.Sprintf("%s: %s.", countOf(len(entries), "entry", "entries"), summariseJournal(entries)),
			"re-run without --dry-run to actually undo them.")
	} else {
		j, err := netcfg.OpenJournal(o.StateDir)
		if err != nil {
			add(SeverityError, "Rollback journal could not be opened", err.Error(),
				"check that "+o.StateDir+" exists and is writable by root.")
		} else {
			var reverted []string
			rerr := j.Rollback(func(step string, data map[string]string) error {
				desc, err := revertJournalStep(pf, hosts, step, data)
				if err != nil {
					return err
				}
				reverted = append(reverted, desc)
				return nil
			})
			_ = j.Close()
			if len(reverted) > 0 {
				add(SeverityInfo, "Rolled back a previous run's changes",
					strings.Join(reverted, "; ")+".", "")
			}
			if rerr != nil {
				add(SeverityError, "Some journal entries could not be rolled back", rerr.Error(),
					"they are still in the journal, so re-running Repair retries them. Entries that name a tunnel "+
						"interface can only be resolved by stopping the process that still holds it.")
			}
		}
	}

	// ---- 2. a stale pf reference -----------------------------------------
	if o.StateDir != "" {
		tokenPath := filepath.Join(o.StateDir, netcfg.PfTokenName)
		tok, err := readTokenFile(tokenPath)
		switch {
		case err != nil && !os.IsNotExist(err):
			add(SeverityWarn, "pf token file could not be read", err.Error(),
				"delete "+tokenPath+" by hand if it is corrupt, then run `sudo pfctl -s References` to see whether "+
					"a reference is still held.")
		case tok != "" && o.DryRun:
			add(SeverityInfo, "Would release the stale pf reference",
				"token "+tok+" recorded in "+tokenPath+".", "re-run without --dry-run.")
		case tok != "":
			// netcfg.PF.Release reads the same token file and removes it on
			// success, which is exactly the semantics we want here.
			if err := pf.Release(); err != nil {
				add(SeverityError, "Could not release the stale pf reference", err.Error(),
					"run `sudo pfctl -X "+tok+"` by hand; if that fails the reference is already gone and you can "+
						"delete "+tokenPath+".")
			} else {
				add(SeverityInfo, "Released the stale pf reference", "token "+tok+" released with `pfctl -X`.", "")
			}
		}
	}

	// ---- 3. our anchor ----------------------------------------------------
	rules, rerr := pf.Rules()
	nat, _ := pf.NatRules()
	switch {
	case rerr != nil:
		add(SeverityWarn, "Our anchor could not be read", rerr.Error(),
			"this needs root and a working pf; `sudo pfctl -a "+o.Anchor+" -s rules` shows the same error.")
	case strings.TrimSpace(rules) == "" && strings.TrimSpace(nat) == "":
		add(SeverityInfo, "Our anchor is already empty", "anchor "+o.Anchor+" holds no rules.", "")
	case o.DryRun:
		add(SeverityInfo, "Would flush our anchor",
			fmt.Sprintf("anchor %s holds %s.", o.Anchor,
				countOf(countNonEmptyLines(rules)+countNonEmptyLines(nat), "rule line", "rule lines")),
			"re-run without --dry-run.")
	default:
		if err := pf.FlushRules(); err != nil {
			add(SeverityError, "Could not flush our anchor", err.Error(),
				"run `sudo pfctl -a "+o.Anchor+" -F all` by hand.")
		} else {
			add(SeverityInfo, "Flushed our anchor",
				fmt.Sprintf("anchor %s emptied (%d rule line(s) removed); no foreign rule was touched.",
					o.Anchor, countNonEmptyLines(rules)+countNonEmptyLines(nat)), "")
		}
	}

	// ---- 4. our hosts block ----------------------------------------------
	applied, herr := hosts.Applied()
	switch {
	case herr != nil && len(applied) == 0:
		add(SeverityWarn, "Our hosts block could not be read", herr.Error(),
			"inspect "+o.HostsPath+" by hand; Repair never removes a line outside our markers.")
	case len(applied) == 0:
		add(SeverityInfo, "No hosts block of ours is present", o.HostsPath+" is untouched.", "")
	case o.DryRun:
		add(SeverityInfo, "Would remove our hosts block",
			fmt.Sprintf("%s inside our markers in %s.", countOf(len(applied), "entry", "entries"), o.HostsPath),
			"re-run without --dry-run.")
	default:
		if err := hosts.Remove(); err != nil {
			add(SeverityError, "Could not remove our hosts block", err.Error(),
				"the file is restored from a byte-exact backup on any failure; look in "+
					filepath.Join(o.StateDir, netcfg.BackupDirName)+".")
		} else {
			add(SeverityInfo, "Removed our hosts block",
				fmt.Sprintf("%s removed from %s; every line outside our markers is byte-identical.",
					countOf(len(applied), "entry", "entries"), o.HostsPath), "")
			if err := netcfg.FlushDNSCache(); err != nil {
				add(SeverityWarn, "DNS cache flush failed after removing the hosts block", err.Error(),
					"run `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`.")
			}
		}
	}

	// ---- 5. what Repair deliberately does not do -------------------------
	if orphans := findOrphanUtuns(entries); len(orphans) > 0 {
		add(SeverityWarn, "Orphaned tunnel interface left in place",
			fmt.Sprintf("%s still %s. A utun cannot be destroyed from outside: it disappears when the process "+
				"holding its control socket exits.",
				strings.Join(orphans, ", "), plural(len(orphans), "exists", "exist")),
			"find the holder with `sudo lsof -nP | grep -i utun` and stop it.")
	}
	return sortFindings(out), ctx.Err()
}

// revertJournalStep undoes one journal entry, returning a human description of
// what it did. Only steps this package can reverse safely are handled; anything
// else is reported as already-nothing-to-do rather than retried forever.
func revertJournalStep(pf *netcfg.PF, hosts *netcfg.Hosts, step string, data map[string]string) (string, error) {
	switch step {
	case netcfg.StepPfToken:
		// Release drops the reference recorded in the state directory, which is
		// the same token this entry names.
		if err := pf.Release(); err != nil {
			return "", err
		}
		return "released pf token " + data["token"], nil

	case netcfg.StepPfConf:
		// Remove only our marker block. RemoveAnchorStatements reports drift as
		// an error AFTER having removed the block, because blanket-restoring our
		// backup over a third party's edit would be the more destructive choice.
		err := pf.RemoveAnchorStatements()
		if err != nil && errors.Is(err, netcfg.ErrPfConfDrift) {
			return "removed our anchor statements from " + data["path"] +
				" (the file had been edited since we patched it, so only our own block was taken out)", nil
		}
		if err != nil {
			return "", err
		}
		return "removed our anchor statements from " + data["path"], nil

	case netcfg.StepPfRules:
		if err := pf.FlushRules(); err != nil {
			return "", err
		}
		return "flushed anchor " + data["anchor"], nil

	case netcfg.StepPfTable:
		name := data["table"]
		if name == "" {
			return "no table named in the journal entry; nothing to flush", nil
		}
		if err := pf.TableFlush(name); err != nil {
			return "", err
		}
		return "flushed pf table <" + name + ">", nil

	case netcfg.StepHosts:
		if err := hosts.Remove(); err != nil {
			return "", err
		}
		return "removed our block from " + orDefault(data["path"], netcfg.DefaultHostsPath), nil

	case netcfg.StepUtun:
		// A utun belongs to whichever process holds its control socket; there is
		// no ioctl to destroy someone else's. Dropping the entry is correct:
		// keeping it would make every future Repair fail forever.
		return "tunnel " + orDefault(data["iface"], "(unnamed)") +
			" cannot be destroyed from outside; it disappears when the process holding it exits", nil

	case netcfg.StepRoute:
		return "route " + orDefault(data["dst"], "(unnamed)") +
			" was recorded but this build installs no routes; nothing to undo", nil

	default:
		return "unknown journal step " + step + " ignored", nil
	}
}

// orString returns a when it is non-empty, otherwise b. Used so a report names
// the anchor path that was actually queried.
func orString(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
