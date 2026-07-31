package netcfg

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// stockPfConf is /etc/pf.conf as macOS 15 ships it, verbatim. Every pf.conf
// test runs against a temp copy of this, never the real file.
const stockPfConf = `#
# Default PF configuration file.
#
# This file contains the main ruleset, which gets automatically loaded
# at startup.  PF will not be automatically enabled, however.  Instead,
# each component which utilizes PF is responsible for enabling and disabling
# PF via -E and -X as documented in pfctl(8).  That will ensure that PF
# is disabled only when the last enable reference is released.
#
# Care must be taken to ensure that the main ruleset does not get flushed,
# as the nested anchors rely on the anchor point defined here. In addition,
# to the anchors loaded by this file, some system services would dynamically
# insert anchors into the main ruleset. These anchors will be added only when
# the system service is used and would removed on termination of the service.
#
# See pf.conf(5) for syntax.
#

#
# com.apple anchor point
#
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
`

// wantPatchedPfConf is stockPfConf with the two marker blocks in the only
// positions macOS pf's section ordering allows.
const wantPatchedPfConf = `#
# Default PF configuration file.
#
# This file contains the main ruleset, which gets automatically loaded
# at startup.  PF will not be automatically enabled, however.  Instead,
# each component which utilizes PF is responsible for enabling and disabling
# PF via -E and -X as documented in pfctl(8).  That will ensure that PF
# is disabled only when the last enable reference is released.
#
# Care must be taken to ensure that the main ruleset does not get flushed,
# as the nested anchors rely on the anchor point defined here. In addition,
# to the anchors loaded by this file, some system services would dynamically
# insert anchors into the main ruleset. These anchors will be added only when
# the system service is used and would removed on termination of the service.
#
# See pf.conf(5) for syntax.
#

#
# com.apple anchor point
#
scrub-anchor "com.apple/*"
# >>> zapret-mac >>>
rdr-anchor "zapret-mac"
# <<< zapret-mac <<<
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
# >>> zapret-mac >>>
anchor "zapret-mac"
# <<< zapret-mac <<<
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
`

// flowseal's two port windows, as they appear in its .bat files.
var (
	flowsealTCPWindow = []PortRange{{80, 80}, {443, 443}, {2053, 2053}, {2083, 2083},
		{2087, 2087}, {2096, 2096}, {8443, 8443}}
	flowsealUDPWindow = []PortRange{{443, 443}, {19294, 19344}, {50000, 50100}}
)

// ---------------------------------------------------------------------------
// pfctl availability
// ---------------------------------------------------------------------------

// pfctlCanParse reports whether `pfctl -n -f -` works for this test process.
// Parsing does not touch /dev/pf on macOS, so it usually works unprivileged,
// but the test must degrade cleanly where it does not.
func pfctlCanParse(t *testing.T) bool {
	t.Helper()
	if _, err := os.Stat(DefaultPfctlPath); err != nil {
		t.Logf("skipping pfctl dry-run checks: %v", err)
		return false
	}
	cmd := exec.Command(DefaultPfctlPath, "-n", "-f", "-")
	cmd.Stdin = strings.NewReader("pass quick on lo0 all\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("skipping pfctl dry-run checks, pfctl -n is not usable as uid %d: %v\n%s",
			os.Geteuid(), err, out)
		return false
	}
	return true
}

// pfctlParse dry-runs a ruleset, optionally inside an anchor, and fails the test
// on a syntax error. Nothing is ever loaded into the kernel: -n stops after
// parsing.
func pfctlParse(t *testing.T, anchor, rules string) {
	t.Helper()
	args := []string{}
	if anchor != "" {
		args = append(args, "-a", anchor)
	}
	args = append(args, "-n", "-f", "-")
	cmd := exec.Command(DefaultPfctlPath, args...)
	cmd.Stdin = strings.NewReader(rules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("pfctl %s rejected the ruleset: %v\n--- ruleset ---\n%s--- pfctl ---\n%s",
			strings.Join(args, " "), err, rules, out)
	}
}

// pfctlParseFile dry-runs a main ruleset from a path.
func pfctlParseFile(t *testing.T, path string) {
	t.Helper()
	out, err := exec.Command(DefaultPfctlPath, "-n", "-f", path).CombinedOutput()
	if err != nil {
		body, _ := os.ReadFile(path)
		t.Errorf("pfctl -n -f %s failed: %v\n--- file ---\n%s--- pfctl ---\n%s", path, err, body, out)
	}
}

// ---------------------------------------------------------------------------
// FormatPorts / ParsePortSpecs
// ---------------------------------------------------------------------------

func TestFormatPorts(t *testing.T) {
	cases := []struct {
		name string
		in   []PortRange
		want string
	}{
		{"empty", nil, ""},
		{"single", []PortRange{{443, 443}}, "{ 443 }"},
		{"two", []PortRange{{80, 80}, {443, 443}}, "{ 80 443 }"},
		{"range uses a colon, not a dash",
			[]PortRange{{19294, 19344}}, "{ 19294:19344 }"},
		{"mixed", []PortRange{{443, 443}, {19294, 19344}}, "{ 443 19294:19344 }"},
		{"flowseal tcp window", flowsealTCPWindow,
			"{ 80 443 2053 2083 2087 2096 8443 }"},
		{"flowseal udp window", flowsealUDPWindow,
			"{ 443 19294:19344 50000:50100 }"},
		{"reversed pair is normalised", []PortRange{{443, 80}}, "{ 80:443 }"},
		{"full range", []PortRange{{1, 65535}}, "{ 1:65535 }"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FormatPorts(c.in); got != c.want {
				t.Errorf("FormatPorts(%v) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestFormatPortsAllFlowsealWindowsParse(t *testing.T) {
	if !pfctlCanParse(t) {
		t.Skip("pfctl -n unavailable")
	}
	for _, w := range [][]PortRange{flowsealTCPWindow, flowsealUDPWindow} {
		rules := "pass out quick inet proto tcp from any to any port " + FormatPorts(w) + " no state\n"
		pfctlParse(t, "", rules)
	}
}

func TestParsePortSpecs(t *testing.T) {
	got, err := ParsePortSpecs([]string{"443", "19294-19344", " 50000:50100 ", ""})
	if err != nil {
		t.Fatalf("ParsePortSpecs: %v", err)
	}
	want := []PortRange{{443, 443}, {19294, 19344}, {50000, 50100}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if FormatPorts(got) != "{ 443 19294:19344 50000:50100 }" {
		t.Errorf("round trip: %q", FormatPorts(got))
	}
	for _, bad := range []string{"0", "65536", "abc", "80-", "-80", "80:x"} {
		if _, err := ParsePortSpecs([]string{bad}); err == nil {
			t.Errorf("ParsePortSpecs(%q) accepted an invalid spec", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// SteerRules
// ---------------------------------------------------------------------------

func TestSteerRulesGolden(t *testing.T) {
	o := SteerOpts{
		Utun:         "utun9",
		TunPeer:      "198.18.0.2",
		TCPPorts:     []PortRange{{80, 80}, {443, 443}},
		UDPPorts:     []PortRange{{443, 443}, {19294, 19344}},
		ExcludeTable: "zmx",
		ExemptRoot:   true,
	}
	want := `table <zmx> persist
pass quick on lo0 all
pass out quick route-to (utun9 198.18.0.2) inet proto tcp from any to ! <zmx> port { 80 443 } user { > root } no state
pass out quick route-to (utun9 198.18.0.2) inet proto udp from any to ! <zmx> port { 443 19294:19344 } user { > root } no state
`
	if got := SteerRules(o); got != want {
		t.Errorf("SteerRules mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

func TestSteerRulesBlockQUICPrecedesUDPSteer(t *testing.T) {
	o := SteerOpts{
		Utun:        "utun9",
		TunPeer:     "198.18.0.2",
		UDPPorts:    []PortRange{{443, 443}},
		TargetTable: "zmt",
		BlockQUIC:   true,
		ExemptRoot:  true,
	}
	got := SteerRules(o)
	want := `table <zmt> persist
pass quick on lo0 all
block return-icmp out quick inet proto udp from any to <zmt> port { 443 }
pass out quick route-to (utun9 198.18.0.2) inet proto udp from any to <zmt> port { 443 } user { > root } no state
`
	if got != want {
		t.Errorf("SteerRules mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
	}
	// Both rules carry `quick`, so the block must come first or it can never
	// fire while UDP/443 is inside the window.
	blockAt := strings.Index(got, "block return-icmp")
	steerAt := strings.Index(got, "route-to (utun9 198.18.0.2) inet proto udp")
	if blockAt < 0 || steerAt < 0 || blockAt > steerAt {
		t.Errorf("BlockQUIC rule must precede the UDP steering rule:\n%s", got)
	}
}

func TestSteerRulesVariants(t *testing.T) {
	cases := []struct {
		name string
		in   SteerOpts
		want string
	}{
		{
			name: "no tables, no root exemption",
			in: SteerOpts{Utun: "utun4", TunPeer: "198.18.0.2",
				TCPPorts: []PortRange{{443, 443}}},
			want: `pass quick on lo0 all
pass out quick route-to (utun4 198.18.0.2) inet proto tcp from any to any port { 443 } no state
`,
		},
		{
			name: "target table wins over exclude table",
			in: SteerOpts{Utun: "utun9", TunPeer: "198.18.0.2",
				TCPPorts:     []PortRange{{443, 443}},
				ExcludeTable: "zmx", TargetTable: "zmt"},
			want: `table <zmx> persist
table <zmt> persist
pass quick on lo0 all
pass out quick route-to (utun9 198.18.0.2) inet proto tcp from any to <zmt> port { 443 } no state
`,
		},
		{
			name: "ipv6 uses inet6 and return-icmp6",
			in: SteerOpts{Utun: "utun9", TunPeer: "198.18.0.2", TunPeer6: "fd00::2",
				UDPPorts: []PortRange{{443, 443}}, IPv6: true, BlockQUIC: true,
				NoLoopbackPass: true},
			want: `block return-icmp6 out quick inet6 proto udp from any to any port { 443 }
pass out quick route-to (utun9 fd00::2) inet6 proto udp from any to any port { 443 } no state
`,
		},
		{
			name: "pre-rendered port list wins",
			in: SteerOpts{Utun: "utun9", TunPeer: "198.18.0.2",
				TCPPorts: []PortRange{{1, 2}}, TCPPortsRaw: "{ 8443 }",
				NoLoopbackPass: true},
			want: `pass out quick route-to (utun9 198.18.0.2) inet proto tcp from any to any port { 8443 } no state
`,
		},
		{
			name: "empty window emits no steering rule",
			in:   SteerOpts{Utun: "utun9", TunPeer: "198.18.0.2"},
			want: "pass quick on lo0 all\n",
		},
		{
			name: "missing utun emits no steering rule",
			in:   SteerOpts{TCPPorts: []PortRange{{443, 443}}, NoLoopbackPass: true},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SteerRules(c.in); got != c.want {
				t.Errorf("mismatch\n--- got ---\n%s--- want ---\n%s", got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RedirectRules
// ---------------------------------------------------------------------------

func TestRedirectRulesGolden(t *testing.T) {
	got := RedirectRules(RedirOpts{
		ListenPort:   10800,
		TCPPorts:     []PortRange{{80, 80}, {443, 443}},
		ExcludeTable: "zmx",
		ExemptRoot:   true,
	})
	want := `table <zmx> persist
rdr pass on lo0 inet proto tcp from ! 127.0.0.0/8 to any port { 80 443 } -> 127.0.0.1 port 10800
pass out quick route-to (lo0 127.0.0.1) inet proto tcp from any to ! <zmx> port { 80 443 } user { > root }
`
	if got != want {
		t.Errorf("RedirectRules mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

func TestRedirectRulesVariants(t *testing.T) {
	cases := []struct {
		name string
		in   RedirOpts
		want string
	}{
		{
			name: "ipv6 mirrors zapret's ::1 / fe80::1 pair",
			in:   RedirOpts{ListenPort: 10800, TCPPorts: []PortRange{{443, 443}}, IPv6: true},
			want: `rdr pass on lo0 inet6 proto tcp from ! ::1 to any port { 443 } -> fe80::1 port 10800
pass out quick route-to (lo0 fe80::1) inet6 proto tcp from any to any port { 443 }
`,
		},
		{
			name: "per-interface route-to",
			in: RedirOpts{ListenPort: 1080, TCPPorts: []PortRange{{443, 443}},
				Ifaces: []string{"en0", "en1"}, TargetTable: "zmt", ExemptRoot: true},
			want: `table <zmt> persist
rdr pass on lo0 inet proto tcp from ! 127.0.0.0/8 to any port { 443 } -> 127.0.0.1 port 1080
pass out quick on en0 route-to (lo0 127.0.0.1) inet proto tcp from any to <zmt> port { 443 } user { > root }
pass out quick on en1 route-to (lo0 127.0.0.1) inet proto tcp from any to <zmt> port { 443 } user { > root }
`,
		},
		{"no ports means no rules", RedirOpts{ListenPort: 1080}, ""},
		{"no listen port means no rules",
			RedirOpts{TCPPorts: []PortRange{{443, 443}}}, ""},
		{"out-of-range listen port means no rules",
			RedirOpts{ListenPort: 70000, TCPPorts: []PortRange{{443, 443}}}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RedirectRules(c.in); got != c.want {
				t.Errorf("mismatch\n--- got ---\n%s--- want ---\n%s", got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// generated rulesets must actually parse
// ---------------------------------------------------------------------------

func TestGeneratedRulesetsParse(t *testing.T) {
	if !pfctlCanParse(t) {
		t.Skip("pfctl -n unavailable")
	}
	steer := []SteerOpts{
		{Utun: "utun9", TunPeer: "198.18.0.2", TCPPorts: flowsealTCPWindow,
			UDPPorts: flowsealUDPWindow, ExcludeTable: "zmx", ExemptRoot: true},
		{Utun: "utun9", TunPeer: "198.18.0.2", TCPPorts: flowsealTCPWindow,
			UDPPorts: flowsealUDPWindow, ExcludeTable: "zmx", TargetTable: "zmt",
			ExemptRoot: true, BlockQUIC: true},
		{Utun: "utun9", TunPeer6: "fd00::2", TCPPorts: flowsealTCPWindow,
			UDPPorts: flowsealUDPWindow, IPv6: true, ExcludeTable: "zmx6",
			ExemptRoot: true, BlockQUIC: true},
		{Utun: "utun9", TunPeer: "198.18.0.2", UDPPorts: flowsealUDPWindow},
	}
	for i, o := range steer {
		rules := SteerRules(o)
		if rules == "" {
			t.Errorf("steer case %d produced no rules", i)
			continue
		}
		pfctlParse(t, "zapret-mac", rules)
	}
	redir := []RedirOpts{
		{ListenPort: 10800, TCPPorts: flowsealTCPWindow, ExcludeTable: "zmx", ExemptRoot: true},
		{ListenPort: 10800, TCPPorts: flowsealTCPWindow, TargetTable: "zmt", Ifaces: []string{"en0"}},
		{ListenPort: 10800, TCPPorts: flowsealTCPWindow, IPv6: true, ExemptRoot: true},
	}
	for i, o := range redir {
		rules := RedirectRules(o)
		if rules == "" {
			t.Errorf("redirect case %d produced no rules", i)
			continue
		}
		pfctlParse(t, "zapret-mac", rules)
	}
}

// ---------------------------------------------------------------------------
// pf.conf planning
// ---------------------------------------------------------------------------

func TestPlanPfConfStock(t *testing.T) {
	plan := planPfConf([]byte(stockPfConf), "zapret-mac")
	if !plan.Changed {
		t.Fatal("stock pf.conf should need patching")
	}
	if string(plan.Content) != wantPatchedPfConf {
		t.Errorf("patched content mismatch\n--- got ---\n%s\n--- want ---\n%s",
			plan.Content, wantPatchedPfConf)
	}
	// Every original line must survive, in its original relative order.
	assertForeignLinesPreserved(t, stockPfConf, string(plan.Content))
}

func TestPlanPfConfIdempotent(t *testing.T) {
	once := planPfConf([]byte(stockPfConf), "zapret-mac")
	twice := planPfConf(once.Content, "zapret-mac")
	if twice.Changed {
		t.Errorf("second patch changed the file again: %s", twice.Note)
	}
	if string(twice.Content) != string(once.Content) {
		t.Errorf("not idempotent:\n%s", twice.Content)
	}
	if twice.Note != "already patched" {
		t.Errorf("note = %q", twice.Note)
	}
}

func TestPlanPfConfRepairsHalfAppliedPatch(t *testing.T) {
	// A crash between the two insertions, or an operator adding one statement
	// by hand: converge to the correct shape without duplicating anything.
	half := strings.Replace(stockPfConf,
		`anchor "com.apple/*"`+"\n"+`load anchor`,
		`anchor "zapret-mac"`+"\n"+`anchor "com.apple/*"`+"\n"+`load anchor`, 1)
	plan := planPfConf([]byte(half), "zapret-mac")
	if !plan.Changed {
		t.Fatal("half-applied patch should be repaired")
	}
	if string(plan.Content) != wantPatchedPfConf {
		t.Errorf("repair mismatch\n--- got ---\n%s\n--- want ---\n%s", plan.Content, wantPatchedPfConf)
	}
	if strings.Count(string(plan.Content), `anchor "zapret-mac"`) != 2 {
		t.Errorf("expected exactly one rdr-anchor and one anchor statement:\n%s", plan.Content)
	}
}

func TestPlanPfConfOrphanedMarkerDoesNotEatForeignLines(t *testing.T) {
	// An opening marker with no terminator must cost exactly one line.
	broken := strings.Replace(stockPfConf,
		`nat-anchor "com.apple/*"`,
		"# >>> zapret-mac >>>\n"+`nat-anchor "com.apple/*"`, 1)
	plan := planPfConf([]byte(broken), "zapret-mac")
	for _, must := range []string{
		`scrub-anchor "com.apple/*"`, `nat-anchor "com.apple/*"`,
		`rdr-anchor "com.apple/*"`, `dummynet-anchor "com.apple/*"`,
		`anchor "com.apple/*"`, `load anchor "com.apple"`,
	} {
		if !strings.Contains(string(plan.Content), must) {
			t.Errorf("orphaned marker swallowed %q:\n%s", must, plan.Content)
		}
	}
}

func TestPlanPfConfRemoval(t *testing.T) {
	patched := planPfConf([]byte(stockPfConf), "zapret-mac")
	removal := planPfConfRemoval(patched.Content, "zapret-mac")
	if !removal.Changed {
		t.Fatal("removal should change the file")
	}
	if string(removal.Content) != stockPfConf {
		t.Errorf("removal did not restore the stock file byte-for-byte\n--- got ---\n%s\n--- want ---\n%s",
			removal.Content, stockPfConf)
	}
	// Removing twice is a no-op.
	again := planPfConfRemoval(removal.Content, "zapret-mac")
	if again.Changed {
		t.Error("second removal changed the file")
	}
}

func TestPlanPfConfRemovalKeepsForeignEdits(t *testing.T) {
	patched := planPfConf([]byte(stockPfConf), "zapret-mac")
	drifted := strings.Replace(string(patched.Content),
		`anchor "com.apple/*"`+"\n"+`load anchor`,
		`anchor "othertool"`+"\n"+`anchor "com.apple/*"`+"\n"+`load anchor`, 1)
	removal := planPfConfRemoval([]byte(drifted), "zapret-mac")
	if !strings.Contains(string(removal.Content), `anchor "othertool"`) {
		t.Errorf("a foreign anchor statement was removed:\n%s", removal.Content)
	}
	if strings.Contains(string(removal.Content), "zapret-mac") {
		t.Errorf("our block survived removal:\n%s", removal.Content)
	}
}

func TestPlanPfConfNoRecognisableSections(t *testing.T) {
	in := "# nothing but comments\nset skip on lo0\n"
	plan := planPfConf([]byte(in), "zapret-mac")
	if !plan.Changed {
		t.Fatal("should still insert something")
	}
	got := string(plan.Content)
	rdrAt := strings.Index(got, `rdr-anchor "zapret-mac"`)
	filtAt := strings.Index(got, "\n"+`anchor "zapret-mac"`)
	if rdrAt < 0 || filtAt < 0 || rdrAt > filtAt {
		t.Errorf("translation statement must precede the filter statement:\n%s", got)
	}
	if !strings.HasPrefix(got, in) {
		t.Errorf("original content was not preserved as a prefix:\n%s", got)
	}
}

func TestPlanPfConfFilterSectionOnly(t *testing.T) {
	// A pf.conf with filter rules but no translation section: both statements
	// must land at the filter boundary, translation first.
	in := "set skip on lo0\nblock drop in all\npass out all\n"
	plan := planPfConf([]byte(in), "zapret-mac")
	got := string(plan.Content)
	want := `set skip on lo0
# >>> zapret-mac >>>
rdr-anchor "zapret-mac"
anchor "zapret-mac"
# <<< zapret-mac <<<
block drop in all
pass out all
`
	if got != want {
		t.Errorf("mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

func TestPatchedPfConfParses(t *testing.T) {
	if !pfctlCanParse(t) {
		t.Skip("pfctl -n unavailable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "pf.conf")
	plan := planPfConf([]byte(stockPfConf), "zapret-mac")
	if err := os.WriteFile(path, plan.Content, 0o644); err != nil {
		t.Fatal(err)
	}
	pfctlParseFile(t, path)
}

func TestSingleContiguousBlockWouldNotParse(t *testing.T) {
	// Documents WHY the patch is two blocks: the naive single block above the
	// first com.apple anchor violates pf's section ordering.
	if !pfctlCanParse(t) {
		t.Skip("pfctl -n unavailable")
	}
	naive := strings.Replace(stockPfConf, `scrub-anchor "com.apple/*"`,
		"# >>> zapret-mac >>>\n"+`rdr-anchor "zapret-mac"`+"\n"+`anchor "zapret-mac"`+
			"\n# <<< zapret-mac <<<\n"+`scrub-anchor "com.apple/*"`, 1)
	dir := t.TempDir()
	path := filepath.Join(dir, "pf.conf")
	if err := os.WriteFile(path, []byte(naive), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(DefaultPfctlPath, "-n", "-f", path).CombinedOutput()
	if err == nil {
		t.Errorf("expected pf to reject a single contiguous block, but it parsed:\n%s", out)
	}
	if !strings.Contains(string(out), "Rules must be in order") {
		t.Logf("pfctl rejected it for a different reason:\n%s", out)
	}
}

func TestAnchorStatementsPresent(t *testing.T) {
	if AnchorStatementsPresent([]byte(stockPfConf), "zapret-mac") {
		t.Error("stock pf.conf should not reference our anchor")
	}
	patched := planPfConf([]byte(stockPfConf), "zapret-mac")
	if !AnchorStatementsPresent(patched.Content, "zapret-mac") {
		t.Error("patched pf.conf should reference our anchor")
	}
	// Only one of the two statements is not enough.
	half := "rdr-anchor \"zapret-mac\"\n"
	if AnchorStatementsPresent([]byte(half), "zapret-mac") {
		t.Error("a lone rdr-anchor must not count as present")
	}
}

func TestAnchorNames(t *testing.T) {
	got := AnchorNames([]byte(stockPfConf))
	if len(got) != 1 || got[0] != "com.apple/*" {
		t.Errorf("AnchorNames(stock) = %v, want [com.apple/*]", got)
	}
	mixed := stockPfConf + "anchor \"zapret\"\nrdr-anchor \"somevpn\"\n" +
		"load anchor \"ignored\" from \"/tmp/x\"\n"
	got = AnchorNames([]byte(mixed))
	if !containsString(got, "zapret") || !containsString(got, "somevpn") {
		t.Errorf("AnchorNames(mixed) = %v", got)
	}
	if containsString(got, "ignored") {
		t.Errorf("`load anchor` must not be reported as an anchor statement: %v", got)
	}
}

// assertForeignLinesPreserved checks that every line of orig still appears in
// patched, in the same relative order.
func assertForeignLinesPreserved(t *testing.T, orig, patched string) {
	t.Helper()
	origLines := strings.Split(strings.TrimSuffix(orig, "\n"), "\n")
	patchLines := strings.Split(strings.TrimSuffix(patched, "\n"), "\n")
	j := 0
	for _, want := range origLines {
		found := false
		for ; j < len(patchLines); j++ {
			if patchLines[j] == want {
				found = true
				j++
				break
			}
		}
		if !found {
			t.Fatalf("line %q is missing from the patched file or was reordered", want)
		}
	}
}

// ---------------------------------------------------------------------------
// PF against a temp pf.conf (no kernel involvement)
// ---------------------------------------------------------------------------

// newTestPF builds a PF whose pf.conf is a temp copy. Because the path is not
// /etc/pf.conf, reloadMainLocked refuses to load it into the kernel, so no test
// can disturb the machine's live ruleset.
func newTestPF(t *testing.T, content string) (*PF, string, string) {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "pf.conf")
	if err := os.WriteFile(conf, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	p := NewPF("zapret-mac", PFOpts{
		PfConfPath: conf,
		StateDir:   state,
		Logf:       func(f string, a ...any) { t.Logf("netcfg: "+f, a...) },
	})
	return p, conf, state
}

func TestEnsureAndRemoveAnchorStatements(t *testing.T) {
	if !pfctlCanParse(t) {
		t.Skip("pfctl -n unavailable; EnsureAnchorStatements verifies with pfctl -n")
	}
	p, conf, state := newTestPF(t, stockPfConf)

	patched, err := p.EnsureAnchorStatements()
	if err != nil {
		t.Fatalf("EnsureAnchorStatements: %v", err)
	}
	if !patched {
		t.Fatal("expected the file to be patched")
	}
	got, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != wantPatchedPfConf {
		t.Errorf("on-disk content mismatch\n--- got ---\n%s\n--- want ---\n%s", got, wantPatchedPfConf)
	}
	if st, err := os.Stat(conf); err != nil {
		t.Fatal(err)
	} else if st.Mode().Perm() != 0o644 {
		t.Errorf("mode changed to %v, want 0644", st.Mode().Perm())
	}

	// A byte-exact backup with its hash must be in the journal.
	entries := readJournalEntries(t, state)
	var rec *Entry
	for i := range entries {
		if entries[i].Step == StepPfConf {
			rec = &entries[i]
		}
	}
	if rec == nil {
		t.Fatal("no pf.conf journal record")
	}
	backup, err := os.ReadFile(rec.Data["backup"])
	if err != nil {
		t.Fatalf("reading recorded backup: %v", err)
	}
	if string(backup) != stockPfConf {
		t.Error("backup is not byte-exact")
	}
	if rec.Data["sha256_before"] != sha256Hex([]byte(stockPfConf)) {
		t.Error("sha256_before does not match the original")
	}
	if rec.Data["sha256_after"] != sha256Hex([]byte(wantPatchedPfConf)) {
		t.Error("sha256_after does not match the patched content")
	}

	// Idempotency.
	patched, err = p.EnsureAnchorStatements()
	if err != nil {
		t.Fatalf("second EnsureAnchorStatements: %v", err)
	}
	if patched {
		t.Error("second call reported a patch")
	}

	// Clean removal with no drift.
	if err := p.RemoveAnchorStatements(); err != nil {
		t.Fatalf("RemoveAnchorStatements: %v", err)
	}
	got, _ = os.ReadFile(conf)
	if string(got) != stockPfConf {
		t.Errorf("removal did not restore the stock file\n--- got ---\n%s", got)
	}
	// Removing again is a no-op.
	if err := p.RemoveAnchorStatements(); err != nil {
		t.Errorf("second RemoveAnchorStatements: %v", err)
	}
}

func TestRemoveAnchorStatementsReportsDrift(t *testing.T) {
	if !pfctlCanParse(t) {
		t.Skip("pfctl -n unavailable")
	}
	p, conf, _ := newTestPF(t, stockPfConf)
	if _, err := p.EnsureAnchorStatements(); err != nil {
		t.Fatalf("EnsureAnchorStatements: %v", err)
	}
	// Simulate a third party editing the file after we patched it.
	cur, _ := os.ReadFile(conf)
	drifted := strings.Replace(string(cur), `anchor "com.apple/*"`+"\n"+`load anchor`,
		`anchor "othertool"`+"\n"+`anchor "com.apple/*"`+"\n"+`load anchor`, 1)
	if err := os.WriteFile(conf, []byte(drifted), 0o644); err != nil {
		t.Fatal(err)
	}

	err := p.RemoveAnchorStatements()
	if err == nil {
		t.Fatal("expected a drift report")
	}
	if !errors.Is(err, ErrPfConfDrift) {
		t.Errorf("error does not wrap ErrPfConfDrift: %v", err)
	}
	// Crucially: the removal happened anyway, and the foreign line survived.
	after, _ := os.ReadFile(conf)
	if strings.Contains(string(after), "zapret-mac") {
		t.Errorf("our block was not removed despite the drift report:\n%s", after)
	}
	if !strings.Contains(string(after), `anchor "othertool"`) {
		t.Errorf("the foreign edit was clobbered:\n%s", after)
	}
}

func TestEnsureAnchorStatementsDryRun(t *testing.T) {
	if !pfctlCanParse(t) {
		t.Skip("pfctl -n unavailable")
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "pf.conf")
	if err := os.WriteFile(conf, []byte(stockPfConf), 0o644); err != nil {
		t.Fatal(err)
	}
	p := NewPF("zapret-mac", PFOpts{PfConfPath: conf, StateDir: filepath.Join(dir, "state"), DryRun: true})
	patched, err := p.EnsureAnchorStatements()
	if err != nil {
		t.Fatalf("dry-run EnsureAnchorStatements: %v", err)
	}
	if !patched {
		t.Error("dry run should report that a patch is needed")
	}
	got, _ := os.ReadFile(conf)
	if string(got) != stockPfConf {
		t.Error("dry run modified the file")
	}
}

func TestEnsureAnchorStatementsRefusesMissingFile(t *testing.T) {
	dir := t.TempDir()
	p := NewPF("zapret-mac", PFOpts{
		PfConfPath: filepath.Join(dir, "absent.conf"),
		StateDir:   filepath.Join(dir, "state"),
	})
	if _, err := p.EnsureAnchorStatements(); err == nil {
		t.Error("expected an error for a missing pf.conf")
	}
	if err := p.RemoveAnchorStatements(); err != nil {
		t.Errorf("removal against a missing file should be a no-op, got %v", err)
	}
}

func TestEnsureAnchorStatementsRefusesWithoutStateDir(t *testing.T) {
	if !pfctlCanParse(t) {
		t.Skip("pfctl -n unavailable")
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "pf.conf")
	if err := os.WriteFile(conf, []byte(stockPfConf), 0o644); err != nil {
		t.Fatal(err)
	}
	p := NewPF("zapret-mac", PFOpts{PfConfPath: conf}) // no StateDir
	if _, err := p.EnsureAnchorStatements(); err == nil {
		t.Fatal("patching a system file without a backup location must be refused")
	}
	got, _ := os.ReadFile(conf)
	if string(got) != stockPfConf {
		t.Errorf("the file was modified despite the refusal:\n%s", got)
	}
}

func TestInvalidAnchorNameRejected(t *testing.T) {
	for _, bad := range []string{"", "a/b", `a"b`, "a b", strings.Repeat("x", 65), "-lead"} {
		p := NewPF(bad, PFOpts{StateDir: t.TempDir()})
		if _, err := p.EnsureAnchorStatements(); err == nil {
			t.Errorf("anchor %q was accepted", bad)
		}
		if err := p.LoadRules("pass all\n"); err == nil {
			t.Errorf("anchor %q was accepted by LoadRules", bad)
		}
	}
}

func TestInvalidTableNameRejected(t *testing.T) {
	p := NewPF("zapret-mac", PFOpts{StateDir: t.TempDir(), DryRun: true})
	for _, bad := range []string{"", "a b", "a>b", "<a>", strings.Repeat("x", 33)} {
		if err := p.TableReplace(bad, []netip.Prefix{netip.MustParsePrefix("1.0.0.0/8")}); err == nil {
			t.Errorf("table %q was accepted", bad)
		}
		if _, err := p.TableCount(bad); err == nil {
			t.Errorf("table %q was accepted by TableCount", bad)
		}
	}
}

func TestPreflightNonRootDryRun(t *testing.T) {
	p, _, _ := newTestPF(t, stockPfConf)
	p.dryRun = true
	if err := p.Preflight(); err != nil {
		t.Fatalf("dry-run preflight should not fail: %v", err)
	}
	res := p.LastPreflight()
	if res.UID != os.Geteuid() {
		t.Errorf("UID = %d, want %d", res.UID, os.Geteuid())
	}
	if !res.PfConfExists {
		t.Error("PfConfExists should be true")
	}
	if res.AnchorReferenced {
		t.Error("stock pf.conf should not reference our anchor yet")
	}
	if os.Geteuid() != 0 && res.Root {
		t.Error("Root must be false when not running as root")
	}
	t.Logf("preflight: iface=%q gw=%q vpn=%v foreign=%v warnings=%v",
		res.DefaultIface, res.DefaultGateway, res.VPNActive, res.ForeignAnchors, res.Warnings)
}

func TestPreflightNonRootHardFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; this test asserts the non-root failure path")
	}
	p, _, _ := newTestPF(t, stockPfConf)
	err := p.Preflight()
	if err == nil {
		t.Fatal("preflight should fail when not root and not in dry-run mode")
	}
	if !errors.Is(err, ErrNotRoot) {
		t.Errorf("error should wrap ErrNotRoot: %v", err)
	}
}

func TestReleaseWithoutTokenIsSafe(t *testing.T) {
	p, _, _ := newTestPF(t, stockPfConf)
	if err := p.Release(); err != nil {
		t.Errorf("Release with no token: %v", err)
	}
	if err := p.Release(); err != nil {
		t.Errorf("second Release: %v", err)
	}
	if got := p.Token(); got != "" {
		t.Errorf("Token = %q, want empty", got)
	}
}

func TestTokenPersistence(t *testing.T) {
	p, _, state := newTestPF(t, stockPfConf)
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	// A token file left behind by a crashed daemon must be picked up.
	if err := os.WriteFile(filepath.Join(state, PfTokenName), []byte("12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := p.Token(); got != "12345" {
		t.Errorf("Token = %q, want 12345", got)
	}
	// Garbage must not be handed to pfctl as an argument.
	if err := os.WriteFile(filepath.Join(state, PfTokenName), []byte("nope; rm -rf /\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := p.Token(); got != "" {
		t.Errorf("Token = %q, want empty for a malformed token file", got)
	}
}

func TestPfctlErrorCarriesStderrVerbatim(t *testing.T) {
	if !pfctlCanParse(t) {
		t.Skip("pfctl -n unavailable")
	}
	p, _, _ := newTestPF(t, stockPfConf)
	err := p.LoadRules("this is not a pf rule\n")
	if err == nil {
		t.Fatal("expected a syntax error")
	}
	var pe *PfctlError
	if !errors.As(err, &pe) {
		t.Fatalf("error is not a *PfctlError: %v", err)
	}
	if !strings.Contains(pe.Stderr, "syntax error") {
		t.Errorf("pfctl stderr was not preserved verbatim: %q", pe.Stderr)
	}
	if !strings.Contains(err.Error(), "syntax error") {
		t.Errorf("Error() must surface pfctl's message: %v", err)
	}
}

func TestLoadRulesDryRunDoesNotLoad(t *testing.T) {
	if !pfctlCanParse(t) {
		t.Skip("pfctl -n unavailable")
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "pf.conf")
	if err := os.WriteFile(conf, []byte(stockPfConf), 0o644); err != nil {
		t.Fatal(err)
	}
	p := NewPF("zapret-mac", PFOpts{PfConfPath: conf, StateDir: filepath.Join(dir, "state"), DryRun: true})
	rules := SteerRules(SteerOpts{Utun: "utun9", TunPeer: "198.18.0.2",
		TCPPorts: flowsealTCPWindow, ExcludeTable: "zmx", ExemptRoot: true})
	if err := p.LoadRules(rules); err != nil {
		t.Fatalf("dry-run LoadRules: %v", err)
	}
	if err := p.FlushRules(); err != nil {
		t.Fatalf("dry-run FlushRules: %v", err)
	}
	if err := p.Verify(); err != nil {
		t.Fatalf("dry-run Verify: %v", err)
	}
}

// readJournalEntries reads the journal from a state directory.
func readJournalEntries(t *testing.T, state string) []Entry {
	t.Helper()
	entries, err := readJournal(filepath.Join(state, JournalName))
	if err != nil {
		t.Fatalf("reading journal: %v", err)
	}
	return entries
}

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------

func TestJournalRoundTrip(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()

	steps := []struct {
		step string
		data map[string]string
	}{
		{StepPfToken, map[string]string{"token": "42"}},
		{StepPfConf, map[string]string{"path": "/etc/pf.conf", "backup": "/tmp/b"}},
		{StepUtun, map[string]string{"iface": "utun9"}},
		{StepRoute, map[string]string{"dst": "0.0.0.0/0", "iface": "utun9"}},
	}
	for _, s := range steps {
		if err := j.Record(s.step, s.data); err != nil {
			t.Fatalf("Record(%s): %v", s.step, err)
		}
	}
	got, err := j.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(steps) {
		t.Fatalf("got %d entries, want %d", len(got), len(steps))
	}
	for i := range steps {
		if got[i].Step != steps[i].step {
			t.Errorf("entry %d step = %q, want %q", i, got[i].Step, steps[i].step)
		}
		if got[i].Seq != i+1 {
			t.Errorf("entry %d seq = %d, want %d", i, got[i].Seq, i+1)
		}
		for k, v := range steps[i].data {
			if got[i].Data[k] != v {
				t.Errorf("entry %d data[%q] = %q, want %q", i, k, got[i].Data[k], v)
			}
		}
	}

	// Rollback must run newest-first and empty the journal on success.
	var order []string
	if err := j.Rollback(func(step string, _ map[string]string) error {
		order = append(order, step)
		return nil
	}); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	want := []string{StepRoute, StepUtun, StepPfConf, StepPfToken}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("rollback order = %v, want %v", order, want)
	}
	if left, _ := j.Entries(); len(left) != 0 {
		t.Errorf("journal not empty after a successful rollback: %v", left)
	}
}

func TestJournalRollbackKeepsFailedEntries(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	for _, s := range []string{StepPfToken, StepPfConf, StepUtun} {
		if err := j.Record(s, map[string]string{"k": s}); err != nil {
			t.Fatal(err)
		}
	}
	boom := errors.New("boom")
	err = j.Rollback(func(step string, _ map[string]string) error {
		if step == StepPfConf {
			return boom
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected the rollback to report the failure")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error does not wrap the handler failure: %v", err)
	}
	left, _ := j.Entries()
	if len(left) != 1 || left[0].Step != StepPfConf {
		t.Fatalf("only the failed entry should remain, got %v", left)
	}
	// A retry that succeeds clears it.
	if err := j.Rollback(func(string, map[string]string) error { return nil }); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if left, _ := j.Entries(); len(left) != 0 {
		t.Errorf("journal not empty after the retry: %v", left)
	}
}

func TestJournalSurvivesReopenAndTornLine(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Record(StepPfToken, map[string]string{"token": "7"}); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	// Append a torn record, as a power loss would leave behind.
	f, err := os.OpenFile(filepath.Join(dir, JournalName), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"time":"2026-01-0`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	j2, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j2.Close()
	got, err := j2.Entries()
	if err != nil {
		t.Fatalf("a torn line must not break reading: %v", err)
	}
	if len(got) != 1 || got[0].Data["token"] != "7" {
		t.Fatalf("entries = %v", got)
	}
	// The sequence continues past the reopen.
	if err := j2.Record(StepUtun, map[string]string{"iface": "utun9"}); err != nil {
		t.Fatal(err)
	}
	got, _ = j2.Entries()
	if len(got) != 2 || got[1].Seq != 2 {
		t.Fatalf("entries = %v", got)
	}
}

func TestJournalClear(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.Record(StepPfToken, map[string]string{"token": "1"}); err != nil {
		t.Fatal(err)
	}
	if err := j.Clear(); err != nil {
		t.Fatal(err)
	}
	if got, _ := j.Entries(); len(got) != 0 {
		t.Fatalf("entries after Clear = %v", got)
	}
	// Still usable afterwards.
	if err := j.Record(StepUtun, map[string]string{"iface": "utun1"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := j.Entries(); len(got) != 1 {
		t.Fatalf("entries = %v", got)
	}
}

func TestJournalRejectsBadInput(t *testing.T) {
	if _, err := OpenJournal(""); err == nil {
		t.Error("OpenJournal(\"\") should fail")
	}
	j, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.Record("", nil); err == nil {
		t.Error("Record with an empty step should fail")
	}
	if err := j.Rollback(nil); err == nil {
		t.Error("Rollback(nil) should fail")
	}
}

// ---------------------------------------------------------------------------
// atomic write
// ---------------------------------------------------------------------------

func TestWriteFileAtomicPreservesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("new"), 0o644, st); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Errorf("content = %q", got)
	}
	st2, _ := os.Stat(path)
	if st2.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600 (inherited from ref)", st2.Mode().Perm())
	}
	// No temp files left behind.
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		names := []string{}
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("temp files left behind: %v", names)
	}
}

// ---------------------------------------------------------------------------
// hosts
// ---------------------------------------------------------------------------

// upstreamHostsPath locates the flowseal hosts fixture in the repo.
func upstreamHostsPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", ".upstream", "service", "hosts")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("fixture %s is unavailable: %v", p, err)
	}
	return p
}

func TestParseHostsFileUpstream(t *testing.T) {
	path := upstreamHostsPath(t)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ParseHostsFile(b)
	if err != nil {
		t.Fatalf("flowseal's hosts file must parse cleanly: %v", err)
	}
	// 243 lines, two of them blank separators.
	if len(entries) != 241 {
		t.Errorf("got %d entries, want 241", len(entries))
	}
	// Spot-check the two features the file exists for.
	var haveGithub, haveDiscordMedia bool
	for _, e := range entries {
		if !e.IP.IsValid() {
			t.Fatalf("entry with an invalid address: %+v", e)
		}
		if len(e.Names) == 0 {
			t.Fatalf("entry with no hostnames: %+v", e)
		}
		for _, n := range e.Names {
			if n == "raw.githubusercontent.com" {
				haveGithub = true
			}
			if strings.HasSuffix(n, ".discord.media") {
				haveDiscordMedia = true
			}
		}
	}
	if !haveGithub || !haveDiscordMedia {
		t.Errorf("expected githubusercontent and discord.media pins (github=%v discord=%v)",
			haveGithub, haveDiscordMedia)
	}
	// Every entry must round-trip through the writer and back.
	var sb strings.Builder
	for _, e := range entries {
		if err := e.Validate(); err != nil {
			t.Fatalf("entry %v does not validate: %v", e, err)
		}
		sb.WriteString(e.String())
		sb.WriteByte('\n')
	}
	again, err := ParseHostsFile([]byte(sb.String()))
	if err != nil {
		t.Fatalf("re-parsing rendered entries: %v", err)
	}
	if len(again) != len(entries) {
		t.Fatalf("round trip lost entries: %d -> %d", len(entries), len(again))
	}
}

func TestParseHostsFileEdgeCases(t *testing.T) {
	in := `# a comment
1.2.3.4 a.example  b.example   # trailing comment

::1 localhost6
fe80::1%lo0 linklocal
not-an-ip host
5.6.7.8
9.9.9.9 bad host!name
10.0.0.1 ok.example
`
	entries, err := ParseHostsFile([]byte(in))
	if err == nil {
		t.Fatal("expected a report about the skipped lines")
	}
	var pe *HostsParseError
	if !errors.As(err, &pe) {
		t.Fatalf("error is not a *HostsParseError: %v", err)
	}
	if pe.Total != 3 {
		t.Errorf("skipped %d line(s), want 3 (%v)", pe.Total, err)
	}
	want := []string{"1.2.3.4", "::1", "fe80::1%lo0", "10.0.0.1"}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries, want %d: %v", len(entries), len(want), entries)
	}
	for i := range want {
		if entries[i].IP.String() != want[i] {
			t.Errorf("entry %d IP = %s, want %s", i, entries[i].IP, want[i])
		}
	}
	if len(entries[0].Names) != 2 || entries[0].Comment != "trailing comment" {
		t.Errorf("entry 0 = %+v", entries[0])
	}
}

func TestHostsApplyRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	original := `##
# Host Database
##
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
`
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	h := NewHosts(path, filepath.Join(dir, "state"))
	h.SetLogf(func(f string, a ...any) { t.Logf("netcfg: "+f, a...) })

	entries := []HostEntry{
		{IP: netip.MustParseAddr("185.199.109.133"), Names: []string{"raw.githubusercontent.com"}},
		{IP: netip.MustParseAddr("104.25.158.178"), Names: []string{"finland10170.discord.media"}},
	}
	if err := h.Apply(entries); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(got), original) {
		t.Errorf("the pre-existing content must be preserved verbatim as a prefix:\n%s", got)
	}
	if !strings.Contains(string(got), markerBegin("zapret-mac")) ||
		!strings.Contains(string(got), markerEnd("zapret-mac")) {
		t.Errorf("markers missing:\n%s", got)
	}

	applied, err := h.Applied()
	if err != nil {
		t.Fatalf("Applied: %v", err)
	}
	if len(applied) != 2 || applied[0].Names[0] != "raw.githubusercontent.com" {
		t.Fatalf("Applied = %+v", applied)
	}

	// Idempotency: applying the same set again must not grow the file.
	before := len(got)
	if err := h.Apply(entries); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	got2, _ := os.ReadFile(path)
	if len(got2) != before {
		t.Errorf("file grew from %d to %d bytes on a repeat Apply", before, len(got2))
	}

	// Replacing the set replaces the block, not appends to it.
	if err := h.Apply(entries[:1]); err != nil {
		t.Fatalf("third Apply: %v", err)
	}
	applied, _ = h.Applied()
	if len(applied) != 1 {
		t.Errorf("Applied after replacement = %+v", applied)
	}

	// A foreign edit outside our block must survive removal.
	cur, _ := os.ReadFile(path)
	drifted := "1.1.1.1 somebodyelse.example\n" + string(cur)
	if err := os.WriteFile(path, []byte(drifted), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	after, _ := os.ReadFile(path)
	if strings.Contains(string(after), "zapret-mac") {
		t.Errorf("our block survived Remove:\n%s", after)
	}
	if !strings.Contains(string(after), "somebodyelse.example") {
		t.Errorf("the foreign edit was clobbered:\n%s", after)
	}
	if !strings.Contains(string(after), "255.255.255.255\tbroadcasthost") {
		t.Errorf("original tab-separated line was rewritten:\n%s", after)
	}
	if applied, err := h.Applied(); err != nil || applied != nil {
		t.Errorf("Applied after Remove = %+v, %v", applied, err)
	}
	// Remove is idempotent.
	if err := h.Remove(); err != nil {
		t.Errorf("second Remove: %v", err)
	}
}

func TestHostsApplyRemoveIsByteExact(t *testing.T) {
	// The strongest property this code can have: an Apply/Remove cycle must
	// leave the file bit-for-bit identical, whatever its original shape.
	originals := []string{
		"127.0.0.1 localhost\n",
		"##\n# Host Database\n##\n127.0.0.1\tlocalhost\n::1             localhost\n",
		"127.0.0.1 localhost\n\n\n", // trailing blank lines
		"127.0.0.1 localhost",       // no trailing newline
		"# only comments\n",         // no entries at all
		"1.1.1.1 a\n# >>> other-tool >>>\n2.2.2.2 b\n# <<< other-tool <<<\n", // foreign block
	}
	entries := []HostEntry{
		{IP: netip.MustParseAddr("185.199.109.133"), Names: []string{"raw.githubusercontent.com"}},
		{IP: netip.MustParseAddr("104.25.158.178"), Names: []string{"a.discord.media", "b.discord.media"}},
	}
	for i, original := range originals {
		dir := t.TempDir()
		path := filepath.Join(dir, "hosts")
		if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
			t.Fatal(err)
		}
		h := NewHosts(path, filepath.Join(dir, "state"))
		if err := h.Apply(entries); err != nil {
			t.Fatalf("case %d Apply: %v", i, err)
		}
		if applied, err := h.Applied(); err != nil || len(applied) != 2 {
			t.Fatalf("case %d Applied = %+v, %v", i, applied, err)
		}
		if err := h.Remove(); err != nil {
			t.Fatalf("case %d Remove: %v", i, err)
		}
		// Appending a block to a file whose last line is unterminated
		// necessarily adds the missing newline; that one byte is the only
		// permitted difference.
		want := original
		if want != "" && !strings.HasSuffix(want, "\n") {
			want += "\n"
		}
		got, _ := os.ReadFile(path)
		if string(got) != want {
			t.Errorf("case %d is not byte-exact after Apply/Remove\n--- got ---\n%q\n--- want ---\n%q",
				i, got, want)
		}
	}
}

func TestHostsRejectsHostileEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := NewHosts(path, filepath.Join(dir, "state"))
	bad := [][]HostEntry{
		{{IP: netip.MustParseAddr("1.2.3.4"), Names: []string{"a.example\n1.1.1.1 evil.example"}}},
		{{IP: netip.MustParseAddr("1.2.3.4"), Names: []string{"a b"}}},
		{{IP: netip.MustParseAddr("1.2.3.4"), Names: nil}},
		{{IP: netip.Addr{}, Names: []string{"a.example"}}},
		{{IP: netip.MustParseAddr("1.2.3.4"), Names: []string{"a.example"}, Comment: "x\n1.1.1.1 evil"}},
		{{IP: netip.MustParseAddr("1.2.3.4"), Names: []string{strings.Repeat("a", 254)}}},
		{{IP: netip.MustParseAddr("1.2.3.4"), Names: []string{"a..b"}}},
	}
	for i, entries := range bad {
		if err := h.Apply(entries); err == nil {
			t.Errorf("case %d was accepted", i)
		}
	}
	got, _ := os.ReadFile(path)
	if string(got) != "127.0.0.1 localhost\n" {
		t.Errorf("a rejected Apply modified the file:\n%s", got)
	}
}

func TestHostsAppliesUpstreamFixture(t *testing.T) {
	src := upstreamHostsPath(t)
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ParseHostsFile(b)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := NewHosts(path, filepath.Join(dir, "state"))
	if err := h.Apply(entries); err != nil {
		t.Fatalf("Apply(%d entries): %v", len(entries), err)
	}
	applied, err := h.Applied()
	if err != nil {
		t.Fatalf("Applied: %v", err)
	}
	if len(applied) != len(entries) {
		t.Fatalf("applied %d entries, want %d", len(applied), len(entries))
	}
	// The journal must name a byte-exact backup.
	entriesJ := readJournalEntries(t, filepath.Join(dir, "state"))
	found := false
	for _, e := range entriesJ {
		if e.Step != StepHosts {
			continue
		}
		found = true
		bk, err := os.ReadFile(e.Data["backup"])
		if err != nil {
			t.Fatalf("reading backup: %v", err)
		}
		if string(bk) != "127.0.0.1 localhost\n" {
			t.Errorf("backup is not byte-exact: %q", bk)
		}
	}
	if !found {
		t.Error("no hosts journal record")
	}
	if err := h.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "127.0.0.1 localhost\n" {
		t.Errorf("Remove did not restore the file:\n%q", got)
	}
}

func TestHostsDryRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := NewHosts(path, filepath.Join(dir, "state"))
	h.SetDryRun(true)
	if err := h.Apply([]HostEntry{{IP: netip.MustParseAddr("1.2.3.4"), Names: []string{"a.example"}}}); err != nil {
		t.Fatalf("dry-run Apply: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "127.0.0.1 localhost\n" {
		t.Errorf("dry run modified the file:\n%s", got)
	}
}

func TestHostsRefusesMissingFile(t *testing.T) {
	dir := t.TempDir()
	h := NewHosts(filepath.Join(dir, "absent"), filepath.Join(dir, "state"))
	if err := h.Apply([]HostEntry{{IP: netip.MustParseAddr("1.2.3.4"), Names: []string{"a.example"}}}); err == nil {
		t.Error("expected an error for a missing hosts file")
	}
	if got, err := h.Applied(); err != nil || got != nil {
		t.Errorf("Applied on a missing file = %v, %v", got, err)
	}
}

func TestStripMarkerBlocksUnterminated(t *testing.T) {
	lines := []string{
		"1.1.1.1 keep.example",
		markerBegin("zapret-mac"),
		"2.2.2.2 ours.example",
		"3.3.3.3 keep-too.example",
	}
	out, removed := stripMarkerBlocks(lines, "zapret-mac")
	if removed != 1 {
		t.Errorf("removed %d lines, want 1", removed)
	}
	if !containsString(out, "3.3.3.3 keep-too.example") ||
		!containsString(out, "1.1.1.1 keep.example") {
		t.Errorf("an unterminated marker swallowed foreign lines: %v", out)
	}
}

// ---------------------------------------------------------------------------
// prefix list / table helpers
// ---------------------------------------------------------------------------

func TestParsePrefixList(t *testing.T) {
	in := []byte("# comment\n1.2.3.4\n10.0.0.0/8\n\n2001:db8::/32 # inline\n1.2.3.4\nnonsense\n")
	got, err := ParsePrefixList(in)
	if err == nil {
		t.Error("expected a report about the malformed line")
	}
	want := []string{"1.2.3.4/32", "10.0.0.0/8", "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("prefix %d = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestParsePrefixListLargeSet(t *testing.T) {
	// 32k entries must go through without any argv involvement; this exercises
	// the parse side of that path.
	var sb strings.Builder
	for i := 0; i < 32768; i++ {
		sb.WriteString(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}).String())
		sb.WriteString("/24\n")
	}
	got, err := ParsePrefixList([]byte(sb.String()))
	if err != nil {
		t.Fatalf("ParsePrefixList: %v", err)
	}
	// /24 masking collapses the 256 addresses per third octet, so duplicates
	// are dropped; just assert a large, sane result.
	if len(got) < 128 {
		t.Errorf("got %d prefixes, expected many more", len(got))
	}
}

func TestTableReplaceDryRun(t *testing.T) {
	p, _, _ := newTestPF(t, stockPfConf)
	p.dryRun = true
	prefixes := make([]netip.Prefix, 0, 32768)
	for i := 0; i < 32768; i++ {
		prefixes = append(prefixes,
			netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}), 32))
	}
	if err := p.TableReplace("zmx", prefixes); err != nil {
		t.Fatalf("TableReplace(32768): %v", err)
	}
	if err := p.TableReplace("zmx", nil); err != nil {
		t.Fatalf("TableReplace(nil) should flush: %v", err)
	}
	if err := p.Table("zmx").Flush(); err != nil {
		t.Fatalf("Table.Flush: %v", err)
	}
}

func TestParsePrefixLoose(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":       "1.2.3.4/32",
		"1.2.3.0/24":    "1.2.3.0/24",
		"1.2.3.4/24":    "1.2.3.0/24", // masked
		"2001:db8::1":   "2001:db8::1/128",
		"2001:db8::/32": "2001:db8::/32",
	}
	for in, want := range cases {
		got, err := parsePrefixLoose(in)
		if err != nil {
			t.Errorf("parsePrefixLoose(%q): %v", in, err)
			continue
		}
		if got.String() != want {
			t.Errorf("parsePrefixLoose(%q) = %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"", "nope", "1.2.3.4/33", "1.2.3.4/", "/24"} {
		if _, err := parsePrefixLoose(bad); err == nil {
			t.Errorf("parsePrefixLoose(%q) accepted invalid input", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// routing
// ---------------------------------------------------------------------------

func TestIsTunnelInterface(t *testing.T) {
	for _, name := range []string{"utun0", "utun9", "ipsec0", "ppp0", "gif0", "stf0", "tun5", "tap1", "wg0"} {
		if !IsTunnelInterface(name) {
			t.Errorf("IsTunnelInterface(%q) = false", name)
		}
	}
	for _, name := range []string{"en0", "lo0", "bridge0", "awdl0", "", "eth0"} {
		if IsTunnelInterface(name) {
			t.Errorf("IsTunnelInterface(%q) = true", name)
		}
	}
}

func TestInterfaceMTU(t *testing.T) {
	mtu, err := InterfaceMTU("lo0")
	if err != nil {
		t.Fatalf("InterfaceMTU(lo0): %v", err)
	}
	// macOS loopback is 16384 by default; accept any sane value.
	if mtu < 1280 {
		t.Errorf("InterfaceMTU(lo0) = %d, implausibly small", mtu)
	}
	t.Logf("lo0 MTU = %d", mtu)

	for _, bad := range []string{"", "no-such-interface-xyz", strings.Repeat("x", 32)} {
		if _, err := InterfaceMTU(bad); err == nil {
			t.Errorf("InterfaceMTU(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestInterfaces(t *testing.T) {
	tbl, err := Interfaces()
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}
	if _, ok := tbl["lo0"]; !ok {
		names := make([]string, 0, len(tbl))
		for n := range tbl {
			names = append(names, n)
		}
		t.Fatalf("lo0 missing from the interface table: %v", names)
	}
	if !tbl["lo0"].Up() {
		t.Error("lo0 should be up")
	}
}

func TestDefaultRoute(t *testing.T) {
	iface, gw, local, mac, err := DefaultRoute()
	if err != nil {
		t.Skipf("no IPv4 default route on this machine: %v", err)
	}
	if iface == "" {
		t.Error("default route has no interface name")
	}
	t.Logf("default route: iface=%s gw=%v local=%v mac=%v tunnel=%v",
		iface, gw, local, mac, IsTunnelInterface(iface))

	r, err := DefaultRoute4()
	if err != nil {
		t.Fatalf("DefaultRoute4: %v", err)
	}
	if r.Iface != iface || r.Gateway != gw || r.Local != local {
		t.Errorf("DefaultRoute and DefaultRoute4 disagree: %+v vs (%s,%v,%v)", r, iface, gw, local)
	}
	if r.MTU != 0 && r.MTU < 1280 {
		t.Errorf("implausible MTU %d on %s", r.MTU, r.Iface)
	}
	// RouteForIface must find the same interface.
	if r2, err := RouteForIface(iface); err == nil {
		if r2.Iface != iface {
			t.Errorf("RouteForIface(%s).Iface = %s", iface, r2.Iface)
		}
	} else {
		t.Logf("RouteForIface(%s): %v (no gateway route, acceptable)", iface, err)
	}
}

func TestARPTable(t *testing.T) {
	tbl, err := ARPTable()
	if err != nil {
		t.Fatalf("ARPTable: %v", err)
	}
	for ip, mac := range tbl {
		if !ip.Is4() {
			t.Errorf("non-IPv4 entry %v", ip)
		}
		if len(mac) != 6 {
			t.Errorf("entry %v has a %d-byte address", ip, len(mac))
		}
	}
	t.Logf("ARP cache holds %d entry/entries", len(tbl))
}

func TestSplitSockaddrsNeverOverruns(t *testing.T) {
	// Hostile/truncated input must not panic or read out of bounds.
	inputs := [][]byte{
		nil, {}, {0}, {1}, {0xff, 0x02, 0, 0},
		{16, 2, 0, 80, 1, 2, 3, 4},
		{255, 2, 0, 0, 1, 2, 3, 4},
		{0, 0, 0, 0, 0, 0, 0, 0},
	}
	for _, in := range inputs {
		for _, mask := range []uint32{0, 1, 0xff, 0xffffffff} {
			sas := splitSockaddrs(in, mask)
			if len(sas) != rtaxMax {
				t.Fatalf("splitSockaddrs returned %d slots", len(sas))
			}
			for _, sa := range sas {
				_, _, _ = sockaddrInet4(sa)
				_, _ = sockaddrIP(sa)
				_ = sockaddrMaskIsZero(sa)
				_, _, _, _ = parseLinkAddr(sa)
			}
		}
	}
}

func TestForEachRouteMessageNeverOverruns(t *testing.T) {
	inputs := [][]byte{
		nil, {}, {0, 0, 0, 0}, {4, 0, byte(0), byte(0)},
		{0xff, 0xff, 5, 4}, // msglen far larger than the buffer
		make([]byte, 200),
	}
	for _, in := range inputs {
		forEachRouteMessage(in, func(msg []byte) {
			if len(msg) <= sizeofRtMsghdr {
				t.Fatalf("callback received a %d-byte message", len(msg))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

func TestFlushDNSCacheToleratesAbsence(t *testing.T) {
	// runDNSHelper is the tolerance mechanism: a missing binary is success.
	if err := runDNSHelper(filepath.Join(t.TempDir(), "no-such-tool"), "-x"); err != nil {
		t.Errorf("a missing helper must be tolerated: %v", err)
	}
	if os.Geteuid() != 0 {
		// dscacheutil -flushcache and killall -HUP mDNSResponder both need
		// privileges; only assert that the call does not hang or panic.
		t.Logf("FlushDNSCache as uid %d: %v", os.Geteuid(), FlushDNSCache())
		return
	}
	if err := FlushDNSCache(); err != nil {
		t.Errorf("FlushDNSCache: %v", err)
	}
}

// ---------------------------------------------------------------------------
// privileged paths (skipped unless root and explicitly enabled)
// ---------------------------------------------------------------------------

// TestPrivilegedPfLifecycle exercises the code paths that actually talk to
// /dev/pf. It is skipped unless the process is root AND
// ZAPRET_MAC_TEST_PF_LIVE=1, because it enables pf and loads rules into an
// anchor on the machine running the test.
func TestPrivilegedPfLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if os.Getenv("ZAPRET_MAC_TEST_PF_LIVE") != "1" {
		t.Skip("set ZAPRET_MAC_TEST_PF_LIVE=1 to exercise live pf changes")
	}
	dir := t.TempDir()
	p := NewPF("zapret-mac-test", PFOpts{
		PfConfPath: DefaultPfConfPath,
		StateDir:   filepath.Join(dir, "state"),
		Logf:       func(f string, a ...any) { t.Logf("netcfg: "+f, a...) },
	})
	if err := p.Preflight(); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if err := p.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	t.Cleanup(func() {
		if err := p.FlushRules(); err != nil {
			t.Errorf("cleanup FlushRules: %v", err)
		}
		if err := p.Release(); err != nil {
			t.Errorf("cleanup Release: %v", err)
		}
	})
	if on, err := p.Enabled(); err != nil || !on {
		t.Fatalf("Enabled() = %v, %v", on, err)
	}
	rules := SteerRules(SteerOpts{Utun: "utun9", TunPeer: "198.18.0.2",
		TCPPorts: flowsealTCPWindow, ExcludeTable: "zmxtest", ExemptRoot: true})
	if err := p.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if got, err := p.Rules(); err != nil || got == "" {
		t.Fatalf("Rules() = %q, %v", got, err)
	}
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.7/32"),
	}
	if err := p.TableReplace("zmxtest", prefixes); err != nil {
		t.Fatalf("TableReplace: %v", err)
	}
	if n, err := p.TableCount("zmxtest"); err != nil || n != 2 {
		t.Errorf("TableCount = %d, %v; want 2", n, err)
	}
	if ents, err := p.TableEntries("zmxtest"); err != nil || len(ents) != 2 {
		t.Errorf("TableEntries = %v, %v", ents, err)
	}
	// Verify only reports drift if the main ruleset does not reference the
	// test anchor, which it will not; just check it does not blow up.
	t.Logf("Verify: %v", p.Verify())
}
