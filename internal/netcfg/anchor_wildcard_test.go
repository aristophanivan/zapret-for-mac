package netcfg

import "testing"

// stockPfConf (declared in netcfg_test.go) is /etc/pf.conf as macOS ships it.
// Its com.apple anchor points are wildcards, which is exactly what makes the
// sub-anchor path possible.

// liveFilterRules / liveNatRules are what `pfctl -s rules` and `pfctl -s nat`
// print on that machine once pf is enabled.
const (
	liveFilterRules = `scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all
`
	liveNatRules = `nat-anchor "com.apple/*" all
rdr-anchor "com.apple/*" all
`
)

func TestWildcardAnchorCovers(t *testing.T) {
	tests := []struct {
		name string
		text string
		sub  string
		want bool
	}{
		{"stock pf.conf covers our sub-anchor", stockPfConf, "com.apple/zapret-mac", true},
		{"live filter ruleset covers it", liveFilterRules, "com.apple/zapret-mac", true},
		{"live nat ruleset covers it", liveNatRules, "com.apple/zapret-mac", true},
		{"a different namespace is not covered", stockPfConf, "org.example/zapret-mac", false},
		{"a top-level anchor is not covered", stockPfConf, "zapret-mac", false},
		// A non-wildcard statement naming the parent must NOT be treated as
		// covering children: pf only descends into sub-anchors for /*.
		{"exact anchor without /* does not cover children", `anchor "com.apple"`, "com.apple/zapret-mac", false},
		{"empty text", "", "com.apple/zapret-mac", false},
		{"commented out statement", `# anchor "com.apple/*"`, "com.apple/zapret-mac", false},
		{"nested wildcard covers a deeper path", `anchor "com.apple/x/*"`, "com.apple/x/zapret-mac", true},
		{"nested wildcard does not cover a sibling", `anchor "com.apple/x/*"`, "com.apple/y/zapret-mac", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WildcardAnchorCovers(tt.text, tt.sub); got != tt.want {
				t.Fatalf("WildcardAnchorCovers(%q) = %v, want %v", tt.sub, got, tt.want)
			}
		})
	}
}

// TestResolveAnchorForcesPfConfMode pins the escape hatch: with
// ForcePfConfAnchor the wildcard path is never taken, so the anchor stays
// top-level and /etc/pf.conf remains the mechanism.
func TestResolveAnchorForcesPfConfMode(t *testing.T) {
	p := NewPF("zapret-mac", PFOpts{
		PfConfPath:        "/nonexistent/pf.conf",
		ForcePfConfAnchor: true,
		DryRun:            true,
	})
	mode, err := p.ResolveAnchor()
	if err != nil {
		t.Fatalf("ResolveAnchor: %v", err)
	}
	if mode != AnchorModePfConf {
		t.Fatalf("mode = %q, want %q", mode, AnchorModePfConf)
	}
	if got := p.EffectiveAnchor(); got != "zapret-mac" {
		t.Fatalf("EffectiveAnchor = %q, want the plain anchor name", got)
	}
}

// TestAppleSubAnchorFor documents the exact path we borrow.
func TestAppleSubAnchorFor(t *testing.T) {
	if got := appleSubAnchorFor("zapret-mac"); got != "com.apple/zapret-mac" {
		t.Fatalf("appleSubAnchorFor = %q", got)
	}
}

// TestEffectiveAnchorDefaultsToPlainName guards the fallback: before
// ResolveAnchor runs, pfctl invocations must still target a valid anchor.
func TestEffectiveAnchorDefaultsToPlainName(t *testing.T) {
	p := NewPF("zapret-mac", PFOpts{DryRun: true})
	if got := p.EffectiveAnchor(); got != "zapret-mac" {
		t.Fatalf("EffectiveAnchor before resolve = %q, want zapret-mac", got)
	}
	if got := p.Mode(); got != AnchorModeUnresolved {
		t.Fatalf("Mode before resolve = %q, want unresolved", got)
	}
}
