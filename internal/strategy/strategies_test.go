package strategy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
)

// This file is the wave-2 acceptance test: every strategy file batconv generated
// from flowseal's *.bat must compile through the real loader, against the real
// lists and the real fake blobs, with the divert transport's capabilities.
//
// It is deliberately an end-to-end check of four separate agents' work at once —
// the .bat converter, the TOML schema, the loader, and every op's registration
// and parameter validation. A strategy that does not load here is a strategy the
// daemon cannot run.

// strategiesDir is where batconv writes its output. The lists and fakes
// directories come from load_test.go's repoLists/repoFakes, and the divert
// transport's LoadOpts from its fullOpts().
const (
	strategiesDir = "../../strategies"

	// minFlowsealProfiles is the smallest profile chain flowseal ships. Its
	// general.bat family has 9 (--new-separated) sections; general (ALT5).bat is
	// the one outlier at 6. Anything below 7 for a flowseal-derived strategy
	// means profiles were silently dropped during conversion, so the threshold
	// is set at 7 and the two known 6-profile files are listed explicitly.
	minFlowsealProfiles = 7
)

// shortChains are the strategies that genuinely have fewer than
// minFlowsealProfiles sections upstream.
var shortChains = map[string]int{
	"general-alt5": 6,
}

// strategyFiles lists every *.toml in the strategies directory.
func strategyFiles(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(strategiesDir, "*.toml"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("no strategy files under %s", strategiesDir)
	}
	sort.Strings(paths)
	return paths
}

// TestGeneratedStrategiesLoad is the acceptance test proper.
func TestGeneratedStrategiesLoad(t *testing.T) {
	paths := strategyFiles(t)
	t.Logf("loading %d strategy files from %s", len(paths), strategiesDir)

	var (
		totalProfiles int
		totalOps      int
		loaded        int
		lines         []string
	)

	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".toml")
		t.Run(name, func(t *testing.T) {
			s, err := Load(path, fullOpts())
			if err != nil {
				t.Fatalf("Load(%s): %v", path, err)
			}
			if s == nil {
				t.Fatalf("Load(%s) returned nil without an error", path)
			}

			// --- profile count ---
			want := minFlowsealProfiles
			if n, ok := shortChains[name]; ok {
				want = n
			}
			if len(s.Profiles) < want {
				t.Errorf("%s has %d profiles, want at least %d", name, len(s.Profiles), want)
			}

			// --- every profile is executable ---
			ops := 0
			for i, p := range s.Profiles {
				if p.Name == "" {
					t.Errorf("%s profile %d has no name", name, i)
				}
				if len(p.Ops) == 0 {
					t.Errorf("%s profile %q compiled to zero ops", name, p.Name)
				}
				for j, co := range p.Ops {
					if co.Op == nil {
						t.Fatalf("%s profile %q op %d is nil", name, p.Name, j)
					}
					ops++
				}
				// engine.run walks Ops in slice order, so the loader must have
				// sorted them by phase: an ip_id or wssize that runs before the
				// segmentation op it is meant to tag would silently do nothing.
				for j := 1; j < len(p.Ops); j++ {
					if p.Ops[j-1].Op.Phase() > p.Ops[j].Op.Phase() {
						t.Errorf("%s profile %q: op %s (phase %d) precedes %s (phase %d)",
							name, p.Name,
							p.Ops[j-1].Op.Name(), p.Ops[j-1].Op.Phase(),
							p.Ops[j].Op.Name(), p.Ops[j].Op.Phase())
					}
				}
			}

			// --- the port window must exist: it is what pf steers ---
			if len(s.WindowTCP) == 0 && len(s.WindowUDP) == 0 {
				t.Errorf("%s declares no port window", name)
			}

			// --- no profile may compile to a match-everything exclude set ---
			//
			// This guards a live wave-1 hazard rather than a hypothetical one.
			// lists.HostSet.LoadFile sets Any=true whenever *one* merged file
			// parses to zero entries, and flowseal ships a comment-only
			// lists/list-exclude-user.txt that nearly every profile names in
			// hostlist_exclude. Merged naively, the exclude set matches every
			// host and the profile silently never fires. The loader dodges it by
			// dropping entry-less files before merging; if that ever regresses,
			// or if lists is fixed and the workaround removed carelessly, the
			// strategies stop working with no other symptom.
			for _, p := range s.Profiles {
				if ex := p.Filter.HostlistExclude; ex != nil && ex.Any {
					t.Errorf("%s profile %q: hostlist_exclude matches every host, so the "+
						"profile can never fire", name, p.Name)
				}
				if ex := p.Filter.IPSetExclude; ex != nil && ex.Any {
					t.Errorf("%s profile %q: ipset_exclude matches every address, so the "+
						"profile can never fire", name, p.Name)
				}
				if hl := p.Filter.Hostlist; hl != nil && hl.Any && len(hl.Files) > 0 {
					t.Errorf("%s profile %q: hostlist matches every host despite naming "+
						"%d files", name, p.Name, len(hl.Files))
				}
			}

			// --- Caps honesty ---
			if bad := s.Unsupported(desync.FullCaps()); len(bad) != 0 {
				t.Errorf("%s cannot run on the divert transport, which should support "+
					"everything: %v", name, bad)
			}
			unsup := s.Unsupported(desync.ProxyCaps())
			if usesInjection(s) && len(unsup) == 0 {
				t.Errorf("%s uses an injection op but reports nothing unsupported under "+
					"ProxyCaps — the Caps honesty system is not working", name)
			}

			totalProfiles += len(s.Profiles)
			totalOps += ops
			loaded++
			lines = append(lines, fmt.Sprintf("%-34s %2d profiles %3d ops  %-38s  proxy-cannot-run: %s",
				name, len(s.Profiles), ops, strings.Join(opNamesOf(s), ","), joinOr(unsup, "-")))
		})
	}

	t.Logf("\n%s", strings.Join(lines, "\n"))
	t.Logf("loaded %d/%d strategies, %d profiles, %d compiled ops",
		loaded, len(paths), totalProfiles, totalOps)
	t.Logf("registered desync ops (%d): %s",
		len(desync.Names()), strings.Join(desync.Names(), ", "))
}

// usesInjection reports whether the strategy contains an op that needs the
// packet-level transport, i.e. one whose Requires() asks for something
// desync.ProxyCaps() does not have.
func usesInjection(s *Strategy) bool {
	for _, p := range s.Profiles {
		for _, co := range p.Ops {
			if _, ok := capsMissing(desync.ProxyCaps(), co.Op.Requires()); !ok {
				return true
			}
		}
	}
	return false
}

func opNamesOf(s *Strategy) []string { return s.opNames() }

func joinOr(v []string, alt string) string {
	if len(v) == 0 {
		return alt
	}
	return strings.Join(v, "; ")
}

// TestGeneratedStrategiesUseFakeOrSeqovlAndAreHonest is the explicit form of the
// acceptance criterion: a strategy that relies on injected decoys or on a
// sub-window sequence overlap must announce that the proxy transport cannot run
// it. Both tricks need capabilities a byte-stream relay does not have, so
// silently accepting them would mean shipping a strategy that looks active and
// does nothing.
func TestGeneratedStrategiesUseFakeOrSeqovlAndAreHonest(t *testing.T) {
	var withFake, withSeqovl int
	for _, path := range strategyFiles(t) {
		name := strings.TrimSuffix(filepath.Base(path), ".toml")
		s, err := Load(path, fullOpts())
		if err != nil {
			t.Fatalf("Load(%s): %v", path, err)
		}

		fake, seqovl := false, false
		for _, p := range s.Profiles {
			for _, co := range p.Ops {
				switch co.Op.Name() {
				case "fake", "fakeknown", "rst", "rstack", "syndata",
					"fakedsplit", "fakeddisorder", "hostfakesplit":
					fake = true
				}
				if co.Params.Seqovl > 0 {
					seqovl = true
				}
			}
		}
		if fake {
			withFake++
		}
		if seqovl {
			withSeqovl++
		}

		unsup := s.Unsupported(desync.ProxyCaps())
		if fake && len(unsup) == 0 {
			t.Errorf("%s uses a fake/injection op but Unsupported(ProxyCaps) is empty", name)
		}
		if seqovl && !seqovlIsDropped(t, s) {
			t.Errorf("%s configures a sequence overlap that the proxy transport would "+
				"silently ignore without a note", name)
		}
	}
	t.Logf("%d strategies use an injection op, %d configure a sequence overlap", withFake, withSeqovl)
}

// seqovlIsDropped verifies that the ops carrying a positive Seqovl either need a
// capability ProxyCaps lacks (so the engine reports them as degraded before they
// run) or are a multisplit, which keeps running on the proxy and drops the
// overlap at runtime with a Plan.Degraded note.
func seqovlIsDropped(t *testing.T, s *Strategy) bool {
	t.Helper()
	for _, p := range s.Profiles {
		for _, co := range p.Ops {
			if co.Params.Seqovl <= 0 {
				continue
			}
			if _, ok := capsMissing(desync.ProxyCaps(), co.Op.Requires()); !ok {
				continue // gated off by Caps: honest
			}
			// Still runs on the proxy: it must be an op that reports the drop.
			// multisplit does, via segSeqovlNote.
			if co.Op.Name() != "multisplit" {
				return false
			}
		}
	}
	return true
}

// TestLoadDirLoadsEveryStrategy checks the directory loader agrees with the
// per-file loader and orders strategies the way flowseal's menu does (ALT2 before
// ALT10, i.e. numerically rather than lexically).
func TestLoadDirLoadsEveryStrategy(t *testing.T) {
	all, err := LoadDir(strategiesDir, fullOpts())
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if got, want := len(all), len(strategyFiles(t)); got != want {
		t.Fatalf("LoadDir returned %d strategies, want %d", got, want)
	}

	var names []string
	for _, s := range all {
		names = append(names, s.Name)
	}
	t.Logf("LoadDir order: %s", strings.Join(names, " < "))

	idx := func(n string) int {
		for i, s := range all {
			if s.Name == n {
				return i
			}
		}
		t.Fatalf("strategy %q missing from LoadDir", n)
		return -1
	}

	// The one ordering property flowseal's menu actually depends on: digit runs
	// are compared numerically, so ALT2 comes before ALT10 rather than after it.
	//
	// Where the bare "general" lands is NOT asserted. nameSortKey sorts over the
	// whole file name, so "general-alt.toml" < "general.toml" ('-' < '.') and the
	// base strategy ends up last. That matches upstream on upstream's own names —
	// service.bat sorts $_.Name, and "general (ALT).bat" < "general.bat" because
	// space sorts before period — so it is faithful, not a regression.
	for _, pair := range [][2]string{
		{"general-alt2", "general-alt10"},
		{"general-alt9", "general-alt10"},
		{"general-fake-tls-auto-alt2", "general-fake-tls-auto-alt3"},
	} {
		if a, b := idx(pair[0]), idx(pair[1]); a > b {
			t.Errorf("%s sorted after %s (%d > %d): digit runs are not compared numerically",
				pair[0], pair[1], a, b)
		}
	}

	// Names are unique and the order is deterministic: the CLI presents this list
	// as a numbered menu, so a reshuffle between runs would change what a saved
	// choice means.
	seen := make(map[string]bool, len(all))
	for _, s := range all {
		if seen[s.Name] {
			t.Errorf("duplicate strategy name %q", s.Name)
		}
		seen[s.Name] = true
	}
	again, err := LoadDir(strategiesDir, fullOpts())
	if err != nil {
		t.Fatalf("second LoadDir: %v", err)
	}
	for i := range again {
		if again[i].Name != all[i].Name {
			t.Fatalf("LoadDir is not deterministic: position %d was %q, now %q",
				i, all[i].Name, again[i].Name)
		}
	}
}

// TestStrategiesLoadWithoutCapsCheck makes sure a strategy can be inspected with
// no transport chosen, which is what `zaprctl list` does.
func TestStrategiesLoadWithoutCapsCheck(t *testing.T) {
	for _, path := range strategyFiles(t) {
		s, err := Load(path, LoadOpts{ListsDir: repoLists, FakesDir: repoFakes})
		if err != nil {
			t.Fatalf("Load(%s) without Caps: %v", path, err)
		}
		if s.Summary() == "" {
			t.Errorf("%s has an empty Summary()", path)
		}
	}
}

// TestStrategiesDirHasNoStrayFiles guards against a half-finished batconv run
// leaving a non-TOML file behind, which the daemon's LoadDir would ignore
// silently.
func TestStrategiesDirHasNoStrayFiles(t *testing.T) {
	ents, err := os.ReadDir(strategiesDir)
	if err != nil {
		t.Fatalf("read %s: %v", strategiesDir, err)
	}
	for _, e := range ents {
		if e.IsDir() {
			t.Errorf("unexpected directory %s in %s", e.Name(), strategiesDir)
			continue
		}
		if filepath.Ext(e.Name()) != ".toml" {
			t.Errorf("unexpected non-TOML file %s in %s", e.Name(), strategiesDir)
		}
	}
}
