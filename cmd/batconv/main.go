// batconv converts Flowseal's winws *.bat strategy files into our TOML
// strategy schema.
//
// Usage:
//
//	batconv --in .upstream/bat --out strategies [--game-filter=off|tcp|udp|all]
//
// Every .bat in --in (except service.bat, which is the launcher, not a
// strategy) becomes one .toml in --out. An unmappable flag is a hard error:
// batconv prints the file, line and flag and exits non-zero, because a silently
// dropped flag is a silently weaker strategy.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "batconv: "+err.Error())
		os.Exit(1)
	}
}

func run() error {
	in := flag.String("in", ".upstream/bat", "directory holding the upstream winws *.bat files")
	out := flag.String("out", "strategies", "directory to write the generated *.toml into")
	gameFilter := flag.String("game-filter", "off",
		"expansion of %GameFilterTCP%/%GameFilterUDP%: off|tcp|udp|all (off = flowseal's dummy port 12)")
	listsDir := flag.String("lists", "lists", "hostlist/ipset directory, checked for dangling references (\"\" disables)")
	fakesDir := flag.String("fakes", "fakes", "fake blob directory, checked for dangling references (\"\" disables)")
	dry := flag.Bool("dry-run", false, "convert and report but do not write files")
	flag.Parse()

	gf, err := GameFilterFor(*gameFilter)
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(*in)
	if err != nil {
		return fmt.Errorf("reading --in: %w", err)
	}
	var bats []string
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".bat") {
			continue
		}
		// service.bat is the launcher/updater, not a strategy.
		if strings.EqualFold(e.Name(), "service.bat") {
			continue
		}
		bats = append(bats, e.Name())
	}
	if len(bats) == 0 {
		return fmt.Errorf("no *.bat found in %s", *in)
	}
	sort.Strings(bats)

	// Every generated file is compiled with the real loader so the summary's
	// ProxyCaps column is strategy.Strategy.Unsupported's own verdict. A
	// dry run compiles from a scratch directory and throws it away.
	dest := *out
	if *dry {
		tmp, err := os.MkdirTemp("", "batconv")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		dest = tmp
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}

	var results []*Result
	var warnings []string
	for _, name := range bats {
		src, err := os.ReadFile(filepath.Join(*in, name))
		if err != nil {
			return err
		}
		res, err := Convert(name, src, gf)
		if err != nil {
			return err
		}
		warnings = append(warnings, res.Warnings...)
		warnings = append(warnings, checkRefs(res, *listsDir, *fakesDir)...)
		dst := filepath.Join(dest, res.OutName)
		if err := os.WriteFile(dst, []byte(res.Marshal()), 0o644); err != nil {
			return err
		}
		// A file that does not compile is a conversion bug, so fail loudly
		// rather than shipping it.
		s, lerr := strategy.Load(dst, strategy.LoadOpts{
			ListsDir: *listsDir, FakesDir: *fakesDir, Caps: desync.FullCaps(),
		})
		if lerr != nil {
			return fmt.Errorf("%s does not compile: %w", res.OutName, lerr)
		}
		res.Unsupported = s.Unsupported(desync.ProxyCaps())
		results = append(results, res)
	}

	printSummary(os.Stdout, results, warnings, *gameFilter)
	return nil
}

// checkRefs warns about hostlist/ipset/fake names that do not exist on disk. A
// typo there produces a strategy that loads and then does nothing, so it is
// worth catching at conversion time.
func checkRefs(r *Result, listsDir, fakesDir string) []string {
	var out []string
	miss := func(dir, name, what string) {
		if dir == "" || name == "" || strings.HasPrefix(name, "0x") {
			return
		}
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			out = append(out, fmt.Sprintf("%s: %s %q not found in %s", r.Source, what, name, dir))
		}
	}
	for i := range r.File.Profiles {
		prof := &r.File.Profiles[i]
		f := &prof.Filter
		for _, n := range f.Hostlist {
			miss(listsDir, n, "hostlist")
		}
		for _, n := range f.HostlistExclude {
			miss(listsDir, n, "hostlist-exclude")
		}
		for _, n := range f.IPSet {
			miss(listsDir, n, "ipset")
		}
		for _, n := range f.IPSetExclude {
			miss(listsDir, n, "ipset-exclude")
		}
		for j := range prof.Ops {
			op := &prof.Ops[j]
			miss(fakesDir, op.SeqovlPattern, "seqovl-pattern")
			miss(fakesDir, op.Pattern, "fakedsplit-pattern")
			miss(fakesDir, op.UDPLenPattern, "udplen-pattern")
			miss(fakesDir, op.Fake.TLS, "fake-tls")
			miss(fakesDir, op.Fake.HTTP, "fake-http")
			miss(fakesDir, op.Fake.QUIC, "fake-quic")
			miss(fakesDir, op.Fake.SynData, "fake-syndata")
			for _, n := range op.Fake.Discord {
				miss(fakesDir, n, "fake-discord")
			}
			for _, n := range op.Fake.STUN {
				miss(fakesDir, n, "fake-stun")
			}
			for _, n := range op.Fake.UnknownUDP {
				miss(fakesDir, n, "fake-unknown-udp")
			}
		}
	}
	return out
}

// printSummary writes the strategy/profiles/ops/proxy-unsupported table.
func printSummary(w *os.File, results []*Result, warnings []string, gameFilter string) {
	type row struct{ strategy, profiles, ops, unsup string }
	rows := make([]row, 0, len(results))
	for _, r := range results {
		// strategy.Strategy.Unsupported prints "op (needs a, b)"; compact it so
		// the column stays narrow.
		var names []string
		for _, s := range r.Unsupported {
			names = append(names, strings.NewReplacer(" (needs ", "(", ", ", "+").Replace(s))
		}
		sort.Strings(names)
		unsup := strings.Join(names, " ")
		if unsup == "" {
			unsup = "-"
		}
		rows = append(rows, row{
			strategy: r.OutName,
			profiles: fmt.Sprint(len(r.File.Profiles)),
			ops:      strings.Join(r.Ops, ","),
			unsup:    unsup,
		})
	}

	hdr := row{"STRATEGY", "PROFILES", "OPS", "WILL NOT RUN UNDER ProxyCaps()"}
	wid := [4]int{len(hdr.strategy), len(hdr.profiles), len(hdr.ops), len(hdr.unsup)}
	for _, r := range rows {
		for i, v := range []string{r.strategy, r.profiles, r.ops, r.unsup} {
			if len(v) > wid[i] {
				wid[i] = len(v)
			}
		}
	}
	line := func(r row) {
		fmt.Fprintf(w, "%-*s  %*s  %-*s  %s\n",
			wid[0], r.strategy, wid[1], r.profiles, wid[2], r.ops, r.unsup)
	}
	fmt.Fprintf(w, "game filter: %s\n\n", gameFilter)
	line(hdr)
	fmt.Fprintf(w, "%s  %s  %s  %s\n",
		strings.Repeat("-", wid[0]), strings.Repeat("-", wid[1]),
		strings.Repeat("-", wid[2]), strings.Repeat("-", wid[3]))
	for _, r := range rows {
		line(r)
	}
	fmt.Fprintf(w, "\n%d strategies converted\n", len(results))

	if len(warnings) > 0 {
		fmt.Fprintf(w, "\n%d fidelity warning(s):\n", len(warnings))
		for _, s := range warnings {
			fmt.Fprintln(w, "  WARN "+s)
		}
	}
}
