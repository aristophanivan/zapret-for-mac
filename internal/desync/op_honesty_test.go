// This file holds the integration wave's honesty check: the guarantee that a
// strategy which cannot really run on the selected transport says so, instead of
// looking active and quietly doing nothing.
//
// The interesting case is --dpi-desync-split-seqovl on multisplit, because it is
// the one trick whose support is NOT decidable from the op alone:
//
//   - multisplitOp.Requires() is {Segment, DropOriginal}, and desync.ProxyCaps()
//     has both. So the engine's static Caps gate (engine.capsSatisfied, and the
//     Strategy.Unsupported list the CLI prints) lets multisplit through on the
//     socket-level transport — correctly, because a plain multisplit is just
//     send() boundaries and works fine there.
//   - The seqovl half needs Caps.Seq: it prepends bytes BELOW the window, which
//     means choosing a TCP sequence number. A byte-stream relay cannot.
//
// Op.Requires() cannot see OpParams, so the honesty has to be reported at
// runtime, on the Plan. This file pins that: under ProxyCaps the overlap is
// dropped AND announced in Plan.Degraded; under FullCaps it is actually emitted.
//
// It lives in the external test package so it can drive the real strategy
// loader (internal/strategy imports internal/desync).
package desync_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// honGeneralPath is the reference strategy: flowseal's "general", whose TLS
// profiles all carry multisplit with seqovl 681 / 568.
func honGeneralPath() string {
	return filepath.Join("..", "..", "strategies", "general.toml")
}

// honLoad compiles a strategy file under the given transport capabilities.
func honLoad(t *testing.T, path string, caps desync.Caps) *strategy.Strategy {
	t.Helper()
	s, err := strategy.Load(path, strategy.LoadOpts{
		ListsDir: filepath.Join("..", "..", "lists"),
		FakesDir: filepath.Join("..", "..", "fakes"),
		Caps:     caps,
	})
	if err != nil {
		t.Fatalf("Load(%s) under %+v: %v", path, caps, err)
	}
	return s
}

// honSeqovlOps returns every compiled op in s that configures a sequence
// overlap, tagged with the profile it came from.
type honOp struct {
	profile string
	co      strategy.CompiledOp
}

func honSeqovlOps(s *strategy.Strategy) []honOp {
	var out []honOp
	for _, p := range s.Profiles {
		for _, co := range p.Ops {
			if co.Params.Seqovl > 0 {
				out = append(out, honOp{profile: p.Name, co: co})
			}
		}
	}
	return out
}

// honSeqovlNote reports whether p carries the runtime note that a sequence
// overlap was dropped for want of Caps.Seq, and returns it for the message.
func honSeqovlNote(p *desync.Plan) (string, bool) {
	for _, d := range p.Degraded {
		if strings.Contains(d, "seqovl") && strings.Contains(d, "cannot choose TCP sequence numbers") {
			return d, true
		}
	}
	return "", false
}

// honBelowWindow returns the first segment sent below the current window, i.e.
// the one carrying the seqovl prefix.
func honBelowWindow(p *desync.Plan) (desync.Seg, bool) {
	for _, s := range p.Segs {
		if s.Kind == desync.SegData && s.SeqOff < 0 {
			return s, true
		}
	}
	return desync.Seg{}, false
}

// TestSeqovlIsDegradedUnderProxyCapsAndHonouredUnderFullCaps is the acceptance
// criterion of the integration wave, asserted on the shipped general.toml rather
// than on a hand-built profile.
func TestSeqovlIsDegradedUnderProxyCapsAndHonouredUnderFullCaps(t *testing.T) {
	path := honGeneralPath()
	hello := fuLoadHello(t)

	// The op set is a property of the file, not of the Caps it was compiled
	// with, so load once per Caps and check both agree on what is there.
	proxyOps := honSeqovlOps(honLoad(t, path, desync.ProxyCaps()))
	fullOps := honSeqovlOps(honLoad(t, path, desync.FullCaps()))
	if len(proxyOps) == 0 {
		t.Fatalf("general.toml carries no op with a sequence overlap; this test guards the wrong file")
	}
	if len(proxyOps) != len(fullOps) {
		t.Fatalf("general.toml compiled to %d seqovl ops under ProxyCaps but %d under FullCaps: "+
			"the loader must not silently drop ops", len(proxyOps), len(fullOps))
	}
	t.Logf("general.toml: %d compiled ops configure a sequence overlap", len(proxyOps))

	var checked int
	for i, po := range proxyOps {
		fo := fullOps[i]
		if po.co.Op.Name() != "multisplit" {
			// Other seqovl carriers (fakedsplit &c.) need Inject/Fooling, so the
			// static Caps gate already stops them on the proxy and the engine
			// reports them through Plan.Degraded. Nothing to prove at runtime.
			continue
		}
		checked++
		name := po.co.Op.Name()
		want := po.co.Params.Seqovl

		t.Run(po.profile, func(t *testing.T) {
			// The premise: ProxyCaps satisfies multisplit's static requirements,
			// so the engine calls Apply (not Degrade) and the runtime note is
			// the ONLY channel that can report the dropped overlap. If this ever
			// fails, the honesty moved to Strategy.Unsupported and the rest of
			// this test is checking a path the engine no longer takes.
			if u := honLoad(t, path, desync.ProxyCaps()).Unsupported(desync.ProxyCaps()); containsOp(u, name) {
				t.Fatalf("%s is now statically unsupported under ProxyCaps (%v); "+
					"the runtime seqovl note is no longer the honesty channel", name, u)
			}

			// --- proxy: the overlap must be dropped AND announced -------------
			pp := &desync.Plan{}
			applyHon(t, po.co, hello, desync.ProxyCaps(), pp)
			note, ok := honSeqovlNote(pp)
			if !ok {
				t.Errorf("%s with seqovl=%d under ProxyCaps: no note said the overlap was dropped; "+
					"Degraded=%v", name, want, pp.Degraded)
			} else {
				t.Logf("ProxyCaps note: %s", note)
			}
			if s, found := honBelowWindow(pp); found {
				t.Errorf("%s under ProxyCaps emitted a segment at SeqOff=%d (%d bytes): a byte-stream "+
					"relay cannot send below the window", name, s.SeqOff, len(s.Data))
			}
			if len(pp.Segs) == 0 {
				t.Errorf("%s under ProxyCaps produced no segments at all; the request would never be sent", name)
			}

			// --- divert: the overlap must actually be on the wire -------------
			fp := &desync.Plan{}
			applyHon(t, fo.co, hello, desync.FullCaps(), fp)
			if note, ok := honSeqovlNote(fp); ok {
				t.Errorf("%s with seqovl=%d under FullCaps reported %q, but the packet datapath "+
					"can choose sequence numbers", name, want, note)
			}
			seg, found := honBelowWindow(fp)
			if !found {
				t.Fatalf("%s with seqovl=%d under FullCaps emitted no below-window segment; Segs=%d",
					name, want, len(fp.Segs))
			}
			if got := int(-seg.SeqOff); got != want {
				t.Errorf("below-window segment starts %d bytes early, want the configured seqovl %d", got, want)
			}
			// The segment carries the overlap pattern followed by the real
			// bytes, so it is exactly seqovl longer than the part it stands for.
			if len(seg.Data) <= want {
				t.Errorf("below-window segment is %d bytes, must exceed the %d-byte overlap it prepends",
					len(seg.Data), want)
			}
			if tail := seg.Data[want:]; !strings.HasPrefix(string(hello), string(tail)) {
				t.Errorf("the bytes after the %d-byte overlap are not the head of the real payload", want)
			}
			t.Logf("FullCaps: %d segments, below-window seg SeqOff=%d len=%d (overlap %d + %d real)",
				len(fp.Segs), seg.SeqOff, len(seg.Data), want, len(seg.Data)-want)
		})
	}
	if checked == 0 {
		t.Fatalf("no multisplit op with a sequence overlap was exercised in %s", path)
	}
	t.Logf("%d multisplit ops with a sequence overlap checked under both Caps", checked)
}

// TestParamDegradationsReportSeqovlOnlyWhenSeqIsMissing pins the static, pre-run
// half of the same property: the list `zaprctl caps` prints under "these ops RUN
// but lose part of the trick". Strategy.Unsupported cannot carry this, because
// multisplit's Requires() is satisfied on both transports.
func TestParamDegradationsReportSeqovlOnlyWhenSeqIsMissing(t *testing.T) {
	path := honGeneralPath()

	proxy := honLoad(t, path, desync.ProxyCaps()).ParamDegradations(desync.ProxyCaps())
	if len(proxy) == 0 {
		t.Fatalf("under ProxyCaps, general.toml reported no parameter-level degradation, "+
			"but its multisplit ops configure a sequence overlap and Caps.Seq is %v",
			desync.ProxyCaps().Seq)
	}
	for _, line := range proxy {
		if !strings.Contains(line, "seqovl") || !strings.Contains(line, "needs seq") {
			t.Errorf("unexpected degradation line %q", line)
		}
		if !strings.HasPrefix(line, "multisplit:") {
			t.Errorf("line %q is not attributed to the op it belongs to", line)
		}
	}
	// general.toml uses two overlap sizes (681 for the google profiles, 568 for
	// the rest); each must be reported once, not once per profile.
	if len(proxy) != 2 {
		t.Errorf("got %d degradation lines, want one per distinct overlap size: %v", len(proxy), proxy)
	}
	t.Logf("ProxyCaps: %s", strings.Join(proxy, " | "))

	// The packet datapath can do all of it, so there must be nothing to report.
	if full := honLoad(t, path, desync.FullCaps()).ParamDegradations(desync.FullCaps()); len(full) != 0 {
		t.Errorf("under FullCaps, general.toml reported %v; the packet datapath honours seqovl", full)
	}

	// An op the static gate already stops must not be reported twice: it will not
	// run at all, so its parameters are moot. fake needs Inject, which ProxyCaps
	// lacks, and general.toml's fake ops carry no overlap — but the rule is what
	// matters, so assert no line names a statically unsupported op.
	s := honLoad(t, path, desync.ProxyCaps())
	unsup := s.Unsupported(desync.ProxyCaps())
	for _, line := range s.ParamDegradations(desync.ProxyCaps()) {
		op := strings.SplitN(line, ":", 2)[0]
		if containsOp(unsup, op) {
			t.Errorf("%q duplicates the statically unsupported op %q (%v)", line, op, unsup)
		}
	}
}

// applyHon runs one compiled op the way engine.run does when the static Caps
// gate is satisfied: Apply, with the op's own compiled params.
func applyHon(t *testing.T, co strategy.CompiledOp, payload []byte, caps desync.Caps, p *desync.Plan) {
	t.Helper()
	c := fuCtx(payload, caps, co.Params)
	if err := co.Op.Apply(c, p); err != nil {
		t.Fatalf("%s.Apply under %+v: %v", co.Op.Name(), caps, err)
	}
}

// containsOp reports whether any Strategy.Unsupported line is about op name.
// The lines read "name (needs cap, cap)".
func containsOp(lines []string, name string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, name+" (needs ") {
			return true
		}
	}
	return false
}
