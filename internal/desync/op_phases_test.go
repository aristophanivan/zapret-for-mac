package desync

import (
	"net/netip"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// This file tests how ops of different phases compose inside one profile, which
// is what engine.run does for a real strategy: it walks prof.Ops in phase order
// and hands every op the same Plan.
//
// The invariant under test is the one nfqws gets for free and our phase model
// has to enforce by hand: a PhaseFake op has to put the real payload into the
// plan itself (engine.run commits Plan.DropOriginal as soon as the plan is
// non-empty), and a PhaseSplit op running after it must *replace* that
// placeholder rather than add to it. Without that, `fake,multisplit` — the most
// common Flowseal recipe, present in 157 of the generated profiles' ops — sends
// the request twice.

// phaseFakeOps are the PhaseFake TCP ops that re-emit the payload themselves.
var phaseFakeOps = []string{"fake", "fakeknown", "rst", "rstack"}

// phaseSplitOps are the ops that own the payload's segmentation.
var phaseSplitOps = []string{"multisplit", "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit"}

// newUDPCtx is newCtx for a UDP flow, which the fake-selection code keys on via
// Flow.Key.Proto.
func newUDPCtx(t *testing.T, payload []byte, caps Caps, p OpParams) *Ctx {
	t.Helper()
	info := proto.Classify(payload, 443, proto.IPProtoUDP)
	return &Ctx{
		Flow: &Flow{Key: FlowKey{
			Proto: proto.IPProtoUDP,
			Dst:   netip.MustParseAddr("93.184.216.34"),
		}},
		Payload: payload,
		Info:    info,
		Caps:    caps,
		Params:  p,
	}
}

// countData totals the payload bytes the plan's data segments carry, ignoring
// the sub-window prefix of a sequence-overlapped segment.
func countData(t *testing.T, p *Plan, payload []byte) int {
	t.Helper()
	idx := segDataIdx(p)
	spans, ok := segSpans(p, idx, len(payload))
	if !ok {
		t.Fatalf("data segments do not tile the payload:\n%s", dumpSegs(p, payload))
	}
	n := 0
	for _, sp := range spans {
		n += sp.to - sp.from
	}
	return n
}

// TestSplitAfterFakeSendsThePayloadOnce is the regression test for the
// cross-agent integration bug: the split family used to append its segments to a
// plan that already held the PhaseFake ops' unsegmented placeholder.
func TestSplitAfterFakeSendsThePayloadOnce(t *testing.T) {
	hello := loadHello(t)
	prm := OpParams{
		Repeats:  2,
		TTL:      5,
		Fool:     FoolBadSum,
		SplitPos: []PosSpec{{Marker: proto.MarkerSNIExt, Offset: 1}},
	}

	for _, fakeName := range phaseFakeOps {
		for _, splitName := range phaseSplitOps {
			t.Run(fakeName+","+splitName, func(t *testing.T) {
				c := newCtx(t, hello, FullCaps(), prm)
				p := &Plan{}

				if err := mustOp(t, fakeName).Apply(c, p); err != nil {
					t.Fatalf("%s.Apply: %v", fakeName, err)
				}
				// The PhaseFake op alone must keep the payload in the plan.
				if got := countData(t, p, hello); got != len(hello) {
					t.Fatalf("%s alone planned %d payload bytes, want %d", fakeName, got, len(hello))
				}
				injected := 0
				for _, s := range p.Segs {
					if s.Kind != SegData {
						injected++
					}
				}
				if injected == 0 {
					t.Fatalf("%s injected nothing", fakeName)
				}

				if err := mustOp(t, splitName).Apply(c, p); err != nil {
					t.Fatalf("%s.Apply: %v", splitName, err)
				}

				// The payload is planned exactly once, and still reassembles.
				if got := countData(t, p, hello); got != len(hello) {
					t.Errorf("%s,%s planned %d payload bytes, want %d:\n%s",
						fakeName, splitName, got, len(hello), dumpSegs(p, hello))
				}
				checkReassembles(t, p, hello)

				// The decoys the PhaseFake op injected survive the takeover, and
				// still precede the real bytes: that ordering is the whole point.
				kept := 0
				firstData := len(p.Segs)
				for i, s := range p.Segs {
					if s.Kind == SegData {
						if i < firstData {
							firstData = i
						}
						continue
					}
					if i < firstData {
						kept++
					}
				}
				if kept < injected {
					t.Errorf("%s,%s: %d of %d injected segments no longer precede the payload:\n%s",
						fakeName, splitName, injected-kept, injected, dumpSegs(p, hello))
				}
			})
		}
	}
}

// TestSplitAfterFakeWithSeqovl repeats the check with the flagship Flowseal
// parameters (--dpi-desync-split-pos=1 --dpi-desync-split-seqovl=681), where the
// first data segment starts below the window and so has a negative SeqOff.
func TestSplitAfterFakeWithSeqovl(t *testing.T) {
	hello := loadHello(t)
	prm := OpParams{
		Repeats:       6,
		TTL:           5,
		SplitPos:      []PosSpec{{Marker: proto.MarkerAbs, Offset: 1}},
		Seqovl:        helloLen,
		SeqovlPattern: hello,
	}
	c := newCtx(t, hello, FullCaps(), prm)
	p := &Plan{}
	if err := mustOp(t, "fake").Apply(c, p); err != nil {
		t.Fatalf("fake.Apply: %v", err)
	}
	if err := mustOp(t, "multisplit").Apply(c, p); err != nil {
		t.Fatalf("multisplit.Apply: %v", err)
	}
	if got := countData(t, p, hello); got != len(hello) {
		t.Errorf("planned %d payload bytes, want %d:\n%s", got, len(hello), dumpSegs(p, hello))
	}
	checkReassembles(t, p, hello)

	// The overlapped segment must be the one that starts the payload.
	first := p.Segs[segDataIdx(p)[0]]
	if first.SeqOff != -int32(helloLen) {
		t.Errorf("first data segment SeqOff = %d, want %d", first.SeqOff, -helloLen)
	}
	if len(first.Data) != helloLen+1 {
		t.Errorf("first data segment carries %d bytes, want %d", len(first.Data), helloLen+1)
	}
}

// TestUDPFakeThenUDPLenSendsTheDatagramOnce is the UDP mirror: udplen replaces
// the datagram fake planted behind the decoys instead of adding a second copy.
func TestUDPFakeThenUDPLenSendsTheDatagramOnce(t *testing.T) {
	payload := loadHello(t) // any opaque UDP body works for udplen
	c := newUDPCtx(t, payload, FullCaps(), OpParams{Repeats: 3, TTL: 4, UDPLenIncrement: 2})
	p := &Plan{}
	if err := mustOp(t, "fake").Apply(c, p); err != nil {
		t.Fatalf("fake.Apply: %v", err)
	}
	if err := mustOp(t, "udplen").Apply(c, p); err != nil {
		t.Fatalf("udplen.Apply: %v", err)
	}
	data := 0
	for _, d := range p.Dgrams {
		if d.Kind == SegData {
			data++
		}
	}
	if data != 1 {
		t.Errorf("plan holds %d data datagrams, want 1", data)
	}
}

// TestModifyAfterFakeRewritesThePlaceholder checks the PhaseModify ops see the
// PhaseFake placeholder as the payload and rewrite it in place rather than
// appending a second copy.
func TestModifyAfterFakeRewritesThePlaceholder(t *testing.T) {
	hello := loadHello(t)
	for _, name := range []string{"tamper", "tlsrec", "ip_id"} {
		t.Run(name, func(t *testing.T) {
			c := newCtx(t, hello, FullCaps(), OpParams{TTL: 5, IPID: IPIDZero})
			p := &Plan{}
			if err := mustOp(t, "fake").Apply(c, p); err != nil {
				t.Fatalf("fake.Apply: %v", err)
			}
			before := len(p.Segs)
			if err := mustOp(t, name).Apply(c, p); err != nil {
				t.Fatalf("%s.Apply: %v", name, err)
			}
			data := 0
			for _, s := range p.Segs {
				if s.Kind == SegData {
					data++
				}
			}
			if data != 1 {
				t.Errorf("%s left %d data segments, want 1:\n%s", name, data, dumpSegs(p, hello))
			}
			if len(p.Segs) != before {
				t.Errorf("%s changed the segment count from %d to %d", name, before, len(p.Segs))
			}
		})
	}
}

// TestCancelledSeqovlStillShipsThePayload covers the faked-split rollback path.
// Upstream reaches send_orig when the overlapped segment does not fit its
// buffers; because engine.run has already committed DropOriginal for the decoys
// an earlier op injected, the op has to put the unsegmented payload back.
func TestCancelledSeqovlStillShipsThePayload(t *testing.T) {
	hello := loadHello(t)
	for _, name := range []string{"fakedsplit", "fakeddisorder"} {
		t.Run(name, func(t *testing.T) {
			c := newCtx(t, hello, FullCaps(), OpParams{
				TTL:      5,
				SplitPos: []PosSpec{{Marker: proto.MarkerAbs, Offset: helloLen - 1}},
				// Far beyond segMaxSegLen, so the overlap cannot be built.
				Seqovl: segMaxSegLen + 1,
			})
			p := &Plan{}
			if err := mustOp(t, "fake").Apply(c, p); err != nil {
				t.Fatalf("fake.Apply: %v", err)
			}
			if err := mustOp(t, name).Apply(c, p); err != nil {
				t.Fatalf("%s.Apply: %v", name, err)
			}
			if got := countData(t, p, hello); got != len(hello) {
				t.Errorf("%s cancelled the split and planned %d payload bytes, want %d:\n%s",
					name, got, len(hello), dumpSegs(p, hello))
			}
			checkReassembles(t, p, hello)
		})
	}
}

// TestDegradeAfterFakeSendsThePayloadOnce is the ProxyCaps mirror: an op whose
// Degrade path runs must also take over the payload rather than add to it.
func TestDegradeAfterFakeSendsThePayloadOnce(t *testing.T) {
	hello := loadHello(t)
	for _, name := range phaseSplitOps {
		t.Run(name, func(t *testing.T) {
			o := mustOp(t, name)
			d, ok := o.(Degrader)
			if !ok {
				t.Skipf("%s has no Degrade", name)
			}
			c := newCtx(t, hello, ProxyCaps(), OpParams{
				SplitPos: []PosSpec{{Marker: proto.MarkerSNIExt, Offset: 1}},
			})
			// Hand-built hostile state: a decoy plus the unsegmented placeholder.
			p := &Plan{Segs: []Seg{
				{Kind: SegFake, Data: []byte("decoy")},
				{Kind: SegData, Data: hello},
			}}
			if err := d.Degrade(c, p); err != nil {
				t.Fatalf("%s.Degrade: %v", name, err)
			}
			if got := countData(t, p, hello); got != len(hello) {
				t.Errorf("%s.Degrade planned %d payload bytes, want %d:\n%s",
					name, got, len(hello), dumpSegs(p, hello))
			}
			checkReassembles(t, p, hello)
			for i, s := range p.Segs {
				if s.Kind != SegData {
					t.Errorf("seg %d survived Degrade with kind %d", i, s.Kind)
				}
			}
		})
	}
}
