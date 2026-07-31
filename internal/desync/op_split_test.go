package desync

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// The google ClientHello is the same blob Flowseal ships as
// tls_clienthello_www_google_com.bin; every offset asserted below was taken
// from it with internal/proto and is stable because the file is a fixture.
const (
	helloLen     = 681 // whole record
	helloHost    = 125 // "www.google.com"
	helloHostLen = 14
	helloEndHost = helloHost + helloHostLen // 139
	helloSLD     = 129                      // "google"
	helloMidSLD  = 132
	helloSNIExt1 = 117 // sniext+1
)

func loadHello(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "fakes", "tls_clienthello_www_google_com.bin"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if len(b) != helloLen {
		t.Fatalf("fixture changed: got %d bytes, want %d", len(b), helloLen)
	}
	return b
}

// newCtx builds the synthetic Ctx the ops see: a parsed payload, a transport's
// capabilities and one op's parameters.
func newCtx(t *testing.T, payload []byte, caps Caps, p OpParams) *Ctx {
	t.Helper()
	info := proto.Classify(payload, 443, proto.IPProtoTCP)
	return &Ctx{
		Flow:    &Flow{},
		Payload: payload,
		Info:    info,
		Caps:    caps,
		Params:  p,
	}
}

func mustOp(t *testing.T, name string) Op {
	t.Helper()
	o, err := Lookup(name)
	if err != nil {
		t.Fatalf("Lookup(%q): %v", name, err)
	}
	return o
}

func apply(t *testing.T, name string, c *Ctx) *Plan {
	t.Helper()
	p := &Plan{}
	if err := mustOp(t, name).Apply(c, p); err != nil {
		t.Fatalf("%s.Apply: %v", name, err)
	}
	return p
}

func degrade(t *testing.T, name string, c *Ctx) *Plan {
	t.Helper()
	o := mustOp(t, name)
	d, ok := o.(Degrader)
	if !ok {
		t.Fatalf("%s does not implement Degrader", name)
	}
	p := &Plan{}
	if err := d.Degrade(c, p); err != nil {
		t.Fatalf("%s.Degrade: %v", name, err)
	}
	return p
}

// want is one expected segment.
type want struct {
	kind   SegKind
	seqOff int32
	// from/to describe the expected Data as payload[from:to]; when prefix > 0 the
	// segment additionally starts with prefix bytes that are not payload.
	from, to int
	prefix   int
	fake     bool // Data is pattern/fake bytes, only the length is checked
}

func checkSegs(t *testing.T, p *Plan, payload []byte, wants []want) {
	t.Helper()
	if len(p.Segs) != len(wants) {
		t.Fatalf("got %d segments, want %d\n%s", len(p.Segs), len(wants), dumpSegs(p, payload))
	}
	for i, w := range wants {
		s := p.Segs[i]
		if s.Kind != w.kind {
			t.Errorf("seg %d: kind %d, want %d", i, s.Kind, w.kind)
		}
		if s.SeqOff != w.seqOff {
			t.Errorf("seg %d: SeqOff %d, want %d", i, s.SeqOff, w.seqOff)
		}
		wantLen := w.prefix + w.to - w.from
		if len(s.Data) != wantLen {
			t.Errorf("seg %d: %d data bytes, want %d", i, len(s.Data), wantLen)
			continue
		}
		if w.fake {
			continue
		}
		if !bytes.Equal(s.Data[w.prefix:], payload[w.from:w.to]) {
			t.Errorf("seg %d: data is not payload[%d:%d]", i, w.from, w.to)
		}
	}
	if t.Failed() {
		t.Logf("plan:\n%s", dumpSegs(p, payload))
	}
}

func dumpSegs(p *Plan, payload []byte) string {
	var sb strings.Builder
	for i, s := range p.Segs {
		fmt.Fprintf(&sb, "  [%d] kind=%d seqOff=%d len=%d ttl=%d repeats=%d\n",
			i, s.Kind, s.SeqOff, len(s.Data), s.TTL, s.Repeats)
	}
	if len(p.Degraded) > 0 {
		fmt.Fprintf(&sb, "  degraded: %v\n", p.Degraded)
	}
	_ = payload
	return sb.String()
}

// checkReassembles is the invariant every segmentation op must satisfy: the data
// segments, taken in ascending payload order, are exactly the original payload.
func checkReassembles(t *testing.T, p *Plan, payload []byte) {
	t.Helper()
	idx := segDataIdx(p)
	got, ok := segJoinData(p, idx, len(payload))
	if !ok {
		t.Fatalf("data segments do not tile the payload:\n%s", dumpSegs(p, payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("reassembled payload differs from the original")
	}
}

// ---------- registration ----------

func TestRegistrationAndAliases(t *testing.T) {
	for name, want := range map[string]string{
		"multisplit":    "multisplit",
		"split2":        "multisplit",
		"multidisorder": "multidisorder",
		"disorder2":     "multidisorder",
		"fakedsplit":    "fakedsplit",
		"split":         "fakedsplit",
		"fakeddisorder": "fakeddisorder",
		"disorder":      "fakeddisorder",
		"hostfakesplit": "hostfakesplit",
		"tamper":        "tamper",
		"tlsrec":        "tlsrec",
		"wssize":        "wssize",
		"ip_id":         "ip_id",
	} {
		o := mustOp(t, name)
		if o.Name() != want {
			t.Errorf("Lookup(%q).Name() = %q, want %q", name, o.Name(), want)
		}
	}
	phases := map[string]Phase{
		"multisplit": PhaseSplit, "multidisorder": PhaseSplit, "fakedsplit": PhaseSplit,
		"fakeddisorder": PhaseSplit, "hostfakesplit": PhaseSplit,
		"tamper": PhaseModify, "tlsrec": PhaseModify, "wssize": PhaseModify, "ip_id": PhaseModify,
	}
	for name, ph := range phases {
		if got := mustOp(t, name).Phase(); got != ph {
			t.Errorf("%s.Phase() = %d, want %d", name, got, ph)
		}
	}
}

// ---------- position resolution ----------

func TestResolveMultiPosSortsDedupesAndDrops(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{})
	specs := []PosSpec{
		{Marker: proto.MarkerMidSLD},                  // 132
		{Marker: proto.MarkerSNIExt, Offset: 1},       // 117
		{Marker: proto.MarkerAbs, Offset: 2},          // 2
		{Marker: proto.MarkerMidSLD},                  // duplicate 132
		{Marker: proto.MarkerMethod, Offset: 2},       // absent in TLS -> dropped
		{Marker: proto.MarkerAbs, Offset: helloLen},   // == len -> dropped
		{Marker: proto.MarkerAbs, Offset: -helloLen},  // clamps to 0 -> dropped
		{Marker: proto.MarkerEndHost, Offset: 100000}, // out of range -> dropped
	}
	got := segResolveMultiPos(c, specs)
	wantPos := []int{2, helloSNIExt1, helloMidSLD}
	if len(got) != len(wantPos) {
		t.Fatalf("got %v, want %v", got, wantPos)
	}
	for i := range wantPos {
		if got[i] != wantPos[i] {
			t.Fatalf("got %v, want %v", got, wantPos)
		}
	}
}

func TestDefaultSplitPosIsAbsTwo(t *testing.T) {
	d := DefaultSplitPos()
	if len(d) != 1 || d[0].Marker != proto.MarkerAbs || d[0].Offset != 2 {
		t.Fatalf("DefaultSplitPos() = %+v, want one abs+2 entry", d)
	}
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{})
	p := apply(t, "multisplit", c)
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: 0, from: 0, to: 2},
		{kind: SegData, seqOff: 2, from: 2, to: helloLen},
	})
	checkReassembles(t, p, hello)
}

// ---------- multisplit ----------

func TestMultisplitMarkerPositions(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{SplitPos: []PosSpec{
		{Marker: proto.MarkerMidSLD},
		{Marker: proto.MarkerSNIExt, Offset: 1},
		{Marker: proto.MarkerHost},
	}})
	p := apply(t, "multisplit", c)
	if !p.DropOriginal {
		t.Error("multisplit must drop the original packet")
	}
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: 0, from: 0, to: helloSNIExt1},
		{kind: SegData, seqOff: helloSNIExt1, from: helloSNIExt1, to: helloHost},
		{kind: SegData, seqOff: helloHost, from: helloHost, to: helloMidSLD},
		{kind: SegData, seqOff: helloMidSLD, from: helloMidSLD, to: helloLen},
	})
	checkReassembles(t, p, hello)
	// The cuts really land inside the SNI hostname: host..midsld is the first
	// half of "www.google.com" up to the middle of the second-level domain.
	if got := hello[helloHost:helloMidSLD]; !bytes.Equal(got, []byte("www.goo")) {
		t.Errorf("host..midsld = %q, want %q", got, "www.goo")
	}
	if got := hello[helloSLD : helloSLD+6]; !bytes.Equal(got, []byte("google")) {
		t.Errorf("sld = %q, want %q", got, "google")
	}
}

// TestMultisplitSeqovlGooglePattern is the Flowseal combination
// --dpi-desync=multisplit --dpi-desync-split-pos=1 --dpi-desync-split-seqovl=681
// --dpi-desync-split-seqovl-pattern=tls_clienthello_www_google_com.bin.
func TestMultisplitSeqovlGooglePattern(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{
		SplitPos:      []PosSpec{{Marker: proto.MarkerAbs, Offset: 1}},
		Seqovl:        helloLen,
		SeqovlPattern: hello,
	})
	p := apply(t, "multisplit", c)
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: -helloLen, from: 0, to: 1, prefix: helloLen},
		{kind: SegData, seqOff: 1, from: 1, to: helloLen},
	})
	if len(p.Degraded) != 0 {
		t.Errorf("unexpected degradation: %v", p.Degraded)
	}
	// The overlap prefix is the pattern, verbatim, and the real byte follows it.
	if !bytes.Equal(p.Segs[0].Data[:helloLen], hello) {
		t.Error("seqovl prefix is not the configured pattern")
	}
	if p.Segs[0].Data[helloLen] != hello[0] {
		t.Error("seqovl segment does not continue with the real payload")
	}
	checkReassembles(t, p, hello)
}

func TestMultisplitSeqovlPatternRepeatsAndZeroFills(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{
		SplitPos:      []PosSpec{{Marker: proto.MarkerAbs, Offset: 4}},
		Seqovl:        10,
		SeqovlPattern: []byte("abc"),
	})
	p := apply(t, "multisplit", c)
	if got := p.Segs[0].Data[:10]; !bytes.Equal(got, []byte("abcabcabca")) {
		t.Errorf("repeated pattern = %q, want %q", got, "abcabcabca")
	}
	// An empty pattern is zapret's default: zero bytes.
	c = newCtx(t, hello, FullCaps(), OpParams{
		SplitPos: []PosSpec{{Marker: proto.MarkerAbs, Offset: 4}},
		Seqovl:   5,
	})
	p = apply(t, "multisplit", c)
	if got := p.Segs[0].Data[:5]; !bytes.Equal(got, make([]byte, 5)) {
		t.Errorf("default pattern = % x, want zeroes", got)
	}
	if p.Segs[0].SeqOff != -5 {
		t.Errorf("SeqOff = %d, want -5", p.Segs[0].SeqOff)
	}
}

// zapret only requires seqovl < split_pos for the *disorder* modes; for
// multisplit an overlap larger than the first part is legal and is exactly what
// the seqovl=681/pos=1 recipe does.
func TestMultisplitSeqovlLargerThanSplitPosIsKept(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{
		SplitPos:      []PosSpec{{Marker: proto.MarkerAbs, Offset: 2}},
		Seqovl:        helloLen,
		SeqovlPattern: hello,
	})
	p := apply(t, "multisplit", c)
	if p.Segs[0].SeqOff != -helloLen {
		t.Fatalf("SeqOff = %d, want %d", p.Segs[0].SeqOff, -helloLen)
	}
	if len(p.Degraded) != 0 {
		t.Fatalf("multisplit must not degrade a large seqovl: %v", p.Degraded)
	}
}

func TestMultisplitSeqovlDroppedWithoutSeqCap(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, ProxyCaps(), OpParams{
		SplitPos:      []PosSpec{{Marker: proto.MarkerAbs, Offset: 2}},
		Seqovl:        helloLen,
		SeqovlPattern: hello,
	})
	p := apply(t, "multisplit", c)
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: 0, from: 0, to: 2},
		{kind: SegData, seqOff: 2, from: 2, to: helloLen},
	})
	if len(p.Degraded) != 1 || !strings.Contains(p.Degraded[0], "seqovl") {
		t.Errorf("Degraded = %v, want a seqovl note", p.Degraded)
	}
	checkReassembles(t, p, hello)
}

func TestMultisplitNoUsablePositionForwardsOriginal(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{SplitPos: []PosSpec{
		{Marker: proto.MarkerMethod, Offset: 2}, // HTTP-only marker on a TLS payload
	}})
	p := apply(t, "multisplit", c)
	if len(p.Segs) != 0 || p.DropOriginal {
		t.Fatalf("expected an empty plan, got %d segs (drop=%v)", len(p.Segs), p.DropOriginal)
	}
}

func TestMultisplitCapsAndIPID(t *testing.T) {
	if r := mustOp(t, "multisplit").Requires(); !r.Segment || !r.DropOriginal || r.Seq || r.Inject {
		t.Errorf("multisplit.Requires() = %+v", r)
	}
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{
		SplitPos: []PosSpec{{Marker: proto.MarkerAbs, Offset: 2}},
		IPID:     IPIDRandom,
	})
	p := apply(t, "multisplit", c)
	for i, s := range p.Segs {
		if s.IPID != IPIDRandom {
			t.Errorf("seg %d: IPID = %d, want %d", i, s.IPID, IPIDRandom)
		}
	}
}

// ---------- multidisorder ----------

func TestMultidisorderReversesOrder(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{SplitPos: []PosSpec{
		{Marker: proto.MarkerSNIExt, Offset: 1},
		{Marker: proto.MarkerMidSLD},
	}})
	p := apply(t, "multidisorder", c)
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: helloMidSLD, from: helloMidSLD, to: helloLen},
		{kind: SegData, seqOff: helloSNIExt1, from: helloSNIExt1, to: helloMidSLD},
		{kind: SegData, seqOff: 0, from: 0, to: helloSNIExt1},
	})
	checkReassembles(t, p, hello)
}

func TestMultidisorderSeqovlOnSecondPart(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{
		SplitPos:      []PosSpec{{Marker: proto.MarkerAbs, Offset: 100}, {Marker: proto.MarkerMidSLD}},
		Seqovl:        8,
		SeqovlPattern: []byte{0xde, 0xad},
	})
	p := apply(t, "multidisorder", c)
	// Transmit order: [132,681), [100,132) with the overlap, [0,100).
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: helloMidSLD, from: helloMidSLD, to: helloLen},
		{kind: SegData, seqOff: 100 - 8, from: 100, to: helloMidSLD, prefix: 8},
		{kind: SegData, seqOff: 0, from: 0, to: 100},
	})
	if got := p.Segs[1].Data[:8]; !bytes.Equal(got, bytes.Repeat([]byte{0xde, 0xad}, 4)) {
		t.Errorf("overlap prefix = % x", got)
	}
	checkReassembles(t, p, hello)
}

func TestMultidisorderSeqovlCancelledAtOrAboveSplitPos(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{
		SplitPos: []PosSpec{{Marker: proto.MarkerAbs, Offset: 8}},
		Seqovl:   8, // seqovl >= split pos -> upstream cancels the overlap
	})
	p := apply(t, "multidisorder", c)
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: 8, from: 8, to: helloLen},
		{kind: SegData, seqOff: 0, from: 0, to: 8},
	})
	if len(p.Degraded) != 1 || !strings.Contains(p.Degraded[0], "cancelled") {
		t.Errorf("Degraded = %v, want a cancellation note", p.Degraded)
	}
	checkReassembles(t, p, hello)
}

func TestMultidisorderRequiresSeq(t *testing.T) {
	if r := mustOp(t, "multidisorder").Requires(); !r.Seq || !r.Segment || !r.DropOriginal {
		t.Errorf("multidisorder.Requires() = %+v, want Seq+Segment+DropOriginal", r)
	}
}

// ---------- fakedsplit ----------

// fakedsplitWants is the expected plan for one altorder, with the split at
// midsld: F1 = fake of [0,132), F2 = fake of [132,681).
func fakedsplitWants(order int) []want {
	f1 := want{kind: SegFake, seqOff: 0, from: 0, to: helloMidSLD, fake: true}
	r1 := want{kind: SegData, seqOff: 0, from: 0, to: helloMidSLD}
	f2 := want{kind: SegFake, seqOff: helloMidSLD, from: helloMidSLD, to: helloLen, fake: true}
	r2 := want{kind: SegData, seqOff: helloMidSLD, from: helloMidSLD, to: helloLen}
	switch order {
	case 0:
		return []want{f1, r1, f1, f2, r2, f2}
	case 1:
		return []want{r1, f1, f2, r2, f2}
	case 2:
		return []want{r1, f2, r2, f2}
	default:
		return []want{r1, f2, r2}
	}
}

func TestFakedsplitAltOrders(t *testing.T) {
	hello := loadHello(t)
	for order := 0; order <= 3; order++ {
		t.Run(fmt.Sprintf("altorder=%d", order), func(t *testing.T) {
			c := newCtx(t, hello, FullCaps(), OpParams{
				SplitPos: []PosSpec{{Marker: proto.MarkerMidSLD}},
				AltOrder: order,
				TTL:      3,
				Fool:     FoolBadSum,
				Repeats:  2,
			})
			p := apply(t, "fakedsplit", c)
			checkSegs(t, p, hello, fakedsplitWants(order))
			checkReassembles(t, p, hello)
			for i, s := range p.Segs {
				switch s.Kind {
				case SegFake:
					if s.TTL != 3 || s.Fool != FoolBadSum || s.Repeats != 2 {
						t.Errorf("seg %d: fake must carry ttl/fooling/repeats, got %+v", i, s)
					}
					// The decoy is the pattern, not the request.
					at := int(s.SeqOff)
					if bytes.Equal(s.Data, hello[at:at+len(s.Data)]) {
						t.Errorf("seg %d: fake data equals the real payload", i)
					}
				case SegData:
					if s.TTL != 0 || s.Fool != FoolNone {
						t.Errorf("seg %d: real segment must not be fooled, got %+v", i, s)
					}
				}
			}
		})
	}
}

func TestFakedsplitDefaultPatternIsZero(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{
		SplitPos: []PosSpec{{Marker: proto.MarkerMidSLD}},
	})
	p := apply(t, "fakedsplit", c)
	for i, s := range p.Segs {
		if s.Kind != SegFake {
			continue
		}
		if !bytes.Equal(s.Data, make([]byte, len(s.Data))) {
			t.Errorf("seg %d: default fake pattern must be zero bytes", i)
		}
	}
}

func TestFakedsplitPatternIsPositionConsistent(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{
		SplitPos: []PosSpec{{Marker: proto.MarkerAbs, Offset: 4}},
		Pattern:  []byte{1, 2, 3},
		AltOrder: 3,
	})
	p := apply(t, "fakedsplit", c)
	// The whole-message pattern is 1,2,3 repeated; the fake of [4,681) must
	// start where that repetition stands at offset 4.
	full := segFillPattern(helloLen, []byte{1, 2, 3}, 0)
	fake := p.Segs[1]
	if fake.Kind != SegFake {
		t.Fatalf("seg 1 is not the fake: %+v", fake)
	}
	if !bytes.Equal(fake.Data, full[4:]) {
		t.Errorf("fake data is not pattern[4:]")
	}
}

func TestFakedsplitSeqovlOnFirstPart(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{
		SplitPos:      []PosSpec{{Marker: proto.MarkerMidSLD}},
		AltOrder:      3,
		Seqovl:        16,
		SeqovlPattern: []byte{0xaa},
	})
	p := apply(t, "fakedsplit", c)
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: -16, from: 0, to: helloMidSLD, prefix: 16},
		{kind: SegFake, seqOff: helloMidSLD, from: helloMidSLD, to: helloLen, fake: true},
		{kind: SegData, seqOff: helloMidSLD, from: helloMidSLD, to: helloLen},
	})
	if got := p.Segs[0].Data[:16]; !bytes.Equal(got, bytes.Repeat([]byte{0xaa}, 16)) {
		t.Errorf("overlap prefix = % x", got)
	}
	checkReassembles(t, p, hello)
}

// A one-byte payload is the only single-packet case where no split position can
// exist, which is what selects zapret's "no split pos" altorder field
// (bits 3..4): 0 -> fake, original, fake; 8 -> original, fake; 16 -> original.
func TestFakedsplitUnsplittedAltOrders(t *testing.T) {
	payload := []byte{0x17}
	for _, tc := range []struct {
		altOrder int
		wants    []want
	}{
		{0, []want{
			{kind: SegFake, seqOff: 0, from: 0, to: 1, fake: true},
			{kind: SegData, seqOff: 0, from: 0, to: 1},
			{kind: SegFake, seqOff: 0, from: 0, to: 1, fake: true},
		}},
		{8, []want{
			{kind: SegData, seqOff: 0, from: 0, to: 1},
			{kind: SegFake, seqOff: 0, from: 0, to: 1, fake: true},
		}},
		{16, []want{
			{kind: SegData, seqOff: 0, from: 0, to: 1},
		}},
	} {
		t.Run(fmt.Sprintf("altorder=%d", tc.altOrder), func(t *testing.T) {
			c := newCtx(t, payload, FullCaps(), OpParams{AltOrder: tc.altOrder, Pattern: []byte{0xff}})
			p := apply(t, "fakedsplit", c)
			checkSegs(t, p, payload, tc.wants)
			checkReassembles(t, p, payload)
		})
	}
}

func TestFakedsplitFallsBackToPositionOne(t *testing.T) {
	hello := loadHello(t)
	// Only an HTTP marker is configured, so nothing resolves on TLS and zapret
	// falls back to a split at offset 1.
	c := newCtx(t, hello, FullCaps(), OpParams{
		SplitPos: []PosSpec{{Marker: proto.MarkerMethod, Offset: 2}},
		AltOrder: 3,
	})
	p := apply(t, "fakedsplit", c)
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: 0, from: 0, to: 1},
		{kind: SegFake, seqOff: 1, from: 1, to: helloLen, fake: true},
		{kind: SegData, seqOff: 1, from: 1, to: helloLen},
	})
}

func TestFakedsplitPrefersRelativeOverAbsolute(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{
		SplitPos: []PosSpec{
			{Marker: proto.MarkerAbs, Offset: 5}, // listed first, still loses
			{Marker: proto.MarkerMidSLD},
		},
		AltOrder: 3,
	})
	p := apply(t, "fakedsplit", c)
	if p.Segs[0].SeqOff != 0 || len(p.Segs[0].Data) != helloMidSLD {
		t.Fatalf("first part = [0,%d), want [0,%d)", len(p.Segs[0].Data), helloMidSLD)
	}
}

// ---------- fakeddisorder ----------

func fakeddisorderWants(order int) []want {
	f1 := want{kind: SegFake, seqOff: 0, from: 0, to: helloMidSLD, fake: true}
	r1 := want{kind: SegData, seqOff: 0, from: 0, to: helloMidSLD}
	f2 := want{kind: SegFake, seqOff: helloMidSLD, from: helloMidSLD, to: helloLen, fake: true}
	r2 := want{kind: SegData, seqOff: helloMidSLD, from: helloMidSLD, to: helloLen}
	switch order {
	case 0:
		return []want{f2, r2, f2, f1, r1, f1}
	case 1:
		return []want{r2, f2, f1, r1, f1}
	case 2:
		return []want{r2, f1, r1, f1}
	default:
		return []want{r2, f1, r1}
	}
}

func TestFakeddisorderAltOrders(t *testing.T) {
	hello := loadHello(t)
	for order := 0; order <= 3; order++ {
		t.Run(fmt.Sprintf("altorder=%d", order), func(t *testing.T) {
			c := newCtx(t, hello, FullCaps(), OpParams{
				SplitPos: []PosSpec{{Marker: proto.MarkerMidSLD}},
				AltOrder: order,
				TTL:      4,
			})
			p := apply(t, "fakeddisorder", c)
			checkSegs(t, p, hello, fakeddisorderWants(order))
			checkReassembles(t, p, hello)
		})
	}
}

func TestFakeddisorderSeqovlOnSecondPart(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{
		SplitPos:      []PosSpec{{Marker: proto.MarkerMidSLD}},
		AltOrder:      3,
		Seqovl:        12,
		SeqovlPattern: []byte{0x5a},
	})
	p := apply(t, "fakeddisorder", c)
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: helloMidSLD - 12, from: helloMidSLD, to: helloLen, prefix: 12},
		{kind: SegFake, seqOff: 0, from: 0, to: helloMidSLD, fake: true},
		{kind: SegData, seqOff: 0, from: 0, to: helloMidSLD},
	})
	checkReassembles(t, p, hello)
}

func TestFakeddisorderSeqovlCancelledAtOrAboveSplitPos(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{
		SplitPos: []PosSpec{{Marker: proto.MarkerAbs, Offset: 10}},
		AltOrder: 3,
		Seqovl:   10,
	})
	p := apply(t, "fakeddisorder", c)
	if p.Segs[0].SeqOff != 10 {
		t.Errorf("SeqOff = %d, want 10 (overlap cancelled)", p.Segs[0].SeqOff)
	}
	if len(p.Degraded) != 1 || !strings.Contains(p.Degraded[0], "cancelled") {
		t.Errorf("Degraded = %v, want a cancellation note", p.Degraded)
	}
}

func TestFakedFamilyRequiresInjectSeqDrop(t *testing.T) {
	for _, name := range []string{"fakedsplit", "fakeddisorder", "hostfakesplit"} {
		r := mustOp(t, name).Requires()
		if !r.Inject || !r.Seq || !r.DropOriginal {
			t.Errorf("%s.Requires() = %+v, want Inject+Seq+DropOriginal", name, r)
		}
	}
}

// ---------- hostfakesplit ----------

func TestHostfakesplitOrder0(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{Repeats: 3, TTL: 2})
	p := apply(t, "hostfakesplit", c)
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: 0, from: 0, to: helloHost},
		{kind: SegFake, seqOff: helloHost, from: helloHost, to: helloEndHost, fake: true},
		{kind: SegData, seqOff: helloHost, from: helloHost, to: helloEndHost},
		{kind: SegFake, seqOff: helloHost, from: helloHost, to: helloEndHost, fake: true},
		{kind: SegData, seqOff: helloEndHost, from: helloEndHost, to: helloLen},
	})
	checkReassembles(t, p, hello)
	fake := p.Segs[1]
	if fake.Repeats != 3 || fake.TTL != 2 {
		t.Errorf("fake host segment = %+v, want repeats 3 ttl 2", fake)
	}
	// Both fake copies must be the same bytes (upstream sends one packet twice).
	if !bytes.Equal(p.Segs[1].Data, p.Segs[3].Data) {
		t.Error("the two fake host copies differ")
	}
	checkGeneratedHost(t, fake.Data, helloHostLen, "")
}

func TestHostfakesplitOrder1(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{AltOrder: 1})
	p := apply(t, "hostfakesplit", c)
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: 0, from: 0, to: helloHost},
		{kind: SegFake, seqOff: helloHost, from: helloHost, to: helloEndHost, fake: true},
		{kind: SegData, seqOff: helloEndHost, from: helloEndHost, to: helloLen},
		{kind: SegData, seqOff: helloHost, from: helloHost, to: helloEndHost},
	})
	checkReassembles(t, p, hello)
}

func TestHostfakesplitMidHost(t *testing.T) {
	hello := loadHello(t)
	// midhost is a position spec now, and "1" in a strategy file compiles to the
	// midsld marker this used to hard-code.
	c := newCtx(t, hello, FullCaps(), OpParams{
		MidHostSet: true, MidHost: PosSpec{Marker: proto.MarkerMidSLD},
	})
	p := apply(t, "hostfakesplit", c)
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: 0, from: 0, to: helloHost},
		{kind: SegFake, seqOff: helloHost, from: helloHost, to: helloEndHost, fake: true},
		{kind: SegData, seqOff: helloHost, from: helloHost, to: helloMidSLD},
		{kind: SegData, seqOff: helloMidSLD, from: helloMidSLD, to: helloEndHost},
		{kind: SegFake, seqOff: helloHost, from: helloHost, to: helloEndHost, fake: true},
		{kind: SegData, seqOff: helloEndHost, from: helloEndHost, to: helloLen},
	})
	checkReassembles(t, p, hello)
}

func TestHostfakesplitHostTemplate(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{HostFakeHost: "ya.ru"})
	p := apply(t, "hostfakesplit", c)
	got := p.Segs[1].Data
	checkGeneratedHost(t, got, helloHostLen, "ya.ru")
	if !bytes.HasSuffix(got, []byte(".ya.ru")) {
		t.Errorf("fake host %q must end with .ya.ru", got)
	}
}

func TestSegFakeHostShapes(t *testing.T) {
	// Template longer than the real host: cut from the left, keeping the TLD.
	if got := string(segFakeHost(7, "google.com")); got != "gle.com" {
		t.Errorf("segFakeHost(7,google.com) = %q, want gle.com", got)
	}
	if got := string(segFakeHost(10, "google.com")); got != "google.com" {
		t.Errorf("segFakeHost(10,google.com) = %q, want google.com", got)
	}
	// Exactly one byte longer: a bare dot prefix.
	if got := string(segFakeHost(11, "google.com")); got != ".google.com" {
		t.Errorf("segFakeHost(11,google.com) = %q, want .google.com", got)
	}
	// Longer: random label, dot, template.
	got := segFakeHost(18, "google.com")
	if !bytes.HasSuffix(got, []byte(".google.com")) || len(got) != 18 {
		t.Fatalf("segFakeHost(18,google.com) = %q", got)
	}
	checkGeneratedHost(t, got, 18, "google.com")
	// Without a template and >= 7 bytes: a random name with a known TLD.
	for _, n := range []int{7, 14, 30} {
		checkGeneratedHost(t, segFakeHost(n, ""), n, "")
	}
	// Short names get no TLD, only random characters.
	short := segFakeHost(6, "")
	if len(short) != 6 || bytes.ContainsRune(short, '.') {
		t.Errorf("segFakeHost(6,\"\") = %q, want 6 dotless characters", short)
	}
	if segFakeHost(0, "") != nil {
		t.Error("segFakeHost(0) must be nil")
	}
}

// checkGeneratedHost asserts the shape zapret guarantees for a fake hostname.
func checkGeneratedHost(t *testing.T, h []byte, size int, template string) {
	t.Helper()
	if len(h) != size {
		t.Fatalf("fake host %q has %d bytes, want %d", h, len(h), size)
	}
	for _, ch := range h {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch == '.') {
			t.Fatalf("fake host %q contains %q, want [0-9a-z.]", h, ch)
		}
	}
	if template != "" {
		if size > len(template) && !bytes.HasSuffix(h, []byte("."+template)) {
			t.Errorf("fake host %q must end with .%s", h, template)
		}
		return
	}
	if size < 7 {
		return
	}
	if h[size-4] != '.' {
		t.Errorf("fake host %q must have a dot before a 3-char TLD", h)
	}
	tld := string(h[size-3:])
	for _, known := range segFakeHostTLD {
		if tld == known {
			return
		}
	}
	t.Errorf("fake host %q ends with unknown TLD %q", h, tld)
}

func TestHostfakesplitSkipsPayloadWithoutHost(t *testing.T) {
	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5}
	c := newCtx(t, payload, FullCaps(), OpParams{})
	p := apply(t, "hostfakesplit", c)
	if len(p.Segs) != 0 || p.DropOriginal {
		t.Fatalf("expected an empty plan, got %d segs", len(p.Segs))
	}
	if len(p.Degraded) != 1 || !strings.Contains(p.Degraded[0], "hostname") {
		t.Errorf("Degraded = %v, want a no-hostname note", p.Degraded)
	}
}

// ---------- tamper ----------

const httpReq = "GET /index.html HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: curl/8\r\n\r\n"

func TestTamperCreatesTheDataSegment(t *testing.T) {
	payload := []byte(httpReq)
	c := newCtx(t, payload, FullCaps(), OpParams{Tamper: proto.TamperOpts{HostCase: true}})
	p := apply(t, "tamper", c)
	if len(p.Segs) != 1 || p.Segs[0].Kind != SegData || p.Segs[0].SeqOff != 0 {
		t.Fatalf("plan = %s", dumpSegs(p, payload))
	}
	if !bytes.Contains(p.Segs[0].Data, []byte("host: www.google.com")) {
		t.Errorf("hostcase not applied: %q", p.Segs[0].Data)
	}
	if len(p.Segs[0].Data) != len(payload) {
		t.Errorf("hostcase must preserve the length: %d vs %d", len(p.Segs[0].Data), len(payload))
	}
	if !p.DropOriginal {
		t.Error("tamper must drop the original packet when it re-emits the payload")
	}
}

func TestTamperRewritesExistingSegmentsInPlace(t *testing.T) {
	payload := []byte(httpReq)
	c := newCtx(t, payload, FullCaps(), OpParams{
		SplitPos: []PosSpec{{Marker: proto.MarkerMethod, Offset: 2}},
	})
	p := apply(t, "multisplit", c)
	if len(p.Segs) != 2 {
		t.Fatalf("multisplit produced %d segs", len(p.Segs))
	}
	c.Params = OpParams{Tamper: proto.TamperOpts{HostCase: true, DomCase: true}}
	if err := mustOp(t, "tamper").Apply(c, p); err != nil {
		t.Fatalf("tamper.Apply: %v", err)
	}
	// Still two segments, still the same boundaries, but the bytes changed.
	if len(p.Segs) != 2 || p.Segs[0].SeqOff != 0 || p.Segs[1].SeqOff != 2 {
		t.Fatalf("tamper changed the segmentation: %s", dumpSegs(p, payload))
	}
	joined, ok := segJoinData(p, segDataIdx(p), len(payload))
	if !ok {
		t.Fatal("segments no longer tile the payload")
	}
	if !bytes.Contains(joined, []byte("host: ")) {
		t.Errorf("hostcase not applied across segments: %q", joined)
	}
	if bytes.Contains(joined, []byte("www.google.com")) {
		t.Errorf("domcase not applied: %q", joined)
	}
	// The original packet buffer must be untouched.
	if string(payload) != httpReq {
		t.Error("tamper wrote into the intercepted payload")
	}
}

func TestTamperLengthChangeIsReported(t *testing.T) {
	payload := []byte(httpReq)
	c := newCtx(t, payload, FullCaps(), OpParams{
		SplitPos: []PosSpec{{Marker: proto.MarkerAbs, Offset: 4}},
	})
	p := apply(t, "multisplit", c)
	c.Params = OpParams{Tamper: proto.TamperOpts{HostDot: true}} // adds a byte
	if err := mustOp(t, "tamper").Apply(c, p); err != nil {
		t.Fatalf("tamper.Apply: %v", err)
	}
	if len(p.Degraded) != 1 || !strings.Contains(p.Degraded[0], "length") {
		t.Fatalf("Degraded = %v, want a length note", p.Degraded)
	}
	joined, _ := segJoinData(p, segDataIdx(p), len(payload))
	if !bytes.Equal(joined, payload) {
		t.Error("a rejected tamper must leave the payload untouched")
	}
}

// TestTamperReadsParamsTamper is the former TestTamperOptsFromParams: the knobs
// used to be smuggled through OpParams.AltOrder/HostFakeHost and are now read
// from OpParams.Tamper, so the same knob set is asserted through what the op
// emits instead of through the deleted TamperOptsFromParams accessor.
func TestTamperReadsParamsTamper(t *testing.T) {
	payload := []byte(httpReq)
	// ProxyCaps: hostnospace/hostpad/methodeol/unixeol all change the byte count,
	// which only a transport that owns the stream may do (see
	// TestTamperLengthChangeIsReportedAtPacketLevel).
	c := newCtx(t, payload, ProxyCaps(), OpParams{Tamper: proto.TamperOpts{
		HostNoSpace: true, MethodEOL: true, UnixEOL: true, HostPad: 40,
	}})
	got := apply(t, "tamper", c).Segs[0].Data
	if !bytes.Contains(got, []byte("Host:www.google.com")) {
		t.Errorf("hostnospace not applied: %q", got)
	}
	if len(got) == 0 || got[0] != '\n' {
		t.Errorf("methodeol not applied: %q", got)
	}
	if bytes.Contains(got, []byte("\r\n")) {
		t.Errorf("unixeol not applied: %q", got)
	}
	if !bytes.Contains(got, []byte("X-Pad: ")) {
		t.Errorf("hostpad not applied: %q", got)
	}
	// Unset flags must not leak: no dot or tab after the hostname, no second
	// space after the method, and the domain keeps its case.
	if !bytes.Contains(got, []byte("www.google.com\n")) {
		t.Errorf("an unset hostdot/hosttab changed the hostname: %q", got)
	}
	if !bytes.Contains(got, []byte("GET /index.html")) {
		t.Errorf("an unset methodspace changed the request line: %q", got)
	}

	c = newCtx(t, payload, FullCaps(), OpParams{Tamper: proto.TamperOpts{HostSpell: "hoSt"}})
	got = apply(t, "tamper", c).Segs[0].Data
	if !bytes.Contains(got, []byte("hoSt: www.google.com")) {
		t.Errorf("hostspell not honoured: %q", got)
	}
	if len(got) != len(payload) {
		t.Errorf("a respelling must preserve the length: %d vs %d", len(got), len(payload))
	}
}

func TestTamperRequiresSegmentOnly(t *testing.T) {
	r := mustOp(t, "tamper").Requires()
	if !r.Segment || r.Inject || r.Seq || r.Fooling {
		t.Errorf("tamper.Requires() = %+v", r)
	}
}

// ---------- tlsrec ----------

func TestTLSRecDefaultSplitsInsideSNI(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, ProxyCaps(), OpParams{})
	p := apply(t, "tlsrec", c)
	if len(p.Segs) != 1 {
		t.Fatalf("plan = %s", dumpSegs(p, hello))
	}
	out := p.Segs[0].Data
	if len(out) != helloLen+5 {
		t.Fatalf("payload is %d bytes, want %d (one extra record header)", len(out), helloLen+5)
	}
	// First record: same type/version, body cut at sniext+1.
	if out[0] != hello[0] || out[1] != hello[1] || out[2] != hello[2] {
		t.Error("first record header does not match the original")
	}
	firstBody := int(out[3])<<8 | int(out[4])
	if firstBody != helloSNIExt1-5 {
		t.Errorf("first record body = %d, want %d", firstBody, helloSNIExt1-5)
	}
	// The two record bodies concatenated are the original record body.
	second := 5 + firstBody
	if out[second] != hello[0] {
		t.Error("second record header missing")
	}
	body := append(append([]byte{}, out[5:second]...), out[second+5:]...)
	if !bytes.Equal(body, hello[5:]) {
		t.Error("record bodies do not reproduce the original handshake")
	}
	if len(p.Degraded) != 0 {
		t.Errorf("tlsrec on the proxy transport must not degrade: %v", p.Degraded)
	}
}

func TestTLSRecShiftsExistingSegmentBoundaries(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, ProxyCaps(), OpParams{SplitPos: []PosSpec{
		{Marker: proto.MarkerAbs, Offset: 20},  // before the record cut
		{Marker: proto.MarkerAbs, Offset: 200}, // after it
	}})
	p := apply(t, "multisplit", c)
	c.Params = OpParams{}
	if err := mustOp(t, "tlsrec").Apply(c, p); err != nil {
		t.Fatalf("tlsrec.Apply: %v", err)
	}
	if len(p.Segs) != 3 {
		t.Fatalf("plan = %s", dumpSegs(p, hello))
	}
	offs := []int32{0, 20, 205} // the boundary past the insertion moves by 5
	total := 0
	for i, s := range p.Segs {
		if s.SeqOff != offs[i] {
			t.Errorf("seg %d: SeqOff %d, want %d", i, s.SeqOff, offs[i])
		}
		total += len(s.Data)
	}
	if total != helloLen+5 {
		t.Errorf("segments carry %d bytes, want %d", total, helloLen+5)
	}
}

func TestTLSRecSkipsNonTLSPayload(t *testing.T) {
	payload := []byte(httpReq)
	c := newCtx(t, payload, ProxyCaps(), OpParams{})
	p := apply(t, "tlsrec", c)
	if len(p.Segs) != 0 || len(p.Degraded) != 0 {
		t.Fatalf("tlsrec must ignore non-TLS payloads: %s", dumpSegs(p, payload))
	}
}

// TestTLSRecWarnsAtPacketLevel: the extra record header grows the payload, which
// at packet level would shift the client's own sequence space for the rest of the
// connection. The op must plan nothing and explain the refusal.
func TestTLSRecWarnsAtPacketLevel(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, FullCaps(), OpParams{})
	p := apply(t, "tlsrec", c)
	if len(p.Segs) != 0 || p.DropOriginal {
		t.Fatalf("plan = %s, want the hello forwarded untouched at packet level", dumpSegs(p, hello))
	}
	if len(p.Degraded) != 1 || !strings.Contains(p.Degraded[0], "sequence space") {
		t.Errorf("Degraded = %v, want a packet-level refusal note", p.Degraded)
	}
}

// ---------- wssize / ip_id ----------

// TestWSSizeSetsTheWindow was TestWSSizeIsRecordedNotApplied: Seg gained Window
// and WindowScale, so the op applies the rewrite instead of only reporting it.
// The Requires() and "--wssize=0 is silent" assertions are unchanged.
func TestWSSizeSetsTheWindow(t *testing.T) {
	hello := loadHello(t)
	if r := mustOp(t, "wssize").Requires(); !r.Fooling {
		t.Errorf("wssize.Requires() = %+v, want Fooling", r)
	}
	c := newCtx(t, hello, FullCaps(), OpParams{WSSize: 1, WSSizeScale: 6})
	p := apply(t, "wssize", c)
	if len(p.Segs) != 1 || p.Segs[0].Kind != SegData || !bytes.Equal(p.Segs[0].Data, hello) {
		t.Fatalf("wssize must carry the payload so the rewritten window reaches the wire: %s", dumpSegs(p, hello))
	}
	if p.Segs[0].Window != 1 || p.Segs[0].WindowScale != 6 {
		t.Fatalf("window = %d:%d, want 1:6", p.Segs[0].Window, p.Segs[0].WindowScale)
	}
	if len(p.Degraded) != 0 {
		t.Fatalf("Degraded = %v, want nothing: the window was applied", p.Degraded)
	}
	// The proxy transport cannot write a TCP header; Degrade says what it can do.
	c = newCtx(t, hello, ProxyCaps(), OpParams{WSSize: 1, WSSizeScale: 6})
	d := degrade(t, "wssize", c)
	if len(d.Degraded) != 1 || !strings.Contains(d.Degraded[0], "TCP_MAXSEG") {
		t.Fatalf("Degraded = %v, want the TCP_MAXSEG approximation", d.Degraded)
	}
	// --wssize=0 is "do not modify".
	c = newCtx(t, hello, FullCaps(), OpParams{})
	if p := apply(t, "wssize", c); len(p.Degraded) != 0 || len(p.Segs) != 0 {
		t.Errorf("wssize=0 must be silent, got %v / %d segs", p.Degraded, len(p.Segs))
	}
}

func TestIPIDTagsPlannedSegments(t *testing.T) {
	hello := loadHello(t)
	if r := mustOp(t, "ip_id").Requires(); !r.IPID {
		t.Errorf("ip_id.Requires() = %+v, want IPID", r)
	}
	if _, ok := mustOp(t, "ip_id").(Degrader); ok {
		t.Error("ip_id must not offer a degraded mode")
	}
	c := newCtx(t, hello, FullCaps(), OpParams{SplitPos: []PosSpec{{Marker: proto.MarkerMidSLD}}})
	p := apply(t, "multisplit", c)
	c.Params = OpParams{IPID: IPIDZero}
	if err := mustOp(t, "ip_id").Apply(c, p); err != nil {
		t.Fatalf("ip_id.Apply: %v", err)
	}
	for i, s := range p.Segs {
		if s.IPID != IPIDZero {
			t.Errorf("seg %d: IPID = %d, want %d", i, s.IPID, IPIDZero)
		}
	}
}

// ---------- degrade paths under ProxyCaps ----------

func TestDegradeMultisplitDropsOverlap(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, ProxyCaps(), OpParams{
		SplitPos:      []PosSpec{{Marker: proto.MarkerSNIExt, Offset: 1}, {Marker: proto.MarkerMidSLD}},
		Seqovl:        helloLen,
		SeqovlPattern: hello,
	})
	p := degrade(t, "multisplit", c)
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: 0, from: 0, to: helloSNIExt1},
		{kind: SegData, seqOff: helloSNIExt1, from: helloSNIExt1, to: helloMidSLD},
		{kind: SegData, seqOff: helloMidSLD, from: helloMidSLD, to: helloLen},
	})
	for i, s := range p.Segs {
		if s.SeqOff < 0 {
			t.Errorf("seg %d has a negative SeqOff under ProxyCaps", i)
		}
	}
	checkReassembles(t, p, hello)
}

func TestDegradeMultidisorderUsesTTL1FirstSegment(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, ProxyCaps(), OpParams{
		SplitPos: []PosSpec{{Marker: proto.MarkerMidSLD}},
		Seqovl:   4,
	})
	p := degrade(t, "multidisorder", c)
	// Ascending order: a stream relay can only write the stream in order; the
	// reordering happens on the wire because the first copy dies at TTL 1.
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: 0, from: 0, to: helloMidSLD},
		{kind: SegData, seqOff: helloMidSLD, from: helloMidSLD, to: helloLen},
	})
	if p.Segs[0].TTL != 1 {
		t.Errorf("first segment TTL = %d, want 1", p.Segs[0].TTL)
	}
	if p.Segs[1].TTL != 0 {
		t.Errorf("second segment TTL = %d, want 0", p.Segs[1].TTL)
	}
	if len(p.Degraded) != 1 || !strings.Contains(p.Degraded[0], "TTL 1") {
		t.Errorf("Degraded = %v, want the disorder emulation note", p.Degraded)
	}
	checkReassembles(t, p, hello)
}

func TestDegradeFakedFamilyDropsFakes(t *testing.T) {
	hello := loadHello(t)
	for _, name := range []string{"fakedsplit", "fakeddisorder"} {
		t.Run(name, func(t *testing.T) {
			c := newCtx(t, hello, ProxyCaps(), OpParams{
				SplitPos: []PosSpec{{Marker: proto.MarkerMidSLD}},
				TTL:      3,
				Seqovl:   8,
			})
			p := degrade(t, name, c)
			checkSegs(t, p, hello, []want{
				{kind: SegData, seqOff: 0, from: 0, to: helloMidSLD},
				{kind: SegData, seqOff: helloMidSLD, from: helloMidSLD, to: helloLen},
			})
			checkReassembles(t, p, hello)
		})
	}
}

func TestDegradeHostfakesplitSplitsAroundHost(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, ProxyCaps(), OpParams{})
	p := degrade(t, "hostfakesplit", c)
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: 0, from: 0, to: helloHost},
		{kind: SegData, seqOff: helloHost, from: helloHost, to: helloEndHost},
		{kind: SegData, seqOff: helloEndHost, from: helloEndHost, to: helloLen},
	})
	checkReassembles(t, p, hello)

	c = newCtx(t, hello, ProxyCaps(), OpParams{
		MidHostSet: true, MidHost: PosSpec{Marker: proto.MarkerMidSLD},
	})
	p = degrade(t, "hostfakesplit", c)
	checkSegs(t, p, hello, []want{
		{kind: SegData, seqOff: 0, from: 0, to: helloHost},
		{kind: SegData, seqOff: helloHost, from: helloHost, to: helloMidSLD},
		{kind: SegData, seqOff: helloMidSLD, from: helloMidSLD, to: helloEndHost},
		{kind: SegData, seqOff: helloEndHost, from: helloEndHost, to: helloLen},
	})
	checkReassembles(t, p, hello)
}

func TestDegradeStripsInjectedSegmentsFromThePlan(t *testing.T) {
	hello := loadHello(t)
	c := newCtx(t, hello, ProxyCaps(), OpParams{SplitPos: []PosSpec{{Marker: proto.MarkerMidSLD}}})
	p := &Plan{Segs: []Seg{{Kind: SegFake, Data: []byte("decoy")}}}
	d := mustOp(t, "fakedsplit").(Degrader)
	if err := d.Degrade(c, p); err != nil {
		t.Fatalf("Degrade: %v", err)
	}
	for i, s := range p.Segs {
		if s.Kind != SegData {
			t.Errorf("seg %d survived Degrade with kind %d", i, s.Kind)
		}
	}
}

// ---------- hostile input ----------

func TestOpsSurviveDegenerateInput(t *testing.T) {
	payloads := [][]byte{
		nil,
		{},
		{0x16},
		bytes.Repeat([]byte{0x16, 0x03, 0x01}, 3),
		append([]byte{0x16, 0x03, 0x01, 0xff, 0xff}, bytes.Repeat([]byte{0xaa}, 40)...),
	}
	params := []OpParams{
		{},
		{SplitPos: []PosSpec{{Marker: proto.MarkerHost, Offset: -5}}, Seqovl: 100},
		{SplitPos: []PosSpec{{Marker: proto.HostlistMarker(200), Offset: 3}}},
		{AltOrder: -1, Seqovl: -7, Repeats: -2, Pattern: []byte{}},
		{MidHostSet: true, MidHost: PosSpec{Marker: proto.MarkerMidSLD},
			HostFakeHost: strings.Repeat("x", 300), WSSize: -1, IPID: IPIDSeq},
		// A midhost that resolves nowhere, a window past the 16-bit field and a
		// tamper knob set on every op that ignores it.
		{MidHostSet: true, WSSize: 1 << 20, WSSizeScale: 300, WSSizeCutoffKind: 's', WSSizeCutoffN: 4,
			IPID: IPIDSeqGroup, Tamper: proto.TamperOpts{HostPad: -3, DomCase: true}},
	}
	names := []string{"multisplit", "multidisorder", "fakedsplit", "fakeddisorder",
		"hostfakesplit", "tamper", "tlsrec", "wssize", "ip_id"}
	for _, name := range names {
		for _, payload := range payloads {
			for _, prm := range params {
				for _, caps := range []Caps{FullCaps(), ProxyCaps(), {}} {
					c := newCtx(t, payload, caps, prm)
					p := &Plan{}
					o := mustOp(t, name)
					if err := o.Apply(c, p); err != nil {
						t.Fatalf("%s.Apply(%d bytes): %v", name, len(payload), err)
					}
					if d, ok := o.(Degrader); ok {
						if err := d.Degrade(c, &Plan{}); err != nil {
							t.Fatalf("%s.Degrade(%d bytes): %v", name, len(payload), err)
						}
					}
					// Whatever came out must still describe real bytes.
					for i, s := range p.Segs {
						if int(s.SeqOff) > len(payload) || int(s.SeqOff)+len(s.Data) > len(payload)+8 {
							t.Fatalf("%s seg %d covers [%d,%d) outside a %d byte payload",
								name, i, s.SeqOff, int(s.SeqOff)+len(s.Data), len(payload))
						}
					}
				}
			}
		}
	}
}
