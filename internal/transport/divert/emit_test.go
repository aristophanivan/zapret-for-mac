package divert

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// The fixtures below stand in for one intercepted client packet. Addresses come
// from the documentation ranges (RFC 5737 / RFC 3849) so a test can never be
// mistaken for something that touched the network.
var (
	testSrc4 = netip.MustParseAddr("192.0.2.10")
	testDst4 = netip.MustParseAddr("198.51.100.20")
	testSrc6 = netip.MustParseAddr("2001:db8::10")
	testDst6 = netip.MustParseAddr("2001:db8::20")
)

const (
	testSrcPort = 51000
	testDstPort = 443
	testSeq     = uint32(1000)
	testAck     = uint32(500000)
	testWindow  = uint16(64240)
	testTTL     = uint8(64)
	testIPID    = uint16(0xbeef)
)

// tsOpts is a realistic option block for a data segment: NOP, NOP, timestamps.
func tsOpts(tsval, tsecho uint32) []byte {
	o := []byte{1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(o[4:8], tsval)
	binary.BigEndian.PutUint32(o[8:12], tsecho)
	return o
}

// mkPkt marshals and re-parses a packet, which is the only honest way to build a
// *proto.Pkt: every field then comes from the same wire image the datapath sees.
func mkPkt(t *testing.T, tmpl proto.Tmpl) *proto.Pkt {
	t.Helper()
	raw, err := tmpl.Marshal()
	if err != nil {
		t.Fatalf("building the fixture packet: %v", err)
	}
	p, err := proto.Parse(raw)
	if err != nil {
		t.Fatalf("parsing the fixture packet: %v", err)
	}
	return p
}

// origTCP is the standard intercepted TCP data packet used by most tests.
func origTCP(t *testing.T, payload, opts []byte) *proto.Pkt {
	t.Helper()
	return mkPkt(t, proto.Tmpl{
		Src: testSrc4, Dst: testDst4,
		SrcPort: testSrcPort, DstPort: testDstPort,
		Seq: testSeq, Ack: testAck,
		Flags: proto.TCPPsh | proto.TCPAck, Window: testWindow,
		TTL: testTTL, IPID: testIPID, DF: true,
		TCPOpts: opts, Payload: payload,
	})
}

// origTCP6 is the IPv6 counterpart.
func origTCP6(t *testing.T, payload, opts []byte) *proto.Pkt {
	t.Helper()
	return mkPkt(t, proto.Tmpl{
		Src: testSrc6, Dst: testDst6,
		SrcPort: testSrcPort, DstPort: testDstPort,
		Seq: testSeq, Ack: testAck,
		Flags: proto.TCPPsh | proto.TCPAck, Window: testWindow,
		TTL: testTTL, DF: true,
		TCPOpts: opts, Payload: payload,
	})
}

// origUDP is the intercepted UDP datagram fixture.
func origUDP(t *testing.T, payload []byte) *proto.Pkt {
	t.Helper()
	return mkPkt(t, proto.Tmpl{
		Src: testSrc4, Dst: testDst4,
		SrcPort: testSrcPort, DstPort: testDstPort,
		TTL: testTTL, IPID: testIPID, UDP: true, Payload: payload,
	})
}

// fixedRand is a deterministic BuildOpts.Rand so tests can assert exact bytes.
func fixedRand(fill byte) func([]byte) {
	return func(b []byte) {
		for i := range b {
			b[i] = fill
		}
	}
}

// out is a decoded view of one produced packet, so assertions read like the
// contract they check.
type out struct {
	raw  []byte
	pkt  *proto.Pkt
	ihl  int
	frag uint16 // the raw IPv4 flags+offset field
}

// decode parses a produced packet without any of proto.Parse's fragment
// rejection: an IPv4 fragment is exactly what some tests are asserting about.
func decode(t *testing.T, raw []byte) out {
	t.Helper()
	o := out{raw: raw}
	if len(raw) < 20 {
		t.Fatalf("produced packet is %d bytes, too short to be IP", len(raw))
	}
	if raw[0]>>4 == 4 {
		o.ihl = int(raw[0]&0x0f) * 4
		o.frag = binary.BigEndian.Uint16(raw[6:8])
	}
	p, err := proto.Parse(raw)
	if err != nil {
		if errors.Is(err, proto.ErrIPFragment) {
			return o // non-initial fragment: only the IP-level fields are usable
		}
		t.Fatalf("parsing the produced packet: %v", err)
	}
	o.pkt = p
	return o
}

// build runs BuildPlanPackets and decodes every packet it produced.
func build(t *testing.T, orig *proto.Pkt, plan *desync.Plan, o BuildOpts) []out {
	t.Helper()
	pkts, err := BuildPlanPackets(orig, plan, o)
	if err != nil {
		t.Fatalf("BuildPlanPackets: %v", err)
	}
	res := make([]out, 0, len(pkts))
	for _, p := range pkts {
		res = append(res, decode(t, p))
	}
	return res
}

// ipHeaderChecksumOK reports whether an IPv4 header's checksum verifies. Summing
// a header that already carries its correct checksum yields zero.
func ipHeaderChecksumOK(raw []byte) bool {
	if len(raw) < 20 || raw[0]>>4 != 4 {
		return true // IPv6 has no header checksum
	}
	ihl := int(raw[0]&0x0f) * 4
	if ihl > len(raw) {
		return false
	}
	return proto.Checksum16(raw[:ihl]) == 0
}

// l4ChecksumOK recomputes the transport checksum of a complete packet.
func l4ChecksumOK(t *testing.T, raw []byte) bool {
	t.Helper()
	p, err := proto.Parse(raw)
	if err != nil {
		t.Fatalf("parsing for the checksum check: %v", err)
	}
	l4 := append([]byte(nil), p.Raw[p.L3Len:]...)
	off := 16
	if p.IsUDP() {
		off = 6
	}
	if len(l4) < off+2 {
		t.Fatalf("L4 header of %d bytes is too short", len(l4))
	}
	got := binary.BigEndian.Uint16(l4[off : off+2])
	l4[off], l4[off+1] = 0, 0
	return got == proto.L4Checksum(p.Src, p.Dst, p.Proto, l4)
}

// ---------------------------------------------------------------------------
// the single most important line in emit.go
// ---------------------------------------------------------------------------

// TestSeqovlLowersSequenceBy681 pins the flowseal general.toml recipe:
// multisplit with pos=1 and --dpi-desync-split-seqovl=681. The first segment must
// be transmitted 681 bytes BELOW the window, which is what makes the peer's TCP
// discard the prefix while a naive DPI reassembler swallows it.
func TestSeqovlLowersSequenceBy681(t *testing.T) {
	payload := bytes.Repeat([]byte{0xaa}, 517)
	orig := origTCP(t, payload, tsOpts(0x11223344, 0x55667788))

	const ovl = 681
	pattern := bytes.Repeat([]byte{0x16, 0x03, 0x01}, 227) // 681 bytes
	first := append(append([]byte(nil), pattern...), payload[:1]...)

	plan := &desync.Plan{
		Segs: []desync.Seg{
			{Kind: desync.SegData, Data: first, SeqOff: -ovl},
			{Kind: desync.SegData, Data: payload[1:], SeqOff: 1},
		},
		DropOriginal: true,
	}

	got := build(t, orig, plan, BuildOpts{})
	if len(got) != 2 {
		t.Fatalf("want 2 packets, got %d", len(got))
	}

	if want := testSeq - ovl; got[0].pkt.Seq != want {
		t.Errorf("first segment seq = %d, want %d (orig %d - %d)", got[0].pkt.Seq, want, testSeq, ovl)
	}
	if n := len(got[0].pkt.Payload()); n != ovl+1 {
		t.Errorf("first segment carries %d bytes, want %d", n, ovl+1)
	}
	if got[1].pkt.Seq != testSeq+1 {
		t.Errorf("second segment seq = %d, want %d", got[1].pkt.Seq, testSeq+1)
	}
	if n := len(got[1].pkt.Payload()); n != len(payload)-1 {
		t.Errorf("second segment carries %d bytes, want %d", n, len(payload)-1)
	}
	// Both must be valid packets: the trick is the sequence number, not corruption.
	for i, g := range got {
		if !ipHeaderChecksumOK(g.raw) {
			t.Errorf("packet %d has a bad IPv4 header checksum", i)
		}
		if !l4ChecksumOK(t, g.raw) {
			t.Errorf("packet %d has a bad TCP checksum", i)
		}
		if g.pkt.TTL != testTTL {
			t.Errorf("packet %d TTL = %d, want the original %d", i, g.pkt.TTL, testTTL)
		}
		if !bytes.Equal(g.pkt.TCPOpts, orig.TCPOpts) {
			t.Errorf("packet %d dropped the original TCP options", i)
		}
	}
}

// TestSeqovlThroughTheRealOp drives desync's own multisplit op, so the -681 does
// not depend on the test's idea of what the op emits.
func TestSeqovlThroughTheRealOp(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 300)
	orig := origTCP(t, payload, nil)

	op, err := desync.Lookup("multisplit")
	if err != nil {
		t.Fatalf("looking up multisplit: %v", err)
	}
	c := &desync.Ctx{
		Flow: &desync.Flow{Key: desync.FlowKey{
			Src: testSrc4, Dst: testDst4,
			SrcPort: testSrcPort, DstPort: testDstPort, Proto: proto.IPProtoTCP,
		}},
		Payload: payload,
		Info:    proto.Classify(payload, testDstPort, proto.IPProtoTCP),
		Caps:    desync.FullCaps(),
		Params: desync.OpParams{
			SplitPos:      []desync.PosSpec{{Marker: proto.MarkerAbs, Offset: 1}},
			Seqovl:        681,
			SeqovlPattern: []byte{0xde, 0xad, 0xbe, 0xef},
		},
	}
	plan := &desync.Plan{}
	if err := op.Apply(c, plan); err != nil {
		t.Fatalf("multisplit.Apply: %v", err)
	}
	if !plan.DropOriginal {
		t.Fatalf("multisplit should claim the original packet")
	}

	got := build(t, orig, plan, BuildOpts{})
	if len(got) != 2 {
		t.Fatalf("want 2 packets, got %d", len(got))
	}
	if want := testSeq - 681; got[0].pkt.Seq != want {
		t.Errorf("seqovl segment seq = %d, want %d", got[0].pkt.Seq, want)
	}
	// The real bytes must still be the last byte of the overlapped segment.
	p0 := got[0].pkt.Payload()
	if len(p0) != 682 || p0[681] != payload[0] {
		t.Errorf("overlapped segment is %d bytes ending in %#x, want 682 ending in %#x",
			len(p0), p0[len(p0)-1], payload[0])
	}
}

// ---------------------------------------------------------------------------
// fakes: TTL, checksum, fooling
// ---------------------------------------------------------------------------

func TestFakeCarriesTTLAndBadSumRealDoesNot(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	orig := origTCP(t, payload, tsOpts(0x01020304, 0x05060708))

	fake := bytes.Repeat([]byte{0x99}, 64)
	plan := &desync.Plan{
		Segs: []desync.Seg{
			{
				Kind: desync.SegFake, Data: fake, SeqOff: 0,
				TTL: 5, Fool: desync.FoolBadSum, FoolP: desync.DefaultFoolParams(),
			},
			{Kind: desync.SegData, Data: payload, SeqOff: 0},
		},
		DropOriginal: true,
	}

	got := build(t, orig, plan, BuildOpts{})
	if len(got) != 2 {
		t.Fatalf("want 2 packets, got %d", len(got))
	}

	// The decoy: low TTL, deliberately wrong TCP checksum, right sequence number.
	if got[0].pkt.TTL != 5 {
		t.Errorf("fake TTL = %d, want 5", got[0].pkt.TTL)
	}
	if got[0].pkt.Seq != testSeq {
		t.Errorf("fake seq = %d, want the real payload's %d", got[0].pkt.Seq, testSeq)
	}
	if l4ChecksumOK(t, got[0].raw) {
		t.Errorf("fake has a VALID TCP checksum; --dpi-desync-fooling=badsum requires a broken one")
	}
	if !ipHeaderChecksumOK(got[0].raw) {
		t.Errorf("fake has a bad IPv4 header checksum: badsum must corrupt L4 only, " +
			"or a router drops the decoy before any DPI sees it")
	}

	// The real segment: untouched TTL, valid checksum.
	if got[1].pkt.TTL != testTTL {
		t.Errorf("real segment TTL = %d, want the original %d", got[1].pkt.TTL, testTTL)
	}
	if !l4ChecksumOK(t, got[1].raw) {
		t.Errorf("real segment has a broken TCP checksum")
	}
	if !bytes.Equal(got[1].pkt.Payload(), payload) {
		t.Errorf("real segment payload was mangled")
	}
}

func TestFoolingTimestampsAndMD5(t *testing.T) {
	payload := []byte("hello")
	const tsval, tsecho = uint32(0x11111111), uint32(0x22222222)
	orig := origTCP(t, payload, tsOpts(tsval, tsecho))

	fp := desync.DefaultFoolParams()
	plan := &desync.Plan{
		Segs: []desync.Seg{
			{Kind: desync.SegFake, Data: []byte{0}, TTL: 3, Fool: desync.FoolTS, FoolP: fp},
			{Kind: desync.SegFake, Data: []byte{0}, TTL: 3, Fool: desync.FoolMD5Sig, FoolP: fp},
			{Kind: desync.SegData, Data: payload},
		},
	}
	got := build(t, orig, plan, BuildOpts{})
	if len(got) != 3 {
		t.Fatalf("want 3 packets, got %d", len(got))
	}

	gotTS, gotEcho, ok := proto.TCPTimestamps(got[0].pkt.TCPOpts)
	if !ok {
		t.Fatalf("the ts-fooled fake lost its timestamp option")
	}
	if want := tsval + uint32(fp.TSIncrement); gotTS != want {
		t.Errorf("fooled TSval = %#x, want %#x (%#x %+d)", gotTS, want, tsval, fp.TSIncrement)
	}
	if gotEcho != tsecho {
		t.Errorf("fooled TSecr = %#x, want the original %#x", gotEcho, tsecho)
	}
	if _, _, ok := proto.TCPTimestamps(got[2].pkt.TCPOpts); !ok {
		t.Errorf("the real segment lost its timestamp option")
	}
	if ts, _, _ := proto.TCPTimestamps(got[2].pkt.TCPOpts); ts != tsval {
		t.Errorf("the real segment's TSval was rewritten to %#x; fooling applies to decoys only", ts)
	}

	// md5sig: kind 19, length 18 must be present on the decoy and absent from the
	// real segment.
	if !hasTCPOption(got[1].pkt.TCPOpts, 19, 18) {
		t.Errorf("the md5sig-fooled fake carries no TCP-MD5 option: %#x", got[1].pkt.TCPOpts)
	}
	if hasTCPOption(got[2].pkt.TCPOpts, 19, 18) {
		t.Errorf("the real segment carries a TCP-MD5 option")
	}
}

// hasTCPOption walks an option block looking for one kind/length pair.
func hasTCPOption(opts []byte, kind, length byte) bool {
	for i := 0; i < len(opts); {
		switch opts[i] {
		case 0:
			return false
		case 1:
			i++
			continue
		}
		if i+1 >= len(opts) {
			return false
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			return false
		}
		if opts[i] == kind && l == int(length) {
			return true
		}
		i += l
	}
	return false
}

func TestFoolingBadSeqAndDataNoAck(t *testing.T) {
	orig := origTCP(t, []byte("x"), nil)
	fp := desync.FoolParams{BadSeqIncrement: -10000, BadAckIncrement: -66000}

	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegFake, Data: []byte{1, 2, 3}, SeqOff: 0, Fool: desync.FoolBadSeq, FoolP: fp},
		{Kind: desync.SegFake, Data: []byte{1, 2, 3}, SeqOff: 0, Fool: desync.FoolDataNoAck, FoolP: fp},
	}}
	got := build(t, orig, plan, BuildOpts{})

	wantSeq := testSeq + uint32(fp.BadSeqIncrement)
	wantAck := testAck + uint32(fp.BadAckIncrement)
	if got[0].pkt.Seq != wantSeq {
		t.Errorf("badseq fake seq = %d, want %d", got[0].pkt.Seq, wantSeq)
	}
	if got[0].pkt.Ack != wantAck {
		t.Errorf("badseq fake ack = %d, want %d", got[0].pkt.Ack, wantAck)
	}
	if got[1].pkt.Flags&proto.TCPAck != 0 {
		t.Errorf("datanoack fake still has the ACK flag set (%#x)", got[1].pkt.Flags)
	}
	if got[1].pkt.Ack != testAck {
		t.Errorf("datanoack fake ack number = %d, want the original %d left in place", got[1].pkt.Ack, testAck)
	}
}

// ---------------------------------------------------------------------------
// ip_id
// ---------------------------------------------------------------------------

func TestIPIDModes(t *testing.T) {
	payload := bytes.Repeat([]byte{7}, 20)
	orig := origTCP(t, payload, nil)

	cases := []struct {
		name string
		mode desync.IPIDMode
		segs []desync.Seg
		want []uint16
	}{
		{
			name: "zero",
			mode: desync.IPIDZero,
			segs: []desync.Seg{
				{Kind: desync.SegData, Data: payload[:5], SeqOff: 0, IPID: desync.IPIDZero},
				{Kind: desync.SegData, Data: payload[5:], SeqOff: 5, IPID: desync.IPIDZero},
			},
			want: []uint16{0, 0},
		},
		{
			name: "same",
			segs: []desync.Seg{
				{Kind: desync.SegData, Data: payload[:5], SeqOff: 0, IPID: desync.IPIDSame},
				{Kind: desync.SegData, Data: payload[5:], SeqOff: 5, IPID: desync.IPIDSame},
			},
			want: []uint16{testIPID, testIPID},
		},
		{
			name: "seq ascending for a split plan",
			segs: []desync.Seg{
				{Kind: desync.SegData, Data: payload[:5], SeqOff: 0, IPID: desync.IPIDSeq},
				{Kind: desync.SegData, Data: payload[5:], SeqOff: 5, IPID: desync.IPIDSeq},
			},
			want: []uint16{100, 101},
		},
		{
			// multidisorder hands the parts over in descending sequence order;
			// nfqws counts the ip_id DOWN so it still ascends in sequence order.
			name: "seq descending for a disorder plan",
			segs: []desync.Seg{
				{Kind: desync.SegData, Data: payload[5:], SeqOff: 5, IPID: desync.IPIDSeq},
				{Kind: desync.SegData, Data: payload[:5], SeqOff: 0, IPID: desync.IPIDSeq},
			},
			want: []uint16{101, 100},
		},
		{
			// fakedsplit: each decoy shares the id of the real part it stands for.
			name: "seqgroup pairs a fake with its real part",
			segs: []desync.Seg{
				{Kind: desync.SegFake, Data: payload[:5], SeqOff: 0, IPID: desync.IPIDSeqGroup},
				{Kind: desync.SegData, Data: payload[:5], SeqOff: 0, IPID: desync.IPIDSeqGroup},
				{Kind: desync.SegFake, Data: payload[5:], SeqOff: 5, IPID: desync.IPIDSeqGroup},
				{Kind: desync.SegData, Data: payload[5:], SeqOff: 5, IPID: desync.IPIDSeqGroup},
			},
			want: []uint16{100, 100, 101, 101},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := build(t, orig, &desync.Plan{Segs: tc.segs}, BuildOpts{IPIDStart: 100})
			if len(got) != len(tc.want) {
				t.Fatalf("want %d packets, got %d", len(tc.want), len(got))
			}
			for i := range tc.want {
				if got[i].pkt.IPID != tc.want[i] {
					t.Errorf("packet %d ip_id = %#x, want %#x", i, got[i].pkt.IPID, tc.want[i])
				}
			}
		})
	}
}

// TestIPIDSeqGroupSurvivesSeqovl checks the group key: a seqovl'd real segment
// starts below the window but ends where its decoy ends, so the two must still
// share an ip_id.
func TestIPIDSeqGroupSurvivesSeqovl(t *testing.T) {
	payload := bytes.Repeat([]byte{7}, 20)
	orig := origTCP(t, payload, nil)
	ovl := bytes.Repeat([]byte{0}, 40)

	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegFake, Data: payload[:5], SeqOff: 0, IPID: desync.IPIDSeqGroup},
		{Kind: desync.SegData, Data: append(append([]byte(nil), ovl...), payload[:5]...), SeqOff: -40, IPID: desync.IPIDSeqGroup},
		{Kind: desync.SegFake, Data: payload[5:], SeqOff: 5, IPID: desync.IPIDSeqGroup},
		{Kind: desync.SegData, Data: payload[5:], SeqOff: 5, IPID: desync.IPIDSeqGroup},
	}}
	got := build(t, orig, plan, BuildOpts{IPIDStart: 7000})
	want := []uint16{7000, 7000, 7001, 7001}
	for i := range want {
		if got[i].pkt.IPID != want[i] {
			t.Errorf("packet %d ip_id = %d, want %d", i, got[i].pkt.IPID, want[i])
		}
	}
}

func TestIPIDRandomUsesTheInjectedSource(t *testing.T) {
	orig := origTCP(t, []byte("abc"), nil)
	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegFake, Data: []byte{1}, IPID: desync.IPIDRandom},
		{Kind: desync.SegData, Data: []byte("abc"), IPID: desync.IPIDDefault},
	}}
	got := build(t, orig, plan, BuildOpts{Rand: fixedRand(0x5a)})
	for i, g := range got {
		if g.pkt.IPID != 0x5a5a {
			t.Errorf("packet %d ip_id = %#x, want the pinned %#x", i, g.pkt.IPID, 0x5a5a)
		}
	}
}

// ---------------------------------------------------------------------------
// repeats, fragments, flags
// ---------------------------------------------------------------------------

func TestRepeatsEmitOnePacketEach(t *testing.T) {
	orig := origTCP(t, []byte("payload"), nil)
	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegFake, Data: []byte{0xff}, TTL: 4, Repeats: 6, IPID: desync.IPIDSeq},
		{Kind: desync.SegData, Data: []byte("payload"), Repeats: 0}, // 0 must mean 1
	}}
	got := build(t, orig, plan, BuildOpts{IPIDStart: 10})
	if len(got) != 7 {
		t.Fatalf("want 6 fake repeats plus 1 real segment = 7 packets, got %d", len(got))
	}
	for i := 0; i < 6; i++ {
		if got[i].pkt.TTL != 4 {
			t.Errorf("repeat %d is not the decoy (TTL %d)", i, got[i].pkt.TTL)
		}
		if want := uint16(10 + i); got[i].pkt.IPID != want {
			t.Errorf("repeat %d ip_id = %d, want %d (each repeat is its own packet)", i, got[i].pkt.IPID, want)
		}
	}
	if !bytes.Equal(got[6].pkt.Payload(), []byte("payload")) {
		t.Errorf("the real segment is missing from the plan output")
	}
}

func TestFragmentSplitsAtTheRequestedOffset(t *testing.T) {
	payload := bytes.Repeat([]byte{0x41}, 200)
	orig := origTCP(t, payload, nil)

	// nfqws' IPFRAG_TCP_DEFAULT is 32: 20 bytes of TCP header plus 12 bytes of
	// payload travel in the first fragment.
	const fragPos = 32
	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegData, Data: payload, SeqOff: 0, Frag: fragPos},
	}}
	got := build(t, orig, plan, BuildOpts{})
	if len(got) != 2 {
		t.Fatalf("want 2 fragments, got %d", len(got))
	}

	first, second := got[0], got[1]
	if first.frag&0x2000 == 0 {
		t.Errorf("first fragment does not have the More-Fragments bit set (%#x)", first.frag)
	}
	if off := first.frag & 0x1fff; off != 0 {
		t.Errorf("first fragment offset = %d, want 0", off*8)
	}
	if got := len(first.raw) - first.ihl; got != fragPos {
		t.Errorf("first fragment carries %d L4 bytes, want %d", got, fragPos)
	}
	if second.frag&0x2000 != 0 {
		t.Errorf("second fragment still has More-Fragments set (%#x)", second.frag)
	}
	if off := int(second.frag&0x1fff) * 8; off != fragPos {
		t.Errorf("second fragment offset = %d bytes, want %d", off, fragPos)
	}
	if got := len(second.raw) - second.ihl; got != 20+len(payload)-fragPos {
		t.Errorf("second fragment carries %d L4 bytes, want %d", got, 20+len(payload)-fragPos)
	}
	for i, g := range got {
		if g.frag&0x4000 != 0 {
			t.Errorf("fragment %d still forbids fragmentation (DF set)", i)
		}
		if !ipHeaderChecksumOK(g.raw) {
			t.Errorf("fragment %d has a bad IPv4 header checksum", i)
		}
		if id := binary.BigEndian.Uint16(g.raw[4:6]); id != binary.BigEndian.Uint16(got[0].raw[4:6]) {
			t.Errorf("fragment %d has ip_id %#x, both fragments must share one", i, id)
		}
	}
}

func TestFragmentFallsBackToAWholePacket(t *testing.T) {
	// A cut position past the end of the packet cannot be honoured; nfqws sends
	// the packet unfragmented, and so must we — never nothing.
	orig := origTCP(t, []byte("tiny"), nil)
	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegData, Data: []byte("tiny"), Frag: 4000},
	}}
	got := build(t, orig, plan, BuildOpts{})
	if len(got) != 1 {
		t.Fatalf("want 1 unfragmented packet, got %d", len(got))
	}
	if got[0].frag&0x2000 != 0 {
		t.Errorf("the fallback packet is marked as a fragment (%#x)", got[0].frag)
	}
}

func TestSegRSTFlags(t *testing.T) {
	orig := origTCP(t, []byte("data"), nil)
	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegRST, SeqOff: 0, TTL: 3},                                     // rst: default flags
		{Kind: desync.SegRST, SeqOff: 0, TTL: 3, Flags: proto.TCPRst | proto.TCPAck}, // rstack
		{Kind: desync.SegData, Data: []byte("data")},
	}}
	got := build(t, orig, plan, BuildOpts{})

	if f := got[0].pkt.Flags; f != proto.TCPRst {
		t.Errorf("rst flags = %#x, want RST (%#x) alone", f, proto.TCPRst)
	}
	if f := got[1].pkt.Flags; f != proto.TCPRst|proto.TCPAck {
		t.Errorf("rstack flags = %#x, want RST|ACK (%#x)", f, proto.TCPRst|proto.TCPAck)
	}
	for i := 0; i < 2; i++ {
		if n := len(got[i].pkt.Payload()); n != 0 {
			t.Errorf("injected RST %d carries %d payload bytes", i, n)
		}
		if got[i].pkt.Seq != testSeq {
			t.Errorf("injected RST %d seq = %d, want the flow's current %d", i, got[i].pkt.Seq, testSeq)
		}
		if got[i].pkt.TTL != 3 {
			t.Errorf("injected RST %d TTL = %d, want 3: it must die before the peer", i, got[i].pkt.TTL)
		}
	}
	if f := got[2].pkt.Flags; f != proto.TCPPsh|proto.TCPAck {
		t.Errorf("data segment flags = %#x, want PSH|ACK", f)
	}
}

func TestSegSynDataRidesOnASyn(t *testing.T) {
	synOpts := []byte{
		2, 4, 0x05, 0xb4, // MSS 1460
		1, 3, 3, 7, // NOP, window scale 7
	}
	orig := mkPkt(t, proto.Tmpl{
		Src: testSrc4, Dst: testDst4,
		SrcPort: testSrcPort, DstPort: testDstPort,
		Seq: testSeq, Flags: proto.TCPSyn, Window: testWindow,
		TTL: testTTL, IPID: testIPID, DF: true, TCPOpts: synOpts,
	})

	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegSynData, Data: bytes.Repeat([]byte{0}, 16), SeqOff: 0, Flags: proto.TCPSyn},
	}}
	got := build(t, orig, plan, BuildOpts{})
	if len(got) != 1 {
		t.Fatalf("want 1 packet, got %d", len(got))
	}
	if f := got[0].pkt.Flags; f != proto.TCPSyn {
		t.Errorf("syndata flags = %#x, want SYN alone", f)
	}
	if n := len(got[0].pkt.Payload()); n != 16 {
		t.Errorf("syndata carries %d payload bytes, want 16", n)
	}
	if got[0].pkt.Seq != testSeq {
		t.Errorf("syndata seq = %d, want the original ISN %d", got[0].pkt.Seq, testSeq)
	}
	if got[0].pkt.TTL != testTTL {
		t.Errorf("syndata TTL = %d, want the original %d: it is meant to reach the server",
			got[0].pkt.TTL, testTTL)
	}
	if !bytes.Equal(got[0].pkt.TCPOpts, orig.TCPOpts) {
		t.Errorf("syndata lost the SYN's options (MSS, window scale):\n got %#x\nwant %#x",
			got[0].pkt.TCPOpts, orig.TCPOpts)
	}
	if !l4ChecksumOK(t, got[0].raw) {
		t.Errorf("syndata has a broken TCP checksum")
	}
}

func TestWindowAndWindowScaleOverride(t *testing.T) {
	orig := origTCP(t, []byte("body"), nil)
	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegData, Data: []byte("body"), Window: 128},
		{Kind: desync.SegData, Data: []byte("body")},
	}}
	got := build(t, orig, plan, BuildOpts{})
	if got[0].pkt.Window != 128 {
		t.Errorf("wssize segment window = %d, want 128", got[0].pkt.Window)
	}
	if got[1].pkt.Window != testWindow {
		t.Errorf("plain segment window = %d, want the original %d", got[1].pkt.Window, testWindow)
	}

	// The scale half only applies on a SYN, where the option lives.
	synOpts := []byte{1, 3, 3, 7, 0, 0, 0, 0}
	synOrig := mkPkt(t, proto.Tmpl{
		Src: testSrc4, Dst: testDst4, SrcPort: testSrcPort, DstPort: testDstPort,
		Seq: testSeq, Flags: proto.TCPSyn, Window: testWindow, TTL: testTTL, TCPOpts: synOpts,
	})
	synPlan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegSynData, Data: []byte{0}, Flags: proto.TCPSyn, Window: 128, WindowScale: 6},
	}}
	synGot := build(t, synOrig, synPlan, BuildOpts{})
	if scale, ok := windowScaleOf(synGot[0].pkt.TCPOpts); !ok || scale != 6 {
		t.Errorf("SYN window scale = %d (present %v), want 6", scale, ok)
	}
}

// windowScaleOf extracts the window-scale shift from an option block.
func windowScaleOf(opts []byte) (uint8, bool) {
	for i := 0; i < len(opts); {
		switch opts[i] {
		case 0:
			return 0, false
		case 1:
			i++
			continue
		}
		if i+1 >= len(opts) {
			return 0, false
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			return 0, false
		}
		if opts[i] == 3 && l == 3 {
			return opts[i+2], true
		}
		i += l
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

func TestIPv6HopByHopInsertion(t *testing.T) {
	payload := []byte("ipv6 request")
	orig := origTCP6(t, payload, nil)
	baseLen := len(orig.Raw)

	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegData, Data: payload, Fool: desync.FoolHopByHop},
		{Kind: desync.SegData, Data: payload, Fool: desync.FoolHopByHop2},
		{Kind: desync.SegData, Data: payload},
	}}
	got := build(t, orig, plan, BuildOpts{})
	if len(got) != 3 {
		t.Fatalf("want 3 packets, got %d", len(got))
	}

	for i, want := range []int{1, 2, 0} {
		raw := got[i].raw
		if n := len(raw); n != baseLen+want*8 {
			t.Errorf("packet %d is %d bytes, want %d (%d extension header(s))", i, n, baseLen+want*8, want)
		}
		if plen := int(binary.BigEndian.Uint16(raw[4:6])); plen != len(raw)-40 {
			t.Errorf("packet %d payload length %d does not match its %d body bytes", i, plen, len(raw)-40)
		}
		if want == 0 {
			if raw[6] != proto.IPProtoTCP {
				t.Errorf("packet %d next header = %d, want TCP", i, raw[6])
			}
			continue
		}
		if raw[6] != proto.IPProtoHopOpt {
			t.Errorf("packet %d next header = %d, want hop-by-hop (%d)", i, raw[6], proto.IPProtoHopOpt)
		}
		// Walk the chain: `want` hop-by-hop headers, then TCP.
		next, off := raw[6], 40
		hops := 0
		for next == proto.IPProtoHopOpt {
			hops++
			next = raw[off]
			off += (int(raw[off+1]) + 1) * 8
		}
		if hops != want {
			t.Errorf("packet %d has %d hop-by-hop header(s), want %d", i, hops, want)
		}
		if next != proto.IPProtoTCP {
			t.Errorf("packet %d chain ends in %d, want TCP", i, next)
		}
		// The pseudo-header did not change, so the checksum must still verify.
		if !l4ChecksumOK(t, raw) {
			t.Errorf("packet %d has a broken TCP checksum after the insertion", i)
		}
	}
}

func TestIPv6FragmentHeaderInsertion(t *testing.T) {
	payload := []byte("ipfrag1")
	orig := origTCP6(t, payload, nil)
	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegData, Data: payload, Fool: desync.FoolIPFrag1},
	}}
	pkts, err := BuildPlanPackets(orig, plan, BuildOpts{Rand: fixedRand(0x11)})
	if err != nil {
		t.Fatalf("BuildPlanPackets: %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("want 1 packet, got %d", len(pkts))
	}
	raw := pkts[0]
	if raw[6] != proto.IPProtoFrag {
		t.Fatalf("next header = %d, want the fragment header (%d)", raw[6], proto.IPProtoFrag)
	}
	if raw[40] != proto.IPProtoTCP {
		t.Errorf("the fragment header hands over to %d, want TCP", raw[40])
	}
	if off := binary.BigEndian.Uint16(raw[42:44]); off != 0 {
		t.Errorf("fragment offset/flags = %#x, want 0 (one fragment covering the whole datagram)", off)
	}
	if id := binary.BigEndian.Uint32(raw[44:48]); id != 0x11111111 {
		t.Errorf("fragment identification = %#x, want the pinned %#x", id, 0x11111111)
	}
	if plen := int(binary.BigEndian.Uint16(raw[4:6])); plen != len(raw)-40 {
		t.Errorf("payload length %d does not match the %d body bytes", plen, len(raw)-40)
	}
	if !l4ChecksumOK(t, raw) {
		t.Errorf("the TCP checksum broke: the IPv6 pseudo-header must be unaffected")
	}
}

func TestIPv6ExtHeaderOrderIsRFCLegal(t *testing.T) {
	// Both bits at once: hop-by-hop must come FIRST and the fragment header after
	// it, or a peer's IPv6 stack rejects the packet.
	payload := []byte("both")
	orig := origTCP6(t, payload, nil)
	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegData, Data: payload, Fool: desync.FoolHopByHop | desync.FoolIPFrag1},
	}}
	pkts, err := BuildPlanPackets(orig, plan, BuildOpts{Rand: fixedRand(2)})
	if err != nil {
		t.Fatalf("BuildPlanPackets: %v", err)
	}
	raw := pkts[0]
	if raw[6] != proto.IPProtoHopOpt {
		t.Fatalf("first next header = %d, want hop-by-hop", raw[6])
	}
	if raw[40] != proto.IPProtoFrag {
		t.Fatalf("second next header = %d, want the fragment header", raw[40])
	}
	if raw[48] != proto.IPProtoTCP {
		t.Fatalf("third next header = %d, want TCP", raw[48])
	}
}

func TestIPv4IgnoresIPv6Fooling(t *testing.T) {
	payload := []byte("v4 only")
	orig := origTCP(t, payload, nil)
	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegData, Data: payload, Fool: desync.FoolHopByHop2 | desync.FoolIPFrag1},
	}}
	got := build(t, orig, plan, BuildOpts{})
	if len(got) != 1 {
		t.Fatalf("want 1 packet, got %d", len(got))
	}
	if got[0].pkt.Proto != proto.IPProtoTCP {
		t.Errorf("IPv4 packet protocol = %d; the IPv6-only fooling bits must be no-ops here",
			got[0].pkt.Proto)
	}
	if !l4ChecksumOK(t, got[0].raw) {
		t.Errorf("the IPv4 packet was mangled")
	}
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

func TestDgramsFakeAndReal(t *testing.T) {
	payload := bytes.Repeat([]byte{0xc0}, 1200) // a QUIC Initial-sized datagram
	orig := origUDP(t, payload)

	fake := bytes.Repeat([]byte{0x40}, 620)
	plan := &desync.Plan{Dgrams: []desync.Dgram{
		{Kind: desync.SegFake, Data: fake, TTL: 3, Fool: desync.FoolBadSum, Repeats: 3},
		{Kind: desync.SegData, Data: payload},
	}}
	got := build(t, orig, plan, BuildOpts{Rand: fixedRand(0x2b)})
	if len(got) != 4 {
		t.Fatalf("want 3 fake repeats plus the real datagram = 4 packets, got %d", len(got))
	}
	for i := 0; i < 3; i++ {
		if !got[i].pkt.IsUDP() {
			t.Fatalf("packet %d is not UDP", i)
		}
		if got[i].pkt.TTL != 3 {
			t.Errorf("fake datagram %d TTL = %d, want 3", i, got[i].pkt.TTL)
		}
		if l4ChecksumOK(t, got[i].raw) {
			t.Errorf("fake datagram %d has a valid UDP checksum, badsum wants it broken", i)
		}
		if n := len(got[i].pkt.Payload()); n != len(fake) {
			t.Errorf("fake datagram %d carries %d bytes, want %d", i, n, len(fake))
		}
	}
	real := got[3]
	if real.pkt.TTL != testTTL {
		t.Errorf("real datagram TTL = %d, want the original %d", real.pkt.TTL, testTTL)
	}
	if !l4ChecksumOK(t, real.raw) {
		t.Errorf("the real datagram has a broken UDP checksum")
	}
	if !bytes.Equal(real.pkt.Payload(), payload) {
		t.Errorf("the real datagram payload was mangled")
	}
	if real.pkt.SrcPort != testSrcPort || real.pkt.DstPort != testDstPort {
		t.Errorf("the 4-tuple changed: %d -> %d", real.pkt.SrcPort, real.pkt.DstPort)
	}
}

func TestDgramFragment(t *testing.T) {
	payload := bytes.Repeat([]byte{0x33}, 100)
	orig := origUDP(t, payload)
	// nfqws' IPFRAG_UDP_DEFAULT is 8: the cut lands right after the UDP header.
	plan := &desync.Plan{Dgrams: []desync.Dgram{
		{Kind: desync.SegData, Data: payload, Frag: 8},
	}}
	got := build(t, orig, plan, BuildOpts{Rand: fixedRand(1)})
	if len(got) != 2 {
		t.Fatalf("want 2 fragments, got %d", len(got))
	}
	if got[0].frag&0x2000 == 0 {
		t.Errorf("first fragment lacks More-Fragments")
	}
	if n := len(got[0].raw) - got[0].ihl; n != 8 {
		t.Errorf("first fragment carries %d L4 bytes, want exactly the 8-byte UDP header", n)
	}
	if off := int(got[1].frag&0x1fff) * 8; off != 8 {
		t.Errorf("second fragment offset = %d, want 8", off)
	}
}

// ---------------------------------------------------------------------------
// contract edges
// ---------------------------------------------------------------------------

func TestBuildPlanPacketsEdgeCases(t *testing.T) {
	orig := origTCP(t, []byte("x"), nil)

	if pkts, err := BuildPlanPackets(orig, nil, BuildOpts{}); err != nil || pkts != nil {
		t.Errorf("a nil plan must produce nothing without an error, got %d packets / %v", len(pkts), err)
	}
	if pkts, err := BuildPlanPackets(orig, &desync.Plan{DropOriginal: true}, BuildOpts{}); err != nil || len(pkts) != 0 {
		t.Errorf("an empty plan (the block op) must produce nothing, got %d packets / %v", len(pkts), err)
	}
	if _, err := BuildPlanPackets(nil, &desync.Plan{}, BuildOpts{}); !errors.Is(err, ErrNoPacket) {
		t.Errorf("a nil packet must yield ErrNoPacket, got %v", err)
	}

	// Segments on a UDP flow (and datagrams on a TCP flow) are engine bugs, and
	// the transport must say so instead of building nonsense.
	udp := origUDP(t, []byte("q"))
	if _, err := BuildPlanPackets(udp, &desync.Plan{Segs: []desync.Seg{{Data: []byte("x")}}}, BuildOpts{}); !errors.Is(err, ErrNoPacket) {
		t.Errorf("TCP segments on a UDP packet must yield ErrNoPacket, got %v", err)
	}
	if _, err := BuildPlanPackets(orig, &desync.Plan{Dgrams: []desync.Dgram{{Data: []byte("x")}}}, BuildOpts{}); !errors.Is(err, ErrNoPacket) {
		t.Errorf("datagrams on a TCP packet must yield ErrNoPacket, got %v", err)
	}
}

func TestTheFourTupleIsNeverRewritten(t *testing.T) {
	payload := []byte("keep my ports")
	orig := origTCP(t, payload, nil)
	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegFake, Data: []byte{1}, TTL: 2},
		{Kind: desync.SegData, Data: payload[:4], SeqOff: 0},
		{Kind: desync.SegData, Data: payload[4:], SeqOff: 4},
	}}
	for i, g := range build(t, orig, plan, BuildOpts{}) {
		if g.pkt.Src != testSrc4 || g.pkt.Dst != testDst4 {
			t.Errorf("packet %d addresses = %s -> %s, want %s -> %s",
				i, g.pkt.Src, g.pkt.Dst, testSrc4, testDst4)
		}
		if g.pkt.SrcPort != testSrcPort || g.pkt.DstPort != testDstPort {
			t.Errorf("packet %d ports = %d -> %d, want %d -> %d",
				i, g.pkt.SrcPort, g.pkt.DstPort, testSrcPort, testDstPort)
		}
	}
}

func TestFragmentForMTU(t *testing.T) {
	orig := origTCP(t, bytes.Repeat([]byte{9}, 1600), nil)

	if got := fragmentForMTU(orig.Raw, 0); len(got) != 1 {
		t.Errorf("mtu 0 must disable the guard, got %d parts", len(got))
	}
	if got := fragmentForMTU(orig.Raw, 4000); len(got) != 1 {
		t.Errorf("a packet under the MTU must not be split, got %d parts", len(got))
	}

	parts := fragmentForMTU(orig.Raw, 1500)
	if len(parts) != 2 {
		t.Fatalf("a %d-byte packet at mtu 1500 wants 2 fragments, got %d", len(orig.Raw), len(parts))
	}
	total := 0
	for i, p := range parts {
		if len(p) > 1500 {
			t.Errorf("fragment %d is %d bytes, over the MTU", i, len(p))
		}
		if !ipHeaderChecksumOK(p) {
			t.Errorf("fragment %d has a bad header checksum", i)
		}
		total += len(p) - 20
	}
	if want := len(orig.Raw) - 20; total != want {
		t.Errorf("fragments carry %d L4 bytes in total, want %d", total, want)
	}

	// IPv6 cannot be fragmented in place; the guard must hand the packet back
	// rather than lose it.
	v6 := origTCP6(t, bytes.Repeat([]byte{9}, 1600), nil)
	if got := fragmentForMTU(v6.Raw, 1500); len(got) != 1 {
		t.Errorf("IPv6 must be returned whole, got %d parts", len(got))
	}
}

func TestTCPOptSetWindowScale(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want []byte
	}{
		{"present", []byte{1, 3, 3, 7}, []byte{1, 3, 3, 2}},
		{"absent", []byte{2, 4, 0x05, 0xb4}, []byte{2, 4, 0x05, 0xb4}},
		{"nil", nil, nil},
		{"truncated length", []byte{3}, []byte{3}},
		{"hostile length", []byte{3, 0, 0, 0}, []byte{3, 0, 0, 0}},
		{"ends at EOL", []byte{0, 3, 3, 7}, []byte{0, 3, 3, 7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tcpOptSetWindowScale(tc.in, 2)
			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %#x, want %#x", got, tc.want)
			}
		})
	}
}

func TestHopByHopCount(t *testing.T) {
	cases := []struct {
		f    desync.Fooling
		want int
	}{
		{desync.FoolNone, 0},
		{desync.FoolBadSum, 0},
		{desync.FoolHopByHop, 1},
		{desync.FoolHopByHop2, 2},
		{desync.FoolHopByHop | desync.FoolHopByHop2, 2},
	}
	for _, tc := range cases {
		if got := hopByHopCount(tc.f); got != tc.want {
			t.Errorf("hopByHopCount(%#x) = %d, want %d", tc.f, got, tc.want)
		}
	}
}

func TestNormaliseChecksums(t *testing.T) {
	t.Run("a correct packet is left alone", func(t *testing.T) {
		p := origTCP(t, []byte("payload"), tsOpts(1, 2))
		before := append([]byte(nil), p.Raw...)
		fixIP, fixL4 := NormaliseChecksums(p)
		if fixIP || fixL4 {
			t.Errorf("a valid packet was reported as repaired (ip=%v l4=%v)", fixIP, fixL4)
		}
		if !bytes.Equal(p.Raw, before) {
			t.Errorf("a valid packet was modified")
		}
	})

	t.Run("an offloaded L4 checksum is recomputed", func(t *testing.T) {
		p := origTCP(t, []byte("payload"), nil)
		p.Raw[p.L3Len+16], p.Raw[p.L3Len+17] = 0, 0 // what checksum offload leaves
		fixIP, fixL4 := NormaliseChecksums(p)
		if fixIP {
			t.Errorf("the IPv4 header checksum was untouched, it must not be reported as fixed")
		}
		if !fixL4 {
			t.Fatalf("a zero TCP checksum was not repaired")
		}
		if !l4ChecksumOK(t, p.Raw) {
			t.Errorf("the repaired TCP checksum does not verify")
		}
	})

	t.Run("an offloaded header checksum is recomputed", func(t *testing.T) {
		p := origUDP(t, []byte("datagram"))
		p.Raw[10], p.Raw[11] = 0, 0
		fixIP, _ := NormaliseChecksums(p)
		if !fixIP {
			t.Fatalf("a zero IPv4 header checksum was not repaired")
		}
		if !ipHeaderChecksumOK(p.Raw) {
			t.Errorf("the repaired header checksum does not verify")
		}
	})

	t.Run("a first fragment keeps its whole-datagram L4 checksum", func(t *testing.T) {
		raw, err := (&proto.Tmpl{
			Src: testSrc4, Dst: testDst4, SrcPort: testSrcPort, DstPort: testDstPort,
			Seq: testSeq, Flags: proto.TCPPsh | proto.TCPAck, Window: testWindow,
			TTL: testTTL, IPID: testIPID, Payload: bytes.Repeat([]byte{1}, 40),
		}).Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		// More-Fragments, offset 0: proto.Parse accepts this, and the L4 checksum
		// covers bytes that are in the other fragment.
		binary.BigEndian.PutUint16(raw[6:8], 0x2000)
		p, err := proto.Parse(raw)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		sum := binary.BigEndian.Uint16(p.Raw[p.L3Len+16 : p.L3Len+18])
		fixIP, fixL4 := NormaliseChecksums(p)
		if !fixIP {
			t.Errorf("the header checksum went stale when MF was set and was not repaired")
		}
		if fixL4 {
			t.Errorf("the L4 checksum of a fragment must never be recomputed")
		}
		if got := binary.BigEndian.Uint16(p.Raw[p.L3Len+16 : p.L3Len+18]); got != sum {
			t.Errorf("the fragment's L4 checksum changed from %#x to %#x", sum, got)
		}
	})

	t.Run("ipv6 with an extension chain is left alone", func(t *testing.T) {
		p6 := origTCP6(t, []byte("body"), nil)
		withHBH, err := proto.AddIPv6ExtHdr(p6.Raw, 1, proto.IPProtoHopOpt)
		if err != nil {
			t.Fatalf("AddIPv6ExtHdr: %v", err)
		}
		p, err := proto.Parse(withHBH)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		p.Raw[p.L3Len+16], p.Raw[p.L3Len+17] = 0, 0
		if _, fixL4 := NormaliseChecksums(p); fixL4 {
			t.Errorf("an IPv6 packet with an extension chain must not have its L4 checksum touched: " +
				"the chain may hide a Fragment header")
		}
	})

	t.Run("plain ipv6 is repaired", func(t *testing.T) {
		p := origTCP6(t, []byte("body"), nil)
		p.Raw[p.L3Len+16], p.Raw[p.L3Len+17] = 0, 0
		if _, fixL4 := NormaliseChecksums(p); !fixL4 {
			t.Fatalf("a zero TCP checksum on plain IPv6 was not repaired")
		}
		if !l4ChecksumOK(t, p.Raw) {
			t.Errorf("the repaired IPv6 TCP checksum does not verify")
		}
	})

	t.Run("hostile input", func(t *testing.T) {
		if ip, l4 := NormaliseChecksums(nil); ip || l4 {
			t.Errorf("a nil packet must be a no-op")
		}
		if ip, l4 := NormaliseChecksums(&proto.Pkt{Ver: 4, Raw: []byte{0x45, 0}}); ip || l4 {
			t.Errorf("a truncated header must be a no-op")
		}
	})
}

func TestInsertIPv6FragHdrRejectsBadInput(t *testing.T) {
	if _, err := insertIPv6FragHdr(nil, 0); err == nil {
		t.Errorf("an empty buffer must be rejected")
	}
	v4 := origTCP(t, []byte("x"), nil)
	if _, err := insertIPv6FragHdr(v4.Raw, 0); err == nil {
		t.Errorf("an IPv4 packet must be rejected")
	}
	// A header claiming more payload than it has.
	bad := make([]byte, 44)
	bad[0] = 0x60
	binary.BigEndian.PutUint16(bad[4:6], 9000)
	if _, err := insertIPv6FragHdr(bad, 0); err == nil {
		t.Errorf("an over-long payload length must be rejected")
	}
}
