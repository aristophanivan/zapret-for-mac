//go:build darwin

package divert

import (
	"errors"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
	"github.com/naladwepo/zapret-for-mac/internal/transport"
)

// Regression tests for the review findings the integration pass fixed in this
// package. Every one of them failed before the fix.

// TestRealSegmentsCarryTheOriginalFlags is finding 4.
//
// BEFORE: every SegData was emitted with a hard-coded PSH|ACK, so a client that
// writes a request and immediately close()s — HTTP/1.0, `curl --http1.0`, any
// write()+close() pair the kernel coalesces into one PSH|ACK|FIN segment — had its
// FIN dropped by the split. The client then sat in FIN_WAIT_1 with an un-ACKed FIN
// while the server waited for request bytes that never came, and the
// retransmission was re-segmented exactly the same way.
func TestRealSegmentsCarryTheOriginalFlags(t *testing.T) {
	payload := []byte("GET / HTTP/1.0\r\nHost: a.example\r\n\r\n")
	orig := mkPkt(t, proto.Tmpl{
		Src: testSrc4, Dst: testDst4,
		SrcPort: testSrcPort, DstPort: testDstPort,
		Seq: testSeq, Ack: testAck,
		// The client's own flags: request, push, and "I am done sending".
		Flags:  proto.TCPPsh | proto.TCPAck | proto.TCPFin | proto.TCPEce,
		Window: testWindow, TTL: testTTL, IPID: testIPID, DF: true,
		Payload: payload,
	})

	cut := 5
	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegData, Data: payload[:cut], SeqOff: 0},
		{Kind: desync.SegData, Data: payload[cut:], SeqOff: int32(cut)},
	}}
	got := build(t, orig, plan, BuildOpts{})
	if len(got) != 2 {
		t.Fatalf("produced %d packets, want 2", len(got))
	}
	// The first segment does NOT close the stream...
	if f := got[0].pkt.Flags; f&proto.TCPFin != 0 {
		t.Errorf("segment 0 flags %#02x carry FIN; only the segment with the last byte may", f)
	}
	// ...the one carrying the last byte does.
	if f := got[1].pkt.Flags; f&proto.TCPFin == 0 {
		t.Errorf("segment 1 flags %#02x lost the client's FIN", f)
	}
	for i, o := range got {
		if f := o.pkt.Flags; f&proto.TCPPsh == 0 || f&proto.TCPAck == 0 {
			t.Errorf("segment %d flags %#02x, want PSH|ACK at minimum", i, f)
		}
		if f := o.pkt.Flags; f&proto.TCPEce == 0 {
			t.Errorf("segment %d flags %#02x dropped the client's ECE bit", i, f)
		}
		if f := o.pkt.Flags; f&proto.TCPSyn != 0 {
			t.Errorf("segment %d flags %#02x carry SYN on a data segment", i, f)
		}
	}
}

// TestFakeSegmentsKeepTheirOwnFlags: a decoy is built by us and must not inherit
// the client's FIN, which would half-close the connection for real.
func TestFakeSegmentsKeepTheirOwnFlags(t *testing.T) {
	payload := []byte("GET / HTTP/1.0\r\n\r\n")
	orig := mkPkt(t, proto.Tmpl{
		Src: testSrc4, Dst: testDst4,
		SrcPort: testSrcPort, DstPort: testDstPort,
		Seq: testSeq, Ack: testAck,
		Flags:  proto.TCPPsh | proto.TCPAck | proto.TCPFin,
		Window: testWindow, TTL: testTTL, IPID: testIPID, DF: true,
		Payload: payload,
	})
	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegFake, Data: []byte("decoy"), SeqOff: 0, TTL: 3},
		{Kind: desync.SegData, Data: payload, SeqOff: 0},
	}}
	got := build(t, orig, plan, BuildOpts{})
	if len(got) != 2 {
		t.Fatalf("produced %d packets, want 2", len(got))
	}
	if f := got[0].pkt.Flags; f&proto.TCPFin != 0 {
		t.Errorf("the decoy carries FIN (%#02x); it must never close the real connection", f)
	}
	if f := got[1].pkt.Flags; f&proto.TCPFin == 0 {
		t.Errorf("the real segment lost the FIN (%#02x)", f)
	}
}

// TestNonFinPacketNeverGainsFin: the FIN logic must be driven by the intercepted
// packet, not by "is this the last segment".
func TestNonFinPacketNeverGainsFin(t *testing.T) {
	payload := []byte("0123456789")
	orig := origTCP(t, payload, nil) // PSH|ACK, no FIN
	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegData, Data: payload[:4], SeqOff: 0},
		{Kind: desync.SegData, Data: payload[4:], SeqOff: 4},
	}}
	for i, o := range build(t, orig, plan, BuildOpts{}) {
		if f := o.pkt.Flags; f&proto.TCPFin != 0 {
			t.Errorf("segment %d invented a FIN (%#02x)", i, f)
		}
	}
}

// TestTrafficClassAndFlowLabelSurvive is finding 14: Tmpl always wrote a zero
// DSCP/ECN byte, so a flow using ECN had its marking stripped from every
// re-emitted segment while its unmodified packets kept theirs — silently
// disabling ECN and handing a DPI fingerprinter a free signal.
func TestTrafficClassAndFlowLabelSurvive(t *testing.T) {
	payload := []byte("0123456789")

	t.Run("ipv4_dscp_ecn", func(t *testing.T) {
		orig := mkPkt(t, proto.Tmpl{
			Src: testSrc4, Dst: testDst4,
			SrcPort: testSrcPort, DstPort: testDstPort,
			Seq: testSeq, Ack: testAck,
			Flags: proto.TCPPsh | proto.TCPAck, Window: testWindow,
			TTL: testTTL, IPID: testIPID, DF: true,
			TrafficClass: 0x8a, // DSCP 34 (AF41) + ECT(0)
			Payload:      payload,
		})
		if orig.TrafficClass != 0x8a {
			t.Fatalf("the fixture did not round-trip: TrafficClass = %#02x", orig.TrafficClass)
		}
		plan := &desync.Plan{Segs: []desync.Seg{
			{Kind: desync.SegData, Data: payload[:4], SeqOff: 0},
			{Kind: desync.SegData, Data: payload[4:], SeqOff: 4},
		}}
		for i, o := range build(t, orig, plan, BuildOpts{}) {
			if got := o.raw[1]; got != 0x8a {
				t.Errorf("segment %d TOS byte = %#02x, want %#02x", i, got, 0x8a)
			}
		}
	})

	t.Run("ipv6_traffic_class_and_flow_label", func(t *testing.T) {
		orig := mkPkt(t, proto.Tmpl{
			Src: testSrc6, Dst: testDst6,
			SrcPort: testSrcPort, DstPort: testDstPort,
			Seq: testSeq, Ack: testAck,
			Flags: proto.TCPPsh | proto.TCPAck, Window: testWindow,
			TTL: testTTL, DF: true,
			TrafficClass: 0x02, // ECT(0)
			FlowLabel:    0xabcde,
			Payload:      payload,
		})
		if orig.TrafficClass != 0x02 || orig.FlowLabel != 0xabcde {
			t.Fatalf("the fixture did not round-trip: tc=%#02x fl=%#x", orig.TrafficClass, orig.FlowLabel)
		}
		plan := &desync.Plan{Segs: []desync.Seg{{Kind: desync.SegData, Data: payload, SeqOff: 0}}}
		got := build(t, orig, plan, BuildOpts{})
		if len(got) != 1 {
			t.Fatalf("produced %d packets, want 1", len(got))
		}
		if got[0].pkt.TrafficClass != 0x02 {
			t.Errorf("traffic class = %#02x, want 0x02", got[0].pkt.TrafficClass)
		}
		if got[0].pkt.FlowLabel != 0xabcde {
			t.Errorf("flow label = %#x, want 0xabcde", got[0].pkt.FlowLabel)
		}
	})
}

// TestPlanMustTileThePayload is the belt-and-braces guard for finding 1: a plan
// whose real segments do not reproduce the intercepted byte stream exactly once
// must be REFUSED, because emitting it desynchronises the client's own TCP
// sequence space for the rest of the connection. The datapath's response to the
// error is to forward the application's own packet, which is always safe.
func TestPlanMustTileThePayload(t *testing.T) {
	payload := []byte("0123456789")
	orig := origTCP(t, payload, nil)

	for _, tc := range []struct {
		name string
		segs []desync.Seg
		ok   bool
	}{
		{"exact", []desync.Seg{
			{Kind: desync.SegData, Data: payload[:4], SeqOff: 0},
			{Kind: desync.SegData, Data: payload[4:], SeqOff: 4},
		}, true},
		{"whole", []desync.Seg{{Kind: desync.SegData, Data: payload, SeqOff: 0}}, true},
		{"seqovl_prefix", []desync.Seg{
			{Kind: desync.SegData, Data: append([]byte("xxxx"), payload[:4]...), SeqOff: -4},
			{Kind: desync.SegData, Data: payload[4:], SeqOff: 4},
		}, true},
		{"five_bytes_too_long", []desync.Seg{
			{Kind: desync.SegData, Data: append(append([]byte{}, payload...), []byte("extra")...), SeqOff: 0},
		}, false},
		{"hole", []desync.Seg{
			{Kind: desync.SegData, Data: payload[:4], SeqOff: 0},
			{Kind: desync.SegData, Data: payload[6:], SeqOff: 6},
		}, false},
		{"short", []desync.Seg{{Kind: desync.SegData, Data: payload[:4], SeqOff: 0}}, false},
		{"fakes_only_is_fine", []desync.Seg{
			{Kind: desync.SegFake, Data: []byte("decoy"), SeqOff: 0},
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := BuildPlan(orig, &desync.Plan{Segs: tc.segs}, BuildOpts{})
			switch {
			case tc.ok && err != nil:
				t.Fatalf("BuildPlan refused a valid plan: %v", err)
			case !tc.ok && err == nil:
				t.Fatal("BuildPlan accepted a plan that does not tile the payload")
			case !tc.ok && !errors.Is(err, ErrNoPacket):
				t.Fatalf("error %v does not wrap ErrNoPacket, so the datapath cannot classify it", err)
			}
		})
	}
}

// TestBuildPlanReportsIPIDCount is finding 15: the transport advanced its running
// --ip-id=seq counter by the number of WIRE packets, but a fragmentation pass turns
// one packet into two that share a single ip_id by construction, so the sequence
// skipped values.
func TestBuildPlanReportsIPIDCount(t *testing.T) {
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = byte(i)
	}
	orig := origTCP(t, payload, nil)

	// One segment, fragmented at offset 24: two wire packets, one ip_id.
	plan := &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegData, Data: payload, SeqOff: 0, IPID: desync.IPIDSeq, Frag: 24},
	}}
	pkts, ids, err := BuildPlan(orig, plan, BuildOpts{IPIDStart: 0x1000})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(pkts) != 2 {
		t.Fatalf("produced %d packets, want 2 fragments", len(pkts))
	}
	if ids != 1 {
		t.Fatalf("ids = %d, want 1 (both fragments share one ip_id)", ids)
	}

	// Three repeats of a fake plus one real segment: four ids, four packets.
	plan = &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegFake, Data: payload[:20], SeqOff: 0, IPID: desync.IPIDSeq, Repeats: 3},
		{Kind: desync.SegData, Data: payload, SeqOff: 0, IPID: desync.IPIDSeq},
	}}
	pkts, ids, err = BuildPlan(orig, plan, BuildOpts{IPIDStart: 0x1000})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(pkts) != 4 || ids != 4 {
		t.Fatalf("%d packets / %d ids, want 4 / 4", len(pkts), ids)
	}
}

// TestNormaliseChecksumsAcceptsAZeroUDPChecksum is finding 13: RFC 768 makes an
// all-zero checksum on IPv4/UDP mean "no checksum", which is legal. Rewriting it
// raised the alarming "the kernel handed us an unset checksum" warning and sent
// operators hunting a checksum-offload bug that does not exist.
func TestNormaliseChecksumsAcceptsAZeroUDPChecksum(t *testing.T) {
	p := origUDP(t, []byte("hello"))
	// Blank the checksum the way a sender that opts out of it would.
	sumOff := p.L3Len + 6
	p.Raw[sumOff], p.Raw[sumOff+1] = 0, 0
	// The header checksum still has to be right, or the IP repair alone would fire.
	want := ipv4HeaderChecksum(p.Raw[:p.L3Len])
	p.Raw[10], p.Raw[11] = byte(want>>8), byte(want)

	fixIP, fixL4 := NormaliseChecksums(p)
	if fixIP {
		t.Errorf("the IPv4 header checksum was rewritten although it was correct")
	}
	if fixL4 {
		t.Error("a legitimately zero IPv4/UDP checksum was reported as kernel corruption")
	}
	if p.Raw[sumOff] != 0 || p.Raw[sumOff+1] != 0 {
		t.Errorf("the zero checksum was overwritten with %#02x%02x", p.Raw[sumOff], p.Raw[sumOff+1])
	}

	// A WRONG non-zero checksum must still be repaired.
	p.Raw[sumOff], p.Raw[sumOff+1] = 0xde, 0xad
	if _, fixL4 = NormaliseChecksums(p); !fixL4 {
		t.Error("a genuinely wrong UDP checksum was left alone")
	}
}

// TestTeardownIsNotALatch is finding 2.
//
// BEFORE: teardown() set a one-shot `torn` flag and returned early on every later
// call. A Close() that landed while setup() was still running therefore found all
// four handles nil, claimed nothing, and LATCHED — so the teardown that Start's own
// defer performed returned immediately and the pf ruleset, the pf reference, the
// utun and the BPF fd stayed installed. pf then route-to'd the whole port window at
// a utun whose datapath was dead (xnu's pf_route drops such a packet), so the user's
// traffic on 80/443 stopped — and Start returned nil, so the log said "clean stop".
//
// The property this pins: a teardown that had nothing to undo must not stop a later
// one from undoing a real install.
func TestTeardownIsNotALatch(t *testing.T) {
	tr := newTestTransport(t, transport.Config{})
	tr.utun = nil

	// First call: nothing installed, nothing to claim.
	if err := tr.teardown(); err != nil {
		t.Fatalf("teardown with nothing installed = %v, want nil", err)
	}

	// Now something IS installed — the state an in-flight setup would have
	// published between two steps.
	cancelled := false
	tr.mu.Lock()
	tr.obsCancel = func() { cancelled = true }
	tr.mu.Unlock()

	if err := tr.teardown(); err != nil {
		t.Fatalf("second teardown = %v, want nil", err)
	}
	if !cancelled {
		t.Fatal("the second teardown claimed nothing: the earlier no-op call latched, " +
			"which is exactly how a Close() racing setup() used to leak the pf ruleset")
	}
	tr.mu.Lock()
	left := tr.obsCancel
	tr.mu.Unlock()
	if left != nil {
		t.Error("teardown did not clear the handle it claimed, so a third call would repeat it")
	}
}

// TestStopRequestedAbortsSetup: setup checks for a Close between its privileged
// steps and reports errStopDuringSetup, which Start turns into a clean stop rather
// than a startup failure the operator has to act on.
func TestStopRequestedAbortsSetup(t *testing.T) {
	tr := newTestTransport(t, transport.Config{})
	if err := tr.stopRequested(); err != nil {
		t.Fatalf("stopRequested before Close = %v, want nil", err)
	}
	tr.closeOnce.Do(func() { close(tr.closed) })
	err := tr.stopRequested()
	if err == nil {
		t.Fatal("stopRequested after Close returned nil")
	}
	if !errors.Is(err, errStopDuringSetup) {
		t.Fatalf("error %v does not wrap errStopDuringSetup, so Start cannot tell a stop from a failure", err)
	}
}
