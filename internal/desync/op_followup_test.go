// This file is the follow-up wave's test set: the contract fields Seg.Window,
// Seg.WindowScale, Dgram.Frag, IPIDSeqGroup/IPIDSame, OpParams.MidHost and
// OpParams.Tamper, from the op that fills them all the way back to the strategy
// loader that compiles them.
//
// It deliberately lives in the external test package: the loader assertions need
// internal/strategy, which imports internal/desync, so an in-package test file
// could not reach it. Everything here therefore goes through desync's exported
// API, which is also the surface a transport sees.
package desync_test

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// nfqws' --dpi-desync-ipfrag-pos-udp default and its fallback, both 8 (one
// 8-byte fragment unit, so the UDP header travels alone in the first fragment).
const fragPosUDPDefault = 8

// httpGet is a minimal, well-formed request with a Host header.
const httpGet = "GET /index.html HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: curl/8\r\n\r\n"

// fuLoadHello returns the ClientHello fixture (SNI www.google.com).
func fuLoadHello(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "fakes", "tls_clienthello_www_google_com.bin"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

// fuCtx builds a TCP Ctx over payload.
func fuCtx(payload []byte, caps desync.Caps, p desync.OpParams) *desync.Ctx {
	return &desync.Ctx{
		Flow:    &desync.Flow{Key: desync.FlowKey{Proto: proto.IPProtoTCP, Dst: netip.MustParseAddr("142.250.185.100")}},
		Payload: payload,
		Info:    proto.Classify(payload, 443, proto.IPProtoTCP),
		Caps:    caps,
		Params:  p,
	}
}

// fuUDPCtx builds a UDP Ctx over payload, for the given peer address.
func fuUDPCtx(payload []byte, dst string, p desync.OpParams) *desync.Ctx {
	return &desync.Ctx{
		Flow:    &desync.Flow{Key: desync.FlowKey{Proto: proto.IPProtoUDP, Dst: netip.MustParseAddr(dst)}},
		Payload: payload,
		Info:    proto.Classify(payload, 443, proto.IPProtoUDP),
		Caps:    desync.FullCaps(),
		Params:  p,
	}
}

// fuApply runs one op over an existing plan (nil for a fresh one).
func fuApply(t *testing.T, name string, c *desync.Ctx, p *desync.Plan) *desync.Plan {
	t.Helper()
	op, err := desync.Lookup(name)
	if err != nil {
		t.Fatalf("Lookup(%q): %v", name, err)
	}
	if p == nil {
		p = &desync.Plan{}
	}
	if err := op.Apply(c, p); err != nil {
		t.Fatalf("%s.Apply: %v", name, err)
	}
	return p
}

// fuDegrade runs one op's socket-level fallback.
func fuDegrade(t *testing.T, name string, c *desync.Ctx) *desync.Plan {
	t.Helper()
	op, err := desync.Lookup(name)
	if err != nil {
		t.Fatalf("Lookup(%q): %v", name, err)
	}
	d, ok := op.(desync.Degrader)
	if !ok {
		t.Fatalf("%s does not implement Degrader", name)
	}
	p := &desync.Plan{}
	if err := d.Degrade(c, p); err != nil {
		t.Fatalf("%s.Degrade: %v", name, err)
	}
	return p
}

// fuNoted reports whether any Degraded entry contains sub.
func fuNoted(p *desync.Plan, sub string) bool {
	for _, d := range p.Degraded {
		if strings.Contains(d, sub) {
			return true
		}
	}
	return false
}

// ---------- wssize ----------

// TestWSSizeSetsWindowOnRealSegments pins the contract fields --wssize now uses:
// every real segment carries the window, decoys do not.
func TestWSSizeSetsWindowOnRealSegments(t *testing.T) {
	hello := fuLoadHello(t)
	prm := desync.OpParams{
		WSSize:      128,
		WSSizeScale: 6,
		SplitPos:    []desync.PosSpec{{Marker: proto.MarkerMidSLD}},
	}
	c := fuCtx(hello, desync.FullCaps(), prm)

	// A plan a split op already filled, plus a decoy that must stay untouched.
	p := fuApply(t, "multisplit", c, &desync.Plan{
		Segs: []desync.Seg{{Kind: desync.SegFake, Data: []byte("decoy")}},
	})
	p = fuApply(t, "wssize", c, p)

	data := 0
	for i, s := range p.Segs {
		switch s.Kind {
		case desync.SegData:
			if s.Window != 128 || s.WindowScale != 6 {
				t.Errorf("seg %d window = %d:%d, want 128:6", i, s.Window, s.WindowScale)
			}
			data++
		default:
			if s.Window != 0 || s.WindowScale != 0 {
				t.Errorf("decoy %d got a window (%d:%d); nfqws builds fakes with their own header",
					i, s.Window, s.WindowScale)
			}
		}
	}
	if data != 2 {
		t.Fatalf("expected the two multisplit segments to carry the window, got %d", data)
	}
	if len(p.Degraded) != 0 {
		t.Errorf("Degraded = %v, want nothing", p.Degraded)
	}
}

// TestWSSizeCarriesThePayloadWhenAlone covers the wssize-only profile: the
// payload has to be re-planned or the rewritten window never reaches the wire.
func TestWSSizeCarriesThePayloadWhenAlone(t *testing.T) {
	hello := fuLoadHello(t)
	c := fuCtx(hello, desync.FullCaps(), desync.OpParams{WSSize: 1})
	p := fuApply(t, "wssize", c, nil)
	if len(p.Segs) != 1 || p.Segs[0].Kind != desync.SegData || !bytes.Equal(p.Segs[0].Data, hello) {
		t.Fatalf("plan = %+v", p.Segs)
	}
	if p.Segs[0].Window != 1 || p.Segs[0].WindowScale != 0 {
		t.Fatalf("window = %d:%d, want 1:0", p.Segs[0].Window, p.Segs[0].WindowScale)
	}
}

// TestWSSizeCutoff walks --wssize-cutoff over all three counter kinds.
func TestWSSizeCutoff(t *testing.T) {
	hello := fuLoadHello(t)
	for _, tc := range []struct {
		name  string
		kind  byte
		n     int
		flow  desync.Flow
		apply bool
	}{
		{"no cutoff", 0, 0, desync.Flow{Pkts: 99, DataPkts: 99}, true},
		{"packets inside", 'n', 3, desync.Flow{Pkts: 3}, true},
		{"packets past", 'n', 3, desync.Flow{Pkts: 4}, false},
		{"data packets inside", 'd', 2, desync.Flow{Pkts: 9, DataPkts: 2}, true},
		{"data packets past", 'd', 2, desync.Flow{Pkts: 9, DataPkts: 3}, false},
		{"sequence inside", 's', 5000, desync.Flow{ISN: 1000, HaveISN: true, LastSeq: 5000}, true},
		{"sequence past", 's', 5000, desync.Flow{ISN: 1000, HaveISN: true, LastSeq: 6001}, false},
		// No data packet seen yet: the relative sequence is 0, not 0-ISN.
		{"sequence before any data", 's', 10, desync.Flow{ISN: 0xFFFFFF00, HaveISN: true}, true},
		// The SYN was never observed (the daemon started on an established
		// connection), so there is no base for a relative sequence: the counter
		// must read 0 rather than the absolute sequence number, which would put
		// the flow permanently past every cutoff.
		{"sequence without an observed SYN", 's', 5000, desync.Flow{ISN: 0, LastSeq: 0x7FFF0000}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fuCtx(hello, desync.FullCaps(), desync.OpParams{
				WSSize: 512, WSSizeCutoffKind: tc.kind, WSSizeCutoffN: tc.n,
			})
			flow := tc.flow
			c.Flow = &flow
			p := fuApply(t, "wssize", c, nil)
			switch {
			case tc.apply && (len(p.Segs) != 1 || p.Segs[0].Window != 512):
				t.Fatalf("window not applied inside the cutoff: %+v", p.Segs)
			case !tc.apply && len(p.Segs) != 0:
				t.Fatalf("window applied past the cutoff: %+v", p.Segs)
			}
			if !tc.apply && len(p.Degraded) != 0 {
				// Stopping at the cutoff is the configured behaviour, not a
				// limitation, so it must be silent.
				t.Errorf("Degraded = %v, want silence past the cutoff", p.Degraded)
			}
		})
	}
}

// TestWSSizeClampsToTheHeaderFields keeps a hostile configuration from silently
// wrapping the 16-bit window or the one-byte scale.
func TestWSSizeClampsToTheHeaderFields(t *testing.T) {
	hello := fuLoadHello(t)
	c := fuCtx(hello, desync.FullCaps(), desync.OpParams{WSSize: 1 << 20, WSSizeScale: 300})
	p := fuApply(t, "wssize", c, nil)
	if len(p.Segs) != 1 || p.Segs[0].Window != 0xFFFF || p.Segs[0].WindowScale != 0xFF {
		t.Fatalf("window = %d:%d, want the clamped 65535:255", p.Segs[0].Window, p.Segs[0].WindowScale)
	}
	if !fuNoted(p, "16-bit") || !fuNoted(p, "one-byte") {
		t.Errorf("Degraded = %v, want both clamps reported", p.Degraded)
	}
}

// TestWSSizeOnASyn covers the packet --wssize matters most for: a bare SYN
// carries no payload, so the window can only ride a syndata segment.
func TestWSSizeOnASyn(t *testing.T) {
	c := fuCtx(nil, desync.FullCaps(), desync.OpParams{WSSize: 64, WSSizeScale: 7})
	c.SynPkt = true

	p := fuApply(t, "wssize", c, nil)
	if len(p.Segs) != 0 {
		t.Fatalf("nothing can be planned for an empty payload: %+v", p.Segs)
	}
	if !fuNoted(p, "no payload") {
		t.Errorf("Degraded = %v, want the bare-SYN limitation reported", p.Degraded)
	}

	// With syndata in the plan the SYN is ours, so the window (and the scale
	// option, which only exists on a SYN) goes on it.
	p = fuApply(t, "wssize", c, &desync.Plan{
		Segs: []desync.Seg{{Kind: desync.SegSynData, Data: []byte("junk"), Flags: proto.TCPSyn}},
	})
	if p.Segs[0].Window != 64 || p.Segs[0].WindowScale != 7 {
		t.Fatalf("syndata window = %d:%d, want 64:7", p.Segs[0].Window, p.Segs[0].WindowScale)
	}
	if len(p.Degraded) != 0 {
		t.Errorf("Degraded = %v, want nothing", p.Degraded)
	}
}

// TestWSSizeDegradeNamesTheApproximation pins the socket-level fallback.
func TestWSSizeDegradeNamesTheApproximation(t *testing.T) {
	c := fuCtx(fuLoadHello(t), desync.ProxyCaps(), desync.OpParams{WSSize: 128, WSSizeScale: 6})
	p := fuDegrade(t, "wssize", c)
	if len(p.Segs) != 0 || p.DropOriginal {
		t.Fatalf("the fallback must not plan anything: %+v", p)
	}
	if !fuNoted(p, "TCP_MAXSEG") {
		t.Fatalf("Degraded = %v, want TCP_MAXSEG named", p.Degraded)
	}
	// --wssize=0 has nothing to say.
	c = fuCtx(fuLoadHello(t), desync.ProxyCaps(), desync.OpParams{})
	if p := fuDegrade(t, "wssize", c); len(p.Degraded) != 0 {
		t.Errorf("Degraded = %v, want silence for wssize=0", p.Degraded)
	}
}

// ---------- tamper ----------

// TestTamperReadsOpParamsTamper is the point of the contract change: the knobs
// arrive in OpParams.Tamper, not smuggled through AltOrder/HostFakeHost.
func TestTamperReadsOpParamsTamper(t *testing.T) {
	payload := []byte(httpGet)
	c := fuCtx(payload, desync.FullCaps(), desync.OpParams{Tamper: proto.TamperOpts{
		HostCase: true, DomCase: true,
	}})
	p := fuApply(t, "tamper", c, nil)
	if len(p.Segs) != 1 || p.Segs[0].Kind != desync.SegData {
		t.Fatalf("plan = %+v", p.Segs)
	}
	got := p.Segs[0].Data
	if len(got) != len(payload) {
		t.Fatalf("length-preserving knobs changed the length: %d -> %d", len(payload), len(got))
	}
	if !bytes.Contains(got, []byte("host: ")) {
		t.Errorf("hostcase not applied: %q", got)
	}
	if bytes.Contains(got, []byte("www.google.com")) {
		t.Errorf("domcase not applied: %q", got)
	}
	if !p.DropOriginal {
		t.Error("a rewritten payload must replace the original packet")
	}
	if string(payload) != httpGet {
		t.Error("tamper wrote into the intercepted payload")
	}
}

// TestTamperWithNoKnobsPlansNothing: an empty TamperOpts is nfqws' no-op tamper
// stage, and re-emitting the payload for it would cost a DropOriginal for free.
func TestTamperWithNoKnobsPlansNothing(t *testing.T) {
	c := fuCtx([]byte(httpGet), desync.FullCaps(), desync.OpParams{})
	p := fuApply(t, "tamper", c, nil)
	if len(p.Segs) != 0 || p.DropOriginal || len(p.Degraded) != 0 {
		t.Fatalf("plan = %+v", p)
	}
}

// TestTamperLengthChangeIsReportedAtPacketLevel keeps the length-preservation
// logic the contract change must not have lost.
//
// A length change is emitted ONLY on a transport that owns the byte stream. At
// packet level the client's TCP has already numbered the original bytes, so
// emitting a different count desynchronises its sequence space for the rest of
// the connection: the op must refuse and say so.
func TestTamperLengthChangeIsReportedAtPacketLevel(t *testing.T) {
	payload := []byte(httpGet)

	// Alone on the proxy transport: the rewrite is emitted, one byte longer.
	c := fuCtx(payload, desync.ProxyCaps(), desync.OpParams{Tamper: proto.TamperOpts{HostDot: true}})
	p := fuApply(t, "tamper", c, nil)
	if len(p.Segs) != 1 || len(p.Segs[0].Data) != len(payload)+1 {
		t.Fatalf("hostdot must add exactly one byte: %d vs %d", len(p.Segs[0].Data), len(payload))
	}
	if len(p.Degraded) != 0 {
		t.Errorf("Degraded = %v, want silence on the transport that can carry it", p.Degraded)
	}

	// Alone at packet level: nothing is planned and the refusal is explained.
	c = fuCtx(payload, desync.FullCaps(), desync.OpParams{Tamper: proto.TamperOpts{HostDot: true}})
	p = fuApply(t, "tamper", c, nil)
	if len(p.Segs) != 0 || p.DropOriginal {
		t.Fatalf("plan = %+v, want the packet forwarded untouched at packet level", p)
	}
	if !fuNoted(p, "length") {
		t.Errorf("Degraded = %v, want the length change reported", p.Degraded)
	}

	// Over segments a split op already planned it cannot be pushed back into the
	// existing boundaries, so the payload is left alone.
	c = fuCtx(payload, desync.FullCaps(), desync.OpParams{
		SplitPos: []desync.PosSpec{{Marker: proto.MarkerAbs, Offset: 4}},
	})
	p = fuApply(t, "multisplit", c, nil)
	c.Params = desync.OpParams{Tamper: proto.TamperOpts{HostTab: true}}
	p = fuApply(t, "tamper", c, p)
	joined := make([]byte, 0, len(payload))
	for _, s := range p.Segs {
		joined = append(joined, s.Data...)
	}
	if !bytes.Equal(joined, payload) {
		t.Errorf("a rejected tamper must leave the payload untouched: %q", joined)
	}
	if !fuNoted(p, "length") {
		t.Errorf("Degraded = %v, want the refusal explained", p.Degraded)
	}
}

// ---------- hostfakesplit midhost ----------

// TestHostfakesplitMidHostPosSpec drives --dpi-desync-hostfakesplit-midhost as
// what it is upstream: a position spec, not a flag.
func TestHostfakesplitMidHostPosSpec(t *testing.T) {
	hello := fuLoadHello(t)
	info := proto.Classify(hello, 443, proto.IPProtoTCP)
	host, endHost := info.HostOff, info.HostOff+info.HostLen
	sld := info.SLDOff

	for _, tc := range []struct {
		name string
		spec desync.PosSpec
		set  bool
		want int // 0 = no extra cut
	}{
		{"sld marker", desync.PosSpec{Marker: proto.MarkerSLD}, true, sld},
		{"midsld marker", desync.PosSpec{Marker: proto.MarkerMidSLD}, true, sld + info.SLDLen/2},
		{"marker with offset", desync.PosSpec{Marker: proto.MarkerSLD, Offset: 1}, true, sld + 1},
		{"absolute position", desync.PosSpec{Marker: proto.MarkerAbs, Offset: host + 3}, true, host + 3},
		// Resolvable, but not inside the hostname: no extra cut.
		{"outside the hostname", desync.PosSpec{Marker: proto.MarkerAbs, Offset: 4}, true, 0},
		{"at the host boundary", desync.PosSpec{Marker: proto.MarkerHost}, true, 0},
		// The gate: a spec that was never configured must not be read.
		{"not set", desync.PosSpec{Marker: proto.MarkerMidSLD}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fuCtx(hello, desync.FullCaps(), desync.OpParams{MidHost: tc.spec, MidHostSet: tc.set})
			p := fuApply(t, "hostfakesplit", c, nil)

			// The real hostname's data segments, in plan order.
			var hostSegs []desync.Seg
			for _, s := range p.Segs {
				if s.Kind == desync.SegData && int(s.SeqOff) >= host && int(s.SeqOff) < endHost {
					hostSegs = append(hostSegs, s)
				}
			}
			if tc.want == 0 {
				if len(hostSegs) != 1 || int(hostSegs[0].SeqOff) != host || len(hostSegs[0].Data) != endHost-host {
					t.Fatalf("expected the hostname in one piece, got %d pieces", len(hostSegs))
				}
				if tc.set && !fuNoted(p, "midhost") {
					t.Errorf("Degraded = %v, want the unusable midhost position reported", p.Degraded)
				}
				if !tc.set && len(p.Degraded) != 0 {
					t.Errorf("Degraded = %v, want silence when midhost was never set", p.Degraded)
				}
				return
			}
			if len(hostSegs) != 2 {
				t.Fatalf("expected the hostname in two pieces, got %d", len(hostSegs))
			}
			if int(hostSegs[0].SeqOff) != host || int(hostSegs[0].SeqOff)+len(hostSegs[0].Data) != tc.want {
				t.Errorf("first piece = [%d,%d), want [%d,%d)",
					hostSegs[0].SeqOff, int(hostSegs[0].SeqOff)+len(hostSegs[0].Data), host, tc.want)
			}
			if int(hostSegs[1].SeqOff) != tc.want || int(hostSegs[1].SeqOff)+len(hostSegs[1].Data) != endHost {
				t.Errorf("second piece = [%d,%d), want [%d,%d)",
					hostSegs[1].SeqOff, int(hostSegs[1].SeqOff)+len(hostSegs[1].Data), tc.want, endHost)
			}
			if len(p.Degraded) != 0 {
				t.Errorf("Degraded = %v, want nothing", p.Degraded)
			}
		})
	}
}

// TestHostfakesplitDegradeHonoursMidHost: the socket-level fallback cuts at the
// same three places, without the decoy.
func TestHostfakesplitDegradeHonoursMidHost(t *testing.T) {
	hello := fuLoadHello(t)
	info := proto.Classify(hello, 443, proto.IPProtoTCP)
	c := fuCtx(hello, desync.ProxyCaps(), desync.OpParams{
		MidHost:    desync.PosSpec{Marker: proto.MarkerSLD},
		MidHostSet: true,
	})
	p := fuDegrade(t, "hostfakesplit", c)
	var bounds []int
	for _, s := range p.Segs {
		if s.Kind != desync.SegData {
			t.Fatalf("a byte-stream fallback cannot carry kind %d", s.Kind)
		}
		bounds = append(bounds, int(s.SeqOff))
	}
	want := []int{0, info.HostOff, info.SLDOff, info.HostOff + info.HostLen}
	if len(bounds) != len(want) {
		t.Fatalf("cuts = %v, want %v", bounds, want)
	}
	for i := range want {
		if bounds[i] != want[i] {
			t.Fatalf("cuts = %v, want %v", bounds, want)
		}
	}
}

// ---------- ip_id ----------

// TestIPIDSameTagsEverything: "same" means every packet the plan emits reuses the
// intercepted packet's ip.id, decoys and RSTs included.
func TestIPIDSameTagsEverything(t *testing.T) {
	hello := fuLoadHello(t)
	c := fuCtx(hello, desync.FullCaps(), desync.OpParams{IPID: desync.IPIDSame})
	p := fuApply(t, "ip_id", c, &desync.Plan{Segs: []desync.Seg{
		{Kind: desync.SegFake, Data: hello},
		{Kind: desync.SegRST, Flags: proto.TCPRst},
		{Kind: desync.SegData, Data: hello},
	}})
	for i, s := range p.Segs {
		if s.IPID != desync.IPIDSame {
			t.Errorf("seg %d IPID = %v, want IPIDSame", i, s.IPID)
		}
	}
	if len(p.Degraded) != 0 {
		t.Errorf("Degraded = %v, want nothing on a TCP flow", p.Degraded)
	}
}

// TestIPIDSeqGroupPairsDecoyWithItsPart is the mode's whole point: the synthetic
// packet that stands in for a real part must be able to reuse that part's ip.id.
func TestIPIDSeqGroupPairsDecoyWithItsPart(t *testing.T) {
	hello := fuLoadHello(t)
	c := fuCtx(hello, desync.FullCaps(), desync.OpParams{
		IPID:     desync.IPIDSeqGroup,
		SplitPos: []desync.PosSpec{{Marker: proto.MarkerMidSLD}},
		Pattern:  []byte{0xAA},
	})
	p := fuApply(t, "fakedsplit", c, nil)

	// Every segment carries the mode: the real part is the anchor the decoy's id
	// is taken from, so it cannot be left untagged.
	for i, s := range p.Segs {
		if s.IPID != desync.IPIDSeqGroup {
			t.Fatalf("seg %d IPID = %v, want IPIDSeqGroup", i, s.IPID)
		}
	}

	groups := desync.SeqGroups(p.Segs)
	if len(groups) != len(p.Segs) {
		t.Fatalf("SeqGroups returned %d entries for %d segments", len(groups), len(p.Segs))
	}
	// Each decoy shares its group with the real part covering the same bytes,
	// and the two parts of the message are in different groups.
	perGroup := map[int][]desync.SegKind{}
	for i, g := range groups {
		perGroup[g] = append(perGroup[g], p.Segs[i].Kind)
	}
	if len(perGroup) != 2 {
		t.Fatalf("fakedsplit at one position must form 2 groups, got %d: %v", len(perGroup), groups)
	}
	for g, kinds := range perGroup {
		var data, fake int
		for _, k := range kinds {
			switch k {
			case desync.SegData:
				data++
			case desync.SegFake:
				fake++
			}
		}
		if data != 1 || fake == 0 {
			t.Errorf("group %d has %d real and %d decoy segments, want one real and at least one decoy",
				g, data, fake)
		}
	}
}

// TestSeqGroupsRules pins the grouping a transport has to implement.
func TestSeqGroupsRules(t *testing.T) {
	seg := func(kind desync.SegKind, off int32, n int) desync.Seg {
		return desync.Seg{Kind: kind, SeqOff: off, Data: make([]byte, n)}
	}
	tests := []struct {
		name string
		segs []desync.Seg
		want []int
	}{
		{"empty", nil, nil},
		{
			// multisplit: disjoint parts, one id each, ascending.
			"disjoint parts",
			[]desync.Seg{seg(desync.SegData, 0, 4), seg(desync.SegData, 4, 6)},
			[]int{0, 1},
		},
		{
			// multidisorder: transmit order is reversed, the ids still ascend
			// with the sequence numbers.
			"reversed transmit order",
			[]desync.Seg{seg(desync.SegData, 4, 6), seg(desync.SegData, 0, 4)},
			[]int{1, 0},
		},
		{
			// fake: the decoy is a hello of its own length, so it does not end
			// where the payload does and keeps an id of its own — which is what
			// nfqws produces too, building that packet from scratch.
			"decoy of a different length",
			[]desync.Seg{seg(desync.SegFake, 0, 680), seg(desync.SegData, 0, 700)},
			[]int{0, 1},
		},
		{
			// fakedsplit: the decoy covers exactly the part it stands in for, so
			// the pair shares one id.
			"decoy over one part",
			[]desync.Seg{seg(desync.SegFake, 0, 4), seg(desync.SegData, 0, 4), seg(desync.SegData, 4, 6)},
			[]int{0, 0, 1},
		},
		{
			// seqovl: the real part starts below the window (SeqOff -8) and still
			// overlaps the decoy that stands in for its first four bytes, so the
			// two share group 0 while the second part gets its own.
			"sequence overlap",
			[]desync.Seg{seg(desync.SegFake, 0, 4), seg(desync.SegData, -8, 12), seg(desync.SegData, 4, 6)},
			[]int{0, 0, 1},
		},
		{
			// A zero-length segment (an injected RST) overlaps nothing.
			"zero length stands alone",
			[]desync.Seg{seg(desync.SegRST, 0, 0), seg(desync.SegData, 0, 4)},
			[]int{0, 1},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := desync.SeqGroups(tc.segs)
			if len(got) != len(tc.want) {
				t.Fatalf("SeqGroups = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("SeqGroups = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestIPIDOnUDPIsReportedAsAGap: Dgram has no IPID field, so a datagram plan
// cannot ask for an ip.id at all. The op has to say so.
func TestIPIDOnUDPIsReportedAsAGap(t *testing.T) {
	payload := bytes.Repeat([]byte{0x42}, 64)
	c := fuUDPCtx(payload, "1.2.3.4", desync.OpParams{IPID: desync.IPIDSeq})
	p := fuApply(t, "ip_id", c, &desync.Plan{
		Dgrams: []desync.Dgram{{Kind: desync.SegData, Data: payload}},
	})
	if !fuNoted(p, "Dgram carries no IPID field") {
		t.Fatalf("Degraded = %v, want the UDP gap reported", p.Degraded)
	}
	// IPIDDefault means "leave it to the transport": nothing to report.
	c = fuUDPCtx(payload, "1.2.3.4", desync.OpParams{})
	if p := fuApply(t, "ip_id", c, nil); len(p.Degraded) != 0 {
		t.Errorf("Degraded = %v, want silence for the default mode", p.Degraded)
	}
}

// ---------- ipfrag on UDP ----------

// TestUDPIPFragTargets pins which datagram each mode fragments: ipfrag1 is the
// first stage and fragments the decoy, ipfrag2 the second and fragments the real
// datagram.
func TestUDPIPFragTargets(t *testing.T) {
	payload := bytes.Repeat([]byte{0x42}, 300)
	decoy := bytes.Repeat([]byte{0x11}, 64)

	for _, tc := range []struct {
		op                 string
		wantFake, wantReal int
	}{
		{"ipfrag1", fragPosUDPDefault, 0},
		{"ipfrag2", 0, fragPosUDPDefault},
	} {
		t.Run(tc.op, func(t *testing.T) {
			c := fuUDPCtx(payload, "1.2.3.4", desync.OpParams{})
			p := fuApply(t, tc.op, c, &desync.Plan{Dgrams: []desync.Dgram{
				{Kind: desync.SegFake, Data: decoy},
				{Kind: desync.SegData, Data: payload},
			}})
			if len(p.Dgrams) != 2 {
				t.Fatalf("plan has %d datagrams, want 2", len(p.Dgrams))
			}
			if p.Dgrams[0].Frag != tc.wantFake {
				t.Errorf("decoy Frag = %d, want %d", p.Dgrams[0].Frag, tc.wantFake)
			}
			if p.Dgrams[1].Frag != tc.wantReal {
				t.Errorf("real Frag = %d, want %d", p.Dgrams[1].Frag, tc.wantReal)
			}
			if len(p.Degraded) != 0 {
				t.Errorf("Degraded = %v, want nothing on an IPv4 datagram", p.Degraded)
			}
		})
	}
}

// TestIPFrag1WithoutADecoySaysSo: a first-stage mode with nothing to decorate
// must not quietly fragment the real datagram instead — that is ipfrag2's job.
func TestIPFrag1WithoutADecoySaysSo(t *testing.T) {
	payload := bytes.Repeat([]byte{0x42}, 300)
	c := fuUDPCtx(payload, "1.2.3.4", desync.OpParams{})
	p := fuApply(t, "ipfrag1", c, &desync.Plan{
		Dgrams: []desync.Dgram{{Kind: desync.SegData, Data: payload}},
	})
	if p.Dgrams[0].Frag != 0 {
		t.Errorf("real datagram Frag = %d, want it untouched", p.Dgrams[0].Frag)
	}
	if !fuNoted(p, "no decoy datagram") {
		t.Fatalf("Degraded = %v, want the missing decoy reported", p.Degraded)
	}
}

// TestUDPIPFragPosition covers --dpi-desync-ipfrag-pos-udp: honoured, rounded
// down to the 8-byte fragment unit, and replaced by nfqws' fallback when it does
// not fit the datagram.
func TestUDPIPFragPosition(t *testing.T) {
	payload := bytes.Repeat([]byte{0x42}, 300)
	for _, tc := range []struct{ pos, want int }{
		{0, fragPosUDPDefault}, // unset: nfqws' IPFRAG_UDP_DEFAULT
		{24, 24},
		{28, 24},                  // rounded down
		{4096, fragPosUDPDefault}, // past the end: fallback
	} {
		c := fuUDPCtx(payload, "1.2.3.4", desync.OpParams{FragPosUDP: tc.pos})
		p := fuApply(t, "ipfrag2", c, nil)
		if len(p.Dgrams) != 1 || p.Dgrams[0].Frag != tc.want {
			t.Errorf("frag_pos %d -> %d, want %d", tc.pos, p.Dgrams[0].Frag, tc.want)
		}
	}
}

// TestUDPLenRederivesTheFragPosition: udplen resizes the datagram after ipfrag2
// picked a split position, so a truncating increment must not leave the transport
// with a position past the end of the bytes actually sent.
func TestUDPLenRederivesTheFragPosition(t *testing.T) {
	payload := bytes.Repeat([]byte{0x42}, 64)
	c := fuUDPCtx(payload, "1.2.3.4", desync.OpParams{FragPosUDP: 32, UDPLenIncrement: -60})
	p := fuApply(t, "ipfrag2", c, nil)
	if p.Dgrams[0].Frag != 32 {
		t.Fatalf("Frag = %d, want the configured 32", p.Dgrams[0].Frag)
	}
	p = fuApply(t, "udplen", c, p)
	if n := len(p.Dgrams[0].Data); n != 4 {
		t.Fatalf("udplen left %d bytes, want 4", n)
	}
	if p.Dgrams[0].Frag != fragPosUDPDefault {
		t.Errorf("Frag = %d, want the fallback %d for a %d byte datagram",
			p.Dgrams[0].Frag, fragPosUDPDefault, len(p.Dgrams[0].Data))
	}
}

// TestIPv6UDPFragStillReportsTheGap: Dgram.Frag is IPv4 fragmentation, and an
// IPv6 datagram would need a Fragment extension header proto cannot build.
func TestIPv6UDPFragStillReportsTheGap(t *testing.T) {
	payload := bytes.Repeat([]byte{0x42}, 300)
	c := fuUDPCtx(payload, "2001:db8::1", desync.OpParams{})
	p := fuApply(t, "ipfrag2", c, nil)
	if len(p.Dgrams) != 0 {
		t.Errorf("ipfrag2 planned an IPv6 datagram it cannot fragment: %+v", p.Dgrams)
	}
	if len(p.Degraded) != 1 || p.Degraded[0] != "ipfrag2" {
		t.Errorf("Degraded = %v, want [ipfrag2]", p.Degraded)
	}
}

// ---------- loader ----------

// fuLoadOpts is a LoadOpts pointing at the repository's real fakes, with the
// divert transport's capabilities so no op is gated off.
func fuLoadOpts(t *testing.T) strategy.LoadOpts {
	t.Helper()
	return strategy.LoadOpts{
		ListsDir: t.TempDir(),
		FakesDir: filepath.Join("..", "..", "fakes"),
		Caps:     desync.FullCaps(),
	}
}

// fuCompile writes body to a temporary .toml and compiles it.
func fuCompile(t *testing.T, body string) (*strategy.Strategy, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return strategy.Load(path, fuLoadOpts(t))
}

// fuOpParams returns the compiled parameters of the named op.
func fuOpParams(t *testing.T, s *strategy.Strategy, name string) desync.OpParams {
	t.Helper()
	for _, p := range s.Profiles {
		for _, co := range p.Ops {
			if co.Op.Name() == name {
				return co.Params
			}
		}
	}
	t.Fatalf("op %q not in the compiled strategy", name)
	return desync.OpParams{}
}

// newKnobsTOML exercises every field this wave added to OpParams.
const newKnobsTOML = `
name = "new-knobs"

[[profile]]
name = "p"

[[profile.ops]]
op = "hostfakesplit"
mod = { host = "ya.ru", altorder = "1", midhost = "midsld+1" }

[[profile.ops]]
op = "tamper"
mod = { hostcase = "1", hostspell = "hoSt", hostpad = "64", domcase = "1", methodspace = "1", methodeol = "1", unixeol = "1", hostdot = "1", hosttab = "1", hostnospace = "1" }

[[profile.ops]]
op = "wssize"
wssize = "128:6"
mod = { cutoff = "d2" }

[[profile.ops]]
op = "ip_id"
mode = "seqgroup"
`

// TestLoaderMapsTheNewKnobs is the loader half of this wave: every new OpParams
// field has to be reachable from a strategy file.
func TestLoaderMapsTheNewKnobs(t *testing.T) {
	s, err := fuCompile(t, newKnobsTOML)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	hfs := fuOpParams(t, s, "hostfakesplit")
	if hfs.HostFakeHost != "ya.ru" || hfs.AltOrder != 1 {
		t.Errorf("hostfakesplit mod = %q/%d", hfs.HostFakeHost, hfs.AltOrder)
	}
	if !hfs.MidHostSet || hfs.MidHost != (desync.PosSpec{Marker: proto.MarkerMidSLD, Offset: 1}) {
		t.Errorf("midhost = %+v (set %v), want midsld+1", hfs.MidHost, hfs.MidHostSet)
	}

	tam := fuOpParams(t, s, "tamper").Tamper
	want := proto.TamperOpts{
		HostCase: true, HostSpell: "hoSt", HostNoSpace: true, HostDot: true, HostTab: true,
		HostPad: 64, DomCase: true, MethodSpace: true, MethodEOL: true, UnixEOL: true,
	}
	if tam != want {
		t.Errorf("tamper = %+v, want %+v", tam, want)
	}

	ws := fuOpParams(t, s, "wssize")
	if ws.WSSize != 128 || ws.WSSizeScale != 6 {
		t.Errorf("wssize = %d:%d, want 128:6", ws.WSSize, ws.WSSizeScale)
	}
	if ws.WSSizeCutoffKind != 'd' || ws.WSSizeCutoffN != 2 {
		t.Errorf("wssize cutoff = %c%d, want d2", ws.WSSizeCutoffKind, ws.WSSizeCutoffN)
	}

	if got := fuOpParams(t, s, "ip_id").IPID; got != desync.IPIDSeqGroup {
		t.Errorf("ip_id mode = %v, want IPIDSeqGroup", got)
	}
}

// TestLoaderMidHostSpellings covers the flag spelling flowseal uses and the
// explicitly-off one.
func TestLoaderMidHostSpellings(t *testing.T) {
	tmpl := func(v string) string {
		return `
name = "midhost"
[[profile]]
name = "p"
[[profile.ops]]
op = "hostfakesplit"
mod = { midhost = "` + v + `" }
`
	}
	for _, tc := range []struct {
		val  string
		set  bool
		want desync.PosSpec
	}{
		{"1", true, desync.PosSpec{Marker: proto.MarkerMidSLD}},
		{"true", true, desync.PosSpec{Marker: proto.MarkerMidSLD}},
		{"0", false, desync.PosSpec{}},
		{"", false, desync.PosSpec{}},
		{"endsld-2", true, desync.PosSpec{Marker: proto.MarkerEndSLD, Offset: -2}},
		{"+120", true, desync.PosSpec{Marker: proto.MarkerAbs, Offset: 120}},
	} {
		s, err := fuCompile(t, tmpl(tc.val))
		if err != nil {
			t.Fatalf("midhost = %q: %v", tc.val, err)
		}
		got := fuOpParams(t, s, "hostfakesplit")
		if got.MidHostSet != tc.set || got.MidHost != tc.want {
			t.Errorf("midhost = %q -> %+v (set %v), want %+v (set %v)",
				tc.val, got.MidHost, got.MidHostSet, tc.want, tc.set)
		}
	}
}

// TestLoaderIPIDNewModes: the two modes that used to be refused or folded away.
func TestLoaderIPIDNewModes(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want desync.IPIDMode
	}{
		{"seqgroup", desync.IPIDSeqGroup},
		{"same", desync.IPIDSame},
		{"seq", desync.IPIDSeq},
		{"zero", desync.IPIDZero},
		{"random", desync.IPIDRandom},
	} {
		s, err := fuCompile(t, `
name = "ipid"
[[profile]]
name = "p"
[[profile.ops]]
op = "ip_id"
mode = "`+tc.mode+`"
`)
		if err != nil {
			t.Fatalf("mode %q: %v", tc.mode, err)
		}
		if got := fuOpParams(t, s, "ip_id").IPID; got != tc.want {
			t.Errorf("mode %q -> %v, want %v", tc.mode, got, tc.want)
		}
	}
}

// TestLoaderRejectsBadNewKnobs: every new knob fails loudly, naming the fix.
func TestLoaderRejectsBadNewKnobs(t *testing.T) {
	for _, tc := range []struct{ name, toml, want string }{
		{
			"tamper without a knob",
			`name="x"
[[profile]]
name="p"
[[profile.ops]]
op = "tamper"`,
			"tamper needs at least one knob",
		},
		{
			"tamper flag is not a boolean",
			`name="x"
[[profile]]
name="p"
[[profile.ops]]
op = "tamper"
mod = { hostcase = "perhaps" }`,
			"not a boolean",
		},
		{
			"hostspell is not a spelling of Host",
			`name="x"
[[profile]]
name="p"
[[profile.ops]]
op = "tamper"
mod = { hostspell = "HOSTNAME" }`,
			`is not a spelling of "Host"`,
		},
		{
			"hostpad is not a number",
			`name="x"
[[profile]]
name="p"
[[profile.ops]]
op = "tamper"
mod = { hostpad = "lots" }`,
			"is not a number of bytes",
		},
		{
			"hostpad out of range",
			`name="x"
[[profile]]
name="p"
[[profile.ops]]
op = "tamper"
mod = { hostpad = "0" }`,
			"outside 1..",
		},
		{
			"tamper knob on another op",
			`name="x"
[[profile]]
name="p"
[[profile.ops]]
op = "multisplit"
pos = ["1"]
mod = { hostcase = "1" }`,
			"only read by tamper",
		},
		{
			"wssize cutoff is not a counter",
			`name="x"
[[profile]]
name="p"
[[profile.ops]]
op = "wssize"
wssize = "128"
mod = { cutoff = "soon" }`,
			"mod.cutoff",
		},
		{
			"cutoff on another op",
			`name="x"
[[profile]]
name="p"
[[profile.ops]]
op = "multisplit"
pos = ["1"]
mod = { cutoff = "d2" }`,
			"only read by wssize",
		},
		{
			"midhost is neither",
			`name="x"
[[profile]]
name="p"
[[profile.ops]]
op = "hostfakesplit"
mod = { midhost = "halfway" }`,
			"not a boolean and not a split position",
		},
		{
			"unknown mod key",
			`name="x"
[[profile]]
name="p"
[[profile.ops]]
op = "tamper"
mod = { hostcase = "1", hostkase = "1" }`,
			`mod key "hostkase" is unknown`,
		},
		{
			"ip_id without a mode",
			`name="x"
[[profile]]
name="p"
[[profile.ops]]
op = "ip_id"`,
			"ip_id needs mode",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fuCompile(t, tc.toml+"\n")
			if err == nil {
				t.Fatalf("compiled, want an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestLoadedWSSizeRunsEndToEnd closes the loop: a compiled wssize op, run over a
// real payload, rewrites the window and honours the cutoff it was compiled with.
func TestLoadedWSSizeRunsEndToEnd(t *testing.T) {
	s, err := fuCompile(t, newKnobsTOML)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	prm := fuOpParams(t, s, "wssize")
	hello := fuLoadHello(t)

	c := fuCtx(hello, desync.FullCaps(), prm)
	c.Flow.DataPkts = 2 // inside cutoff = "d2"
	p := fuApply(t, "wssize", c, nil)
	if len(p.Segs) != 1 || p.Segs[0].Window != 128 || p.Segs[0].WindowScale != 6 {
		t.Fatalf("plan = %+v", p.Segs)
	}

	c = fuCtx(hello, desync.FullCaps(), prm)
	c.Flow.DataPkts = 3 // past it
	if p := fuApply(t, "wssize", c, nil); len(p.Segs) != 0 {
		t.Fatalf("the compiled cutoff was not honoured: %+v", p.Segs)
	}
}
