package desync

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// ---------- fixtures ----------

// injLoadFake reads one of the real payload vectors from fakes/.
func injLoadFake(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "fakes", name))
	if err != nil {
		t.Skipf("test vector %s unavailable: %v", name, err)
	}
	if len(b) == 0 {
		t.Fatalf("test vector %s is empty", name)
	}
	return b
}

// injAddr parses an address or fails the test.
func injAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

// injCtx builds a Ctx the way engine.OnTCP/OnUDP would: the flow key carries the
// L4 protocol and the peer address, and Info comes from proto.Classify.
func injCtx(t *testing.T, ipproto uint8, dst string, payload []byte) *Ctx {
	t.Helper()
	d := injAddr(t, dst)
	src := injAddr(t, "192.168.1.2")
	if d.Is6() && !d.Is4In6() {
		src = injAddr(t, "2001:db8::2")
	}
	port := uint16(443)
	f := &Flow{Key: FlowKey{
		Src: src, Dst: d, SrcPort: 51000, DstPort: port, Proto: ipproto,
	}, ProfileIdx: -1}
	info := proto.Classify(payload, port, ipproto)
	f.L7 = info.Proto
	f.Host = info.Host
	return &Ctx{Flow: f, Payload: payload, Info: info, Caps: FullCaps()}
}

// injCapsOK mirrors engine.capsSatisfied: every capability the op needs must be
// present in the transport's Caps. Duplicated here because internal/engine
// imports internal/desync, so the test cannot go the other way.
func injCapsOK(have, need Caps) bool {
	pairs := [][2]bool{
		{need.Inject, have.Inject},
		{need.Seq, have.Seq},
		{need.DropOriginal, have.DropOriginal},
		{need.PerPacketTTL, have.PerPacketTTL},
		{need.Fooling, have.Fooling},
		{need.IPID, have.IPID},
		{need.UDP, have.UDP},
		{need.IPv6ExtHdr, have.IPv6ExtHdr},
		{need.Frag, have.Frag},
		{need.Segment, have.Segment},
		{need.TLSRec, have.TLSRec},
	}
	for _, p := range pairs {
		if p[0] && !p[1] {
			return false
		}
	}
	return true
}

// injRun executes ops against a plan the way engine.run does: Caps gate first
// (unsupported ops are recorded and skipped, and none of the injection ops
// implements Degrader), then Apply, then DropOriginal for a non-empty plan.
func injRun(t *testing.T, caps Caps, c *Ctx, params OpParams, ops ...Op) *Plan {
	t.Helper()
	c.Caps = caps
	p := &Plan{}
	for _, op := range ops {
		c.Params = params
		if !injCapsOK(caps, op.Requires()) {
			if _, isDegrader := op.(Degrader); isDegrader {
				t.Errorf("op %s implements Degrader: an injected packet has no honest socket-level approximation", op.Name())
			}
			p.Degraded = append(p.Degraded, op.Name())
			continue
		}
		if err := op.Apply(c, p); err != nil {
			t.Fatalf("op %s: Apply: %v", op.Name(), err)
		}
	}
	if len(p.Segs) > 0 || len(p.Dgrams) > 0 {
		p.DropOriginal = true
	}
	return p
}

// injKinds lists the segment kinds of a plan, for order assertions.
func injKinds(p *Plan) []SegKind {
	out := make([]SegKind, len(p.Segs))
	for i, s := range p.Segs {
		out[i] = s.Kind
	}
	return out
}

// injDgramKinds is injKinds for UDP.
func injDgramKinds(p *Plan) []SegKind {
	out := make([]SegKind, len(p.Dgrams))
	for i, d := range p.Dgrams {
		out[i] = d.Kind
	}
	return out
}

// injWantKinds asserts the exact segment order.
func injWantKinds(t *testing.T, got, want []SegKind) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("plan has %d segments %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("segment kinds = %v, want %v", got, want)
		}
	}
}

// injHTTPRequest is a minimal client request that proto.Classify sees as HTTP.
const injHTTPRequest = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"

// injDiscordIPDiscovery builds a valid Discord voice IP-discovery datagram.
func injDiscordIPDiscovery() []byte {
	b := make([]byte, 74)
	binary.BigEndian.PutUint16(b[0:2], 1)  // request
	binary.BigEndian.PutUint16(b[2:4], 70) // body length
	binary.BigEndian.PutUint32(b[4:8], 0x11223344)
	return b
}

// injSTUNBinding builds a valid STUN binding request.
func injSTUNBinding() []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], 0x0001)
	binary.BigEndian.PutUint16(b[2:4], 0)
	binary.BigEndian.PutUint32(b[4:8], 0x2112a442)
	return b
}

// injTestFooling is a non-trivial fooling set to check propagation.
var injTestFooling = FoolBadSum | FoolBadSeq

// injTestParams is the shared knob set: three repeats, TTL 5, two fooling modes.
func injTestParams() OpParams {
	return OpParams{
		Repeats: 3,
		TTL:     5,
		Fool:    injTestFooling,
		FoolP:   DefaultFoolParams(),
	}
}

// ---------- registration ----------

func TestInjectionOpsAreRegistered(t *testing.T) {
	want := map[string]struct {
		name  string
		phase Phase
	}{
		"fake":      {"fake", PhaseFake},
		"fakeknown": {"fakeknown", PhaseFake},
		"rst":       {"rst", PhaseFake},
		"rstack":    {"rstack", PhaseFake},
		"syndata":   {"syndata", PhaseSyn},
		"block":     {"block", PhaseFake},
		"udplen":    {"udplen", PhaseModify},
		"ipfrag1":   {"ipfrag1", PhaseModify},
		"ipfrag2":   {"ipfrag2", PhaseModify},
		"hopbyhop":  {"hopbyhop", PhaseModify},
		"destopt":   {"destopt", PhaseModify},
	}
	for spelling, w := range want {
		op, err := Lookup(spelling)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", spelling, err)
		}
		if op.Name() != w.name {
			t.Errorf("Lookup(%q).Name() = %q, want %q", spelling, op.Name(), w.name)
		}
		if op.Phase() != w.phase {
			t.Errorf("%s.Phase() = %d, want %d", spelling, op.Phase(), w.phase)
		}
	}
}

// ---------- fake, TCP ----------

func TestFakeTLSPlanIsDecoyThenPayload(t *testing.T) {
	payload := injLoadFake(t, "tls_clienthello_www_google_com.bin")
	fake := injLoadFake(t, "tls_clienthello_max_ru.bin")

	c := injCtx(t, proto.IPProtoTCP, "142.250.185.100", payload)
	if c.Info.Proto != proto.L7TLS {
		t.Fatalf("payload classified as %#x, want TLS", c.Info.Proto)
	}
	c.Fakes = FakeSet{TLS: fake}

	p := injRun(t, FullCaps(), c, injTestParams(), &fakeOp{})

	injWantKinds(t, injKinds(p), []SegKind{SegFake, SegData})
	if !p.DropOriginal {
		t.Error("plan does not drop the original packet, so the payload would be sent twice")
	}
	// A custom fake is sent verbatim: nfqws only applies the compatibility
	// tls-mod default when the profile has no custom fake ClientHello.
	if !bytes.Equal(p.Segs[0].Data, fake) {
		t.Errorf("fake payload is not the blob from fakes/: got %d bytes, want %d", len(p.Segs[0].Data), len(fake))
	}
	if p.Segs[0].SeqOff != 0 {
		t.Errorf("fake SeqOff = %d, want 0 (the decoy must claim the real payload's sequence number)", p.Segs[0].SeqOff)
	}
	if p.Segs[0].Repeats != 3 {
		t.Errorf("fake Repeats = %d, want 3", p.Segs[0].Repeats)
	}
	if p.Segs[0].TTL != 5 {
		t.Errorf("fake TTL = %d, want 5", p.Segs[0].TTL)
	}
	if p.Segs[0].Fool != injTestFooling {
		t.Errorf("fake Fool = %#x, want %#x", p.Segs[0].Fool, injTestFooling)
	}
	if p.Segs[0].FoolP != DefaultFoolParams() {
		t.Errorf("fake FoolP = %+v, want %+v", p.Segs[0].FoolP, DefaultFoolParams())
	}

	if !bytes.Equal(p.Segs[1].Data, payload) {
		t.Error("data segment does not carry the original payload")
	}
	if p.Segs[1].SeqOff != 0 {
		t.Errorf("data SeqOff = %d, want 0", p.Segs[1].SeqOff)
	}
	// The payload must reach the server untouched: no low TTL, no fooling.
	if p.Segs[1].TTL != 0 || p.Segs[1].Fool != FoolNone || p.Segs[1].Repeats != 0 {
		t.Errorf("data segment was decorated like a fake: %+v", p.Segs[1])
	}
}

func TestFakeRepeatsDefaultToOne(t *testing.T) {
	c := injCtx(t, proto.IPProtoTCP, "1.2.3.4", []byte(injHTTPRequest))
	p := injRun(t, FullCaps(), c, OpParams{}, &fakeOp{})
	injWantKinds(t, injKinds(p), []SegKind{SegFake, SegData})
	if p.Segs[0].Repeats != 1 {
		t.Errorf("Repeats = %d, want 1 (nfqws dp_init default)", p.Segs[0].Repeats)
	}
}

func TestFakeHTTPUsesHTTPFamily(t *testing.T) {
	payload := []byte(injHTTPRequest)
	c := injCtx(t, proto.IPProtoTCP, "1.2.3.4", payload)
	if c.Info.Proto != proto.L7HTTP {
		t.Fatalf("payload classified as %#x, want HTTP", c.Info.Proto)
	}
	httpFake := []byte("GET / HTTP/1.1\r\nHost: www.example.org\r\n\r\n")
	c.Fakes = FakeSet{TLS: injLoadFake(t, "tls_clienthello_max_ru.bin"), HTTP: httpFake}

	p := injRun(t, FullCaps(), c, injTestParams(), &fakeOp{})
	injWantKinds(t, injKinds(p), []SegKind{SegFake, SegData})
	if !bytes.Equal(p.Segs[0].Data, httpFake) {
		t.Errorf("fake = %q, want the HTTP blob %q", p.Segs[0].Data, httpFake)
	}
}

func TestFakeFallsBackToZapretDefaults(t *testing.T) {
	// TCP HTTP with an empty FakeSet: nfqws' fake_http_request_default.
	c := injCtx(t, proto.IPProtoTCP, "1.2.3.4", []byte(injHTTPRequest))
	p := injRun(t, FullCaps(), c, OpParams{}, &fakeOp{})
	if got := string(p.Segs[0].Data); got != injDefaultFakeHTTP {
		t.Errorf("default HTTP fake = %q, want zapret's fake_http_request_default", got)
	}

	// TCP, unrecognised L7: fake_unknown is 256 zero bytes.
	c = injCtx(t, proto.IPProtoTCP, "1.2.3.4", []byte{0x01, 0x02, 0x03, 0x04})
	if c.Info.Proto != proto.L7Unknown {
		t.Fatalf("payload classified as %#x, want unknown", c.Info.Proto)
	}
	p = injRun(t, FullCaps(), c, OpParams{}, &fakeOp{})
	if n := len(p.Segs[0].Data); n != injDefaultUnknownTCPLen {
		t.Errorf("default TCP unknown fake is %d bytes, want %d", n, injDefaultUnknownTCPLen)
	}
	if !bytes.Equal(p.Segs[0].Data, make([]byte, injDefaultUnknownTCPLen)) {
		t.Error("default TCP unknown fake is not zero-filled")
	}

	// UDP QUIC: fake_quic is 620 zero bytes with the long-header fixed bit set.
	quic := injLoadFake(t, "quic_initial_www_google_com.bin")
	c = injCtx(t, proto.IPProtoUDP, "142.250.185.100", quic)
	p = injRun(t, FullCaps(), c, OpParams{}, &fakeOp{})
	got := p.Dgrams[0].Data
	if len(got) != injDefaultQUICLen || got[0] != 0x40 {
		t.Fatalf("default QUIC fake: len=%d first=%#02x, want len=%d first=0x40", len(got), got[0], injDefaultQUICLen)
	}
	if !bytes.Equal(got[1:], make([]byte, injDefaultQUICLen-1)) {
		t.Error("default QUIC fake tail is not zero-filled")
	}

	// UDP, unrecognised L7: 64 zero bytes.
	c = injCtx(t, proto.IPProtoUDP, "1.2.3.4", []byte{0xff, 0xff, 0xff, 0xff, 0xff})
	p = injRun(t, FullCaps(), c, OpParams{}, &fakeOp{})
	if n := len(p.Dgrams[0].Data); n != injDefaultUDPLen {
		t.Errorf("default UDP fake is %d bytes, want %d", n, injDefaultUDPLen)
	}
}

func TestInjDefaultFakeTLSIsZapretsHello(t *testing.T) {
	b := injDefaultTLS()
	if len(b) != 680 {
		t.Fatalf("built-in fake ClientHello is %d bytes, want 680", len(b))
	}
	info, ok := proto.ParseTLSClientHello(b)
	if !ok {
		t.Fatal("built-in fake ClientHello does not parse as a ClientHello")
	}
	if info.Host != "www.microsoft.com" {
		t.Errorf("built-in fake SNI = %q, want www.microsoft.com", info.Host)
	}
}

func TestFakeTLSModForcedSNI(t *testing.T) {
	payload := injLoadFake(t, "tls_clienthello_www_google_com.bin")
	c := injCtx(t, proto.IPProtoTCP, "142.250.185.100", payload)
	c.Fakes = FakeSet{TLS: injLoadFake(t, "tls_clienthello_max_ru.bin")}

	params := injTestParams()
	params.TLSMod = TLSMod{SNI: "www.forced-example.com"}

	p := injRun(t, FullCaps(), c, params, &fakeOp{})
	injWantKinds(t, injKinds(p), []SegKind{SegFake, SegData})

	info, ok := proto.ParseTLSClientHello(p.Segs[0].Data)
	if !ok {
		t.Fatal("modified fake no longer parses as a ClientHello")
	}
	if info.Host != "www.forced-example.com" {
		t.Errorf("fake SNI = %q, want www.forced-example.com", info.Host)
	}
	if !bytes.Equal(p.Segs[1].Data, payload) {
		t.Error("the real payload was modified")
	}
}

func TestFakeTLSDefaultModAppliesWithoutCustomFake(t *testing.T) {
	payload := injLoadFake(t, "tls_clienthello_www_google_com.bin")
	c := injCtx(t, proto.IPProtoTCP, "142.250.185.100", payload)
	// No FakeSet.TLS and no Params.FakeTLS: nfqws falls back to its built-in
	// hello and applies the compatibility tls-mod "rnd,rndsni,dupsid".
	p := injRun(t, FullCaps(), c, injTestParams(), &fakeOp{})

	info, ok := proto.ParseTLSClientHello(p.Segs[0].Data)
	if !ok {
		t.Fatal("default-modded fake does not parse as a ClientHello")
	}
	if info.Host == "" {
		t.Error("default-modded fake lost its SNI")
	}
	if info.Host == "www.microsoft.com" {
		t.Error("rndsni did not randomise the built-in hello's SNI")
	}
	if bytes.Equal(p.Segs[0].Data, injDefaultTLS()) {
		t.Error("default tls-mod left the built-in hello byte-identical")
	}
	// rnd randomises the 32-byte ClientHello.random at offset 11.
	if bytes.Equal(p.Segs[0].Data[11:43], injDefaultTLS()[11:43]) {
		t.Error("rnd did not randomise ClientHello.random")
	}
}

func TestFakeTLSModNoneKeepsCustomFakeVerbatim(t *testing.T) {
	payload := injLoadFake(t, "tls_clienthello_www_google_com.bin")
	fake := injLoadFake(t, "tls_clienthello_4pda_to.bin")
	c := injCtx(t, proto.IPProtoTCP, "142.250.185.100", payload)

	params := injTestParams()
	params.FakeTLS = fake
	params.TLSMod = TLSMod{None: true}

	p := injRun(t, FullCaps(), c, params, &fakeOp{})
	if !bytes.Equal(p.Segs[0].Data, fake) {
		t.Error("tls_mod=none must send the op's own fake blob unchanged")
	}
}

func TestFakeKnownSkipsUnknownProtocol(t *testing.T) {
	c := injCtx(t, proto.IPProtoTCP, "1.2.3.4", []byte{0x01, 0x02, 0x03, 0x04})
	if c.Info.Proto != proto.L7Unknown {
		t.Fatalf("payload classified as %#x, want unknown", c.Info.Proto)
	}
	p := injRun(t, FullCaps(), c, injTestParams(), &fakeOp{knownOnly: true})
	if len(p.Segs) != 0 || p.DropOriginal {
		t.Fatalf("fakeknown acted on an unrecognised protocol: %+v", p)
	}

	// The same op on a recognised protocol does inject.
	c = injCtx(t, proto.IPProtoTCP, "1.2.3.4", []byte(injHTTPRequest))
	p = injRun(t, FullCaps(), c, injTestParams(), &fakeOp{knownOnly: true})
	injWantKinds(t, injKinds(p), []SegKind{SegFake, SegData})
}

func TestFakeSkipsBareSyn(t *testing.T) {
	// nfqws runs only desync_mode0 on a SYN and then sends it as-is.
	for _, op := range []Op{&fakeOp{}, &fakeOp{knownOnly: true}, &rstOp{}, &rstOp{ack: true},
		&udpLenOp{}, &ipFrag2Op{}, &ipv6ExtOp{}, &ipv6ExtOp{destOpt: true}, &ipFrag1Op{}} {
		c := injCtx(t, proto.IPProtoTCP, "2001:db8::1", nil)
		c.SynPkt = true
		p := injRun(t, FullCaps(), c, injTestParams(), op)
		if len(p.Segs) != 0 || len(p.Dgrams) != 0 || p.DropOriginal {
			t.Errorf("%s acted on a bare SYN: %+v", op.Name(), p)
		}
	}
}

func TestFakeInsertsBeforeSegmentsAlreadyPlanned(t *testing.T) {
	payload := injLoadFake(t, "tls_clienthello_www_google_com.bin")
	c := injCtx(t, proto.IPProtoTCP, "142.250.185.100", payload)
	c.Fakes = FakeSet{TLS: injLoadFake(t, "tls_clienthello_max_ru.bin")}

	// What a PhaseSplit op leaves behind: the payload as two data segments.
	split := len(payload) / 2
	p := &Plan{Segs: []Seg{
		{Kind: SegData, Data: payload[:split], SeqOff: 0},
		{Kind: SegData, Data: payload[split:], SeqOff: int32(split)},
	}}
	c.Params = injTestParams()
	c.Caps = FullCaps()
	if err := (&fakeOp{}).Apply(c, p); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	injWantKinds(t, injKinds(p), []SegKind{SegFake, SegData, SegData})
	// The payload must appear exactly once across the data segments.
	var got []byte
	for _, s := range p.Segs {
		if s.Kind == SegData {
			got = append(got, s.Data...)
		}
	}
	if !bytes.Equal(got, payload) {
		t.Error("fake duplicated or truncated the already-planned payload")
	}
}

// ---------- fake, UDP ----------

func TestFakeUDPQUICBlobIsTheRealFile(t *testing.T) {
	payload := injLoadFake(t, "quic_initial_4pda.to.bin")
	fake := injLoadFake(t, "quic_initial_www_google_com.bin")

	c := injCtx(t, proto.IPProtoUDP, "142.250.185.100", payload)
	if c.Info.Proto != proto.L7QUIC {
		t.Fatalf("payload classified as %#x, want QUIC", c.Info.Proto)
	}
	c.Fakes = FakeSet{QUIC: fake}

	p := injRun(t, FullCaps(), c, injTestParams(), &fakeOp{})

	injWantKinds(t, injDgramKinds(p), []SegKind{SegFake, SegData})
	if len(p.Segs) != 0 {
		t.Errorf("a UDP flow produced %d TCP segments", len(p.Segs))
	}
	if !bytes.Equal(p.Dgrams[0].Data, fake) {
		t.Error("fake datagram is not fakes/quic_initial_www_google_com.bin byte for byte")
	}
	if p.Dgrams[0].Repeats != 3 || p.Dgrams[0].TTL != 5 || p.Dgrams[0].Fool != injTestFooling {
		t.Errorf("fake datagram lost its knobs: %+v", p.Dgrams[0])
	}
	if !bytes.Equal(p.Dgrams[1].Data, payload) {
		t.Error("data datagram does not carry the original payload")
	}
	if p.Dgrams[1].TTL != 0 || p.Dgrams[1].Fool != FoolNone || p.Dgrams[1].Repeats != 0 {
		t.Errorf("data datagram was decorated like a fake: %+v", p.Dgrams[1])
	}
}

func TestFakeUDPDiscordBlobIsTheRealFile(t *testing.T) {
	payload := injDiscordIPDiscovery()
	discord := injLoadFake(t, "ACTIVE_DISCORD_UDP.bin")

	c := injCtx(t, proto.IPProtoUDP, "66.22.200.1", payload)
	if c.Info.Proto != proto.L7Discord {
		t.Fatalf("payload classified as %#x, want Discord", c.Info.Proto)
	}
	c.Fakes = FakeSet{Discord: [][]byte{discord}}

	p := injRun(t, FullCaps(), c, injTestParams(), &fakeOp{})
	injWantKinds(t, injDgramKinds(p), []SegKind{SegFake, SegData})
	if !bytes.Equal(p.Dgrams[0].Data, discord) {
		t.Error("fake datagram is not fakes/ACTIVE_DISCORD_UDP.bin byte for byte")
	}
}

func TestFakeUDPMultiValuedSetSendsEveryBlob(t *testing.T) {
	// nfqws walks the whole blob list and sends each entry desync_repeats times,
	// in list order.
	payload := injSTUNBinding()
	c := injCtx(t, proto.IPProtoUDP, "66.22.200.1", payload)
	if c.Info.Proto != proto.L7STUN {
		t.Fatalf("payload classified as %#x, want STUN", c.Info.Proto)
	}
	one := injLoadFake(t, "stun.bin")
	two := injLoadFake(t, "stun2.bin")
	c.Fakes = FakeSet{STUN: [][]byte{one, two}}

	p := injRun(t, FullCaps(), c, injTestParams(), &fakeOp{})
	injWantKinds(t, injDgramKinds(p), []SegKind{SegFake, SegFake, SegData})
	if !bytes.Equal(p.Dgrams[0].Data, one) || !bytes.Equal(p.Dgrams[1].Data, two) {
		t.Error("multi-valued STUN fake set was not emitted in list order")
	}
	for i := 0; i < 2; i++ {
		if p.Dgrams[i].Repeats != 3 {
			t.Errorf("fake[%d] Repeats = %d, want 3 for every list entry", i, p.Dgrams[i].Repeats)
		}
	}
}

func TestFakeUDPOpParamsOverrideTheFakeSet(t *testing.T) {
	payload := injLoadFake(t, "quic_initial_4pda.to.bin")
	c := injCtx(t, proto.IPProtoUDP, "1.2.3.4", payload)
	c.Fakes = FakeSet{QUIC: injLoadFake(t, "quic_initial_tencent_com.bin")}

	params := injTestParams()
	params.FakeQUIC = injLoadFake(t, "quic_initial_steamcommunity_com.bin")

	p := injRun(t, FullCaps(), c, params, &fakeOp{})
	if !bytes.Equal(p.Dgrams[0].Data, params.FakeQUIC) {
		t.Error("the op's own --dpi-desync-fake-quic did not win over the engine-wide set")
	}
}

// ---------- rst / rstack ----------

func TestRSTPlanKeepsThePayload(t *testing.T) {
	payload := injLoadFake(t, "tls_clienthello_www_google_com.bin")
	for _, tc := range []struct {
		op    *rstOp
		name  string
		flags uint8
	}{
		{&rstOp{}, "rst", proto.TCPRst},
		{&rstOp{ack: true}, "rstack", proto.TCPRst | proto.TCPAck},
	} {
		c := injCtx(t, proto.IPProtoTCP, "142.250.185.100", payload)
		p := injRun(t, FullCaps(), c, injTestParams(), tc.op)

		injWantKinds(t, injKinds(p), []SegKind{SegRST, SegData})
		if tc.op.Name() != tc.name {
			t.Errorf("Name() = %q, want %q", tc.op.Name(), tc.name)
		}
		if p.Segs[0].Flags != tc.flags {
			t.Errorf("%s flags = %#02x, want %#02x", tc.name, p.Segs[0].Flags, tc.flags)
		}
		if len(p.Segs[0].Data) != 0 {
			t.Errorf("%s carries %d payload bytes, want none", tc.name, len(p.Segs[0].Data))
		}
		if p.Segs[0].SeqOff != 0 || p.Segs[0].Repeats != 3 || p.Segs[0].TTL != 5 || p.Segs[0].Fool != injTestFooling {
			t.Errorf("%s lost its knobs: %+v", tc.name, p.Segs[0])
		}
		if !bytes.Equal(p.Segs[1].Data, payload) {
			t.Errorf("%s did not keep the real payload in the plan", tc.name)
		}
	}
}

func TestRSTIsTCPOnly(t *testing.T) {
	c := injCtx(t, proto.IPProtoUDP, "1.2.3.4", injSTUNBinding())
	p := injRun(t, FullCaps(), c, injTestParams(), &rstOp{})
	if len(p.Segs) != 0 || len(p.Dgrams) != 0 {
		t.Errorf("rst acted on a UDP flow: %+v", p)
	}
}

// ---------- syndata ----------

func TestSynDataOnBareSyn(t *testing.T) {
	c := injCtx(t, proto.IPProtoTCP, "1.2.3.4", nil)
	c.SynPkt = true
	p := injRun(t, FullCaps(), c, injTestParams(), &synDataOp{})

	injWantKinds(t, injKinds(p), []SegKind{SegSynData})
	if !p.DropOriginal {
		t.Error("syndata must replace the kernel's SYN, so the original has to be dropped")
	}
	if n := len(p.Segs[0].Data); n != injSynDataDefaultLen {
		t.Fatalf("default SYN payload is %d bytes, want %d", n, injSynDataDefaultLen)
	}
	if !bytes.Equal(p.Segs[0].Data, make([]byte, injSynDataDefaultLen)) {
		t.Error("default SYN payload is not zero-filled")
	}
	if p.Segs[0].Flags != proto.TCPSyn {
		t.Errorf("flags = %#02x, want SYN (%#02x)", p.Segs[0].Flags, proto.TCPSyn)
	}
	if p.Segs[0].Repeats != 3 {
		t.Errorf("Repeats = %d, want 3", p.Segs[0].Repeats)
	}
	// nfqws sends this one with the original TTL and no fooling: it is meant to
	// reach the server.
	if p.Segs[0].TTL != 0 || p.Segs[0].Fool != FoolNone {
		t.Errorf("SYN data was decorated like a fake: %+v", p.Segs[0])
	}
}

func TestSynDataUsesConfiguredPayload(t *testing.T) {
	c := injCtx(t, proto.IPProtoTCP, "1.2.3.4", nil)
	c.SynPkt = true
	c.Fakes = FakeSet{SynData: []byte("from-the-fakeset")}
	p := injRun(t, FullCaps(), c, OpParams{}, &synDataOp{})
	if !bytes.Equal(p.Segs[0].Data, []byte("from-the-fakeset")) {
		t.Errorf("SYN payload = %q, want the FakeSet blob", p.Segs[0].Data)
	}

	params := OpParams{FakeSynData: []byte("from-the-op")}
	c = injCtx(t, proto.IPProtoTCP, "1.2.3.4", nil)
	c.SynPkt = true
	c.Fakes = FakeSet{SynData: []byte("from-the-fakeset")}
	p = injRun(t, FullCaps(), c, params, &synDataOp{})
	if !bytes.Equal(p.Segs[0].Data, []byte("from-the-op")) {
		t.Errorf("SYN payload = %q, want the op's own blob", p.Segs[0].Data)
	}
}

func TestSynDataSkippedOffSyn(t *testing.T) {
	// A data packet.
	c := injCtx(t, proto.IPProtoTCP, "142.250.185.100", injLoadFake(t, "tls_clienthello_www_google_com.bin"))
	p := injRun(t, FullCaps(), c, injTestParams(), &synDataOp{})
	if len(p.Segs) != 0 || p.DropOriginal {
		t.Fatalf("syndata acted on a data packet: %+v", p)
	}

	// A SYN that already carries data (TCP fast open with a cookie): nfqws
	// refuses to touch it.
	c = injCtx(t, proto.IPProtoTCP, "1.2.3.4", []byte("early-data"))
	c.SynPkt = true
	p = injRun(t, FullCaps(), c, injTestParams(), &synDataOp{})
	if len(p.Segs) != 0 || p.DropOriginal {
		t.Fatalf("syndata acted on a SYN that already carried payload: %+v", p)
	}

	// UDP has no SYN.
	c = injCtx(t, proto.IPProtoUDP, "1.2.3.4", injSTUNBinding())
	c.SynPkt = true
	p = injRun(t, FullCaps(), c, injTestParams(), &synDataOp{})
	if len(p.Segs) != 0 || len(p.Dgrams) != 0 {
		t.Fatalf("syndata acted on a UDP flow: %+v", p)
	}
}

// ---------- udplen ----------

func TestUDPLenGrowsByExactlyTheIncrement(t *testing.T) {
	payload := injLoadFake(t, "quic_initial_4pda.to.bin")
	for _, inc := range []int{1, 2, 8, 64} {
		c := injCtx(t, proto.IPProtoUDP, "1.2.3.4", payload)
		params := OpParams{UDPLenIncrement: inc}
		p := injRun(t, FullCaps(), c, params, &udpLenOp{})

		injWantKinds(t, injDgramKinds(p), []SegKind{SegData})
		got := p.Dgrams[0].Data
		if len(got) != len(payload)+inc {
			t.Fatalf("increment %d: datagram is %d bytes, want %d", inc, len(got), len(payload)+inc)
		}
		if !bytes.Equal(got[:len(payload)], payload) {
			t.Errorf("increment %d: the original payload was modified", inc)
		}
		if !bytes.Equal(got[len(payload):], make([]byte, inc)) {
			t.Errorf("increment %d: tail is not zero-filled without a pattern", inc)
		}
		if !p.DropOriginal {
			t.Errorf("increment %d: the unmodified datagram would also be sent", inc)
		}
	}
}

func TestUDPLenDefaultIncrementAndPattern(t *testing.T) {
	payload := injSTUNBinding()
	c := injCtx(t, proto.IPProtoUDP, "1.2.3.4", payload)
	// Increment 0 means "unset": nfqws' dp_init default is 2.
	p := injRun(t, FullCaps(), c, OpParams{}, &udpLenOp{})
	if n := len(p.Dgrams[0].Data); n != len(payload)+injUDPLenDefaultIncrement {
		t.Fatalf("default increment produced %d bytes, want %d", n, len(payload)+injUDPLenDefaultIncrement)
	}

	c = injCtx(t, proto.IPProtoUDP, "1.2.3.4", payload)
	params := OpParams{UDPLenIncrement: 5, UDPLenPattern: []byte{0xab, 0xcd}}
	p = injRun(t, FullCaps(), c, params, &udpLenOp{})
	tail := p.Dgrams[0].Data[len(payload):]
	want := []byte{0xab, 0xcd, 0xab, 0xcd, 0xab}
	if !bytes.Equal(tail, want) {
		t.Errorf("padding = % x, want the pattern tiled cyclically % x", tail, want)
	}
}

func TestUDPLenNegativeIncrementTruncates(t *testing.T) {
	payload := injSTUNBinding() // 20 bytes
	c := injCtx(t, proto.IPProtoUDP, "1.2.3.4", payload)
	p := injRun(t, FullCaps(), c, OpParams{UDPLenIncrement: -4}, &udpLenOp{})
	if got := p.Dgrams[0].Data; len(got) != 16 || !bytes.Equal(got, payload[:16]) {
		t.Errorf("negative increment gave %d bytes, want the first 16", len(got))
	}

	// nfqws never lets the payload shrink below one byte.
	c = injCtx(t, proto.IPProtoUDP, "1.2.3.4", payload)
	p = injRun(t, FullCaps(), c, OpParams{UDPLenIncrement: -1000}, &udpLenOp{})
	if n := len(p.Dgrams[0].Data); n != 1 {
		t.Errorf("clamped payload is %d bytes, want 1", n)
	}
}

func TestUDPLenReusesAPlannedDatagram(t *testing.T) {
	payload := injSTUNBinding()
	c := injCtx(t, proto.IPProtoUDP, "2001:db8::1", payload)
	c.Params = OpParams{UDPLenIncrement: 4}
	c.Caps = FullCaps()
	// hopbyhop already marked the real datagram; udplen must not lose that.
	p := &Plan{Dgrams: []Dgram{{Kind: SegData, Data: payload, Fool: FoolHopByHop}}}
	if err := (&udpLenOp{}).Apply(c, p); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(p.Dgrams) != 1 {
		t.Fatalf("plan has %d datagrams, want 1", len(p.Dgrams))
	}
	if p.Dgrams[0].Fool != FoolHopByHop {
		t.Error("udplen dropped the fooling another op had set on the real datagram")
	}
	if len(p.Dgrams[0].Data) != len(payload)+4 {
		t.Error("udplen did not resize the planned datagram")
	}
}

func TestUDPLenIsUDPOnly(t *testing.T) {
	c := injCtx(t, proto.IPProtoTCP, "1.2.3.4", []byte(injHTTPRequest))
	p := injRun(t, FullCaps(), c, OpParams{UDPLenIncrement: 4}, &udpLenOp{})
	if len(p.Segs) != 0 || len(p.Dgrams) != 0 {
		t.Errorf("udplen acted on a TCP flow: %+v", p)
	}
}

// ---------- ipfrag2 ----------

func TestIPFrag2MarksDataSegments(t *testing.T) {
	payload := injLoadFake(t, "tls_clienthello_www_google_com.bin")
	c := injCtx(t, proto.IPProtoTCP, "142.250.185.100", payload)
	p := injRun(t, FullCaps(), c, OpParams{}, &ipFrag2Op{})

	injWantKinds(t, injKinds(p), []SegKind{SegData})
	if p.Segs[0].Frag != injFragPosDefaultTCP {
		t.Errorf("Frag = %d, want the nfqws default %d", p.Segs[0].Frag, injFragPosDefaultTCP)
	}
	if !p.DropOriginal {
		t.Error("the unfragmented original would also be sent")
	}
}

func TestIPFrag2PositionRoundingAndFallback(t *testing.T) {
	payload := injLoadFake(t, "tls_clienthello_www_google_com.bin")

	// Not a multiple of 8: rounded down, since a fragment offset counts 8-byte
	// units.
	c := injCtx(t, proto.IPProtoTCP, "1.2.3.4", payload)
	p := injRun(t, FullCaps(), c, OpParams{FragPosTCP: 43}, &ipFrag2Op{})
	if p.Segs[0].Frag != 40 {
		t.Errorf("Frag = %d, want 40", p.Segs[0].Frag)
	}

	// Past the end of the packet: nfqws falls back to 24 for TCP.
	c = injCtx(t, proto.IPProtoTCP, "1.2.3.4", []byte("short"))
	p = injRun(t, FullCaps(), c, OpParams{FragPosTCP: 4096}, &ipFrag2Op{})
	if p.Segs[0].Frag != injFragPosFallbackTCP {
		t.Errorf("Frag = %d, want the nfqws fallback %d", p.Segs[0].Frag, injFragPosFallbackTCP)
	}
}

func TestIPFrag2MarksEverySegmentOfASplitPayload(t *testing.T) {
	payload := injLoadFake(t, "tls_clienthello_www_google_com.bin")
	c := injCtx(t, proto.IPProtoTCP, "1.2.3.4", payload)
	c.Params = OpParams{}
	c.Caps = FullCaps()
	p := &Plan{Segs: []Seg{
		{Kind: SegFake, Data: payload},
		{Kind: SegData, Data: payload[:10]},
		{Kind: SegData, Data: payload[10:], SeqOff: 10},
	}}
	if err := (&ipFrag2Op{}).Apply(c, p); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if p.Segs[0].Frag != 0 {
		t.Error("ipfrag2 fragmented the decoy; nfqws applies it to the real packet only")
	}
	for i := 1; i < 3; i++ {
		if p.Segs[i].Frag != injFragPosDefaultTCP {
			t.Errorf("segment %d Frag = %d, want %d", i, p.Segs[i].Frag, injFragPosDefaultTCP)
		}
	}
}

// TestIPFrag2UDPFragmentsTheDatagram was TestIPFrag2UDPIsReportedAsAGap: Dgram
// gained a Frag field, so an IPv4 datagram is really fragmented now. The gap the
// old assertions pinned survives only for IPv6, where proto.IPFragment cannot
// help and a Fragment extension header would be needed.
func TestIPFrag2UDPFragmentsTheDatagram(t *testing.T) {
	payload := injLoadFake(t, "quic_initial_4pda.to.bin")
	c := injCtx(t, proto.IPProtoUDP, "1.2.3.4", payload)
	p := injRun(t, FullCaps(), c, OpParams{}, &ipFrag2Op{})
	injWantKinds(t, injDgramKinds(p), []SegKind{SegData})
	if p.Dgrams[0].Frag != injFragPosDefaultUDP {
		t.Errorf("Frag = %d, want the nfqws UDP default %d", p.Dgrams[0].Frag, injFragPosDefaultUDP)
	}
	if !p.DropOriginal {
		t.Error("the unfragmented original would also be sent")
	}
	if len(p.Degraded) != 0 {
		t.Errorf("Degraded = %v, want nothing on an IPv4 datagram", p.Degraded)
	}

	c = injCtx(t, proto.IPProtoUDP, "2001:db8::1", payload)
	p = injRun(t, FullCaps(), c, OpParams{}, &ipFrag2Op{})
	if len(p.Dgrams) != 0 || p.DropOriginal {
		t.Errorf("ipfrag2 claimed to fragment an IPv6 datagram it cannot express: %+v", p)
	}
	if len(p.Degraded) != 1 || p.Degraded[0] != "ipfrag2" {
		t.Errorf("Degraded = %v, want [ipfrag2]", p.Degraded)
	}
}

// ---------- hopbyhop / destopt / ipfrag1 ----------

func TestHopByHopMarksRealSegmentsOnly(t *testing.T) {
	payload := injLoadFake(t, "tls_clienthello_www_google_com.bin")
	c := injCtx(t, proto.IPProtoTCP, "2001:db8::1", payload)
	c.Fakes = FakeSet{TLS: injLoadFake(t, "tls_clienthello_max_ru.bin")}

	p := injRun(t, FullCaps(), c, injTestParams(), &fakeOp{}, &ipv6ExtOp{})
	injWantKinds(t, injKinds(p), []SegKind{SegFake, SegData})
	if p.Segs[0].Fool != injTestFooling {
		t.Errorf("hopbyhop changed the decoy's fooling: %#x", p.Segs[0].Fool)
	}
	if p.Segs[1].Fool != FoolHopByHop {
		t.Errorf("data segment Fool = %#x, want FoolHopByHop (%#x)", p.Segs[1].Fool, FoolHopByHop)
	}
	if len(p.Degraded) != 0 {
		t.Errorf("Degraded = %v, want empty for an IPv6 flow", p.Degraded)
	}
}

func TestHopByHopOnUDPMarksTheDatagram(t *testing.T) {
	payload := injLoadFake(t, "quic_initial_4pda.to.bin")
	c := injCtx(t, proto.IPProtoUDP, "2001:db8::1", payload)
	p := injRun(t, FullCaps(), c, OpParams{}, &ipv6ExtOp{})
	injWantKinds(t, injDgramKinds(p), []SegKind{SegData})
	if p.Dgrams[0].Fool != FoolHopByHop {
		t.Errorf("datagram Fool = %#x, want FoolHopByHop", p.Dgrams[0].Fool)
	}
}

func TestIPv6OnlyOpsDegradeOnIPv4(t *testing.T) {
	payload := injLoadFake(t, "tls_clienthello_www_google_com.bin")
	for _, op := range []Op{&ipv6ExtOp{}, &ipv6ExtOp{destOpt: true}, &ipFrag1Op{}} {
		c := injCtx(t, proto.IPProtoTCP, "142.250.185.100", payload)
		p := injRun(t, FullCaps(), c, injTestParams(), op)
		if len(p.Segs) != 0 || p.DropOriginal {
			t.Errorf("%s acted on an IPv4 flow: %+v", op.Name(), p)
		}
		if len(p.Degraded) != 1 || p.Degraded[0] != op.Name() {
			t.Errorf("%s: Degraded = %v, want [%s]", op.Name(), p.Degraded, op.Name())
		}
	}
}

func TestDestOptIsReportedAsAnApproximation(t *testing.T) {
	// Fooling has no destination-options bit, so destopt is emitted as a
	// hop-by-hop header and says so.
	payload := injLoadFake(t, "tls_clienthello_www_google_com.bin")
	c := injCtx(t, proto.IPProtoTCP, "2001:db8::1", payload)
	p := injRun(t, FullCaps(), c, injTestParams(), &ipv6ExtOp{destOpt: true})
	injWantKinds(t, injKinds(p), []SegKind{SegData})
	if p.Segs[0].Fool != FoolHopByHop {
		t.Errorf("data segment Fool = %#x, want FoolHopByHop", p.Segs[0].Fool)
	}
	if len(p.Degraded) != 1 || p.Degraded[0] != "destopt" {
		t.Errorf("Degraded = %v, want [destopt]", p.Degraded)
	}
}

func TestIPFrag1MarksIPv6AndReportsTheGap(t *testing.T) {
	payload := injLoadFake(t, "tls_clienthello_www_google_com.bin")
	c := injCtx(t, proto.IPProtoTCP, "2001:db8::1", payload)
	p := injRun(t, FullCaps(), c, injTestParams(), &ipFrag1Op{})
	injWantKinds(t, injKinds(p), []SegKind{SegData})
	if p.Segs[0].Fool != FoolIPFrag1 {
		t.Errorf("data segment Fool = %#x, want FoolIPFrag1 (%#x)", p.Segs[0].Fool, FoolIPFrag1)
	}
	if p.Segs[0].Frag != 0 {
		t.Error("ipfrag1 is IPv6 extension-header fooling, not IPv4 fragmentation")
	}
	if len(p.Degraded) != 1 || p.Degraded[0] != "ipfrag1" {
		t.Errorf("Degraded = %v, want [ipfrag1]", p.Degraded)
	}
}

// ---------- block ----------

func TestBlockDropsThePayloadAndNothingElse(t *testing.T) {
	payload := injLoadFake(t, "quic_initial_4pda.to.bin")
	c := injCtx(t, proto.IPProtoUDP, "142.250.185.100", payload)
	p := injRun(t, FullCaps(), c, injTestParams(), &blockOp{})
	if !p.DropOriginal {
		t.Fatal("block did not drop the payload")
	}
	if len(p.Segs) != 0 || len(p.Dgrams) != 0 {
		t.Fatalf("block put something on the wire: %+v", p)
	}
}

func TestBlockDiscardsAnythingAlreadyPlanned(t *testing.T) {
	payload := injLoadFake(t, "quic_initial_4pda.to.bin")
	c := injCtx(t, proto.IPProtoUDP, "142.250.185.100", payload)
	p := injRun(t, FullCaps(), c, injTestParams(), &fakeOp{}, &blockOp{})
	if len(p.Dgrams) != 0 || len(p.Segs) != 0 {
		t.Fatalf("block left %d datagrams and %d segments planned", len(p.Dgrams), len(p.Segs))
	}
	if !p.DropOriginal {
		t.Error("block did not drop the payload")
	}
}

func TestBlockWorksUnderProxyCaps(t *testing.T) {
	// The kill-switch needs nothing but the ability to drop, so it survives the
	// socket-level transport.
	c := injCtx(t, proto.IPProtoTCP, "1.2.3.4", []byte(injHTTPRequest))
	p := injRun(t, ProxyCaps(), c, OpParams{}, &blockOp{})
	if !p.DropOriginal || len(p.Degraded) != 0 {
		t.Errorf("block under ProxyCaps: %+v", p)
	}
}

// ---------- Caps gating ----------

func TestInjectionOpsDegradeUnderProxyCaps(t *testing.T) {
	payload := injLoadFake(t, "tls_clienthello_www_google_com.bin")
	quic := injLoadFake(t, "quic_initial_4pda.to.bin")

	cases := []struct {
		op      Op
		ipproto uint8
		payload []byte
		syn     bool
	}{
		{&fakeOp{}, proto.IPProtoTCP, payload, false},
		{&fakeOp{knownOnly: true}, proto.IPProtoTCP, payload, false},
		{&rstOp{}, proto.IPProtoTCP, payload, false},
		{&rstOp{ack: true}, proto.IPProtoTCP, payload, false},
		{&synDataOp{}, proto.IPProtoTCP, nil, true},
		{&udpLenOp{}, proto.IPProtoUDP, quic, false},
		{&ipFrag1Op{}, proto.IPProtoTCP, payload, false},
		{&ipFrag2Op{}, proto.IPProtoTCP, payload, false},
		{&ipv6ExtOp{}, proto.IPProtoTCP, payload, false},
		{&ipv6ExtOp{destOpt: true}, proto.IPProtoTCP, payload, false},
	}
	for _, tc := range cases {
		c := injCtx(t, tc.ipproto, "2001:db8::1", tc.payload)
		c.SynPkt = tc.syn
		c.Fakes = FakeSet{TLS: payload, QUIC: quic}
		p := injRun(t, ProxyCaps(), c, injTestParams(), tc.op)

		if len(p.Degraded) != 1 || p.Degraded[0] != tc.op.Name() {
			t.Errorf("%s: Degraded = %v, want [%s]", tc.op.Name(), p.Degraded, tc.op.Name())
		}
		if len(p.Segs) != 0 || len(p.Dgrams) != 0 {
			t.Errorf("%s: plan is not empty under ProxyCaps: %+v", tc.op.Name(), p)
		}
		if p.DropOriginal {
			t.Errorf("%s: a degraded injection op must not drop the payload", tc.op.Name())
		}
	}
}

func TestInjectionOpsRequireInjection(t *testing.T) {
	for _, op := range []Op{&fakeOp{}, &fakeOp{knownOnly: true}, &rstOp{}, &rstOp{ack: true}, &synDataOp{}} {
		if !op.Requires().Inject {
			t.Errorf("%s does not declare Inject", op.Name())
		}
	}
	if !(&udpLenOp{}).Requires().UDP {
		t.Error("udplen does not declare UDP")
	}
	for _, op := range []Op{&ipFrag1Op{}, &ipFrag2Op{}} {
		if !op.Requires().Frag {
			t.Errorf("%s does not declare Frag", op.Name())
		}
	}
	for _, op := range []Op{&ipv6ExtOp{}, &ipv6ExtOp{destOpt: true}, &ipFrag1Op{}} {
		if !op.Requires().IPv6ExtHdr {
			t.Errorf("%s does not declare IPv6ExtHdr", op.Name())
		}
	}
}

// ---------- hostile input ----------

func TestInjectionOpsSurviveDegenerateInput(t *testing.T) {
	ops := []Op{&fakeOp{}, &fakeOp{knownOnly: true}, &rstOp{}, &rstOp{ack: true}, &synDataOp{},
		&blockOp{}, &udpLenOp{}, &ipFrag1Op{}, &ipFrag2Op{}, &ipv6ExtOp{}, &ipv6ExtOp{destOpt: true}}

	payloads := [][]byte{
		nil,
		{},
		{0x16},                   // a one-byte TLS record start
		{0x16, 0x03, 0x01, 0xff}, // a truncated record header
		bytes.Repeat([]byte{0xff}, 3000),
	}
	for _, op := range ops {
		for _, ipproto := range []uint8{proto.IPProtoTCP, proto.IPProtoUDP, 0} {
			for _, pl := range payloads {
				for _, syn := range []bool{false, true} {
					c := injCtx(t, ipproto, "1.2.3.4", pl)
					c.SynPkt = syn
					c.Params = injTestParams()
					c.Caps = FullCaps()
					p := &Plan{}
					if err := op.Apply(c, p); err != nil {
						t.Fatalf("%s: Apply: %v", op.Name(), err)
					}
					// Nothing may be planned for an empty payload except the
					// kill-switch and syndata's own segment.
					if len(pl) == 0 && op.Name() != "block" && op.Name() != "syndata" {
						if len(p.Segs) != 0 || len(p.Dgrams) != 0 {
							t.Errorf("%s planned %d segs / %d dgrams for an empty payload",
								op.Name(), len(p.Segs), len(p.Dgrams))
						}
					}
				}
			}
		}
	}

	// A nil Ctx or Plan must not panic either.
	for _, op := range ops {
		if err := op.Apply(nil, &Plan{}); err != nil {
			t.Errorf("%s: Apply(nil ctx): %v", op.Name(), err)
		}
		if err := op.Apply(&Ctx{}, nil); err != nil {
			t.Errorf("%s: Apply(nil plan): %v", op.Name(), err)
		}
	}
}
