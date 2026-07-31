package divert

// This file is the project's headline claim, executed: a real Flowseal strategy,
// loaded from strategies/*.toml through the real loader, run through the real
// engine, and turned into wire images by the real BuildPlanPackets — then every
// produced packet is re-parsed with proto.Parse and checked byte by byte against
// what winws would have put on the link.
//
// Nothing here touches the network, a socket, or /dev. The whole pipeline
// (strategy.Load -> desync.FakeSet -> engine.New -> engine.OnTCP/OnUDP ->
// BuildPlanPackets) is pure, which is the entire reason parity is provable
// without root: what stays unproven is delivery, not content. See
// TestParityDeliveryIsOutOfScopeWithoutRoot and docs/parity.md.
//
// The numbers asserted below are the source of docs/parity.md. Changing one
// means the documented wire behaviour changed, so update both together.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/engine"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// Repository directories, relative to internal/transport/divert. The real
// strategies, the real lists and the real fake blobs are used: a parity test
// against invented inputs would prove nothing.
const (
	parityRepoRoot   = "../../.."
	parityStrategies = parityRepoRoot + "/strategies"
	parityListsDir   = parityRepoRoot + "/lists"
	parityFakesDir   = parityRepoRoot + "/fakes"
)

// The simulated client and peer.
//
// parityClientIP is an RFC 1918 address, i.e. a plausible LAN client.
// parityServerIP is inside 142.250.0.0/15, which lists/ipset-all.txt carries and
// lists/ipset-exclude.txt does not — that is what makes general.toml's
// ipset-gated UDP profile match. It is never contacted: no test in this file
// opens a socket.
var (
	parityClientIP = netip.MustParseAddr("192.168.3.130")
	parityServerIP = netip.MustParseAddr("142.250.185.198")
)

// The intercepted packet's own header fields. Every one of them must survive
// into every produced packet unless a desync op deliberately changes it, so they
// are distinctive rather than round.
const (
	parityClientPort = uint16(54321)
	parityHTTPSPort  = uint16(443)

	// Discord voice: the client's own source port and the voice server's port.
	// general.toml's second profile filters on --filter-udp=50000-50100, which
	// is the DESTINATION port, so the two are kept distinct to make "the decoy
	// leaves from the client's own source port" a real assertion.
	parityVoiceSrcPort = uint16(50001)
	parityVoiceDstPort = uint16(50004)

	parityISN    = uint32(0x30000000)
	parityAck    = uint32(0x11112222)
	parityWindow = uint16(2058)
	parityTTL    = uint8(64)
	parityIPID   = uint16(0x4a3b)
	parityTSVal  = uint32(0x0abbccdd)
	parityTSEcho = uint32(0x76543210)

	// BuildOpts inputs, pinned so every random field is reproducible.
	parityIPIDStart = uint16(0x1000)
	parityRandFill  = byte(0x5a)
	// parityRandIPID is what fixedRand(parityRandFill) yields for a 16-bit
	// field: the ip.id of a UDP datagram, which Dgram cannot request a mode for.
	parityRandIPID = uint16(0x5a5a)

	// zapret's --dpi-desync-fooling defaults (desync.DefaultFoolParams), written
	// as the magnitude each field is shifted BACK by, because that is how the
	// assertions read: badseq -10000, badack -66000, ts -600000.
	// TestParityFoolingDefaults keeps these tied to desync's own numbers.
	parityBadSeqBack = uint32(10000)
	parityBadAckBack = uint32(66000)
	parityTSBack     = uint32(600000)

	// Fake blob names, as the strategies spell them.
	parityTLSBlob     = "tls_clienthello_www_google_com.bin"
	parityQUICBlob    = "quic_initial_www_google_com.bin"
	parityDiscordBlob = "ACTIVE_DISCORD_UDP.bin"

	// The googlevideo host the simulated client asks for. lists/list-google.txt
	// carries "googlevideo.com", and HostSet matching is suffix-with-label-
	// boundary, so this is what selects general.toml's --filter-tcp=443
	// --hostlist=list-google.txt profile.
	parityGoogleVideoHost = "rr3---sn-4g5ednek.googlevideo.com"

	// Offsets inside a TLS ClientHello, fixed by the record layout: a 5-byte
	// record header, a 4-byte handshake header and a 2-byte legacy_version put
	// ClientHello.random at 11 and the legacy_session_id length byte right after
	// it at 43.
	parityHelloRandomOff = 11
	parityHelloRandomLen = 32
	parityHelloSIDLenOff = parityHelloRandomOff + parityHelloRandomLen

	// parityMTU is the Ethernet MTU the fixtures are sized against. Splitting an
	// over-MTU packet is the datapath's job (fragmentForMTU, covered by
	// TestFragmentForMTU), not BuildPlanPackets': a packet over the MTU here
	// would mean the sizes documented in docs/parity.md describe something that
	// cannot leave as one frame.
	parityMTU = 1500
)

// parityFake reads one blob out of the repository's fakes directory.
func parityFake(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(parityFakesDir, name))
	if err != nil {
		t.Fatalf("reading the fake blob %s: %v", name, err)
	}
	if len(b) == 0 {
		t.Fatalf("the fake blob %s is empty", name)
	}
	return b
}

// parityFakeSet builds the engine-wide FakeSet exactly the way cmd/zapretd does
// (see Daemon.loadFakes and its defaultFakeFile table): the same blob names, in
// the same slots, so an op that names no fake of its own falls back to the same
// bytes the daemon would give it.
func parityFakeSet(t *testing.T) desync.FakeSet {
	t.Helper()
	return desync.FakeSet{
		TLS:        parityFake(t, parityTLSBlob),
		QUIC:       parityFake(t, parityQUICBlob),
		Discord:    [][]byte{parityFake(t, parityDiscordBlob)},
		STUN:       [][]byte{parityFake(t, "stun.bin"), parityFake(t, "stun2.bin")},
		UnknownUDP: [][]byte{parityFake(t, "ACTIVE_GAME_UDP.bin")},
	}
}

// parityStrategyCache keeps compiled strategies between tests. Compiling one
// parses lists/ipset-all.txt (32k CIDRs); a *Strategy is read-only once compiled
// and the engine never mutates it, so sharing is safe.
var (
	parityStrategyMu    sync.Mutex
	parityStrategyCache = map[string]*strategy.Strategy{}
)

// parityLoad compiles strategies/<name>.toml with the divert transport's
// capabilities, against the repository's real lists and fakes.
func parityLoad(t *testing.T, name string) *strategy.Strategy {
	t.Helper()
	parityStrategyMu.Lock()
	defer parityStrategyMu.Unlock()
	if s, ok := parityStrategyCache[name]; ok {
		return s
	}
	s, err := strategy.Load(filepath.Join(parityStrategies, name+".toml"), strategy.LoadOpts{
		ListsDir: parityListsDir,
		FakesDir: parityFakesDir,
		Caps:     desync.FullCaps(),
	})
	if err != nil {
		t.Fatalf("loading strategies/%s.toml: %v", name, err)
	}
	parityStrategyCache[name] = s
	return s
}

// parityClientHello builds the request the simulated client sends: the real
// captured ClientHello from fakes/tls_clienthello_www_google_com.bin with its SNI
// rewritten to a googlevideo host, so the payload is a genuine, structurally
// valid hello that the Google-slot hostlist matches — and is NOT the blob the
// strategy uses as a decoy, which is what makes "the decoy is not the client's
// own request" checkable.
func parityClientHello(t *testing.T) []byte {
	t.Helper()
	blob := parityFake(t, parityTLSBlob)
	hello := proto.ModifyTLSFake(blob, proto.TLSMod{SNI: parityGoogleVideoHost})
	info, ok := proto.ParseTLSClientHello(hello)
	if !ok {
		t.Fatalf("the rewritten ClientHello does not parse as one")
	}
	if info.Host != parityGoogleVideoHost {
		t.Fatalf("rewritten SNI is %q, want %q", info.Host, parityGoogleVideoHost)
	}
	if bytes.Equal(hello, blob) {
		t.Fatalf("the rewritten hello is byte-identical to the decoy blob; the test would prove nothing")
	}
	if hello[0] != 0x16 {
		t.Fatalf("the hello does not start with the TLS handshake record type: %#02x", hello[0])
	}
	return hello
}

// parityTCPPkt is the intercepted client->server TCP data packet: PSH|ACK with
// the RFC 7323 timestamp option a real macOS client negotiates.
func parityTCPPkt(t *testing.T, payload []byte, srcPort uint16) *proto.Pkt {
	t.Helper()
	return mkPkt(t, proto.Tmpl{
		Src: parityClientIP, Dst: parityServerIP,
		SrcPort: srcPort, DstPort: parityHTTPSPort,
		Seq: parityISN, Ack: parityAck,
		Flags: proto.TCPPsh | proto.TCPAck, Window: parityWindow,
		TTL: parityTTL, IPID: parityIPID, DF: true,
		TCPOpts: tsOpts(parityTSVal, parityTSEcho), Payload: payload,
	})
}

// parityUDPPkt is the intercepted client->server datagram.
func parityUDPPkt(t *testing.T, payload []byte, srcPort, dstPort uint16) *proto.Pkt {
	t.Helper()
	return mkPkt(t, proto.Tmpl{
		Src: parityClientIP, Dst: parityServerIP,
		SrcPort: srcPort, DstPort: dstPort,
		TTL: parityTTL, IPID: parityIPID, DF: true,
		UDP: true, Payload: payload,
	})
}

// parityBuildOpts is the deterministic BuildOpts every test here uses.
func parityBuildOpts() BuildOpts {
	return BuildOpts{IPIDStart: parityIPIDStart, Rand: fixedRand(parityRandFill)}
}

// parityRunTCP drives the full pipeline for one TCP packet and returns the plan
// plus every produced packet, already re-parsed.
func parityRunTCP(t *testing.T, strategyName string, pkt *proto.Pkt) (*desync.Plan, []out) {
	t.Helper()
	eng := engine.New(parityLoad(t, strategyName), desync.FullCaps(), parityFakeSet(t))
	plan, err := eng.OnTCP(pkt)
	if err != nil {
		t.Fatalf("%s: engine.OnTCP: %v", strategyName, err)
	}
	if plan == nil {
		t.Fatalf("%s: no profile matched the packet, so nothing would be desynced", strategyName)
	}
	if !plan.DropOriginal {
		t.Fatalf("%s: the plan re-emits the payload but does not claim DropOriginal; "+
			"the request would go out twice", strategyName)
	}
	return plan, build(t, pkt, plan, parityBuildOpts())
}

// parityRunUDP is parityRunTCP for a datagram.
func parityRunUDP(t *testing.T, strategyName string, pkt *proto.Pkt) (*desync.Plan, []out) {
	t.Helper()
	eng := engine.New(parityLoad(t, strategyName), desync.FullCaps(), parityFakeSet(t))
	plan, err := eng.OnUDP(pkt)
	if err != nil {
		t.Fatalf("%s: engine.OnUDP: %v", strategyName, err)
	}
	if plan == nil {
		t.Fatalf("%s: no profile matched the datagram", strategyName)
	}
	if !plan.DropOriginal {
		t.Fatalf("%s: the plan re-emits the datagram but does not claim DropOriginal", strategyName)
	}
	return plan, build(t, pkt, plan, parityBuildOpts())
}

// ---------------------------------------------------------------------------
// wire-fact helpers
// ---------------------------------------------------------------------------

// parityTupleAndSums is the invariant that holds for EVERY packet the divert
// transport emits, whatever the strategy: the 4-tuple is the application's own,
// byte for byte, and both checksums are the ones the peer will recompute.
//
// The 4-tuple is compared as raw header bytes rather than as parsed values,
// because "we never re-NAT" is a statement about the bytes on the link.
func parityTupleAndSums(t *testing.T, label string, o out, orig *proto.Pkt) {
	t.Helper()
	if o.pkt == nil {
		t.Fatalf("%s: the produced packet did not re-parse", label)
	}
	if !bytes.Equal(o.raw[12:20], orig.Raw[12:20]) {
		t.Errorf("%s: IPv4 addresses changed: % x, want % x", label, o.raw[12:20], orig.Raw[12:20])
	}
	if !bytes.Equal(o.raw[o.ihl:o.ihl+4], orig.Raw[orig.L3Len:orig.L3Len+4]) {
		t.Errorf("%s: ports changed: % x, want % x", label,
			o.raw[o.ihl:o.ihl+4], orig.Raw[orig.L3Len:orig.L3Len+4])
	}
	if o.pkt.Src != orig.Src || o.pkt.Dst != orig.Dst ||
		o.pkt.SrcPort != orig.SrcPort || o.pkt.DstPort != orig.DstPort {
		t.Errorf("%s: 4-tuple is %s:%d -> %s:%d, want %s:%d -> %s:%d", label,
			o.pkt.Src, o.pkt.SrcPort, o.pkt.Dst, o.pkt.DstPort,
			orig.Src, orig.SrcPort, orig.Dst, orig.DstPort)
	}
	if o.pkt.Proto != orig.Proto {
		t.Errorf("%s: IP protocol is %d, want %d", label, o.pkt.Proto, orig.Proto)
	}
	if !ipHeaderChecksumOK(o.raw) {
		t.Errorf("%s: IPv4 header checksum does not verify", label)
	}
	if !l4ChecksumOK(t, o.raw) {
		t.Errorf("%s: L4 checksum does not verify", label)
	}
	if len(o.raw) > parityMTU {
		t.Errorf("%s: the produced packet is %d bytes, over the %d-byte MTU these "+
			"fixtures are sized for; the documented sizes assume one frame per packet",
			label, len(o.raw), parityMTU)
	}
}

// parityNoDesyncTTL asserts that a profile configures no --dpi-desync-ttl at all.
//
// It exists because docs/parity.md records that every decoy in these strategies
// travels with the CLIENT's own hop limit, which is a fact about flowseal's
// command lines (none of the 21 converted .bat files sets --dpi-desync-ttl), not
// about our transport. Checking it at the source turns that sentence from prose
// into an assertion, so a future strategy that does set a TTL fails here instead
// of quietly contradicting the document.
func parityNoDesyncTTL(t *testing.T, strategyName string, profileIdx int) {
	t.Helper()
	prof := parityLoad(t, strategyName).Profiles[profileIdx]
	for _, op := range prof.Ops {
		if op.Params.TTL != 0 || op.Params.TTLAuto {
			t.Fatalf("%s profile %q op %s configures a desync TTL (ttl=%d auto=%v); "+
				"docs/parity.md documents that these profiles configure none",
				strategyName, prof.Name, op.Op.Name(), op.Params.TTL, op.Params.TTLAuto)
		}
	}
}

// parityTSVals reads the RFC 7323 timestamps off a produced TCP packet.
func parityTSVals(t *testing.T, label string, o out) (tsval, tsecho uint32) {
	t.Helper()
	tsval, tsecho, ok := proto.TCPTimestamps(o.pkt.TCPOpts)
	if !ok {
		t.Fatalf("%s: the produced packet carries no timestamp option, but the "+
			"intercepted one did; the peer would drop it", label)
	}
	return tsval, tsecho
}

// parityStreamOffset is a produced packet's position in the client's byte
// stream: negative for a segment sent below the receive window
// (--dpi-desync-split-seqovl).
func parityStreamOffset(o out, orig *proto.Pkt) int {
	return int(int32(o.pkt.Seq - orig.Seq))
}

// parityReassemble rebuilds the byte stream a peer's TCP delivers to the
// application from the DATA packets of a plan: each payload is written at its own
// sequence offset, and anything below offset 0 — the seqovl prefix, which is
// below the window — is discarded exactly as the peer's TCP discards it.
//
// It fails on a gap, on a write past the end of the request, and on two packets
// claiming the same offset with different bytes, so "the server still sees a
// valid stream" is proven and not assumed.
func parityReassemble(t *testing.T, label string, data []out, orig *proto.Pkt, want int) []byte {
	t.Helper()
	stream := make([]byte, want)
	filled := make([]bool, want)
	for i, o := range data {
		off := parityStreamOffset(o, orig)
		for j, b := range o.pkt.Payload() {
			at := off + j
			if at < 0 {
				continue // below the receive window
			}
			if at >= want {
				t.Fatalf("%s: data packet %d writes stream offset %d, past the %d-byte request",
					label, i, at, want)
			}
			if filled[at] && stream[at] != b {
				t.Fatalf("%s: data packet %d overwrites stream offset %d (%#02x -> %#02x)",
					label, i, at, stream[at], b)
			}
			stream[at], filled[at] = b, true
		}
	}
	for i, ok := range filled {
		if !ok {
			t.Fatalf("%s: stream offset %d was never transmitted, the request is incomplete", label, i)
		}
	}
	return stream
}

// parityGroup is one run of consecutive packets a strategy produces: N copies of
// a segment with a known stream offset and payload length. Spelling the expected
// transmission out as a table is what makes a reordering or a lost repeat a
// failure rather than a silent behaviour change.
type parityGroup struct {
	what   string // human-readable role, used in failure messages
	count  int    // how many packets in a row
	seqOff int    // stream offset of the first payload byte (TCP only)
	length int    // payload length
}

// parityWalk checks a produced packet list against a group table — count, order,
// per-packet payload length, stream offset and the universal 4-tuple/checksum
// invariant — and returns, for each group, the packets that belong to it.
func parityWalk(t *testing.T, label string, pkts []out, orig *proto.Pkt, groups []parityGroup) [][]out {
	t.Helper()
	total := 0
	for _, g := range groups {
		total += g.count
	}
	if len(pkts) != total {
		t.Fatalf("%s: %d packets on the wire, want %d (%s)", label, len(pkts), total, parityGroupsText(groups))
	}
	res := make([][]out, 0, len(groups))
	at := 0
	for gi, g := range groups {
		set := pkts[at : at+g.count]
		for i, o := range set {
			lbl := fmt.Sprintf("%s: %s (group %d, copy %d/%d)", label, g.what, gi, i+1, g.count)
			parityTupleAndSums(t, lbl, o, orig)
			if got := len(o.pkt.Payload()); got != g.length {
				t.Errorf("%s: payload is %d bytes, want %d", lbl, got, g.length)
			}
			if orig.IsTCP() {
				if got := parityStreamOffset(o, orig); got != g.seqOff {
					t.Errorf("%s: stream offset is %d, want %d", lbl, got, g.seqOff)
				}
			}
		}
		res = append(res, set)
		at += g.count
	}
	return res
}

// parityGroupsText renders a group table for a failure message.
func parityGroupsText(groups []parityGroup) string {
	s := ""
	for i, g := range groups {
		if i > 0 {
			s += " + "
		}
		s += fmt.Sprintf("%dx %s", g.count, g.what)
	}
	return s
}

// parityIdentical reports whether every packet in set carries the same wire
// image. --dpi-desync-repeats re-sends one buffer, so this is the expected shape
// of a repeated decoy, not a defect.
func parityIdentical(set []out) bool {
	for i := 1; i < len(set); i++ {
		if !bytes.Equal(set[i].raw, set[0].raw) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// the numbers this file is pinned to
// ---------------------------------------------------------------------------

// TestParityFoolingDefaults ties the shift magnitudes the assertions use to
// desync's own defaults. None of the strategies overrides badseq_increment,
// badack_increment or ts_increment, so a change in DefaultFoolParams changes
// every wire number below — and must fail here rather than silently.
func TestParityFoolingDefaults(t *testing.T) {
	got := desync.DefaultFoolParams()
	want := desync.FoolParams{
		BadSeqIncrement: -int32(parityBadSeqBack),
		BadAckIncrement: -int32(parityBadAckBack),
		TSIncrement:     -int32(parityTSBack),
	}
	if got != want {
		t.Fatalf("desync.DefaultFoolParams() = %+v, this file is pinned to %+v; "+
			"update the constants and docs/parity.md together", got, want)
	}
}

// ---------------------------------------------------------------------------
// general.toml — the Google slot: multisplit, pos 1, seqovl 681, ip-id=zero
// ---------------------------------------------------------------------------

// TestParityGeneralGoogleSlot is the flagship assertion of the whole project.
//
// strategies/general.toml's fourth profile is flowseal's
//
//	--filter-tcp=443 --hostlist=list-google.txt --ip-id=zero
//	--dpi-desync=multisplit --dpi-desync-split-pos=1 --dpi-desync-split-seqovl=681
//	--dpi-desync-split-seqovl-pattern=tls_clienthello_www_google_com.bin
//
// On the wire that is exactly two packets and no decoys: the first carries 681
// bytes of a real, unrelated ClientHello followed by the single first byte of the
// client's own request, sent 681 bytes BELOW the sequence window; the second
// carries the rest. A DPI box that reassembles by sequence number swallows the
// decoy hello and loses the real SNI; the peer's TCP drops the below-window
// prefix and reassembles the request intact.
func TestParityGeneralGoogleSlot(t *testing.T) {
	const (
		ovl   = 681 // --dpi-desync-split-seqovl
		split = 1   // --dpi-desync-split-pos
	)

	blob := parityFake(t, parityTLSBlob)
	if len(blob) != ovl {
		t.Fatalf("fakes/%s is %d bytes; general.toml's seqovl is %d, so the "+
			"pattern must be exactly that long to fill it without repeating",
			parityTLSBlob, len(blob), ovl)
	}

	strat := parityLoad(t, "general")
	if !strat.WindowTCP.Has(parityHTTPSPort) {
		t.Fatalf("general.toml's --wf-tcp window does not cover port %d, so pf would "+
			"never steer this flow into the tunnel", parityHTTPSPort)
	}

	client := parityClientHello(t)
	orig := parityTCPPkt(t, client, parityClientPort)
	plan, pkts := parityRunTCP(t, "general", orig)

	if len(plan.Degraded) != 0 {
		t.Errorf("the divert transport degraded %v; with FullCaps nothing should be", plan.Degraded)
	}

	groups := parityWalk(t, "general/google", pkts, orig, []parityGroup{
		{what: "overlapped first segment", count: 1, seqOff: -ovl, length: ovl + split},
		{what: "the rest of the request", count: 1, seqOff: split, length: len(client) - split},
	})
	first, second := groups[0][0], groups[1][0]

	// --- no decoys at all: multisplit injects nothing ---
	if len(plan.Segs) != 2 {
		t.Fatalf("the plan holds %d segments, want 2 (multisplit alone injects no fakes)", len(plan.Segs))
	}
	for i, s := range plan.Segs {
		if s.Kind != desync.SegData {
			t.Errorf("segment %d is kind %d, want SegData: this profile has no fake op", i, s.Kind)
		}
	}

	// --- packet 1: sequence 681 below the window ---
	if got := parityStreamOffset(first, orig); got != -ovl {
		t.Errorf("packet 1 sits at stream offset %d, want %d (seq %#08x, want %#08x)",
			got, -ovl, first.pkt.Seq, orig.Seq-ovl)
	}
	if first.pkt.Seq != orig.Seq-ovl {
		t.Errorf("packet 1 seq is %#08x, want %#08x", first.pkt.Seq, orig.Seq-ovl)
	}
	p1 := first.pkt.Payload()
	if !bytes.Equal(p1[:ovl], blob) {
		t.Errorf("packet 1's first %d bytes are not byte-identical to fakes/%s", ovl, parityTLSBlob)
	}
	if p1[ovl] != 0x16 || p1[ovl] != client[0] {
		t.Errorf("packet 1 byte %d is %#02x, want the ClientHello's first byte %#02x (0x16)",
			ovl+1, p1[ovl], client[0])
	}
	if bytes.Equal(p1[:ovl], client[:ovl]) {
		t.Errorf("the overlap prefix is the client's own request; it must be the unrelated decoy hello")
	}

	// --- packet 2: the remainder, at the window's true start + 1 ---
	if second.pkt.Seq != orig.Seq+split {
		t.Errorf("packet 2 seq is %#08x, want %#08x", second.pkt.Seq, orig.Seq+split)
	}
	if !bytes.Equal(second.pkt.Payload(), client[split:]) {
		t.Errorf("packet 2's payload is not the rest of the ClientHello")
	}

	// --- --ip-id=zero on both ---
	for i, o := range pkts {
		if o.pkt.IPID != 0 {
			t.Errorf("packet %d has ip.id %#04x, want 0 (--ip-id=zero)", i+1, o.pkt.IPID)
		}
	}

	// --- every other header field is the application's own ---
	for i, o := range pkts {
		if o.pkt.TTL != parityTTL {
			t.Errorf("packet %d has TTL %d, want the client's own %d: multisplit forges no TTL",
				i+1, o.pkt.TTL, parityTTL)
		}
		if o.pkt.Flags != proto.TCPPsh|proto.TCPAck {
			t.Errorf("packet %d has flags %#02x, want PSH|ACK", i+1, o.pkt.Flags)
		}
		if o.pkt.Ack != parityAck {
			t.Errorf("packet %d has ack %#08x, want the client's own %#08x", i+1, o.pkt.Ack, parityAck)
		}
		if o.pkt.Window != parityWindow {
			t.Errorf("packet %d advertises window %d, want the client's own %d", i+1, o.pkt.Window, parityWindow)
		}
		if !o.pkt.DF {
			t.Errorf("packet %d lost the client's Don't-Fragment bit", i+1)
		}
		if tsval, tsecho := parityTSVals(t, fmt.Sprintf("packet %d", i+1), o); tsval != parityTSVal || tsecho != parityTSEcho {
			t.Errorf("packet %d timestamps are (%#08x,%#08x), want the client's own (%#08x,%#08x): "+
				"a real segment carries no fooling", i+1, tsval, tsecho, parityTSVal, parityTSEcho)
		}
	}

	// --- the peer still receives exactly the request the client sent ---
	got := parityReassemble(t, "general/google", pkts, orig, len(client))
	if !bytes.Equal(got, client) {
		t.Fatalf("the reassembled stream is not the client's ClientHello (%d bytes vs %d)", len(got), len(client))
	}
	if info, ok := proto.ParseTLSClientHello(got); !ok || info.Host != parityGoogleVideoHost {
		t.Fatalf("the reassembled stream does not parse as the client's hello for %q (ok=%v host=%q)",
			parityGoogleVideoHost, ok, info.Host)
	}
}

// ---------------------------------------------------------------------------
// general-alt.toml — fake + fakedsplit, fooling=ts, repeats=6
// ---------------------------------------------------------------------------

// TestParityGeneralAltFakeAndFakedSplit pins strategies/general-alt.toml's
// Google slot, flowseal's
//
//	--filter-tcp=443 --hostlist=list-google.txt --ip-id=zero
//	--dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts
//	--dpi-desync-fake-tls=tls_clienthello_www_google_com.bin
//	--dpi-desync-fakedsplit-pattern=0x00
//
// Two decoy families ride in front of the real bytes: six copies of a whole
// unrelated ClientHello (the `fake` op), and, around each real part, six copies
// of a zero-filled segment covering exactly that part's sequence range (the
// `fakedsplit` op, upstream's F1 R1 F1 F2 R2 F2 order). Every decoy carries a
// timestamp shifted 600000 ticks into the past, which is what makes the peer's
// PAWS check discard it while a stateless DPI still parses its payload; the real
// segments carry the client's own timestamp untouched.
func TestParityGeneralAltFakeAndFakedSplit(t *testing.T) {
	const (
		reps  = 6 // --dpi-desync-repeats
		split = 2 // fakedsplit's default --dpi-desync-split-pos
	)

	blob := parityFake(t, parityTLSBlob)
	client := parityClientHello(t)
	orig := parityTCPPkt(t, client, parityClientPort)
	plan, pkts := parityRunTCP(t, "general-alt", orig)

	if len(plan.Degraded) != 0 {
		t.Errorf("the divert transport degraded %v; with FullCaps nothing should be", plan.Degraded)
	}

	tail := len(client) - split
	groups := parityWalk(t, "general-alt/google", pkts, orig, []parityGroup{
		{what: "fake op decoy hello", count: reps, seqOff: 0, length: len(blob)},
		{what: "fakedsplit F1 before R1", count: reps, seqOff: 0, length: split},
		{what: "real part 1", count: 1, seqOff: 0, length: split},
		{what: "fakedsplit F1 after R1", count: reps, seqOff: 0, length: split},
		{what: "fakedsplit F2 before R2", count: reps, seqOff: split, length: tail},
		{what: "real part 2", count: 1, seqOff: split, length: tail},
		{what: "fakedsplit F2 after R2", count: reps, seqOff: split, length: tail},
	})

	// --- six decoys of the configured hello lead the transmission ---
	lead := groups[0]
	for i, o := range lead {
		if got := o.pkt.Payload(); !bytes.Equal(got, blob) {
			t.Errorf("decoy %d/%d is not byte-identical to fakes/%s", i+1, reps, parityTLSBlob)
		}
		if bytes.Equal(o.pkt.Payload(), client) {
			t.Errorf("decoy %d/%d carries the client's real ClientHello; the DPI would "+
				"latch onto the true SNI", i+1, reps)
		}
	}
	if !parityIdentical(lead) {
		t.Errorf("the %d repeats of the decoy differ; --dpi-desync-repeats re-sends one buffer", reps)
	}
	if info, ok := proto.ParseTLSClientHello(lead[0].pkt.Payload()); !ok || info.Host != "www.google.com" {
		t.Errorf("the decoy does not parse as a ClientHello for www.google.com (ok=%v host=%q)", ok, info.Host)
	}

	// --- fooling=ts: every decoy's timestamp is shifted, no real one is ---
	wantFakeTS := parityTSVal - parityTSBack
	for gi, g := range []struct {
		set  []out
		what string
		fake bool
	}{
		{groups[0], "fake op decoy", true},
		{groups[1], "F1 before R1", true},
		{groups[2], "real part 1", false},
		{groups[3], "F1 after R1", true},
		{groups[4], "F2 before R2", true},
		{groups[5], "real part 2", false},
		{groups[6], "F2 after R2", true},
	} {
		for i, o := range g.set {
			lbl := fmt.Sprintf("%s copy %d", g.what, i+1)
			tsval, tsecho := parityTSVals(t, lbl, o)
			want := parityTSVal
			if g.fake {
				want = wantFakeTS
			}
			if tsval != want {
				t.Errorf("%s (group %d): TSval is %#08x, want %#08x", lbl, gi, tsval, want)
			}
			if tsecho != parityTSEcho {
				t.Errorf("%s (group %d): TSecr is %#08x, want the client's own %#08x", lbl, gi, tsecho, parityTSEcho)
			}
			// fooling=ts alone: the sequence numbers and the checksum stay honest,
			// which is exactly why PAWS is what has to kill the decoy.
			if o.pkt.Ack != parityAck {
				t.Errorf("%s (group %d): ack is %#08x, want %#08x", lbl, gi, o.pkt.Ack, parityAck)
			}
		}
	}

	// --- the fakedsplit decoys are the 0x00 pattern, covering exactly the
	// sequence range of the real part they stand in for (parityWalk already
	// checked the offsets) ---
	for _, gi := range []int{1, 3} {
		for i, o := range groups[gi] {
			if !bytes.Equal(o.pkt.Payload(), make([]byte, split)) {
				t.Errorf("F1 copy %d is not the 0x00 --dpi-desync-fakedsplit-pattern", i+1)
			}
		}
	}
	for _, gi := range []int{4, 6} {
		for i, o := range groups[gi] {
			if !bytes.Equal(o.pkt.Payload(), make([]byte, tail)) {
				t.Errorf("F2 copy %d is not the 0x00 --dpi-desync-fakedsplit-pattern", i+1)
			}
		}
	}

	// --- the two real segments carry the real bytes, in order ---
	r1, r2 := groups[2][0], groups[5][0]
	if !bytes.Equal(r1.pkt.Payload(), client[:split]) {
		t.Errorf("real part 1 is not the request's first %d bytes", split)
	}
	if !bytes.Equal(r2.pkt.Payload(), client[split:]) {
		t.Errorf("real part 2 is not the rest of the request")
	}
	if r1.pkt.Seq != orig.Seq {
		t.Errorf("real part 1 seq is %#08x, want the client's own %#08x", r1.pkt.Seq, orig.Seq)
	}
	if r2.pkt.Seq != orig.Seq+split {
		t.Errorf("real part 2 seq is %#08x, want %#08x", r2.pkt.Seq, orig.Seq+split)
	}
	got := parityReassemble(t, "general-alt/real", []out{r1, r2}, orig, len(client))
	if !bytes.Equal(got, client) {
		t.Fatalf("the two real segments do not reassemble into the client's request")
	}

	// --- --ip-id=zero covers the decoys too, and no packet carries a forged TTL:
	// what has to kill the decoy here is the peer's PAWS check, nothing else ---
	parityNoDesyncTTL(t, "general-alt", 3)
	for i, o := range pkts {
		if o.pkt.IPID != 0 {
			t.Errorf("packet %d has ip.id %#04x, want 0 (--ip-id=zero)", i+1, o.pkt.IPID)
		}
		if o.pkt.TTL != parityTTL {
			t.Errorf("packet %d has TTL %d, want the client's own %d: general-alt.toml "+
				"configures no --dpi-desync-ttl", i+1, o.pkt.TTL, parityTTL)
		}
	}
}

// ---------------------------------------------------------------------------
// general-fake-tls-auto.toml — fake + multidisorder, fooling=badseq, repeats=11
// ---------------------------------------------------------------------------

// TestParityGeneralFakeTLSAutoBadSeqAndDisorder pins
// strategies/general-fake-tls-auto.toml's Google slot, flowseal's
//
//	--filter-tcp=443 --hostlist=list-google.txt --ip-id=zero
//	--dpi-desync=fake,multidisorder --dpi-desync-repeats=11
//	--dpi-desync-fooling=badseq
//	--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com
//	--dpi-desync-split-pos=1,midsld
//
// Eleven decoys go out first, each a mutated copy of the engine-wide fake
// ClientHello: a fresh random and session id (rnd), that session id duplicated
// inside its own field (dupsid) and the SNI forced to www.google.com. Each is
// sent 10000 bytes below the real sequence number and 66000 below the real ack,
// so the peer's TCP has no window for it at all. The real request then follows in
// three segments transmitted in DESCENDING sequence order — that is what
// "disorder" means.
func TestParityGeneralFakeTLSAutoBadSeqAndDisorder(t *testing.T) {
	const (
		reps    = 11  // --dpi-desync-repeats
		split   = 1   // --dpi-desync-split-pos=1
		midSLD  = 148 // ...,midsld resolved against the client's own SNI
		sidLen  = 32  // the source blob's legacy_session_id length
		fakeLen = 713 // 681 + sidLen: dupsid doubles the session id
	)

	blob := parityFake(t, parityTLSBlob)
	client := parityClientHello(t)
	orig := parityTCPPkt(t, client, parityClientPort)
	plan, pkts := parityRunTCP(t, "general-fake-tls-auto", orig)

	if len(plan.Degraded) != 0 {
		t.Errorf("the divert transport degraded %v; with FullCaps nothing should be", plan.Degraded)
	}

	// midsld is resolved from the client's own hello, so re-derive it rather
	// than trusting the constant: a change in the SNI or in hostSLDSpan must
	// fail here, not silently shift the split.
	info, ok := proto.ParseTLSClientHello(client)
	if !ok {
		t.Fatalf("the client hello does not parse")
	}
	if got := proto.FindSplitPos(client, info, proto.MarkerMidSLD, 0); got != midSLD {
		t.Fatalf("midsld resolves to %d, the test is pinned to %d", got, midSLD)
	}

	groups := parityWalk(t, "general-fake-tls-auto/google", pkts, orig, []parityGroup{
		// The decoy's stream offset is negative because --dpi-desync-fooling=badseq
		// moves the sequence number itself, not the segment's place in the request.
		{what: "badseq decoy hello", count: reps, seqOff: -int(parityBadSeqBack), length: fakeLen},
		{what: "real part 3 (tail, sent first)", count: 1, seqOff: midSLD, length: len(client) - midSLD},
		{what: "real part 2 (middle)", count: 1, seqOff: split, length: midSLD - split},
		{what: "real part 1 (head, sent last)", count: 1, seqOff: 0, length: split},
	})
	fakes, real3, real2, real1 := groups[0], groups[1][0], groups[2][0], groups[3][0]

	// --- badseq: the decoys are outside the peer's window in both directions ---
	wantSeq := orig.Seq - parityBadSeqBack
	wantAck := orig.Ack - parityBadAckBack
	for i, o := range fakes {
		if o.pkt.Seq != wantSeq {
			t.Errorf("decoy %d/%d seq is %#08x, want %#08x (%d below the real one)",
				i+1, reps, o.pkt.Seq, wantSeq, parityBadSeqBack)
		}
		if o.pkt.Ack != wantAck {
			t.Errorf("decoy %d/%d ack is %#08x, want %#08x", i+1, reps, o.pkt.Ack, wantAck)
		}
		// badseq is the only fooling mode here: the timestamps stay honest.
		if tsval, _ := parityTSVals(t, fmt.Sprintf("decoy %d", i+1), o); tsval != parityTSVal {
			t.Errorf("decoy %d/%d TSval is %#08x, want the untouched %#08x", i+1, reps, tsval, parityTSVal)
		}
	}

	// --- every decoy is a valid ClientHello announcing www.google.com ---
	for i, o := range fakes {
		fi, fok := proto.ParseTLSClientHello(o.pkt.Payload())
		if !fok {
			t.Fatalf("decoy %d/%d does not re-parse as a ClientHello", i+1, reps)
		}
		if fi.Host != "www.google.com" {
			t.Errorf("decoy %d/%d announces SNI %q, want www.google.com (fake-tls-mod sni=)",
				i+1, reps, fi.Host)
		}
		if bytes.Equal(o.pkt.Payload(), client) {
			t.Errorf("decoy %d/%d is the client's own request", i+1, reps)
		}
	}

	// --- rnd and dupsid actually changed the blob ---
	fake := fakes[0].pkt.Payload()
	if len(fake) != len(blob)+sidLen {
		t.Errorf("the decoy is %d bytes, want %d (%d + a duplicated %d-byte session id)",
			len(fake), len(blob)+sidLen, len(blob), sidLen)
	}
	if bytes.Equal(fake[parityHelloRandomOff:parityHelloRandomOff+parityHelloRandomLen],
		blob[parityHelloRandomOff:parityHelloRandomOff+parityHelloRandomLen]) {
		t.Errorf("the decoy's ClientHello.random is the blob's own; fake-tls-mod=rnd did not fire")
	}
	if got := int(fake[parityHelloSIDLenOff]); got != sidLen*2 {
		t.Fatalf("the decoy's legacy_session_id length is %d, want %d (dupsid doubles it)", got, sidLen*2)
	}
	sid := fake[parityHelloSIDLenOff+1 : parityHelloSIDLenOff+1+sidLen*2]
	if !bytes.Equal(sid[:sidLen], sid[sidLen:]) {
		t.Errorf("the decoy's doubled session id halves differ; dupsid must duplicate, not re-randomise")
	}

	// --- the 11 repeats are one buffer re-sent, and a second flow gets a fresh
	// mutation: rnd is re-derived per desync, not per packet, exactly as nfqws
	// builds the fake once and sends it --dpi-desync-repeats times ---
	if !parityIdentical(fakes) {
		t.Errorf("the %d repeats differ from each other; nfqws re-sends one buffer", reps)
	}
	otherOrig := parityTCPPkt(t, client, parityClientPort+1)
	_, otherPkts := parityRunTCP(t, "general-fake-tls-auto", otherOrig)
	if bytes.Equal(otherPkts[0].pkt.Payload(), fake) {
		t.Errorf("two different flows sent byte-identical decoys; fake-tls-mod=rnd must " +
			"re-randomise per desync so the decoys are not fingerprintable")
	}

	// --- multidisorder: the real segments descend in sequence order ---
	realOrder := []out{real3, real2, real1}
	for i := 1; i < len(realOrder); i++ {
		prev := parityStreamOffset(realOrder[i-1], orig)
		cur := parityStreamOffset(realOrder[i], orig)
		if cur >= prev {
			t.Errorf("real segment %d sits at stream offset %d, not below the previous %d: "+
				"multidisorder must transmit in descending sequence order", i+1, cur, prev)
		}
	}
	if real3.pkt.Seq != orig.Seq+midSLD || real2.pkt.Seq != orig.Seq+split || real1.pkt.Seq != orig.Seq {
		t.Errorf("real sequence numbers are (%#08x,%#08x,%#08x), want (%#08x,%#08x,%#08x)",
			real3.pkt.Seq, real2.pkt.Seq, real1.pkt.Seq,
			orig.Seq+midSLD, orig.Seq+split, orig.Seq)
	}
	if !bytes.Equal(real1.pkt.Payload(), client[:split]) ||
		!bytes.Equal(real2.pkt.Payload(), client[split:midSLD]) ||
		!bytes.Equal(real3.pkt.Payload(), client[midSLD:]) {
		t.Errorf("the reversed segments do not carry the request's three parts")
	}
	got := parityReassemble(t, "general-fake-tls-auto/real", realOrder, orig, len(client))
	if !bytes.Equal(got, client) {
		t.Fatalf("the reversed segments do not reassemble into the client's request")
	}

	// --- --ip-id=zero everywhere, and no forged TTL: badseq alone is what keeps
	// the decoy out of the peer's window ---
	parityNoDesyncTTL(t, "general-fake-tls-auto", 3)
	for i, o := range pkts {
		if o.pkt.IPID != 0 {
			t.Errorf("packet %d has ip.id %#04x, want 0 (--ip-id=zero)", i+1, o.pkt.IPID)
		}
		if o.pkt.TTL != parityTTL {
			t.Errorf("packet %d has TTL %d, want the client's own %d: "+
				"general-fake-tls-auto.toml configures no --dpi-desync-ttl",
				i+1, o.pkt.TTL, parityTTL)
		}
	}
}

// ---------------------------------------------------------------------------
// general.toml — the QUIC slot
// ---------------------------------------------------------------------------

// TestParityGeneralQUICFakeDatagrams pins general.toml's UDP/443 profile,
// flowseal's
//
//	--filter-udp=443 --ipset=ipset-all.txt --dpi-desync=fake
//	--dpi-desync-repeats=6 --dpi-desync-fake-quic=quic_initial_www_google_com.bin
//
// Six decoy Initials carrying the configured blob go out before the client's own
// datagram. There is nothing to split in a QUIC Initial — the ClientHello is
// inside an AEAD-protected packet — so the whole technique is the decoys.
func TestParityGeneralQUICFakeDatagrams(t *testing.T) {
	const reps = 6

	strat := parityLoad(t, "general")
	if !strat.WindowUDP.Has(443) {
		t.Fatalf("general.toml's --wf-udp window does not cover port 443")
	}
	// Which profile fires matters for the doc, so pin the two facts that decide
	// it: the QUIC SNI is not in the first profile's hostlist, and the peer is
	// inside the sixth profile's ipset.
	quic := parityFake(t, parityQUICBlob)
	sni, ok := proto.QUICSNI(quic)
	if !ok || sni != "www.google.com" {
		t.Fatalf("fakes/%s decrypts to SNI %q (ok=%v), want www.google.com", parityQUICBlob, sni, ok)
	}
	if strat.Profiles[0].Filter.Hostlist.Match(sni) {
		t.Fatalf("%q is in list-general.txt now; this test assumes the ipset-gated "+
			"profile p6 is the one that matches", sni)
	}
	if !strat.Profiles[5].Filter.IPSet.Match(parityServerIP) {
		t.Fatalf("%s is not in lists/ipset-all.txt, so general.toml's p6 would not match", parityServerIP)
	}
	// As in the voice slot: no --dpi-desync-ttl anywhere in general.bat.
	parityNoDesyncTTL(t, "general", 5)

	// Two client datagrams: the blob itself (what the brief calls for) and a
	// different real Initial, whose different length proves the decoy is the
	// CONFIGURED blob and not an echo of whatever the client sent.
	for _, tc := range []struct {
		name   string
		client []byte
	}{
		{"client sends the same Initial as the decoy", quic},
		{"client sends a different Initial", parityFake(t, "quic_initial_4pda.to.bin")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !proto.IsQUICInitial(tc.client) {
				t.Fatalf("the client datagram is not a QUIC Initial")
			}
			orig := parityUDPPkt(t, tc.client, parityClientPort, 443)
			_, pkts := parityRunUDP(t, "general", orig)

			groups := parityWalk(t, "general/quic", pkts, orig, []parityGroup{
				{what: "decoy QUIC Initial", count: reps, length: len(quic)},
				{what: "the client's own Initial", count: 1, length: len(tc.client)},
			})
			for i, o := range groups[0] {
				if !bytes.Equal(o.pkt.Payload(), quic) {
					t.Errorf("decoy %d/%d is not byte-identical to fakes/%s", i+1, reps, parityQUICBlob)
				}
			}
			if !bytes.Equal(groups[1][0].pkt.Payload(), tc.client) {
				t.Errorf("the last datagram is not the client's own")
			}
			for i, o := range pkts {
				if o.pkt.TTL != parityTTL {
					t.Errorf("datagram %d has TTL %d, want the client's own %d: general.toml "+
						"sets no --dpi-desync-ttl", i+1, o.pkt.TTL, parityTTL)
				}
				if o.pkt.IPID != parityRandIPID {
					t.Errorf("datagram %d has ip.id %#04x, want %#04x from BuildOpts.Rand: "+
						"Dgram carries no IPID mode, so the transport randomises like the kernel",
						i+1, o.pkt.IPID, parityRandIPID)
				}
				if o.pkt.SrcPort != parityClientPort || o.pkt.DstPort != 443 {
					t.Errorf("datagram %d is %d -> %d, want %d -> 443",
						i+1, o.pkt.SrcPort, o.pkt.DstPort, parityClientPort)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// general.toml — the Discord voice slot
// ---------------------------------------------------------------------------

// TestParityGeneralDiscordVoiceFakeDatagrams pins general.toml's voice profile,
// flowseal's
//
//	--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun
//	--dpi-desync=fake --dpi-desync-repeats=6
//	--dpi-desync-fake-discord=ACTIVE_DISCORD_UDP.bin
//
// The trick only means anything because the decoys leave from the client's own
// source port: a TSPU classifies a voice flow on the 4-tuple, so a decoy sent
// from anywhere else would be a different flow and would teach it nothing. That
// is the property this test exists for.
func TestParityGeneralDiscordVoiceFakeDatagrams(t *testing.T) {
	const reps = 6

	strat := parityLoad(t, "general")
	if !strat.WindowUDP.Has(parityVoiceDstPort) {
		t.Fatalf("general.toml's --wf-udp window does not cover port %d", parityVoiceDstPort)
	}
	if !strat.Profiles[1].Filter.Ports.Has(parityVoiceDstPort) {
		t.Fatalf("general.toml's voice profile does not filter port %d", parityVoiceDstPort)
	}
	// docs/parity.md records that the decoys here travel with the client's own
	// hop limit because flowseal configures no --dpi-desync-ttl.
	parityNoDesyncTTL(t, "general", 1)

	// Discord's voice IP-discovery request: 74 bytes, type 0x0001, length 70.
	// proto.IsDiscordIPDiscovery is what classifies it, so build it to that
	// shape and check the classification rather than assuming it.
	client := make([]byte, 74)
	binary.BigEndian.PutUint16(client[0:2], 0x0001)
	binary.BigEndian.PutUint16(client[2:4], 70)
	binary.BigEndian.PutUint32(client[4:8], 0x0badc0de) // SSRC
	if !proto.IsDiscordIPDiscovery(client) {
		t.Fatalf("the fixture is not recognised as a Discord IP-discovery datagram")
	}
	if info := proto.Classify(client, parityVoiceDstPort, proto.IPProtoUDP); info.Proto != proto.L7Discord {
		t.Fatalf("Classify reports L7 %d, want L7Discord (%d)", info.Proto, proto.L7Discord)
	}

	blob := parityFake(t, parityDiscordBlob)
	orig := parityUDPPkt(t, client, parityVoiceSrcPort, parityVoiceDstPort)
	_, pkts := parityRunUDP(t, "general", orig)

	groups := parityWalk(t, "general/discord", pkts, orig, []parityGroup{
		{what: "decoy voice datagram", count: reps, length: len(blob)},
		{what: "the client's own IP-discovery request", count: 1, length: len(client)},
	})
	for i, o := range groups[0] {
		if !bytes.Equal(o.pkt.Payload(), blob) {
			t.Errorf("decoy %d/%d is not byte-identical to fakes/%s", i+1, reps, parityDiscordBlob)
		}
	}
	if !bytes.Equal(groups[1][0].pkt.Payload(), client) {
		t.Errorf("the last datagram is not the client's own IP-discovery request")
	}

	// THE property: the client's own 4-tuple, on the decoys too.
	for i, o := range pkts {
		if o.pkt.SrcPort != parityVoiceSrcPort {
			t.Errorf("datagram %d leaves from source port %d, want the client's own %d: "+
				"a decoy from another port is another flow and fools nothing",
				i+1, o.pkt.SrcPort, parityVoiceSrcPort)
		}
		if o.pkt.DstPort != parityVoiceDstPort {
			t.Errorf("datagram %d goes to port %d, want %d", i+1, o.pkt.DstPort, parityVoiceDstPort)
		}
		// general.bat sets no --dpi-desync-ttl on any profile (verified against
		// .upstream/bat/general.bat), so the decoys travel with the client's own
		// hop limit and do reach the voice server, which ignores them. There is
		// no lowered decoy TTL to assert here.
		if o.pkt.TTL != parityTTL {
			t.Errorf("datagram %d has TTL %d, want the client's own %d: general.toml's "+
				"voice profile configures no desync TTL", i+1, o.pkt.TTL, parityTTL)
		}
	}
}

// ---------------------------------------------------------------------------
// the proxy transport: the same strategy under desync.ProxyCaps
// ---------------------------------------------------------------------------

// TestParityProxyPathDropsSeqovlHonestly runs the same Google flow through
// engine.PlanStream with the socket-level transport's capabilities.
//
// A byte-stream relay cannot choose TCP sequence numbers, so the below-window
// prefix is impossible: what survives is the split position alone. The point of
// the test is that the loss is REPORTED — Plan.Degraded names the op and the
// number that was dropped — and that no segment carries a negative SeqOff, which
// the relay could not honour and would silently mis-send.
func TestParityProxyPathDropsSeqovlHonestly(t *testing.T) {
	client := parityClientHello(t)
	eng := engine.New(parityLoad(t, "general"), desync.ProxyCaps(), parityFakeSet(t))
	key := desync.FlowKey{
		Src: parityClientIP, Dst: parityServerIP,
		SrcPort: parityClientPort, DstPort: parityHTTPSPort,
		Proto: proto.IPProtoTCP,
	}
	plan, err := eng.PlanStream(key, client)
	if err != nil {
		t.Fatalf("engine.PlanStream: %v", err)
	}
	if plan == nil {
		t.Fatalf("no profile matched the stream")
	}

	if len(plan.Segs) != 2 {
		t.Fatalf("the plan holds %d segments, want 2 (a plain split at pos 1)", len(plan.Segs))
	}
	for i, s := range plan.Segs {
		if s.Kind != desync.SegData {
			t.Errorf("segment %d is kind %d; a stream relay can only write real bytes", i, s.Kind)
		}
		if s.SeqOff < 0 {
			t.Errorf("segment %d has SeqOff %d; a socket-level transport cannot send below "+
				"the window, so a negative offset would be silently mis-sent", i, s.SeqOff)
		}
	}
	if plan.Segs[0].SeqOff != 0 || plan.Segs[1].SeqOff != 1 {
		t.Errorf("segment offsets are (%d,%d), want (0,1)", plan.Segs[0].SeqOff, plan.Segs[1].SeqOff)
	}
	if !plan.DropOriginal {
		t.Errorf("the plan re-emits the payload but does not claim DropOriginal")
	}

	// The relay writes the segments in order; that stream must be the request.
	var stream []byte
	for _, s := range plan.Segs {
		stream = append(stream, s.Data...)
	}
	if !bytes.Equal(stream, client) {
		t.Fatalf("the segments do not concatenate into the client's request")
	}

	// --- the loss is named, with the number ---
	var namedSeqovl, namedIPID bool
	for _, d := range plan.Degraded {
		if strings.Contains(d, "multisplit") && strings.Contains(d, "seqovl 681") {
			namedSeqovl = true
		}
		if d == "ip_id" {
			namedIPID = true
		}
	}
	if !namedSeqovl {
		t.Errorf("Plan.Degraded is %q; it must name multisplit and the seqovl 681 it dropped", plan.Degraded)
	}
	if !namedIPID {
		t.Errorf("Plan.Degraded is %q; it must name ip_id, which needs the IP header", plan.Degraded)
	}
}

// ---------------------------------------------------------------------------
// what this file cannot prove
// ---------------------------------------------------------------------------

// TestParityDeliveryIsOutOfScopeWithoutRoot records, as executable
// documentation, the two wire facts no pure-function test can establish. Both are
// about DELIVERY, not content: every byte above is proven, what is not proven is
// that those bytes reach the link.
//
//  1. that the pf rule `pass out quick route-to (utunN peer) ... user { > root }
//     no state` actually delivers the client's packet to the utun file
//     descriptor — i.e. that reading it IS the interception;
//  2. that a BPF Ethernet write on the uplink actually puts the frame on the
//     wire, bypassing pf so the injection does not loop back through the steer
//     rule.
//
// Both need root, a live uplink and a real peer, which this suite must never
// touch. diag.Detect performs exactly those two experiments reversibly and
// reports them as Capabilities.SteerOK/SteerTested and Capabilities.BpfWriteOK
// (`zaprctl doctor` prints them as steer=ok|failed|untested and bpf=true|false);
// internal/diag/diag_test.go covers them under the same root gate.
func TestParityDeliveryIsOutOfScopeWithoutRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("not root: route-to steering and BPF injection cannot be exercised, " +
			"and this file deliberately proves packet CONTENT rather than delivery; " +
			"run `zaprctl doctor` (diag.Detect) for steer= and bpf=")
	}
	t.Skip("running as root, but confirming delivery means putting a real frame on a " +
		"real uplink and steering a real connection: no test in this repository sends " +
		"traffic. diag.Detect owns those two experiments (Capabilities.SteerOK, " +
		"Capabilities.BpfWriteOK); `zapret-probe` and `zaprctl doctor` run them on demand")
}
