package desync

import (
	"encoding/hex"
	"sync"

	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// This file implements the injection family of --dpi-desync modes: the ones that
// put extra packets on the wire in front of the real payload (fake, fakeknown,
// rst, rstack, syndata) plus our own "block" pseudo-op.
//
// Ground truth is nfq/desync.c. Two structural facts from there shape every op
// in this file:
//
//   - A bare SYN only ever runs desync_mode0 (synack/syndata) and is then sent
//     as-is: nfqws does `if (tcp_syn_segment(...)) { switch (dp->desync_mode0)
//     ... ; goto send_orig; }`. So every non-SYN op must skip a SYN packet, and
//     syndata must skip everything else.
//   - The first stage (fake/rst) never suppresses the payload; the payload is
//     emitted afterwards by the second stage or by send_orig. Because our engine
//     sets Plan.DropOriginal as soon as a plan carries any segment, an op that
//     injects a segment must also make sure the real payload is in the plan —
//     otherwise "inject a decoy" would silently turn into "drop the request".

// zapret's built-in fallbacks (nfq/params.c dp_fake_defaults). They are only
// reached when neither the op's own --dpi-desync-fake-* override nor the
// engine-wide FakeSet has a blob for the flow's L7 class, which is exactly when
// nfqws synthesises these.
const (
	// injDefaultUnknownTCPLen is fake_unknown: 256 zero bytes.
	injDefaultUnknownTCPLen = 256
	// injDefaultQUICLen is fake_quic: 620 zero bytes with the QUIC long-header
	// fixed bit set, so the decoy at least looks like a long-header packet.
	injDefaultQUICLen = 620
	// injDefaultUDPLen is fake_wg / fake_dht / fake_discord / fake_stun /
	// fake_unknown_udp: 64 zero bytes.
	injDefaultUDPLen = 64
	// injMaxRepeats is nfqws' --dpi-desync-repeats ceiling.
	injMaxRepeats = 1024
)

// injDefaultFakeHTTP is nfqws' fake_http_request_default, byte for byte.
const injDefaultFakeHTTP = "GET / HTTP/1.1\r\nHost: www.iana.org\r\n" +
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0\r\n" +
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" +
	"Accept-Encoding: gzip, deflate, br\r\n\r\n"

// injDefaultFakeTLSHex is nfqws' fake_tls_clienthello_default (680 bytes): a
// real Chrome-shaped ClientHello for www.microsoft.com. Kept as hex rather than
// a byte-array literal so the blob stays diffable against upstream.
const injDefaultFakeTLSHex = "16030102a30100029f03034188822d4ffd81489ee790651fba057bffa75af95b8a8f458b41f03d1bdde3f8209b23a5d2" +
	"211e9fe7856cfc61803a3fbab960bab30e98276cf7382865805d40380022130113031302c02bc02fcca9cca8c02cc030" +
	"c00ac009c013c014009c009d002f0035010002340000001600140000117777772e6d6963726f736f66742e636f6d0017" +
	"0000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474" +
	"702f312e310005000501000000000022000a00080403050306030203001200000033006b0069001d0020691516296dad" +
	"d56888272fdeafac3c4ca4e4d8c8fb4187f4764e0efa64c4e9290017004104fe62b908c8c32ab9873784426b5ccdc9ca" +
	"6238d3d9998ac42dc6d0a360b21254418e525ee3abf9c20781dcf8f26a91402fcba4ff6f24c74d77772d6fe077aa9200" +
	"2b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001" +
	"001b000706000100020003fe0d0119000001000321002062e883d897058abea1f2634ece93848ecfe7ddb2e48706ac11" +
	"19be0e7187f1a600efd86b275ec0a75d424e8cdcf39f1c5162efff5bedc8fdee6fbb889bb1309c6642ab0f6689188b11" +
	"c16de72aeb963b7f5278dbf86d04f7951aa8f064520739f0a81d0d1636b7180ec84427fef331f0de8c74f5a1d88f6f45" +
	"9769795e2ed4b02c0c1a6fccce90c7ddc66095f3c219de5080bfdef22563152663091fc5df32f5ea9cd2ff994e67a2e5" +
	"1a9485e3df36a5834b0a1cafd748c94b8a27dd587f95f26bde2b12d3ec4d69379c139b16b04552387769efaa6519bcc2" +
	"934db01b7f5b41ffafba5051c3f1270925f5609009b1e5c0c74278543b23197d8e7213b4d3cd63b6c44a283d453e8bdb" +
	"844f78643069e21b"

// injDefaultTLS decodes injDefaultFakeTLSHex once. A malformed constant would be
// a programming error, so a decode failure yields nil and the fake op falls back
// to the generic zero-filled blob rather than panicking on the datapath.
var injDefaultTLS = sync.OnceValue(func() []byte {
	b, err := hex.DecodeString(injDefaultFakeTLSHex)
	if err != nil {
		return nil
	}
	return b
})

// injSynDataDefaultLen is nfqws' dp_init default: fake_syndata_size = 16 over a
// zero-initialised buffer, i.e. sixteen zero bytes.
const injSynDataDefaultLen = 16

func init() {
	Register("fake", func() Op { return &fakeOp{} })
	Register("fakeknown", func() Op { return &fakeOp{knownOnly: true} })
	Register("rst", func() Op { return &rstOp{} })
	Register("rstack", func() Op { return &rstOp{ack: true} })
	Register("syndata", func() Op { return &synDataOp{} })
	Register("block", func() Op { return &blockOp{} })
}

// ---------- shared helpers ----------

// injRepeats normalises --dpi-desync-repeats: nfqws defaults it to 1 in dp_init
// and refuses anything above 1024 at parse time.
func injRepeats(p *OpParams) int {
	switch {
	case p.Repeats < 1:
		return 1
	case p.Repeats > injMaxRepeats:
		return injMaxRepeats
	default:
		return p.Repeats
	}
}

// injIsUDP reports whether the intercepted flow is UDP.
func injIsUDP(c *Ctx) bool {
	return c != nil && c.Flow != nil && c.Flow.Key.Proto == proto.IPProtoUDP
}

// injIsIPv6 reports whether the flow's peer address is a real IPv6 address.
// An IPv4-mapped address (::ffff:a.b.c.d) is IPv4 on the wire, so the IPv6-only
// ops must not fire for it.
func injIsIPv6(c *Ctx) bool {
	if c == nil || c.Flow == nil {
		return false
	}
	d := c.Flow.Key.Dst
	return d.IsValid() && d.Is6() && !d.Is4In6()
}

// injL7 is the L7 class the fake selection keys on. nfqws reads it from the
// conntrack entry, so it survives past the packet that revealed it; we prefer
// this packet's own classification and fall back to the flow's remembered one.
func injL7(c *Ctx) proto.L7 {
	if c.Info.Proto != 0 && c.Info.Proto != proto.L7Unknown {
		return c.Info.Proto
	}
	if c.Flow != nil && c.Flow.L7 != 0 {
		return c.Flow.L7
	}
	return proto.L7Unknown
}

// injFakeKind maps an L7 class to the --dpi-desync-fake-* family nfqws picks for
// it (desync.c, the two `switch (l7proto)` blocks that assign `fake`).
//
// GAP: FakeSet has no fake_wg / fake_dht slot, so WireGuard and DHT land on the
// unknown-UDP family. That is byte-identical to nfqws as long as the strategy
// does not set --dpi-desync-fake-wg / -dht (both default to the same 64 zero
// bytes); a strategy that does set them cannot be expressed.
func injFakeKind(l7 proto.L7, udp bool) string {
	if udp {
		switch l7 {
		case proto.L7QUIC:
			return "quic"
		case proto.L7Discord:
			return "discord"
		case proto.L7STUN:
			return "stun"
		default: // wireguard, dht, unknown
			return "unknown_udp"
		}
	}
	switch l7 {
	case proto.L7TLS:
		return "tls"
	case proto.L7HTTP:
		return "http"
	default:
		return "unknown"
	}
}

// injFakeSetLen reports how many blobs the engine-wide FakeSet holds for a kind.
func injFakeSetLen(f FakeSet, kind string) int {
	switch kind {
	case "tls":
		if len(f.TLS) > 0 {
			return 1
		}
	case "http":
		if len(f.HTTP) > 0 {
			return 1
		}
	case "quic":
		if len(f.QUIC) > 0 {
			return 1
		}
	case "discord":
		return len(f.Discord)
	case "stun":
		return len(f.STUN)
	case "unknown", "unknown_udp":
		return len(f.UnknownUDP)
	}
	return 0
}

// injParamsFakes returns the op-level --dpi-desync-fake-* override for a kind.
func injParamsFakes(p *OpParams, kind string) [][]byte {
	switch kind {
	case "tls":
		if len(p.FakeTLS) > 0 {
			return [][]byte{p.FakeTLS}
		}
	case "http":
		if len(p.FakeHTTP) > 0 {
			return [][]byte{p.FakeHTTP}
		}
	case "quic":
		if len(p.FakeQUIC) > 0 {
			return [][]byte{p.FakeQUIC}
		}
	case "discord":
		return p.FakeDiscord
	case "stun":
		return p.FakeSTUN
	case "unknown", "unknown_udp":
		return p.FakeUnknownUDP
	}
	return nil
}

// injDefaultFake synthesises zapret's built-in fallback blob for a kind.
func injDefaultFake(kind string) []byte {
	switch kind {
	case "tls":
		if b := injDefaultTLS(); len(b) > 0 {
			out := make([]byte, len(b))
			copy(out, b)
			return out
		}
		return make([]byte, injDefaultUnknownTCPLen)
	case "http":
		return []byte(injDefaultFakeHTTP)
	case "quic":
		b := make([]byte, injDefaultQUICLen)
		// nfqws sets only the long-header fixed bit; the rest stays zero.
		b[0] = 0x40
		return b
	case "unknown":
		return make([]byte, injDefaultUnknownTCPLen)
	default:
		return make([]byte, injDefaultUDPLen)
	}
}

// injFakeBlobs is the ordered list of decoy payloads for this flow.
//
// Precedence mirrors how nfqws builds dp->fake_*: an explicit per-op blob wins,
// then the engine-wide loaded set (picked through FakeSet.FakeFor so a
// multi-valued family rotates exactly as several --dpi-desync-fake-discord
// arguments do), then zapret's built-in default. nfqws walks the whole blob list
// and sends each entry --dpi-desync-repeats times, in list order, so the list
// length is the number of distinct packets, not a modulus over the repeats.
func injFakeBlobs(c *Ctx, kind string) [][]byte {
	if own := injParamsFakes(&c.Params, kind); len(own) > 0 {
		return own
	}
	if n := injFakeSetLen(c.Fakes, kind); n > 0 {
		out := make([][]byte, 0, n)
		for i := 0; i < n; i++ {
			if b := c.Fakes.FakeFor(kind, i); len(b) > 0 {
				out = append(out, b)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return [][]byte{injDefaultFake(kind)}
}

// injTLSMod resolves --dpi-desync-fake-tls-mod for this op.
//
// nfqws (nfqws.c onetime_tls_mod) applies the compatibility default
// "rnd,rndsni,dupsid" only when the profile set neither an explicit tls-mod nor
// a custom fake ClientHello; a custom fake is otherwise sent verbatim. The zero
// TLSMod means "nothing configured", TLSMod{None:true} means an explicit
// "none", which ModifyTLSFake honours by copying the hello unchanged.
func injTLSMod(c *Ctx, customFake bool) proto.TLSMod {
	if c.Params.TLSMod != (TLSMod{}) {
		// desync.TLSMod and proto.TLSMod are declared with identical field sets
		// precisely so this conversion is legal; proto cannot import desync.
		return proto.TLSMod(c.Params.TLSMod)
	}
	if customFake {
		return proto.TLSMod{}
	}
	return proto.TLSMod{Rnd: true, RndSNI: true, DupSID: true}
}

// injHasCustomFakeTLS reports whether a TLS fake came from the strategy rather
// than from zapret's built-in default hello.
func injHasCustomFakeTLS(c *Ctx) bool {
	return len(c.Params.FakeTLS) > 0 || len(c.Fakes.TLS) > 0
}

// injInsertSegs splices segs into the plan just before the first SegData, so
// injected decoys always precede the real payload no matter which order the
// strategy lists its ops in. With no data segment yet they go at the end and
// injEnsureDataSeg appends the payload behind them.
func injInsertSegs(p *Plan, segs []Seg) {
	if len(segs) == 0 {
		return
	}
	at := len(p.Segs)
	for i := range p.Segs {
		if p.Segs[i].Kind == SegData {
			at = i
			break
		}
	}
	out := make([]Seg, 0, len(p.Segs)+len(segs))
	out = append(out, p.Segs[:at]...)
	out = append(out, segs...)
	out = append(out, p.Segs[at:]...)
	p.Segs = out
}

// injInsertDgrams is injInsertSegs for UDP.
func injInsertDgrams(p *Plan, dgrams []Dgram) {
	if len(dgrams) == 0 {
		return
	}
	at := len(p.Dgrams)
	for i := range p.Dgrams {
		if p.Dgrams[i].Kind == SegData {
			at = i
			break
		}
	}
	out := make([]Dgram, 0, len(p.Dgrams)+len(dgrams))
	out = append(out, p.Dgrams[:at]...)
	out = append(out, dgrams...)
	out = append(out, p.Dgrams[at:]...)
	p.Dgrams = out
}

// injEnsureDataSeg puts the real payload into the plan when nothing else has.
//
// This is what keeps a first-stage-only profile faithful to nfqws: there the
// payload is still sent (send_orig) after the decoys. Our engine drops the
// original packet whenever the plan is non-empty, so the payload has to be
// re-emitted from the plan itself. A PhaseSplit op that already segmented the
// payload owns those segments and is left alone.
//
// Data aliases c.Payload: a Plan lives only for the duration of the transport
// call that consumes it.
func injEnsureDataSeg(c *Ctx, p *Plan) {
	if len(c.Payload) == 0 {
		return
	}
	for i := range p.Segs {
		if p.Segs[i].Kind == SegData {
			return
		}
	}
	p.Segs = append(p.Segs, Seg{Kind: SegData, Data: c.Payload})
}

// injEnsureDataDgram is injEnsureDataSeg for UDP.
func injEnsureDataDgram(c *Ctx, p *Plan) {
	if len(c.Payload) == 0 {
		return
	}
	for i := range p.Dgrams {
		if p.Dgrams[i].Kind == SegData {
			return
		}
	}
	p.Dgrams = append(p.Dgrams, Dgram{Kind: SegData, Data: c.Payload})
}

// injDegrade records that an op ran but could not be honoured, without touching
// the wire. The engine adds the same note when Caps gate an op off; ops use it
// for the cases Caps cannot express (wrong address family, an abstraction gap).
func injDegrade(p *Plan, name string) {
	for _, d := range p.Degraded {
		if d == name {
			return
		}
	}
	p.Degraded = append(p.Degraded, name)
}

// ---------- fake / fakeknown ----------

// fakeOp implements --dpi-desync=fake and --dpi-desync=fakeknown: N copies of a
// decoy packet carrying the real payload's sequence number go out first, so the
// DPI records the decoy's SNI/Host and the server discards it (a low TTL or a
// bad checksum keeps it from ever being accepted), then the real payload
// follows and lands in a TCP stream the DPI has already given up on.
type fakeOp struct{ knownOnly bool }

// Name reports the --dpi-desync spelling.
func (o *fakeOp) Name() string {
	if o.knownOnly {
		return "fakeknown"
	}
	return "fake"
}

// Phase reports that fakes are injected before the payload is segmented.
func (*fakeOp) Phase() Phase { return PhaseFake }

// Requires reports the capabilities a decoy needs: injection plus at least the
// means to stop the decoy from being accepted by the server. Caps is a
// conjunction, so both TTL and fooling are demanded even though nfqws needs
// only one of them — a transport that can inject but can neither limit the TTL
// nor corrupt the packet would push the decoy into the server's real stream.
func (*fakeOp) Requires() Caps {
	return Caps{Inject: true, PerPacketTTL: true, Fooling: true}
}

// Apply prepends the decoys and makes sure the real payload still ships.
func (o *fakeOp) Apply(c *Ctx, p *Plan) error {
	if c == nil || p == nil || c.Flow == nil {
		return nil
	}
	// nfqws runs only desync_mode0 on a bare SYN.
	if c.SynPkt || len(c.Payload) == 0 {
		return nil
	}
	l7 := injL7(c)
	if o.knownOnly && l7 == proto.L7Unknown {
		// "not applying fake because of unknown protocol"
		return nil
	}
	udp := injIsUDP(c)
	kind := injFakeKind(l7, udp)
	blobs := injFakeBlobs(c, kind)
	reps := injRepeats(&c.Params)

	if udp {
		dgrams := make([]Dgram, 0, len(blobs))
		for _, b := range blobs {
			if len(b) == 0 {
				continue
			}
			dgrams = append(dgrams, Dgram{
				Kind:    SegFake,
				Data:    b,
				TTL:     c.Params.TTL,
				Fool:    c.Params.Fool,
				FoolP:   c.Params.FoolP,
				Repeats: reps,
			})
		}
		injInsertDgrams(p, dgrams)
		injEnsureDataDgram(c, p)
		return nil
	}

	mod := injTLSMod(c, injHasCustomFakeTLS(c))
	segs := make([]Seg, 0, len(blobs))
	for _, b := range blobs {
		if len(b) == 0 {
			continue
		}
		data := b
		if kind == "tls" {
			// runtime_tls_mod(): rnd/dupsid/padencap are re-derived per packet so
			// two flows never send byte-identical decoys.
			data = proto.ModifyTLSFake(b, mod)
		}
		segs = append(segs, Seg{
			Kind: SegFake,
			Data: data,
			// SeqOff 0: the decoy claims the exact sequence number of the real
			// payload, which is what makes the DPI accept it as the request.
			SeqOff:  0,
			TTL:     c.Params.TTL,
			Fool:    c.Params.Fool,
			FoolP:   c.Params.FoolP,
			Repeats: reps,
			IPID:    c.Params.IPID,
		})
	}
	injInsertSegs(p, segs)
	injEnsureDataSeg(c, p)
	return nil
}

// ---------- rst / rstack ----------

// rstOp implements --dpi-desync=rst and =rstack: a spoofed RST (RST+ACK for
// rstack) on the flow's current seq/ack makes the DPI tear down its own state
// for the connection while the real endpoints, which never see the RST because
// of the TTL or the broken checksum, keep talking.
type rstOp struct{ ack bool }

// Name reports the --dpi-desync spelling.
func (o *rstOp) Name() string {
	if o.ack {
		return "rstack"
	}
	return "rst"
}

// Phase reports that the RST is injected before the payload is segmented.
func (*rstOp) Phase() Phase { return PhaseFake }

// Requires reports the same capabilities as a fake: the RST must not reach the
// peer, or it would kill the connection it is meant to protect.
func (*rstOp) Requires() Caps {
	return Caps{Inject: true, PerPacketTTL: true, Fooling: true}
}

// Apply injects the RST and keeps the real payload in the plan.
func (o *rstOp) Apply(c *Ctx, p *Plan) error {
	if c == nil || p == nil || c.Flow == nil {
		return nil
	}
	if c.SynPkt || len(c.Payload) == 0 {
		return nil
	}
	if injIsUDP(c) {
		// nfqws' UDP path has no RST stage: there is no connection to reset.
		return nil
	}
	flags := proto.TCPRst
	if o.ack {
		flags |= proto.TCPAck
	}
	injInsertSegs(p, []Seg{{
		Kind: SegRST,
		// nfqws sends the RST with the intercepted packet's own seq and ack;
		// SeqOff 0 is that sequence number, and the transport supplies the ack
		// from the flow state.
		SeqOff:  0,
		Flags:   flags,
		TTL:     c.Params.TTL,
		Fool:    c.Params.Fool,
		FoolP:   c.Params.FoolP,
		Repeats: injRepeats(&c.Params),
		IPID:    c.Params.IPID,
	}})
	injEnsureDataSeg(c, p)
	return nil
}

// ---------- syndata ----------

// synDataOp implements --dpi-desync=syndata: the SYN itself is re-sent carrying
// a payload. A DPI that latches onto "first data packet of the connection" reads
// the garbage on the SYN, while the server's TCP ignores payload on a SYN it did
// not negotiate fast open for.
type synDataOp struct{}

// Name reports the --dpi-desync spelling.
func (*synDataOp) Name() string { return "syndata" }

// Phase reports that syndata is a zero-stage (SYN-time) mode.
func (*synDataOp) Phase() Phase { return PhaseSyn }

// Requires reports injection plus the ability to suppress the kernel's own SYN,
// which the rewritten SYN replaces (nfqws returns VERDICT_DROP for it). No TTL
// or fooling capability is needed: nfqws sends this one with the original TTL
// and no fooling at all, because it is meant to reach the server.
func (*synDataOp) Requires() Caps {
	return Caps{Inject: true, DropOriginal: true}
}

// Apply emits the SYN-with-payload, or does nothing when this is not a bare SYN.
func (o *synDataOp) Apply(c *Ctx, p *Plan) error {
	if c == nil || p == nil || c.Flow == nil {
		return nil
	}
	if !c.SynPkt || injIsUDP(c) {
		return nil
	}
	// "received SYN with data payload. syndata desync is not applied."
	//
	// GAP: nfqws also skips a SYN that carries the TCP fast open option, so it
	// cannot break a real TFO handshake. Ctx exposes no TCP options, so that
	// check is impossible here; a TFO cookie in the SYN would be dropped along
	// with the original packet.
	if len(c.Payload) != 0 {
		return nil
	}
	data := c.Params.FakeSynData
	if len(data) == 0 {
		data = c.Fakes.FakeFor("syndata", 0)
	}
	if len(data) == 0 {
		data = make([]byte, injSynDataDefaultLen)
	}
	p.Segs = append(p.Segs, Seg{
		Kind:   SegSynData,
		Data:   data,
		SeqOff: 0,
		// nfqws reuses flags_orig here, i.e. a plain SYN; TTL and fooling stay
		// at the original packet's values.
		Flags:   proto.TCPSyn,
		Repeats: injRepeats(&c.Params),
		IPID:    c.Params.IPID,
	})
	return nil
}

// ---------- block ----------

// blockOp is not a zapret mode: it is our kill-switch. The payload is dropped
// and nothing is sent in its place.
//
// It exists because pf can express "steer these ports into the tunnel" but not
// "block exactly the UDP datagrams whose QUIC Initial carries an SNI from this
// hostlist". Deciding that in userspace and then dropping the datagram makes the
// browser time out its QUIC attempt and fall back to TCP, where the real desync
// ops apply.
//
// block is terminal: it discards whatever the plan already held, because the
// point is that nothing leaves the machine. It drops any packet it is applied
// to, including a bare SYN, so scope it with the profile's filter (proto, port,
// l7) rather than expecting it to spare the handshake.
type blockOp struct{}

// Name reports the pseudo-op's spelling in a strategy file.
func (*blockOp) Name() string { return "block" }

// Phase reports that block runs where the injection ops do; anything a later
// phase would have planned is pointless once the payload is gone.
func (*blockOp) Phase() Phase { return PhaseFake }

// Requires reports only DropOriginal, which every transport has, so the
// kill-switch works behind the proxy transport too.
func (*blockOp) Requires() Caps { return Caps{DropOriginal: true} }

// Apply empties the plan and marks the payload as dropped.
func (o *blockOp) Apply(c *Ctx, p *Plan) error {
	if p == nil {
		return nil
	}
	p.Segs = nil
	p.Dgrams = nil
	p.DropOriginal = true
	return nil
}
