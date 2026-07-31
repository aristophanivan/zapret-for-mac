package desync

// Fragmentation and IPv6 extension-header ops: --dpi-desync=ipfrag1, ipfrag2,
// hopbyhop, destopt.
//
// All four decorate the REAL packet rather than injecting a decoy. In nfqws
// hopbyhop/destopt/ipfrag1 are classified as first-stage modes
// (desync_valid_first_stage) but all they do is set `fooling_orig`, which is
// then applied to whatever the second stage emits; ipfrag2 is a second-stage
// mode that re-emits the original packet as two IP fragments. In our phase model
// that makes every one of them PhaseModify: they have to run after PhaseSplit so
// they can decorate the segments a split op produced.

// injFragPosDefaultTCP / injFragPosDefaultUDP are nfqws' IPFRAG_TCP_DEFAULT and
// IPFRAG_UDP_DEFAULT (dp_init).
const (
	injFragPosDefaultTCP = 32
	injFragPosDefaultUDP = 8
)

// injFragPosFallbackTCP / injFragPosFallbackUDP are the positions nfqws uses
// when the configured one does not fit inside the packet's transport length
// (desync.c: `(pos && pos < transport_len) ? pos : 24` for TCP, `: sizeof(struct
// udphdr)` for UDP).
const (
	injFragPosFallbackTCP = 24
	injFragPosFallbackUDP = 8
)

// injMinTCPHdr / injUDPHdr are the transport header sizes used to estimate the
// packet's transport length at plan time. A TCP header with options is longer,
// but the option set belongs to the transport, so the minimum is the only
// number available here.
const (
	injMinTCPHdr = 20
	injUDPHdr    = 8
)

// FoolIPFrag1 extends Fooling beyond the bits the contract defines.
//
// --dpi-desync=ipfrag1 is IPv6-only and works by putting an 8-byte IPv6 Fragment
// extension header (next=L4, offset 0, no more-fragments, random identification)
// in front of the transport header of the REAL packet — see nfqws'
// prepare_tcp_segment6/prepare_udp_segment6 under FOOL_IPFRAG1. A DPI that
// refuses to walk past a Fragment header stops parsing, while the peer's IPv6
// stack reassembles a single-fragment datagram without complaint.
//
// desync.Fooling has bits for hopbyhop and hopbyhop2 only, and
// proto.AddIPv6ExtHdr deliberately accepts just hop-by-hop and
// destination-options, so the mode cannot be expressed with the contract's own
// vocabulary; the bit is defined here so the plan states the intent rather than
// silently emitting an ordinary packet.
//
// A transport honouring it has to build the Fragment header itself — the divert
// transport does (its emit path inserts an 8-byte Fragment header with offset 0
// when it sees this bit) — so ipfrag1 still records itself in Plan.Degraded on
// the IPv6 path: the bit is outside the contract, and a transport that merely
// claims Caps.IPv6ExtHdr/Frag without special-casing it would drop the fooling
// on the floor. Over-reporting there is deliberate; silently trusting an
// out-of-contract bit is not.
const FoolIPFrag1 Fooling = 1 << 8

func init() {
	Register("ipfrag1", func() Op { return &ipFrag1Op{} })
	Register("ipfrag2", func() Op { return &ipFrag2Op{} })
	Register("hopbyhop", func() Op { return &ipv6ExtOp{} })
	Register("destopt", func() Op { return &ipv6ExtOp{destOpt: true} })
}

// injFragPos resolves --dpi-desync-ipfrag-pos-tcp / -udp for the intercepted
// packet.
func injFragPos(c *Ctx, udp bool) int {
	return injFragPosLen(c, udp, len(c.Payload))
}

// injFragPosLen resolves --dpi-desync-ipfrag-pos-tcp / -udp for a packet whose
// L4 payload is payloadLen bytes long.
//
// The position counts from the first byte of the transport header, exactly like
// nfqws' ipfrag_pos and proto.IPFragment's pos, so the L4 header travels in the
// first fragment. It is rounded down to the 8-byte granularity of the IPv4
// fragment-offset field, and falls back to nfqws' hard-coded value when it does
// not fit the packet.
//
// The length is a parameter rather than always len(c.Payload) because udplen
// resizes the datagram after this op has run: a position that fitted the
// original payload can be past the end of the padded or truncated one.
func injFragPosLen(c *Ctx, udp bool, payloadLen int) int {
	pos, alt := c.Params.FragPosTCP, c.Params.FragPosUDP
	def, fallback, hdr := injFragPosDefaultTCP, injFragPosFallbackTCP, injMinTCPHdr
	if udp {
		pos, alt = c.Params.FragPosUDP, c.Params.FragPosTCP
		def, fallback, hdr = injFragPosDefaultUDP, injFragPosFallbackUDP, injUDPHdr
	}
	if pos <= 0 {
		// A strategy loader that fills only one of the two fields still gets the
		// position it asked for.
		pos = alt
	}
	if pos <= 0 {
		pos = def
	}
	pos &^= 7 // fragment offsets count 8-byte units
	transportLen := hdr + payloadLen
	if pos < 8 || pos >= transportLen {
		pos = fallback
	}
	return pos
}

// ---------- ipfrag2 ----------

// ipFrag2Op implements --dpi-desync=ipfrag2: the real packet leaves as two IPv4
// fragments split inside the transport header or just past it, so a DPI that
// does not reassemble never sees the SNI, the Host: header or the QUIC Initial.
type ipFrag2Op struct{}

// Name reports the --dpi-desync spelling.
func (*ipFrag2Op) Name() string { return "ipfrag2" }

// Phase reports that ipfrag2 marks segments another op may already have planned.
func (*ipFrag2Op) Phase() Phase { return PhaseModify }

// Requires reports fragment emission plus suppression of the unfragmented
// original.
func (*ipFrag2Op) Requires() Caps { return Caps{Frag: true, DropOriginal: true} }

// Apply marks the plan's real segments or datagrams for fragmentation.
func (o *ipFrag2Op) Apply(c *Ctx, p *Plan) error {
	if c == nil || p == nil || c.Flow == nil {
		return nil
	}
	// A second stage never runs on a bare SYN in nfqws.
	if c.SynPkt || len(c.Payload) == 0 {
		return nil
	}
	if injIsUDP(c) {
		if injIsIPv6(c) {
			// Dgram.Frag is IPv4 fragmentation (proto.IPFragment refuses IPv6 and
			// tells the caller to build a Fragment extension header instead, which
			// proto.AddIPv6ExtHdr cannot do). Saying so beats asking the transport
			// for a split it has no way to emit.
			injDegrade(p, o.Name())
			return nil
		}
		injEnsureDataDgram(c, p)
		for i := range p.Dgrams {
			if p.Dgrams[i].Kind == SegData {
				// Per datagram, not per flow: udplen may already have resized this
				// one, and the position has to fit the bytes actually sent.
				p.Dgrams[i].Frag = injFragPosLen(c, true, len(p.Dgrams[i].Data))
			}
		}
		return nil
	}
	pos := injFragPos(c, false)
	injEnsureDataSeg(c, p)
	for i := range p.Segs {
		if p.Segs[i].Kind == SegData {
			p.Segs[i].Frag = pos
		}
	}
	return nil
}

// ---------- hopbyhop / destopt ----------

// ipv6ExtOp implements --dpi-desync=hopbyhop and =destopt: an empty IPv6
// hop-by-hop-options or destination-options header is inserted in front of the
// transport header of the REAL packet. A DPI that gives up when the next-header
// chain is not "IPv6 then TCP" loses the flow; the peer's stack skips the
// (padding-only) option and delivers the segment normally.
//
// Both modes are IPv6-only. nfqws' IPv4 packet builders ignore the
// FOOL_HOPBYHOP/FOOL_DESTOPT bits entirely, so on an IPv4 flow the mode is a
// no-op there too — recorded here in Plan.Degraded so the user sees why nothing
// happened.
type ipv6ExtOp struct{ destOpt bool }

// Name reports the --dpi-desync spelling.
func (o *ipv6ExtOp) Name() string {
	if o.destOpt {
		return "destopt"
	}
	return "hopbyhop"
}

// Phase reports that the header decorates segments another op may have planned.
func (*ipv6ExtOp) Phase() Phase { return PhaseModify }

// Requires reports extension-header insertion plus suppression of the
// undecorated original.
func (*ipv6ExtOp) Requires() Caps { return Caps{IPv6ExtHdr: true, DropOriginal: true} }

// Apply sets the hop-by-hop fooling bit on every real segment or datagram.
//
// APPROXIMATION: destopt is emitted as a hop-by-hop header. Fooling has bits for
// hopbyhop and hopbyhop2 only, so "destination options" cannot be requested,
// even though proto.AddIPv6ExtHdr can build one (kind proto.IPProtoDstOpt).
// FoolHopByHop2 is the deliberately RFC 8200-violating doubled hop-by-hop
// header: two of them in one packet is illegal, which is precisely why DPI
// stacks that re-walk the chain give up while the peer still accepts it.
func (o *ipv6ExtOp) Apply(c *Ctx, p *Plan) error {
	if c == nil || p == nil || c.Flow == nil {
		return nil
	}
	if c.SynPkt || len(c.Payload) == 0 {
		return nil
	}
	if !injIsIPv6(c) {
		injDegrade(p, o.Name())
		return nil
	}
	if o.destOpt {
		injDegrade(p, o.Name())
	}
	if injIsUDP(c) {
		injEnsureDataDgram(c, p)
		for i := range p.Dgrams {
			if p.Dgrams[i].Kind == SegData {
				p.Dgrams[i].Fool |= FoolHopByHop
			}
		}
		return nil
	}
	injEnsureDataSeg(c, p)
	for i := range p.Segs {
		if p.Segs[i].Kind == SegData {
			p.Segs[i].Fool |= FoolHopByHop
		}
	}
	return nil
}

// ---------- ipfrag1 ----------

// ipFrag1Op implements --dpi-desync=ipfrag1, the first-stage fragmentation mode.
//
// On IPv6 it is the sibling of hopbyhop/destopt: the transport header of the
// packet is hidden behind an IPv6 Fragment extension header (nfqws' FOOL_IPFRAG1
// in prepare_tcp_segment6/prepare_udp_segment6), which the frozen contract cannot
// express — see FoolIPFrag1 — so the op sets that bit and reports itself
// degraded.
//
// On an IPv4 UDP flow there is one more thing it can do honestly now that Dgram
// carries a Frag field: fragment the DECOY. ipfrag1 is the first stage, so the
// packet it decorates is the one the first stage put on the wire — the fake — and
// ipfrag2 is the second stage that fragments the real datagram. A decoy that
// arrives as two IPv4 fragments is invisible to a DPI that does not reassemble,
// which is the whole point of pairing ipfrag1 with a fake.
type ipFrag1Op struct{}

// Name reports the --dpi-desync spelling.
func (*ipFrag1Op) Name() string { return "ipfrag1" }

// Phase reports that the header decorates segments another op may have planned.
func (*ipFrag1Op) Phase() Phase { return PhaseModify }

// Requires reports both extension-header insertion and fragment emission: the
// header it needs is an IPv6 fragment header.
func (*ipFrag1Op) Requires() Caps {
	return Caps{IPv6ExtHdr: true, Frag: true, DropOriginal: true}
}

// Apply fragments the decoy on an IPv4 UDP flow, and otherwise marks the real
// segments with FoolIPFrag1 and records the gap.
func (o *ipFrag1Op) Apply(c *Ctx, p *Plan) error {
	if c == nil || p == nil || c.Flow == nil {
		return nil
	}
	if c.SynPkt || len(c.Payload) == 0 {
		return nil
	}
	if injIsUDP(c) && !injIsIPv6(c) {
		return o.applyUDPv4(c, p)
	}
	// FoolIPFrag1 is outside the contract's Fooling vocabulary, and on IPv4 TCP
	// nfqws itself does nothing, so either way the op is not fully expressible
	// through Caps alone. See the note on FoolIPFrag1.
	injDegrade(p, o.Name())
	if !injIsIPv6(c) {
		return nil
	}
	if injIsUDP(c) {
		injEnsureDataDgram(c, p)
		for i := range p.Dgrams {
			if p.Dgrams[i].Kind == SegData {
				p.Dgrams[i].Fool |= FoolIPFrag1
			}
		}
		return nil
	}
	injEnsureDataSeg(c, p)
	for i := range p.Segs {
		if p.Segs[i].Kind == SegData {
			p.Segs[i].Fool |= FoolIPFrag1
		}
	}
	return nil
}

// applyUDPv4 marks every decoy datagram for IPv4 fragmentation.
//
// The position is --dpi-desync-ipfrag-pos-udp (nfqws' default 8, i.e. the split
// falls just past the UDP header), resolved per datagram because a decoy is not
// the same length as the real payload.
//
// With no decoy in the plan there is nothing for a first-stage mode to decorate:
// ipfrag1 is not ipfrag2, so the real datagram is deliberately left alone and the
// mismatch is reported instead of quietly fragmenting the wrong packet.
func (o *ipFrag1Op) applyUDPv4(c *Ctx, p *Plan) error {
	n := 0
	for i := range p.Dgrams {
		if p.Dgrams[i].Kind != SegFake {
			continue
		}
		p.Dgrams[i].Frag = injFragPosLen(c, true, len(p.Dgrams[i].Data))
		n++
	}
	if n == 0 {
		segNote(p, "ipfrag1: no decoy datagram in the plan to fragment — pair it with a fake op "+
			"(ipfrag1 is nfqws' first stage), or use ipfrag2 to fragment the real datagram")
	}
	return nil
}
