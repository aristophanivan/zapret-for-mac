package desync

import "slices"

// This file holds the two header-level pseudo-ops of the segmentation family:
// `wssize` (--wssize) and `ip_id` (--ip-id). Neither produces payload; both only
// describe how the transport should fill in TCP/IP header fields.

func init() {
	Register("wssize", func() Op { return wssizeOp{} })
	Register("ip_id", func() Op { return ipIDOp{} })
}

// wssizeMaxWindow and wssizeMaxScale are the field widths a Seg can carry: the
// TCP window is 16 bits and the window-scale option value is one byte.
const (
	wssizeMaxWindow = 0xFFFF
	wssizeMaxScale  = 0xFF
)

// wssizeOp implements --wssize=<window>[:<scale>]: rewrite the TCP window the
// client advertises to the server, so the server is forced to answer in small
// segments (the classic way to make a TLS ServerHello arrive fragmented).
//
// The rewrite is expressed by setting Seg.Window / Seg.WindowScale on the real
// segments of the plan; the transport, which writes the TCP header, puts those
// numbers on the wire: Window goes into the window field verbatim and, on a SYN,
// WindowScale into the window-scale option. Both halves travel separately
// because the option only exists on the SYN.
//
// APPROXIMATION: the two numbers are passed through as configured. nfqws'
// tcp_rewrite_winsize additionally divides the requested window by the scale the
// connection negotiated, so that --wssize=<n>:<scale> yields an *effective*
// window of n; here <n> is what lands in the header field, so a strategy whose
// scale is non-zero advertises n<<scale bytes to a peer that scales. The
// contract's Seg.Window is defined as the window field, not as the effective
// window, so pre-dividing here would misreport what goes on the wire; the
// arithmetic belongs to whichever layer knows the negotiated scale.
//
// Upstream applies --wssize to every client packet from the connection's start,
// not only to the one carrying the request, and stops at --wssize-cutoff (or on
// a recognised L7 request). Our engine only calls ops for packets inside the
// profile's own start/cutoff window, so the op enforces the wssize cutoff itself
// against the flow counters and otherwise tags whatever the plan carries.
type wssizeOp struct{}

// Name implements Op.
func (wssizeOp) Name() string { return "wssize" }

// Phase implements Op.
func (wssizeOp) Phase() Phase { return PhaseModify }

// Requires implements Op: owning the TCP header is what a window rewrite needs,
// which is exactly the Fooling capability. A socket-level transport does not
// have it, so the engine reports the op as degraded there and calls Degrade
// instead of Apply.
func (wssizeOp) Requires() Caps { return Caps{Fooling: true} }

// Apply implements Op.
func (o wssizeOp) Apply(c *Ctx, p *Plan) error {
	if c == nil || p == nil {
		return nil
	}
	if c.Params.WSSize <= 0 {
		// --wssize=0 is upstream's explicit "do not modify".
		return nil
	}
	if !wssizeActive(c) {
		// Past --wssize-cutoff: nfqws stops rewriting and lets the client's own
		// window through. That is the configured behaviour, not a limitation, so
		// it is silent — and nothing about the values is worth reporting either.
		return nil
	}
	win, scale := wssizeValues(c, p)

	n := wssizeTag(c, p, win, scale)
	if n == 0 && len(c.Payload) > 0 {
		// wssize running alone (or ahead of every segmentation op): the payload
		// has to be in the plan for the rewritten window to reach the wire, the
		// same reason the injection ops call injEnsureDataSeg.
		injEnsureDataSeg(c, p)
		n = wssizeTag(c, p, win, scale)
	}
	if n == 0 {
		// A bare SYN with no syndata segment: there is no Seg to hang the window
		// on, and the contract has no "re-emit the intercepted packet with these
		// header fields" segment kind.
		segNote(p, "wssize: window %d scale %d not applied to this packet — it carries no payload, so "+
			"the plan has no segment to hold the window; the transport must rewrite the window (and, on "+
			"a SYN, the window-scale option) of the intercepted packet itself",
			win, scale)
	}
	return nil
}

// wssizeTag writes the window onto every segment that legitimately carries the
// client's window, and reports how many it found.
//
// Real payload always does. A syndata segment does too, but only while this
// packet is the SYN: that is where the window-scale option lives, and getting
// the scale onto the wire is the whole reason --wssize takes one. Decoys are
// left alone: a fake is built by the transport with its own header fields and is
// never seen by the server's TCP, so its window means nothing.
func wssizeTag(c *Ctx, p *Plan, win uint16, scale uint8) int {
	n := 0
	for i := range p.Segs {
		if !wssizeCarriesWindow(p.Segs[i].Kind, c.SynPkt) {
			continue
		}
		p.Segs[i].Window, p.Segs[i].WindowScale = win, scale
		n++
	}
	return n
}

// wssizeCarriesWindow reports whether a segment of this kind advertises the
// client's own receive window.
func wssizeCarriesWindow(k SegKind, synPkt bool) bool {
	switch k {
	case SegData:
		return true
	case SegSynData:
		return synPkt
	}
	return false
}

// wssizeValues clamps --wssize to the field widths Seg can carry, reporting any
// clamp it had to make.
func wssizeValues(c *Ctx, p *Plan) (win uint16, scale uint8) {
	size, sc := c.Params.WSSize, c.Params.WSSizeScale
	if size > wssizeMaxWindow {
		segNote(p, "wssize: window %d does not fit the 16-bit TCP window field, using %d", size, wssizeMaxWindow)
		size = wssizeMaxWindow
	}
	if sc < 0 {
		sc = 0
	}
	if sc > wssizeMaxScale {
		segNote(p, "wssize: window scale %d does not fit the one-byte scale option, using %d", sc, wssizeMaxScale)
		sc = wssizeMaxScale
	}
	return uint16(size), uint8(sc)
}

// wssizeActive applies --wssize-cutoff: 'n' counts client packets, 'd' client
// packets carrying payload and 's' bytes into the client's stream. Kind 0 means
// no bound, i.e. rewrite until the flow ends.
//
// The comparison is the engine's own (counter > bound means "past it"), so a
// --wssize-cutoff=n2 covers the same two packets a --dpi-desync-cutoff=n2 would.
func wssizeActive(c *Ctx) bool {
	kind, want := c.Params.WSSizeCutoffKind, c.Params.WSSizeCutoffN
	if kind == 0 || c.Flow == nil {
		return true
	}
	f := c.Flow
	var v int
	switch kind {
	case 'n':
		v = f.Pkts
	case 'd':
		v = f.DataPkts
	case 's':
		// Relative sequence, computed exactly like engine.counterValue: the
		// flow's last data sequence number minus the client's ISN. LastSeq is 0
		// until the first payload byte, and without an observed SYN there is no
		// base to subtract — both cases mean "before the window", i.e. 0, never
		// the absolute sequence number.
		if f.LastSeq != 0 && f.HaveISN {
			v = int(f.LastSeq - f.ISN)
		}
	default:
		return true // a kind the loader cannot produce: never gate on it
	}
	return v <= want
}

// Degrade implements Degrader.
//
// A socket-level relay never sees a TCP header: the window it advertises is the
// kernel's, derived from the receive buffer of the socket it accepted. The
// closest honest approximation is setsockopt(TCP_MAXSEG) on the upstream socket,
// which caps the peer's segment size instead of the client's receive window —
// related in effect (the server answers in smaller pieces) but not equivalent:
// it does not shrink the amount of data in flight, and it cannot carry a window
// scale, which is the half of --wssize that only exists on the SYN.
func (o wssizeOp) Degrade(c *Ctx, p *Plan) error {
	if c == nil || p == nil || c.Params.WSSize <= 0 {
		return nil
	}
	segNote(p, "wssize: window %d scale %d needs the TCP header, which a socket-level relay does not own; "+
		"the closest approximation is setsockopt(TCP_MAXSEG) on the upstream socket, which caps the peer's "+
		"segment size rather than the client's receive window and cannot carry the window scale",
		c.Params.WSSize, c.Params.WSSizeScale)
	return nil
}

// ipIDOp implements --ip-id=zero|seq|seqgroup|same|random: how the IPv4
// identification field of the packets this plan emits is chosen.
//
// zapret sets the mode per desync profile and nfqws then walks its own ip_id
// counter across every packet it sends, so that a DPI checking for the OS'
// monotonic ip_id sequence is not tipped off by injected segments. The plan can
// only tag the segments; the counter itself is transport state. The tag means:
//
//	IPIDDefault   the transport picks (a fresh id per packet, like the kernel)
//	IPIDZero      ip.id = 0
//	IPIDRandom    a fresh random id per packet
//	IPIDSeq       one running counter, +1 per transmitted packet (a reversed
//	              plan counts DOWN, see the note on multidisorder)
//	IPIDSeqGroup  one id per sequence group — see SeqGroups: a decoy that stands
//	              in for a real part is emitted with that part's id, so the pair
//	              looks like one packet retransmitted rather than two packets
//	              claiming the same bytes
//	IPIDSame      the ip.id of the intercepted packet, on everything
type ipIDOp struct{}

// Name implements Op.
func (ipIDOp) Name() string { return "ip_id" }

// Phase implements Op.
func (ipIDOp) Phase() Phase { return PhaseModify }

// Requires implements Op.
func (ipIDOp) Requires() Caps { return Caps{IPID: true} }

// Apply implements Op: tag every segment the plan already holds, of every kind.
// Segments added by a later op are not reached, which is why the loader places
// ip_id last (it is a PhaseModify op) and why the segmentation ops copy
// OpParams.IPID onto their own segments as well.
//
// Tagging the real segments too is deliberate for IPIDSeqGroup and IPIDSame:
// both modes are defined by a *relation* between the decoy and the real bytes it
// stands in for, so the real segment has to carry the mode as well or the
// transport has no anchor to relate the decoy to.
//
// There is deliberately no Degrade: a transport that cannot choose the ip-id
// field has no honest approximation of this op.
func (ipIDOp) Apply(c *Ctx, p *Plan) error {
	if c == nil || p == nil || c.Params.IPID == IPIDDefault {
		return nil
	}
	for i := range p.Segs {
		p.Segs[i].IPID = c.Params.IPID
	}
	if injIsUDP(c) {
		// GAP: Dgram has no IPID field, so a UDP plan cannot ask for an ip.id at
		// all. Saying so beats letting a QUIC profile believe --ip-id fired.
		segNote(p, "ip_id: mode %s not applied on this UDP flow — Dgram carries no IPID field, "+
			"so a datagram plan cannot request an ip.id", ipIDModeName(c.Params.IPID))
	}
	return nil
}

// ipIDModeName spells an IPIDMode the way --ip-id does, for diagnostics.
func ipIDModeName(m IPIDMode) string {
	switch m {
	case IPIDZero:
		return "zero"
	case IPIDRandom:
		return "random"
	case IPIDSeq:
		return "seq"
	case IPIDSeqGroup:
		return "seqgroup"
	case IPIDSame:
		return "same"
	}
	return "default"
}

// SeqGroups assigns a sequence-group number to every segment of a plan. It is
// how a transport implements IPIDSeqGroup: all segments of one group go out with
// the same IPv4 identification, and the groups are numbered in ascending
// sequence order so the ids still climb the way a real stream's do.
//
// A group is keyed by the offset one past the last byte a segment covers, i.e.
// SeqOff+len(Data). That is what pairs a decoy with the original part it stands
// in for: the fakedsplit family builds each decoy over exactly one part's byte
// range, so the two end together and share an id — a DPI sees one packet
// retransmitted rather than two packets fighting over the same bytes — while the
// two parts of a message keep distinct ids. Keying on the END rather than on the
// start is deliberate: --dpi-desync-split-seqovl moves a real segment's start
// below the window (SeqOff goes negative) without moving its end, so an
// overlapped plan still groups correctly.
//
// The rule is exactly the one the divert transport implements in
// planBuilder.prepare; this function is its authoritative statement, so a
// transport can use it instead of re-deriving the grouping.
//
// Two consequences worth knowing: a decoy that does NOT cover the same range as
// the real bytes it precedes — the `fake` op's blob is a whole ClientHello of its
// own length — ends elsewhere and therefore gets its own id, which is also what
// nfqws produces since it builds that packet from scratch; and a zero-length
// segment (an injected RST) is grouped by its sequence number alone.
//
// The result is indexed like segs and group numbers start at 0.
func SeqGroups(segs []Seg) []int {
	out := make([]int, len(segs))
	if len(segs) == 0 {
		return out
	}
	ends := make([]int32, 0, len(segs))
	for i := range segs {
		if e := segEnd(segs[i]); !slices.Contains(ends, e) {
			ends = append(ends, e)
		}
	}
	slices.Sort(ends)
	group := make(map[int32]int, len(ends))
	for i, e := range ends {
		group[e] = i
	}
	for i := range segs {
		out[i] = group[segEnd(segs[i])]
	}
	return out
}

// segEnd is the stream offset one past the last byte a segment carries.
func segEnd(s Seg) int32 { return s.SeqOff + int32(len(s.Data)) }
