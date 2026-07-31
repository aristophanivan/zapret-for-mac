// Package divert is the packet-level transport: pf steers a narrow port window
// into a utun the daemon owns, reading a packet off the utun IS the
// interception, not re-emitting it IS the drop verdict, and re-emission happens
// with a raw Ethernet write on the physical uplink (which bypasses pf, so there
// is no loop).
//
// The consequence that shapes every file here: we author every byte of L3/L4
// ourselves, which is what makes ip_id, deliberately bad checksums, per-packet
// TTL, sub-window sequence numbers and IPv6 extension headers possible — i.e.
// desync.FullCaps, winws-class parity. Inbound traffic is never steered: replies
// go straight into the application's own socket, so there is no userspace TCP
// stack, no NAT and no source-port remap, and the application's real 4-tuple is
// preserved end to end.
package divert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// Header geometry this file needs. proto keeps its own copies unexported, so the
// few constants used by the packet math are restated here.
const (
	// tcpOptSpace is the TCP option area: a 60-byte maximum header minus the
	// 20-byte fixed part.
	tcpOptSpace = 40
	// tcpOptLenMD5 is the length of the TCP-MD5 signature option that
	// Tmpl.MD5Sig appends (kind 19, len 18).
	tcpOptLenMD5 = 18
	// tcpOptKindWScale / tcpOptLenWScale are the window-scale option
	// (RFC 7323 2.2): kind 3, length 3, one shift byte.
	tcpOptKindWScale = 3
	tcpOptLenWScale  = 3
	// tcpOptKindEOL / tcpOptKindNOP end and pad an option list.
	tcpOptKindEOL = 0
	tcpOptKindNOP = 1

	// ipv6HdrLen is the fixed IPv6 header length; ipv6FragHdrLen is the length
	// of a Fragment extension header.
	ipv6HdrLen     = 40
	ipv6FragHdrLen = 8
)

// ErrNoPacket reports that a plan asked for something this transport cannot put
// on the wire at all (e.g. TCP segments for a UDP flow). It is a programming
// error in the engine or the strategy compiler, never something hostile input
// can trigger, so the datapath forwards the original packet and counts it.
var ErrNoPacket = errors.New("divert: plan does not match the intercepted packet")

// BuildOpts pins the two things about packet construction that are neither
// derived from the intercepted packet nor from the plan, so tests can assert
// exact bytes.
type BuildOpts struct {
	// IPIDStart is the first value of the running IPv4 identification counter
	// used by desync.IPIDSeq and desync.IPIDSeqGroup.
	IPIDStart uint16
	// Rand fills b with random bytes. nil means math/rand/v2, which is the
	// right choice on the datapath: an ip_id or an IPv6 fragment identification
	// needs to be unpredictable to a DPI box, not cryptographically strong.
	Rand func(b []byte)
}

// randBytes fills b, defaulting to math/rand/v2.
func (o BuildOpts) randBytes(b []byte) {
	if o.Rand != nil {
		o.Rand(b)
		return
	}
	for i := 0; i+4 <= len(b); i += 4 {
		binary.BigEndian.PutUint32(b[i:i+4], rand.Uint32())
	}
	if rem := len(b) % 4; rem != 0 {
		var tail [4]byte
		binary.BigEndian.PutUint32(tail[:], rand.Uint32())
		copy(b[len(b)-rem:], tail[:rem])
	}
}

// BuildPlanPackets turns one desync.Plan into the exact wire images the
// transport has to inject, in transmit order. It is pure: no syscalls, no
// randomness beyond BuildOpts.Rand, no shared state — which is what makes the
// whole packet math testable without root.
//
// orig is the intercepted packet (the application's own, still carrying its real
// 4-tuple). Every produced packet reuses that 4-tuple: the divert transport
// never rewrites addresses or ports, because inbound traffic is not steered and
// must keep landing in the application's socket.
func BuildPlanPackets(orig *proto.Pkt, plan *desync.Plan, o BuildOpts) ([][]byte, error) {
	pkts, _, err := BuildPlan(orig, plan, o)
	return pkts, err
}

// BuildPlan is BuildPlanPackets plus the number of IPv4 identification values the
// plan actually consumed.
//
// The two numbers differ: an IPv4 fragmentation pass turns one packet into two
// that share a single ip_id by construction, so advancing the transport's running
// --ip-id=seq counter by len(pkts) would leave gaps in a sequence a DPI box may
// be checking for contiguity.
func BuildPlan(orig *proto.Pkt, plan *desync.Plan, o BuildOpts) ([][]byte, int, error) {
	if orig == nil {
		return nil, 0, fmt.Errorf("%w: no intercepted packet", ErrNoPacket)
	}
	if plan == nil || (len(plan.Segs) == 0 && len(plan.Dgrams) == 0) {
		return nil, 0, nil
	}
	b := &planBuilder{orig: orig, o: o, ipv6: orig.Ver == 6}
	b.origTSVal, b.origTSEcho, b.haveTS = proto.TCPTimestamps(orig.TCPOpts)
	b.payloadLen = len(orig.Payload())
	b.origFin = orig.IsTCP() && orig.Flags&proto.TCPFin != 0

	if len(plan.Segs) > 0 {
		if !orig.IsTCP() {
			return nil, 0, fmt.Errorf("%w: %d TCP segment(s) planned for an IP proto %d packet",
				ErrNoPacket, len(plan.Segs), orig.Proto)
		}
		if err := checkDataTiling(plan.Segs, b.payloadLen); err != nil {
			return nil, 0, err
		}
		b.prepare(plan.Segs)
		for i := range plan.Segs {
			if err := b.seg(&plan.Segs[i]); err != nil {
				return nil, 0, err
			}
		}
	}
	if len(plan.Dgrams) > 0 {
		if !orig.IsUDP() {
			return nil, 0, fmt.Errorf("%w: %d datagram(s) planned for an IP proto %d packet",
				ErrNoPacket, len(plan.Dgrams), orig.Proto)
		}
		for i := range plan.Dgrams {
			if err := b.dgram(&plan.Dgrams[i]); err != nil {
				return nil, 0, err
			}
		}
	}
	return b.out, b.ids, nil
}

// checkDataTiling is the datapath's last line of defence against a plan whose
// real segments do not reproduce the intercepted byte stream exactly once.
//
// WHY it is worth a check rather than an assumption: this transport does not own
// the client's TCP sequence space — the client's own kernel already committed
// sequence numbers for `want` bytes. A plan that emits more, fewer or
// non-contiguous bytes desynchronises that sequence space for the rest of the
// connection, and the failure is permanent because the client's retransmission
// takes the identical path. Returning an error makes the datapath forward the
// application's own packet untouched, which is always safe.
//
// The tiling rule is the same one desync.segSpans uses: walk the SegData
// segments in ascending SeqOff, allow a leading prefix that an earlier segment
// (or a seqovl filler below the window) already covered, and require the walk to
// land exactly on want.
func checkDataTiling(segs []desync.Seg, want int) error {
	idx := make([]int, 0, len(segs))
	for i := range segs {
		if segs[i].Kind == desync.SegData {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		if want == 0 {
			return nil
		}
		// Injected segments only (a bare fake or RST alongside the original):
		// the original is still forwarded, so there is nothing to tile.
		return nil
	}
	slices.SortStableFunc(idx, func(a, b int) int {
		return int(segs[a].SeqOff) - int(segs[b].SeqOff)
	})
	pos := 0
	for _, i := range idx {
		start := int(segs[i].SeqOff)
		prefix := pos - start
		end := start + len(segs[i].Data)
		if prefix < 0 || prefix > len(segs[i].Data) || end > want {
			return fmt.Errorf("%w: data segment [%d,%d) does not continue the stream at %d (payload %d bytes)",
				ErrNoPacket, start, end, pos, want)
		}
		pos = end
	}
	if pos != want {
		return fmt.Errorf("%w: data segments cover %d of %d payload bytes",
			ErrNoPacket, pos, want)
	}
	return nil
}

// planBuilder holds the per-plan state the ip_id modes need.
type planBuilder struct {
	orig *proto.Pkt
	o    BuildOpts
	out  [][]byte

	ipv6 bool

	// origTSVal/origTSEcho are the intercepted packet's RFC 7323 timestamps,
	// the base --dpi-desync-fooling=ts works from.
	origTSVal, origTSEcho uint32
	haveTS                bool

	// origFin and payloadLen decide which real segment carries the FIN the
	// client set on the intercepted packet. See dataFlags.
	origFin    bool
	payloadLen int

	// ids counts the ip_id values actually issued, so the transport's running
	// --ip-id=seq counter advances by that many and not by the number of wire
	// packets (an IPv4 fragmentation pass shares one id across both halves).
	ids int

	// seqNext/seqStep implement desync.IPIDSeq. nfqws does IP4_IP_ID_ADD(n)
	// followed by IP4_IP_ID_PREV per packet for a disorder plan, so the ids
	// still ASCEND in sequence order while DESCENDING in transmit order; seqStep
	// is -1 for exactly that case.
	seqNext uint16
	seqStep int

	// groups implements desync.IPIDSeqGroup: one id per "part" of the original
	// payload, so a decoy and the real bytes it stands in for share an ip_id and
	// look like one retransmission.
	groups map[int32]uint16
}

// segRepeats normalises Seg.Repeats/Dgram.Repeats: at least one transmission.
func segRepeats(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// prepare precomputes the ip_id bookkeeping that depends on the whole segment
// list: the sequence-group map and the direction of the IPIDSeq counter.
func (b *planBuilder) prepare(segs []desync.Seg) {
	// A "group" is keyed by the payload offset one past the last byte the
	// segment covers. That is what makes a decoy and the real segment it stands
	// in for land in the same group even when the real one carries a
	// --dpi-desync-split-seqovl prefix: the overlap moves the START of the
	// segment below the window but not its end.
	ends := make([]int32, 0, len(segs))
	for i := range segs {
		e := segs[i].SeqOff + int32(len(segs[i].Data))
		if !slices.Contains(ends, e) {
			ends = append(ends, e)
		}
	}
	slices.Sort(ends)
	b.groups = make(map[int32]uint16, len(ends))
	for i, e := range ends {
		b.groups[e] = b.o.IPIDStart + uint16(i)
	}

	// Disorder detection: the data segments of a multidisorder/fakeddisorder
	// plan are handed to us in descending sequence order. Fakes are ignored
	// because they are interleaved and would mask the direction.
	var (
		prev  int32
		first = true
		asc   bool
		desc  bool
		nseq  int
	)
	for i := range segs {
		if segs[i].IPID == desync.IPIDSeq {
			nseq += segRepeats(segs[i].Repeats)
		}
		if segs[i].Kind != desync.SegData {
			continue
		}
		if !first {
			switch {
			case segs[i].SeqOff < prev:
				desc = true
			case segs[i].SeqOff > prev:
				asc = true
			}
		}
		prev, first = segs[i].SeqOff, false
	}
	b.seqNext, b.seqStep = b.o.IPIDStart, 1
	if desc && !asc && nseq > 0 {
		b.seqNext, b.seqStep = b.o.IPIDStart+uint16(nseq-1), -1
	}
}

// ipid resolves one packet's IPv4 identification field. group is the segment's
// sequence-group key (see prepare).
func (b *planBuilder) ipid(mode desync.IPIDMode, group int32) uint16 {
	b.ids++
	switch mode {
	case desync.IPIDZero:
		return 0
	case desync.IPIDSame:
		return b.orig.IPID
	case desync.IPIDSeq:
		v := b.seqNext
		// Deliberate uint16 wrap-around: the field is 16 bits and a DPI box
		// checking for monotonicity expects it to wrap, not to stall.
		b.seqNext = uint16(int(b.seqNext) + b.seqStep)
		return v
	case desync.IPIDSeqGroup:
		if id, ok := b.groups[group]; ok {
			return id
		}
		return b.o.IPIDStart
	default: // IPIDDefault, IPIDRandom
		return b.randU16()
	}
}

// randU16 draws a random 16-bit value through BuildOpts.Rand.
func (b *planBuilder) randU16() uint16 {
	var v [2]byte
	b.o.randBytes(v[:])
	return binary.BigEndian.Uint16(v[:])
}

// randU32 draws a random 32-bit value through BuildOpts.Rand.
func (b *planBuilder) randU32() uint32 {
	var v [4]byte
	b.o.randBytes(v[:])
	return binary.BigEndian.Uint32(v[:])
}

// dataFlags derives the TCP flags of one real segment from the intercepted
// packet, the way nfqws does (it captures flags_orig once and hands it to the
// real-segment builder).
//
// Hard-coding PSH|ACK loses every other flag the client set. The one that
// matters is FIN: a client that writes a request and immediately close()s sends
// PSH|ACK|FIN in a single segment, and dropping the FIN leaves it in FIN_WAIT_1
// while the server waits for request bytes that will never come — the connection
// then hangs until an idle timeout, and the retransmission is re-segmented the
// same way. ECE/CWR/URG are lost just as silently.
//
// FIN is moved onto whichever segment carries the last payload byte, so a split
// still closes the stream at the right sequence number; a reordered plan
// (multidisorder) may therefore send the FIN first, which is correct — a FIN's
// sequence number is what orders it, not its arrival time.
func (b *planBuilder) dataFlags(s *desync.Seg) uint8 {
	flags := b.orig.Flags
	// SYN never belongs on a data segment: SegSynData is the kind that carries a
	// payload on the SYN, and it sets the flag itself.
	flags &^= proto.TCPSyn
	// The client always has an established connection at this point, so PSH|ACK
	// is the floor even if the intercepted packet somehow lacked them.
	flags |= proto.TCPPsh | proto.TCPAck
	if b.origFin {
		if int(s.SeqOff)+len(s.Data) >= b.payloadLen {
			flags |= proto.TCPFin
		} else {
			flags &^= proto.TCPFin
		}
	}
	return flags
}

// seg builds and appends every packet one TCP segment of the plan stands for.
func (b *planBuilder) seg(s *desync.Seg) error {
	orig := b.orig

	flags := s.Flags
	if flags == 0 {
		switch s.Kind {
		case desync.SegRST:
			flags = proto.TCPRst
		case desync.SegSynData:
			flags = proto.TCPSyn
		default:
			flags = b.dataFlags(s)
		}
	}

	ttl := s.TTL
	if ttl == 0 {
		ttl = orig.TTL
	}
	window := s.Window
	if window == 0 {
		window = orig.Window
	}

	t := proto.Tmpl{
		Src:     orig.Src,
		Dst:     orig.Dst,
		SrcPort: orig.SrcPort,
		DstPort: orig.DstPort,
		// THE line of this file. SeqOff is int32 so a negative value produces
		// the below-the-window sequence number --dpi-desync-split-seqovl needs:
		// the converted uint32 wraps, and modulo-2^32 arithmetic is exactly what
		// a TCP sequence space is.
		Seq:    orig.Seq + uint32(s.SeqOff),
		Ack:    orig.Ack,
		Flags:  flags,
		Window: window,
		TTL:    ttl,
		// The DSCP/ECN byte and the IPv6 traffic class + flow label travel with
		// the segment: a connection whose packets are inconsistently marked both
		// loses ECN and hands a DPI fingerprinter a free signal.
		TrafficClass: orig.TrafficClass,
		FlowLabel:    orig.FlowLabel,
		DF:           orig.DF,
		Payload:      s.Data,
	}

	// Real segments carry the application's own options verbatim: dropping the
	// timestamp option from a flow that negotiated RFC 7323 would make the peer
	// discard the segment.
	opts := orig.TCPOpts
	if s.Kind == desync.SegFake || s.Kind == desync.SegRST {
		// A decoy must not be accepted by the peer, and the fooling modes are
		// how that is guaranteed. They only ever apply to injected packets:
		// nfqws passes fooling_orig == FOOL_NONE for the real ones.
		if s.Fool&desync.FoolTS != 0 && b.haveTS {
			opts = proto.SetTCPTimestamps(opts, b.origTSVal+uint32(s.FoolP.TSIncrement), b.origTSEcho)
		}
		if s.Fool&desync.FoolMD5Sig != 0 {
			t.MD5Sig = true
			if len(opts)+tcpOptLenMD5 > tcpOptSpace {
				// The signature is what the middlebox looks at; the original
				// options are expendable on a packet that must die anyway.
				opts = nil
			}
		}
		if s.Fool&desync.FoolBadSeq != 0 {
			t.Seq += uint32(s.FoolP.BadSeqIncrement)
			t.Ack += uint32(s.FoolP.BadAckIncrement)
		}
		if s.Fool&desync.FoolBadSum != 0 {
			t.BadSum = true
		}
		if s.Fool&desync.FoolDataNoAck != 0 {
			t.NoAck = true
		}
	}
	if s.WindowScale != 0 && flags&proto.TCPSyn != 0 {
		// --wssize's scale half. Only an option the client already negotiated is
		// rewritten: adding window scaling to a SYN whose own stack does not
		// scale would make the peer misread every window we later advertise.
		opts = tcpOptSetWindowScale(opts, s.WindowScale)
	}
	t.TCPOpts = opts

	group := s.SeqOff + int32(len(s.Data))
	reps := segRepeats(s.Repeats)
	for i := 0; i < reps; i++ {
		t.IPID = b.ipid(s.IPID, group)
		pkt, err := t.Marshal()
		if err != nil {
			return fmt.Errorf("divert: building %s segment (seqoff %d, %d bytes): %w",
				segKindName(s.Kind), s.SeqOff, len(s.Data), err)
		}
		if err := b.emit(pkt, s.Fool, s.Frag); err != nil {
			return err
		}
	}
	return nil
}

// dgram builds and appends every packet one UDP datagram of the plan stands for.
func (b *planBuilder) dgram(d *desync.Dgram) error {
	orig := b.orig

	ttl := d.TTL
	if ttl == 0 {
		ttl = orig.TTL
	}
	t := proto.Tmpl{
		Src:          orig.Src,
		Dst:          orig.Dst,
		SrcPort:      orig.SrcPort,
		DstPort:      orig.DstPort,
		TTL:          ttl,
		TrafficClass: orig.TrafficClass,
		FlowLabel:    orig.FlowLabel,
		DF:           orig.DF,
		UDP:          true,
		Payload:      d.Data,
	}
	// Only the fooling bits that mean anything without a TCP header apply here;
	// badseq, md5sig and datanoack are TCP-only and nfqws ignores them for UDP
	// too.
	if d.Kind != desync.SegData && d.Fool&desync.FoolBadSum != 0 {
		t.BadSum = true
	}

	reps := segRepeats(d.Repeats)
	for i := 0; i < reps; i++ {
		// Dgram carries no IPID field, so the datagrams follow the kernel's own
		// behaviour: Darwin randomises ip_id per packet (net.inet.ip.random_id),
		// which is also what makes a decoy indistinguishable from real traffic.
		t.IPID = b.randU16()
		pkt, err := t.Marshal()
		if err != nil {
			return fmt.Errorf("divert: building %s datagram (%d bytes): %w",
				segKindName(d.Kind), len(d.Data), err)
		}
		if err := b.emit(pkt, d.Fool, d.Frag); err != nil {
			return err
		}
	}
	return nil
}

// emit applies the post-marshal header tricks and appends the result.
//
// Order matters: the IPv6 Fragment header goes closest to the transport header
// and the hop-by-hop options in front of it, because RFC 8200 fixes that order
// and a peer's stack rejects the reverse. AddIPv6ExtHdr always inserts directly
// after the fixed header, so it has to run last.
func (b *planBuilder) emit(pkt []byte, fool desync.Fooling, frag int) error {
	if b.ipv6 {
		if fool&desync.FoolIPFrag1 != 0 {
			out, err := insertIPv6FragHdr(pkt, b.randU32())
			if err != nil {
				return fmt.Errorf("divert: ipfrag1: %w", err)
			}
			pkt = out
		}
		if n := hopByHopCount(fool); n > 0 {
			out, err := proto.AddIPv6ExtHdr(pkt, n, proto.IPProtoHopOpt)
			if err != nil {
				return fmt.Errorf("divert: hop-by-hop x%d: %w", n, err)
			}
			pkt = out
		}
	}
	// frag > 0 is --dpi-desync=ipfrag2: IPv4 fragmentation at an offset inside
	// (or just past) the transport header. IPFragment rounds down to the 8-byte
	// granularity of the offset field and rejects a position outside the
	// payload; either way the honest fallback is the unfragmented packet, which
	// is also what nfqws sends when it cannot fragment.
	if frag > 0 && !b.ipv6 {
		if frags, err := proto.IPFragment(pkt, frag); err == nil {
			b.out = append(b.out, frags...)
			return nil
		}
	}
	b.out = append(b.out, pkt)
	return nil
}

// hopByHopCount maps the fooling bits onto the number of hop-by-hop headers to
// insert. hopbyhop2 deliberately violates RFC 8200 (at most one, and only
// first): a DPI stack that re-walks the chain gives up while the peer's IPv6
// stack still accepts the packet.
func hopByHopCount(f desync.Fooling) int {
	switch {
	case f&desync.FoolHopByHop2 != 0:
		return 2
	case f&desync.FoolHopByHop != 0:
		return 1
	default:
		return 0
	}
}

// segKindName renders a SegKind for error messages.
func segKindName(k desync.SegKind) string {
	switch k {
	case desync.SegData:
		return "data"
	case desync.SegFake:
		return "fake"
	case desync.SegRST:
		return "rst"
	case desync.SegSynData:
		return "syndata"
	default:
		return fmt.Sprintf("kind%d", uint8(k))
	}
}

// insertIPv6FragHdr inserts an 8-byte IPv6 Fragment extension header with
// offset 0 and the More-Fragments bit clear between the fixed header and
// whatever follows it — the packet stays one whole datagram, it merely looks
// fragmented.
//
// This is --dpi-desync=ipfrag1: a DPI box that refuses to walk past a Fragment
// header never sees the SNI, while the peer's IPv6 stack reassembles a
// one-fragment datagram trivially. proto.AddIPv6ExtHdr cannot build this header
// (it only writes options headers), which is why it lives here.
//
// L4 checksums are unaffected: the IPv6 pseudo-header's next-header field is the
// upper-layer protocol number, not the value in the IPv6 header, and neither the
// addresses nor the upper-layer length change.
func insertIPv6FragHdr(pkt []byte, id uint32) ([]byte, error) {
	if len(pkt) < ipv6HdrLen {
		return nil, fmt.Errorf("ipv6 header wants %d bytes, have %d", ipv6HdrLen, len(pkt))
	}
	if pkt[0]>>4 != 6 {
		return nil, fmt.Errorf("not an IPv6 packet (version %d)", pkt[0]>>4)
	}
	plen := int(binary.BigEndian.Uint16(pkt[4:6]))
	switch {
	case plen == 0:
		// Jumbogram or offload: the buffer length is the only truth available.
		plen = len(pkt) - ipv6HdrLen
	case ipv6HdrLen+plen > len(pkt):
		return nil, fmt.Errorf("ipv6 payload length %d, have %d", plen, len(pkt)-ipv6HdrLen)
	}
	if plen+ipv6FragHdrLen > 0xffff {
		return nil, fmt.Errorf("fragment header overflows the ipv6 payload length (%d + %d)", plen, ipv6FragHdrLen)
	}

	out := make([]byte, ipv6HdrLen+ipv6FragHdrLen+plen)
	copy(out, pkt[:ipv6HdrLen])
	binary.BigEndian.PutUint16(out[4:6], uint16(plen+ipv6FragHdrLen))
	out[6] = proto.IPProtoFrag
	out[ipv6HdrLen] = pkt[6] // the fragment header hands over to the original next header
	out[ipv6HdrLen+1] = 0    // reserved
	// Fragment offset 0, res 0, M 0: this "fragment" is the whole datagram.
	binary.BigEndian.PutUint16(out[ipv6HdrLen+2:ipv6HdrLen+4], 0)
	binary.BigEndian.PutUint32(out[ipv6HdrLen+4:ipv6HdrLen+8], id)
	copy(out[ipv6HdrLen+ipv6FragHdrLen:], pkt[ipv6HdrLen:ipv6HdrLen+plen])
	return out, nil
}

// tcpOptSetWindowScale returns a copy of opts with the window-scale option's
// shift replaced. When there is no such option opts is returned unchanged: see
// the call site for why we never add one.
func tcpOptSetWindowScale(opts []byte, shift uint8) []byte {
	for i := 0; i < len(opts); {
		switch opts[i] {
		case tcpOptKindEOL:
			return opts
		case tcpOptKindNOP:
			i++
			continue
		}
		if i+1 >= len(opts) {
			return opts
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			// Malformed option list: stop rather than read out of range. Hostile
			// input reaches this through a crafted TCP header.
			return opts
		}
		if opts[i] == tcpOptKindWScale && l == tcpOptLenWScale {
			out := make([]byte, len(opts))
			copy(out, opts)
			out[i+2] = shift
			return out
		}
		i += l
	}
	return opts
}

// NormaliseChecksums repairs an intercepted packet's checksums in place and
// reports which ones it had to touch.
//
// WHY this exists: a packet we take off the utun is re-emitted with a raw
// Ethernet write, which skips the kernel's transmit path entirely — so whatever
// the checksum fields hold at that moment is what goes on the wire. macOS leaves
// them unset or partially summed whenever the outgoing interface advertises
// checksum offload. utun advertises none, and the capability probe observed
// correct checksums on every packet it read from one, so in practice this is a
// no-op; it is here because the failure mode it guards against (every forwarded
// packet silently dropped by the peer) is indistinguishable from "the desync
// does not work".
//
// pkt.Raw is modified in place, which is safe because it aliases the datapath's
// read buffer and is consumed before the next read.
//
// The L4 checksum is left alone for any packet that is only a piece of a larger
// datagram (an IPv4 first fragment, or IPv6 with an extension-header chain that
// may include a Fragment header): there the field covers bytes we cannot see, and
// recomputing it over the piece would be the corruption this function is meant to
// prevent.
func NormaliseChecksums(pkt *proto.Pkt) (fixedIP, fixedL4 bool) {
	if pkt == nil || len(pkt.Raw) < pkt.L3Len {
		return false, false
	}
	raw := pkt.Raw

	wholeDatagram := true
	if pkt.Ver == 4 {
		if len(raw) < 20 {
			return false, false
		}
		// Recompute the header checksum unconditionally: it covers the header
		// alone, so it is always safe and always cheap.
		want := ipv4HeaderChecksum(raw[:pkt.L3Len])
		if binary.BigEndian.Uint16(raw[10:12]) != want {
			binary.BigEndian.PutUint16(raw[10:12], want)
			fixedIP = true
		}
		frag := binary.BigEndian.Uint16(raw[6:8])
		// More-Fragments set, or a non-zero offset: this is a piece.
		wholeDatagram = frag&0x2000 == 0 && frag&0x1fff == 0
	} else if pkt.Ver == 6 {
		// Only a bare IPv6 header (no extension chain) is certainly whole.
		wholeDatagram = len(raw) > 6 && (raw[6] == proto.IPProtoTCP || raw[6] == proto.IPProtoUDP)
	}

	if !wholeDatagram || pkt.L4Len == 0 {
		return fixedIP, false
	}
	sumOff := pkt.L3Len + 16 // TCP
	if pkt.IsUDP() {
		sumOff = pkt.L3Len + 6
	} else if !pkt.IsTCP() {
		return fixedIP, false
	}
	if sumOff+2 > len(raw) {
		return fixedIP, false
	}

	l4 := raw[pkt.L3Len:]
	had := binary.BigEndian.Uint16(raw[sumOff : sumOff+2])
	if pkt.Ver == 4 && pkt.IsUDP() && had == 0 {
		// RFC 768: an all-zero checksum on IPv4/UDP means "no checksum", which is
		// legal and is what some senders do. Rewriting it would still produce a
		// valid datagram, but it would also raise the "the kernel handed us an
		// unset checksum" alarm and send an operator hunting an offload bug that
		// does not exist. (IPv6 has no such exemption: RFC 8200 requires a UDP
		// checksum, so a zero there really is broken.)
		return fixedIP, false
	}
	binary.BigEndian.PutUint16(raw[sumOff:sumOff+2], 0)
	want := proto.L4Checksum(pkt.Src, pkt.Dst, pkt.Proto, l4)
	if had == want {
		binary.BigEndian.PutUint16(raw[sumOff:sumOff+2], had)
		return fixedIP, false
	}
	binary.BigEndian.PutUint16(raw[sumOff:sumOff+2], want)
	return fixedIP, true
}

// ipv4HeaderChecksum computes an IPv4 header checksum with the checksum field
// itself treated as zero, without modifying hdr.
func ipv4HeaderChecksum(hdr []byte) uint16 {
	if len(hdr) < 20 {
		return 0
	}
	saved0, saved1 := hdr[10], hdr[11]
	hdr[10], hdr[11] = 0, 0
	sum := proto.Checksum16(hdr)
	hdr[10], hdr[11] = saved0, saved1
	return sum
}

// fragmentForMTU splits an over-MTU IPv4 packet into two fragments so the link
// layer accepts it.
//
// This is needed because we author the packets ourselves and therefore bypass
// the kernel's own fragmentation: a --dpi-desync-split-seqovl prefix or an
// inserted extension header can push a full-size segment past the uplink MTU,
// and the driver would silently drop the oversize frame. Anything that cannot be
// fragmented (IPv6, or a packet whose L4 content is too short to cut) is
// returned as-is for the caller to attempt and count.
func fragmentForMTU(pkt []byte, mtu int) [][]byte {
	if mtu <= 0 || len(pkt) <= mtu || len(pkt) < 1 || pkt[0]>>4 != 4 {
		return [][]byte{pkt}
	}
	ihl := int(pkt[0]&0x0f) * 4
	// Cut at the largest 8-byte multiple that still fits the MTU.
	pos := (mtu - ihl) &^ 7
	frags, err := proto.IPFragment(pkt, pos)
	if err != nil {
		return [][]byte{pkt}
	}
	// The tail may still be over the MTU for a very large packet; recurse on it.
	// A fresh slice is built rather than appending to frags[:1], whose backing
	// array still holds the tail we are about to re-fragment.
	tail := fragmentForMTU(frags[1], mtu)
	out := make([][]byte, 0, 1+len(tail))
	out = append(out, frags[0])
	return append(out, tail...)
}
