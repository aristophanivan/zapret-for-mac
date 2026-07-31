package desync

import (
	"fmt"
	"slices"

	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// This file implements the position-driven segmentation family
// (--dpi-desync=multisplit / multidisorder) plus the helpers shared with the
// faked-split family in op_fakedsplit.go.
//
// Everything here is a port of nfq/desync.c (cases DESYNC_MULTISPLIT and
// DESYNC_MULTIDISORDER) together with nfq/protocol.c ResolveMultiPos() and
// nfqws.c split_compat(). Comments name the upstream function whenever the
// behaviour is not obvious from the code.

// segMaxSplits mirrors zapret's MAX_SPLITS: the number of --dpi-desync-split-pos
// entries a profile may carry. Extra entries are ignored rather than rejected,
// because the datapath must never fail on a config the loader let through.
const segMaxSplits = 64

// segMaxFakeLen mirrors DPI_DESYNC_MAX_FAKE_LEN from nfq/desync.h: the largest
// payload nfqws is willing to copy into a synthetic segment.
const segMaxFakeLen = 9216

// segMaxSegLen is the size of nfqws' on-stack segment buffers (ovlseg/fakeseg,
// DPI_DESYNC_MAX_FAKE_LEN + 100). A segment that does not fit makes nfqws
// cancel the whole desync and forward the original packet, which we express as
// an empty plan.
const segMaxSegLen = segMaxFakeLen + 100

// DefaultSplitPos is zapret's implicit --dpi-desync-split-pos when none is
// configured: absolute offset 2 (nfqws.c split_compat()).
func DefaultSplitPos() []PosSpec {
	return []PosSpec{{Marker: proto.MarkerAbs, Offset: 2}}
}

// segSplitSpecs returns the split-position list an op should use, substituting
// zapret's default and clipping the list to MAX_SPLITS entries.
func segSplitSpecs(p OpParams) []PosSpec {
	if len(p.SplitPos) == 0 {
		return DefaultSplitPos()
	}
	if len(p.SplitPos) > segMaxSplits {
		return p.SplitPos[:segMaxSplits]
	}
	return p.SplitPos
}

// segResolveMultiPos ports protocol.c ResolveMultiPos() plus the
// pos_normalize() filter loop desync.c runs over its result.
//
// Each spec is resolved against the payload; a marker the protocol does not
// have resolves to 0 and is dropped. Surviving offsets are sorted and
// deduplicated, and any offset that is not strictly inside the payload is
// dropped: a cut at 0 or at len(payload) is not a cut at all. (Upstream's
// pos_normalize() also subtracts the reassembly offset of the current packet in
// a multi-packet message; we never reassemble, so that term is always 0.)
func segResolveMultiPos(c *Ctx, specs []PosSpec) []int {
	n := len(c.Payload)
	out := make([]int, 0, len(specs))
	for _, s := range specs {
		pos := proto.FindSplitPos(c.Payload, c.Info, s.Marker, s.Offset)
		if pos <= 0 || pos >= n {
			continue
		}
		out = append(out, pos)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// segRepeats is --dpi-desync-repeats for injected packets; zapret's default is
// one transmission.
func segRepeats(p OpParams) int {
	if p.Repeats < 1 {
		return 1
	}
	return p.Repeats
}

// segDataSeg builds a real-payload segment. Real segments never carry fooling
// or a forged TTL: nfqws passes fooling_orig (FOOL_NONE) and ttl_orig for them.
func segDataSeg(data []byte, seqOff int, p OpParams) Seg {
	return Seg{Kind: SegData, Data: data, SeqOff: int32(seqOff), Repeats: 1, IPID: p.IPID}
}

// segFakeSeg builds a decoy segment: it carries the desync TTL, the fooling
// mode and the repeat count, so it dies before the server but is seen by DPI.
func segFakeSeg(data []byte, seqOff int, p OpParams) Seg {
	return Seg{
		Kind: SegFake, Data: data, SeqOff: int32(seqOff),
		TTL: p.TTL, Fool: p.Fool, FoolP: p.FoolP,
		Repeats: segRepeats(p), IPID: p.IPID,
	}
}

// segFillPattern ports helpers.c fill_pattern(): n bytes produced by repeating
// pattern, starting offset bytes into it. An empty pattern yields zero bytes,
// which is also zapret's default --dpi-desync-fakedsplit-pattern (a 64-byte
// zero block) and its default seqovl pattern (a zeroed array).
func segFillPattern(n int, pattern []byte, offset int) []byte {
	if n <= 0 {
		return nil
	}
	out := make([]byte, n)
	if len(pattern) == 0 {
		return out
	}
	i := 0
	if off := offset % len(pattern); off != 0 {
		i += copy(out, pattern[off:])
	}
	for i < n {
		i += copy(out[i:], pattern)
	}
	return out
}

// segNote records an honest description of something the op could not do.
func segNote(p *Plan, format string, args ...any) {
	p.Degraded = append(p.Degraded, fmt.Sprintf(format, args...))
}

// segTakeOverData hands the plan's payload segmentation over to the PhaseSplit
// op that is about to run: every SegData already present is dropped, while
// injected segments (SegFake/SegRST/SegSynData) keep their place and order.
//
// WHY this is needed at all — it is the one place our phase model diverges from
// nfqws' control flow. A PhaseFake op (fake, rst) must put the real payload into
// the plan itself, because engine.run sets Plan.DropOriginal as soon as the plan
// is non-empty; without that segment the request would never reach the server.
// So the segment injEnsureDataSeg adds is a placeholder meaning "the payload,
// not yet segmented". A PhaseSplit op then re-emits those same bytes cut into
// pieces, so the placeholder has to go or the request is transmitted twice —
// once whole, once in parts. nfqws has no such hazard: there the first stage only
// injects and the second stage alone owns send_orig.
//
// Every PhaseSplit op calls this before appending its own segments, so the
// flagship Flowseal recipe `--dpi-desync=fake,multisplit` plans one copy of the
// payload behind the decoys.
func segTakeOverData(p *Plan) {
	kept := p.Segs[:0]
	for _, s := range p.Segs {
		if s.Kind != SegData {
			kept = append(kept, s)
		}
	}
	p.Segs = kept
}

// segTakeOverAll clears the plan's segments entirely: the Degrade counterpart of
// segTakeOverData. A socket-level transport writes a byte stream, so it can
// neither put a decoy, an RST or a SYN payload on the wire nor keep a
// pre-existing data segment the degraded segmentation is about to replace.
func segTakeOverAll(p *Plan) {
	p.Segs = p.Segs[:0]
}

// segMultiSegments cuts the payload at pos and returns the parts in ascending
// offset order, applying sequence overlap to the part zapret picks for the mode.
//
// ok is false when upstream would abandon the desync and forward the original
// packet (the overlapped segment does not fit nfqws' buffer).
func segMultiSegments(c *Ctx, pos []int, disorder bool) (segs []Seg, ovlUsed int, ok bool) {
	p := c.Params
	n := len(c.Payload)

	// nfqws applies seqovl to the first transmitted part: part 0 for
	// multisplit, part 1 (the one starting at the first split position) for
	// multidisorder, whose part 0 is transmitted last.
	target := 0
	if disorder {
		target = 1
	}

	ovl := p.Seqovl
	switch {
	case ovl <= 0:
		ovl = 0
	case !c.Caps.Seq:
		// A negative SeqOff means "send below the current window", which needs
		// control over the TCP sequence number. A byte-stream transport cannot.
		ovl = 0
	case disorder && ovl >= pos[0]:
		// desync.c: "seqovl>=split_pos. cancelling seqovl". The disorder trick
		// relies on the first part later overwriting the overlap junk, which
		// cannot happen once the overlap reaches into the first part.
		ovl = 0
	}

	segs = make([]Seg, 0, len(pos)+1)
	from := 0
	for i := 0; i <= len(pos); i++ {
		to := n
		if i < len(pos) {
			to = pos[i]
		}
		if ovl > 0 && i == target {
			if ovl+(to-from) > segMaxSegLen {
				return nil, 0, false // upstream: "seqovl is too large" -> send original
			}
			// The overlap prefix sits below the window: the server's TCP drops
			// it and keeps only [from,to), while a naive DPI reassembler
			// swallows the pattern and loses sync with the real stream.
			data := make([]byte, 0, ovl+to-from)
			data = append(data, segFillPattern(ovl, p.SeqovlPattern, 0)...)
			data = append(data, c.Payload[from:to]...)
			segs = append(segs, segDataSeg(data, from-ovl, p))
		} else {
			segs = append(segs, segDataSeg(c.Payload[from:to], from, p))
		}
		from = to
	}
	return segs, ovl, true
}

// segSeqovlNote explains, when needed, why a configured sequence overlap did
// not make it into the plan.
func segSeqovlNote(c *Ctx, p *Plan, op string, firstPos, ovlUsed int, disorder bool) {
	want := c.Params.Seqovl
	if want <= 0 || ovlUsed > 0 {
		return
	}
	switch {
	case !c.Caps.Seq:
		segNote(p, "%s: seqovl %d dropped, transport cannot choose TCP sequence numbers", op, want)
	case disorder && want >= firstPos:
		segNote(p, "%s: seqovl %d >= split pos %d, overlap cancelled (nfqws does the same)", op, want, firstPos)
	}
}

// ---------- multisplit ----------

// multisplitOp implements --dpi-desync=multisplit (legacy name: split2):
// re-emit the payload as len(pos)+1 segments cut at every resolved
// --dpi-desync-split-pos, in ascending order.
type multisplitOp struct{}

func init() {
	Register("multisplit", func() Op { return multisplitOp{} })
	Alias("split2", "multisplit")
	Register("multidisorder", func() Op { return multidisorderOp{} })
	Alias("disorder2", "multidisorder")
}

// Name implements Op.
func (multisplitOp) Name() string { return "multisplit" }

// Phase implements Op.
func (multisplitOp) Phase() Phase { return PhaseSplit }

// Requires implements Op. Segmentation plus suppressing the original packet is
// all a plain multisplit needs, so it is a first-class op on both transports.
// --dpi-desync-split-seqovl additionally needs Seq; because Requires cannot see
// the parameters, Apply drops the overlap (and says so) when Seq is missing.
func (multisplitOp) Requires() Caps {
	return Caps{Segment: true, DropOriginal: true}
}

// Apply implements Op.
func (o multisplitOp) Apply(c *Ctx, p *Plan) error {
	pos := segResolveMultiPos(c, segSplitSpecs(c.Params))
	if len(pos) == 0 {
		// desync.c: "all multisplit pos are outside of this packet" -> the
		// packet is forwarded untouched.
		return nil
	}
	segs, ovl, ok := segMultiSegments(c, pos, false)
	if !ok {
		segNote(p, "multisplit: seqovl segment exceeds %d bytes, split cancelled", segMaxSegLen)
		return nil
	}
	segSeqovlNote(c, p, "multisplit", pos[0], ovl, false)
	segTakeOverData(p)
	p.Segs = append(p.Segs, segs...)
	p.DropOriginal = true
	return nil
}

// Degrade implements Degrader: the same cut positions, but expressed as plain
// send() boundaries — no sub-window prefix and no injected segments.
func (o multisplitOp) Degrade(c *Ctx, p *Plan) error {
	pos := segResolveMultiPos(c, segSplitSpecs(c.Params))
	if len(pos) == 0 {
		return nil
	}
	noSeq := *c
	noSeq.Caps.Seq = false
	segs, _, ok := segMultiSegments(&noSeq, pos, false)
	if !ok {
		return nil
	}
	segTakeOverAll(p)
	p.Segs = append(p.Segs, segs...)
	p.DropOriginal = true
	return nil
}

// ---------- multidisorder ----------

// multidisorderOp implements --dpi-desync=multidisorder (legacy name:
// disorder2): the same segment set as multisplit, transmitted in reverse order
// so the DPI sees the tail of the request before its head.
type multidisorderOp struct{}

// Name implements Op.
func (multidisorderOp) Name() string { return "multidisorder" }

// Phase implements Op.
func (multidisorderOp) Phase() Phase { return PhaseSplit }

// Requires implements Op. Reversed transmission means segments arrive with
// sequence numbers out of order, which only a transport that writes its own
// TCP headers can do; a stream relay can merely emulate it (see Degrade).
func (multidisorderOp) Requires() Caps {
	return Caps{Segment: true, DropOriginal: true, Seq: true}
}

// Apply implements Op.
//
// IP-ID note: with --ip-id=seq nfqws pre-adds the segment count to the running
// ip_id and then decrements it per transmitted packet (IP4_IP_ID_ADD followed
// by IP4_IP_ID_PREV), so the ids still ascend in *sequence* order while
// descending in *transmit* order. Seg carries only the mode, so the transport
// owns that arithmetic: for a reversed plan with IPIDSeq it must count down.
func (o multidisorderOp) Apply(c *Ctx, p *Plan) error {
	pos := segResolveMultiPos(c, segSplitSpecs(c.Params))
	if len(pos) == 0 {
		return nil
	}
	segs, ovl, ok := segMultiSegments(c, pos, true)
	if !ok {
		segNote(p, "multidisorder: seqovl segment exceeds %d bytes, split cancelled", segMaxSegLen)
		return nil
	}
	segSeqovlNote(c, p, "multidisorder", pos[0], ovl, true)
	slices.Reverse(segs)
	segTakeOverData(p)
	p.Segs = append(p.Segs, segs...)
	p.DropOriginal = true
	return nil
}

// Degrade implements Degrader with the tpws --disorder trick.
//
// A byte-stream transport cannot hand the kernel out-of-order segments, so the
// segments stay in ascending order and the first one is marked TTL 1: that copy
// dies in transit, the later segments arrive first, and the client's own
// retransmission delivers the head afterwards. The observable order on the wire
// is the reversed one; the order in the plan cannot be, because the relay must
// write the stream in stream order.
func (o multidisorderOp) Degrade(c *Ctx, p *Plan) error {
	pos := segResolveMultiPos(c, segSplitSpecs(c.Params))
	if len(pos) == 0 {
		return nil
	}
	noSeq := *c
	noSeq.Caps.Seq = false
	segs, _, ok := segMultiSegments(&noSeq, pos, true)
	if !ok {
		return nil
	}
	segs[0].TTL = 1
	segTakeOverAll(p)
	p.Segs = append(p.Segs, segs...)
	p.DropOriginal = true
	segNote(p, "multidisorder: emulated with a TTL 1 first segment (tpws --disorder); "+
		"the relay must set IP_TTL on that write")
	return nil
}
