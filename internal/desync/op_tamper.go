package desync

import (
	"slices"

	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// This file implements the two payload-rewriting ops: `tamper` (zapret's
// --hostcase / --hostspell / --domcase / --methodeol family, nfqws' packet
// modification path plus tpws' extra knobs) and `tlsrec` (tpws' --tlsrec).
//
// Unlike the segmentation ops these two do not add segments: they rewrite the
// bytes of the data segments a split op already planned, or create the single
// data segment when they run alone.

func init() {
	Register("tamper", func() Op { return tamperOp{} })
	Register("tlsrec", func() Op { return tlsrecOp{} })
}

// tamperOpts is the tamper op's view of its parameters: OpParams.Tamper, with
// the one value the datapath must not trust normalised.
//
// It replaces the stopgap that used to smuggle these knobs through
// OpParams.AltOrder and OpParams.HostFakeHost; OpParams now carries a
// proto.TamperOpts of its own, so this is a plain accessor.
func tamperOpts(p OpParams) proto.TamperOpts {
	o := p.Tamper
	if o.HostPad < 0 {
		// proto.TamperHost ignores a negative pad anyway; zeroing it here is what
		// makes "a pad of -3 and nothing else" compare equal to "no knob set", so
		// the op skips it instead of re-emitting the payload unchanged.
		o.HostPad = 0
	}
	return o
}

// segDataIdx lists the indices of the plan's real-payload segments, ordered by
// the sequence offset they start at. Injected segments are skipped: a decoy is
// pattern data or a fake hostname, never the request the tamper knobs describe.
func segDataIdx(p *Plan) []int {
	idx := make([]int, 0, len(p.Segs))
	for i := range p.Segs {
		if p.Segs[i].Kind == SegData {
			idx = append(idx, i)
		}
	}
	slices.SortStableFunc(idx, func(a, b int) int {
		return int(p.Segs[a].SeqOff) - int(p.Segs[b].SeqOff)
	})
	return idx
}

// segSpan describes what one data segment contributes to the payload: prefix
// leading bytes that are not payload (the --dpi-desync-split-seqovl filler, or
// bytes an earlier segment already carried), then payload[from:to].
//
// The prefix cannot be read off a single Seg — a sequence-overlapped segment has
// SeqOff = start-overlap, which is negative only when it starts the payload —
// so it is derived by walking the segments in order.
type segSpan struct {
	idx      int
	prefix   int
	from, to int
}

// segSpans reassembles the plan's data segments the way a TCP receiver would.
//
// ok is false unless the segments cover [0,want) exactly once with no gap,
// which is what every op in this package produces; anything else means some
// other op built a plan whose bytes must not be second-guessed.
func segSpans(p *Plan, idx []int, want int) (spans []segSpan, ok bool) {
	spans = make([]segSpan, 0, len(idx))
	pos := 0
	for _, i := range idx {
		s := p.Segs[i]
		start := int(s.SeqOff)
		prefix := pos - start
		if prefix < 0 || prefix > len(s.Data) {
			return nil, false // a hole, or a segment entirely below the stream
		}
		end := start + len(s.Data)
		if end > want {
			return nil, false
		}
		spans = append(spans, segSpan{idx: i, prefix: prefix, from: pos, to: end})
		pos = end
	}
	if pos != want {
		return nil, false
	}
	return spans, true
}

// segJoinData returns the payload the plan's data segments carry.
func segJoinData(p *Plan, idx []int, want int) (payload []byte, ok bool) {
	spans, ok := segSpans(p, idx, want)
	if !ok {
		return nil, false
	}
	out := make([]byte, 0, want)
	for _, sp := range spans {
		out = append(out, p.Segs[sp.idx].Data[sp.prefix:]...)
	}
	return out, true
}

// segRewriteData writes newPayload back into the plan's data segments,
// remapping every segment boundary through mapOff (identity for a rewrite that
// keeps the length, a shift for one that inserts bytes).
//
// Data is always freshly allocated: the incoming segments alias the intercepted
// packet buffer, which must never be written to.
func segRewriteData(p *Plan, spans []segSpan, newPayload []byte, mapOff func(int) int) {
	for _, sp := range spans {
		s := &p.Segs[sp.idx]
		nf, nt := mapOff(sp.from), mapOff(sp.to)
		if nf < 0 || nt > len(newPayload) || nf > nt {
			continue
		}
		data := make([]byte, 0, sp.prefix+nt-nf)
		data = append(data, s.Data[:sp.prefix]...)
		data = append(data, newPayload[nf:nt]...)
		s.Data = data
		s.SeqOff = int32(nf - sp.prefix)
	}
}

// ---------- tamper ----------

// tamperOp implements zapret's in-place L7 mangling: --hostcase, --hostspell,
// --hostnospace, --hostdot, --hosttab, --hostpad, --domcase, --methodspace,
// --methodeol and --unixeol, via proto.TamperHost.
//
// nfqws only offers the length-preserving subset (that is why --hostnospace
// compensates by padding User-Agent and --methodeol removes the space after
// "Host:"): rewriting a packet in place must not move the TCP sequence space.
// The length-changing knobs are tpws-only, i.e. proxy-transport only, and this
// op says so through Plan.Degraded rather than quietly breaking a connection.
//
// The knobs come from OpParams.Tamper, which the strategy loader fills from the
// op's `mod` map (mod = {hostcase="1", hostspell="hoSt", ...}).
type tamperOp struct{}

// Name implements Op.
func (tamperOp) Name() string { return "tamper" }

// Phase implements Op.
func (tamperOp) Phase() Phase { return PhaseModify }

// Requires implements Op: rewriting planned payload bytes is possible on every
// transport.
func (tamperOp) Requires() Caps { return Caps{Segment: true} }

// Apply implements Op.
func (o tamperOp) Apply(c *Ctx, p *Plan) error {
	if c == nil || p == nil {
		return nil
	}
	opts := tamperOpts(c.Params)
	if opts == (proto.TamperOpts{}) {
		// No knob set: nfqws' tamper stage is a no-op then too. Re-emitting the
		// payload unchanged would only cost a DropOriginal for nothing.
		return nil
	}
	idx := segDataIdx(p)

	if len(idx) == 0 {
		// Nothing planned yet: tamper alone re-emits the whole payload.
		out := proto.TamperHost(c.Payload, c.Info, opts)
		if !o.lengthAllowed(c, p, len(c.Payload), len(out)) {
			return nil
		}
		p.Segs = append(p.Segs, segDataSeg(out, 0, c.Params))
		p.DropOriginal = true
		return nil
	}

	spans, ok := segSpans(p, idx, len(c.Payload))
	if !ok {
		segNote(p, "tamper: planned segments do not tile the payload, request left unchanged")
		return nil
	}
	src, _ := segJoinData(p, idx, len(c.Payload))
	out := proto.TamperHost(src, c.Info, opts)
	if len(out) != len(src) {
		// A length change cannot be pushed back into existing segment
		// boundaries without moving every offset behind the edit.
		segNote(p, "tamper: rewrite changes the length by %+d, which needs the whole payload in one segment; "+
			"place tamper before the split op", len(out)-len(src))
		return nil
	}
	segRewriteData(p, spans, out, func(off int) int { return off })
	return nil
}

// lengthAllowed decides whether a rewrite that changes the payload length may go
// on the wire at all, and records the refusal when it may not.
//
// Only a stream relay can change the byte count. At packet level the client's own
// TCP has already committed sequence numbers for `before` bytes: emitting
// `after` bytes instead makes the server acknowledge data the client never sent,
// the client discard that ACK (SEG.ACK > SND.NXT), and every later client segment
// land at the wrong stream offset. The connection then fails identically on every
// retransmission, so the honest answer is to leave the packet alone.
func (tamperOp) lengthAllowed(c *Ctx, p *Plan, before, after int) bool {
	if before == after || !c.Caps.Inject {
		return true
	}
	segNote(p, "tamper: rewrite changes the payload length by %+d, which would desynchronise the "+
		"client's own TCP sequence space; request left unchanged (these knobs are proxy-transport only)",
		after-before)
	return false
}

// ---------- tlsrec ----------

// tlsrecOp implements tpws' --tlsrec: re-wrap the ClientHello into two TLS
// records so that a DPI engine which only parses the first record never sees
// the SNI. It is the only split that needs no privilege at all, because the
// change is inside the application data.
//
// bol-van warns that --tlsrec breaks a significant number of sites (CDNs and
// DDoS guards reject the split hello even though TLS libraries accept it), so a
// profile using it must stay hostlist-gated.
type tlsrecOp struct{}

// Name implements Op.
func (tlsrecOp) Name() string { return "tlsrec" }

// Phase implements Op.
func (tlsrecOp) Phase() Phase { return PhaseModify }

// Requires implements Op.
func (tlsrecOp) Requires() Caps { return Caps{TLSRec: true} }

// tlsrecDefaultPos is tpws' documented --tlsrec position: one byte into the SNI
// extension's data field, so the hostname is cut across the record boundary.
func tlsrecDefaultPos() PosSpec {
	return PosSpec{Marker: proto.MarkerSNIExt, Offset: 1}
}

// Apply implements Op.
//
// The record header of the second record adds 5 bytes to the payload. That is
// fine for a stream relay, which owns the sequence space it writes, but at
// packet level it desynchronises the client's own TCP sequence numbers, so the
// op records that hazard instead of pretending it is free.
func (o tlsrecOp) Apply(c *Ctx, p *Plan) error {
	// --tlsrec takes a single position marker; the first configured entry wins.
	spec := tlsrecDefaultPos()
	if len(c.Params.SplitPos) > 0 {
		spec = c.Params.SplitPos[0]
	}
	pos := proto.FindSplitPos(c.Payload, c.Info, spec.Marker, spec.Offset)
	if pos <= 0 || pos >= len(c.Payload) {
		// tpws: "don't split if SNI is not present".
		return nil
	}

	out, err := proto.TLSRecordSplit(c.Payload, pos)
	if err != nil {
		// Not a single complete TLS record: nothing to re-wrap, forward as is.
		return nil
	}
	grow := len(out) - len(c.Payload)
	if !o.growAllowed(c, p, grow) {
		return nil
	}

	idx := segDataIdx(p)
	if len(idx) == 0 {
		p.Segs = append(p.Segs, segDataSeg(out, 0, c.Params))
		p.DropOriginal = true
		return nil
	}
	spans, ok := segSpans(p, idx, len(c.Payload))
	if !ok {
		segNote(p, "tlsrec: planned segments do not tile the original payload, record left unsplit")
		return nil
	}
	if src, _ := segJoinData(p, idx, len(c.Payload)); !slices.Equal(src, c.Payload) {
		segNote(p, "tlsrec: planned payload differs from the intercepted one, record left unsplit")
		return nil
	}
	// The extra record header is inserted exactly at pos, so every segment
	// boundary at or after pos moves by its size and the earlier ones do not.
	segRewriteData(p, spans, out, func(off int) int {
		if off < pos {
			return off
		}
		return off + grow
	})
	return nil
}

// growAllowed refuses to grow the payload on a transport that does not own the
// TCP sequence space, and records why.
//
// The second record header adds 5 bytes. A stream relay simply writes 5 more
// bytes and its kernel numbers them. At packet level the client's TCP has already
// committed sequence numbers for the original length, so those 5 bytes shift the
// server's RCV.NXT past the client's SND.NXT for the rest of the connection: the
// handshake never completes, and it fails the same way on every retransmission.
// Forwarding the ClientHello untouched is the only sound outcome.
func (tlsrecOp) growAllowed(c *Ctx, p *Plan, grow int) bool {
	if grow == 0 || !c.Caps.Inject {
		return true
	}
	segNote(p, "tlsrec: the second record header adds %d bytes, which at packet level would shift the "+
		"client's own TCP sequence space for the rest of the connection; record left unsplit "+
		"(tlsrec is a proxy-transport technique)", grow)
	return false
}
