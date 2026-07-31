package desync

import (
	"math/rand/v2"

	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// This file implements the fake-mixing segmentation family, ported from
// nfq/desync.c cases DESYNC_FAKEDSPLIT, DESYNC_FAKEDDISORDER and
// DESYNC_HOSTFAKESPLIT. The idea in all three is the same: emit a decoy segment
// that occupies the same TCP sequence range as real data but carries a low TTL
// (or another --dpi-desync-fooling), so DPI reassembles the decoy while the
// server only ever receives the real bytes.

func init() {
	Register("fakedsplit", func() Op { return fakedsplitOp{} })
	Alias("split", "fakedsplit")
	Register("fakeddisorder", func() Op { return fakeddisorderOp{} })
	Alias("disorder", "fakeddisorder")
	Register("hostfakesplit", func() Op { return hostfakesplitOp{} })
}

// segResolveSinglePos ports the "special algorithm" desync.c uses to pick the
// one split position of fakedsplit/fakeddisorder out of the --dpi-desync-split-pos
// list: relative markers first, absolute ones second, and position 1 when
// nothing resolves.
//
// The result is 0 only when the payload is too short for any cut to exist
// (upstream's pos_normalize() rejecting 1); that selects the "no split pos"
// variant of the op, which fakes the whole message instead of a part of it.
func segResolveSinglePos(c *Ctx, specs []PosSpec) int {
	pos := 0
	for _, s := range specs {
		if s.Marker == proto.MarkerAbs {
			continue
		}
		if pos = proto.FindSplitPos(c.Payload, c.Info, s.Marker, s.Offset); pos != 0 {
			break
		}
	}
	if pos == 0 {
		for _, s := range specs {
			if s.Marker != proto.MarkerAbs {
				continue
			}
			if pos = proto.FindSplitPos(c.Payload, c.Info, s.Marker, s.Offset); pos != 0 {
				break
			}
		}
	}
	if pos == 0 {
		pos = 1 // desync.c: "if (!split_pos) split_pos = 1"
	}
	// pos_normalize(): a cut must be strictly inside the payload.
	if pos >= len(c.Payload) {
		return 0
	}
	return pos
}

// segFakePattern builds the fake payload of fakedsplit/fakeddisorder: the
// --dpi-desync-fakedsplit-pattern repeated over the whole message length, so
// that a fake covering [from,to) is pattern[from:to] and therefore stays
// consistent across the parts of one message. Default pattern: a zero byte.
//
// ok is false for a message larger than nfqws' pattern buffer, where upstream
// logs "packet is too large" and forwards the original.
func segFakePattern(c *Ctx) (pat []byte, ok bool) {
	if len(c.Payload) > segMaxFakeLen {
		return nil, false
	}
	// Upstream also offsets into the pattern by the packet's position inside a
	// multi-packet message; we never reassemble, so the offset is always 0.
	return segFillPattern(len(c.Payload), c.Params.Pattern, 0), true
}

// segSplitOrder returns the altorder sub-field desync.c uses: bits 0..1 when a
// split position exists, bits 3..4 for the "no split pos" variant.
func segSplitOrder(altOrder int, split bool) int {
	if split {
		return altOrder & 3
	}
	return (altOrder >> 3) & 3
}

// ---------- fakedsplit ----------

// fakedsplitOp implements --dpi-desync=fakedsplit (legacy name: split): one
// split position, with a fake copy of each part mixed in around the real parts.
type fakedsplitOp struct{}

// Name implements Op.
func (fakedsplitOp) Name() string { return "fakedsplit" }

// Phase implements Op.
func (fakedsplitOp) Phase() Phase { return PhaseSplit }

// Requires implements Op: injected decoys (Inject), decoys sharing the sequence
// range of real data (Seq) and suppression of the application's own packet.
func (fakedsplitOp) Requires() Caps {
	return Caps{Inject: true, Seq: true, DropOriginal: true}
}

// Apply implements Op.
//
// Emission order, ported verbatim from desync.c (F1 = fake of part 1, R1 = real
// part 1, and so on; the fake of part 2 before R2 is unconditional upstream):
//
//	altorder=0  F1 R1 F1 F2 R2 F2
//	altorder=1  R1 F1 F2 R2 F2
//	altorder=2  R1 F2 R2 F2
//	altorder=3  R1 F2 R2
//
// Without a usable split position (a one-byte message, or a multi-packet
// message whose cut falls outside this packet) the whole payload is faked and
// bits 3..4 of altorder select: 0 -> F R F, 8 -> R F, 16 -> R.
func (o fakedsplitOp) Apply(c *Ctx, p *Plan) error {
	pat, ok := segFakePattern(c)
	if !ok {
		segNote(p, "fakedsplit: payload of %d bytes exceeds the %d byte fake limit", len(c.Payload), segMaxFakeLen)
		return nil
	}
	prm := c.Params
	n := len(c.Payload)
	segTakeOverData(p)  // this op owns the payload's segmentation from here on
	base := len(p.Segs) // rollback point: a cancelled desync must add nothing

	splitPos := segResolveSinglePos(c, segSplitSpecs(prm))
	order := segSplitOrder(prm.AltOrder, splitPos != 0)
	if splitPos == 0 {
		// desync.c sets split_pos = len_payload here: one real segment, faked
		// in full, and no second part.
		splitPos = n
	}

	// seqovl only makes sense while there is a second part to overlap into.
	ovl := prm.Seqovl
	if ovl < 0 || splitPos >= n || !c.Caps.Seq {
		if ovl > 0 && !c.Caps.Seq {
			segNote(p, "fakedsplit: seqovl %d dropped, transport cannot choose TCP sequence numbers", ovl)
		}
		ovl = 0
	}

	fake1 := segFakeSeg(pat[:splitPos], 0, prm)
	if order == 0 {
		p.Segs = append(p.Segs, fake1)
	}

	real1 := c.Payload[:splitPos]
	seq1 := 0
	if ovl > 0 {
		if ovl+splitPos > segMaxSegLen {
			p.Segs = p.Segs[:base]
			// Upstream reaches send_orig here, so the unsegmented payload must go
			// back into the plan: engine.run already committed DropOriginal for
			// whatever an earlier PhaseFake op injected.
			injEnsureDataSeg(c, p)
			segNote(p, "fakedsplit: seqovl segment exceeds %d bytes, split cancelled", segMaxSegLen)
			return nil
		}
		data := make([]byte, 0, ovl+splitPos)
		data = append(data, segFillPattern(ovl, prm.SeqovlPattern, 0)...)
		data = append(data, real1...)
		real1, seq1 = data, -ovl
	}
	p.Segs = append(p.Segs, segDataSeg(real1, seq1, prm))

	if order <= 1 {
		p.Segs = append(p.Segs, fake1)
	}

	if splitPos < n {
		fake2 := segFakeSeg(pat[splitPos:], splitPos, prm)
		p.Segs = append(p.Segs, fake2)
		p.Segs = append(p.Segs, segDataSeg(c.Payload[splitPos:], splitPos, prm))
		if order <= 2 {
			p.Segs = append(p.Segs, fake2)
		}
	}
	p.DropOriginal = true
	return nil
}

// Degrade implements Degrader: a plain split at the same position, without any
// decoy — all a byte-stream transport can express.
func (o fakedsplitOp) Degrade(c *Ctx, p *Plan) error {
	return segDegradeSplit(c, p, segResolveSinglePos(c, segSplitSpecs(c.Params)))
}

// segDegradeSplit is the shared socket-level fallback of the faked-split
// family: cut the payload at pos and emit the two real parts in order.
func segDegradeSplit(c *Ctx, p *Plan, pos int) error {
	if pos <= 0 || pos >= len(c.Payload) {
		return nil
	}
	segTakeOverAll(p)
	p.Segs = append(p.Segs,
		segDataSeg(c.Payload[:pos], 0, c.Params),
		segDataSeg(c.Payload[pos:], pos, c.Params),
	)
	p.DropOriginal = true
	return nil
}

// ---------- fakeddisorder ----------

// fakeddisorderOp implements --dpi-desync=fakeddisorder (legacy name:
// disorder): fakedsplit with the second part transmitted first.
type fakeddisorderOp struct{}

// Name implements Op.
func (fakeddisorderOp) Name() string { return "fakeddisorder" }

// Phase implements Op.
func (fakeddisorderOp) Phase() Phase { return PhaseSplit }

// Requires implements Op.
func (fakeddisorderOp) Requires() Caps {
	return Caps{Inject: true, Seq: true, DropOriginal: true}
}

// Apply implements Op.
//
// Emission order, ported verbatim from desync.c (the fake of part 1 ahead of R1
// is unconditional upstream):
//
//	altorder=0  F2 R2 F2 F1 R1 F1
//	altorder=1  R2 F2 F1 R1 F1
//	altorder=2  R2 F1 R1 F1
//	altorder=3  R2 F1 R1
//
// Here the overlap goes on the *second* part (the first one transmitted):
// the receiving OS holds it until the head arrives, and the head then
// overwrites the overlap junk. That only works while the overlap stays below
// the split position, which is why upstream cancels it otherwise.
func (o fakeddisorderOp) Apply(c *Ctx, p *Plan) error {
	pat, ok := segFakePattern(c)
	if !ok {
		segNote(p, "fakeddisorder: payload of %d bytes exceeds the %d byte fake limit", len(c.Payload), segMaxFakeLen)
		return nil
	}
	prm := c.Params
	segTakeOverData(p)  // this op owns the payload's segmentation from here on
	base := len(p.Segs) // rollback point: a cancelled desync must add nothing

	splitPos := segResolveSinglePos(c, segSplitSpecs(prm))
	order := segSplitOrder(prm.AltOrder, splitPos != 0)

	ovl := prm.Seqovl
	switch {
	case ovl <= 0:
		ovl = 0
	case !c.Caps.Seq:
		segNote(p, "fakeddisorder: seqovl %d dropped, transport cannot choose TCP sequence numbers", ovl)
		ovl = 0
	case splitPos == 0:
		ovl = 0
	case ovl >= splitPos:
		segNote(p, "fakeddisorder: seqovl %d >= split pos %d, overlap cancelled (nfqws does the same)", ovl, splitPos)
		ovl = 0
	}

	fake2 := segFakeSeg(pat[splitPos:], splitPos, prm)
	if order == 0 {
		p.Segs = append(p.Segs, fake2)
	}

	real2 := c.Payload[splitPos:]
	seq2 := splitPos
	if ovl > 0 {
		if ovl+len(real2) > segMaxSegLen {
			p.Segs = p.Segs[:base]
			// See the matching note in fakedsplit: upstream forwards the original,
			// so the payload has to be re-planned unsegmented.
			injEnsureDataSeg(c, p)
			segNote(p, "fakeddisorder: seqovl segment exceeds %d bytes, split cancelled", segMaxSegLen)
			return nil
		}
		data := make([]byte, 0, ovl+len(real2))
		data = append(data, segFillPattern(ovl, prm.SeqovlPattern, 0)...)
		data = append(data, real2...)
		real2, seq2 = data, splitPos-ovl
	}
	p.Segs = append(p.Segs, segDataSeg(real2, seq2, prm))

	if order <= 1 {
		p.Segs = append(p.Segs, fake2)
	}

	if splitPos > 0 {
		fake1 := segFakeSeg(pat[:splitPos], 0, prm)
		p.Segs = append(p.Segs, fake1)
		p.Segs = append(p.Segs, segDataSeg(c.Payload[:splitPos], 0, prm))
		if order <= 2 {
			p.Segs = append(p.Segs, fake1)
		}
	}
	p.DropOriginal = true
	return nil
}

// Degrade implements Degrader: plain split at the same position, no decoy and
// no reordering (a stream relay writes in stream order).
func (o fakeddisorderOp) Degrade(c *Ctx, p *Plan) error {
	return segDegradeSplit(c, p, segResolveSinglePos(c, segSplitSpecs(c.Params)))
}

// ---------- hostfakesplit ----------

// hostfakesplitOp implements --dpi-desync=hostfakesplit: split around the
// hostname and inject a fake segment that covers exactly the hostname bytes,
// filled with a plausible-looking wrong host. Because the decoy is a hostname
// and not a pattern, DPI cannot tell the real and the fake copy apart by shape.
type hostfakesplitOp struct{}

// segFakeHostTLD is nfq_params.c's tld[6]: the TLDs a generated fake host may
// end with.
var segFakeHostTLD = [...]string{"com", "org", "net", "edu", "gov", "biz"}

const (
	segFakeHostAlpha = "abcdefghijklmnopqrstuvwxyz"
	segFakeHostAlnum = "0123456789abcdefghijklmnopqrstuvwxyz"
)

// segFakeHost generates the fake hostname of hostfakesplit, size bytes long so
// the decoy occupies exactly the real hostname's sequence range. Ported from
// desync.c's DESYNC_HOSTFAKESPLIT block.
//
// Without a template the name is random [0-9a-z] starting with a letter, and
// from 7 bytes up the last four are replaced by "." plus a known 3-char TLD.
// With a template the name is the template grown to the left with random
// characters ("google.com" -> "nb4auv9.google.com"), reduced to a dot prefix
// when only one byte is missing (".google.com"), or cut from the left when the
// real hostname is shorter ("google.com" -> "gle.com").
func segFakeHost(size int, template string) []byte {
	if size <= 0 {
		return nil
	}
	out := make([]byte, size)
	if template != "" {
		t := []byte(template)
		if size <= len(t) {
			copy(out, t[len(t)-size:])
			return out
		}
		sz := size - len(t)
		copy(out[sz:], t)
		sz-- // the byte just left of the template becomes the separating dot
		out[sz] = '.'
		if sz > 0 {
			out[0] = segFakeHostAlpha[rand.IntN(len(segFakeHostAlpha))]
			segFillRandom(out[1:sz], segFakeHostAlnum)
		}
		return out
	}
	out[0] = segFakeHostAlpha[rand.IntN(len(segFakeHostAlpha))]
	segFillRandom(out[1:], segFakeHostAlnum)
	if size >= 7 {
		out[size-4] = '.'
		copy(out[size-3:], segFakeHostTLD[rand.IntN(len(segFakeHostTLD))])
	}
	return out
}

// segFillRandom fills dst with characters drawn uniformly from set.
func segFillRandom(dst []byte, set string) {
	for i := range dst {
		dst[i] = set[rand.IntN(len(set))]
	}
}

// segResolveMidHost resolves --dpi-desync-hostfakesplit-midhost for a payload
// whose hostname spans [posHost,posEndHost).
//
// The option is a full position spec upstream, not a flag: any marker plus
// offset may be given (the usual spelling is "midsld", i.e. the middle of the
// second-level domain), and OpParams.MidHostSet says whether it was configured
// at all — a zero PosSpec is "absolute offset 0", which is a real value the
// loader can produce, so presence cannot be inferred from the value.
//
// A cut is returned only when it lands strictly inside the hostname: outside it,
// the "real host in two parts" shape upstream builds would either duplicate a
// boundary the op already has or move bytes out of the decoy's sequence range.
// 0 means "no extra cut".
func segResolveMidHost(c *Ctx, p *Plan, posHost, posEndHost int) int {
	if !c.Params.MidHostSet {
		return 0
	}
	spec := c.Params.MidHost
	m := proto.FindSplitPos(c.Payload, c.Info, spec.Marker, spec.Offset)
	if m > posHost && m < posEndHost {
		return m
	}
	segNote(p, "hostfakesplit: midhost position %d is not inside the hostname [%d,%d), extra cut skipped",
		m, posHost, posEndHost)
	return 0
}

// Name implements Op.
func (hostfakesplitOp) Name() string { return "hostfakesplit" }

// Phase implements Op.
func (hostfakesplitOp) Phase() Phase { return PhaseSplit }

// Requires implements Op.
func (hostfakesplitOp) Requires() Caps {
	return Caps{Inject: true, Seq: true, DropOriginal: true}
}

// Apply implements Op.
//
// Emission order, ported from desync.c (H = fake host, RH = the real host, in
// one or two parts when midhost is set):
//
//	altorder=0  before-host, H, RH..., H, after-host
//	altorder=1  before-host, H, after-host, RH...
//
// The op is skipped when the payload has no hostname (upstream:
// "host and endhost positions not found"), which keeps it safe on non-TLS,
// non-HTTP traffic.
func (o hostfakesplitOp) Apply(c *Ctx, p *Plan) error {
	prm := c.Params
	n := len(c.Payload)

	// Upstream resolves a fixed two-entry {host, endhost} list through
	// ResolveMultiPos, so the same "drop, sort, dedupe, must be inside the
	// payload" rules apply.
	pos := segResolveMultiPos(c, []PosSpec{
		{Marker: proto.MarkerHost},
		{Marker: proto.MarkerEndHost},
	})
	if len(pos) != 2 {
		segNote(p, "hostfakesplit: no usable hostname in this payload")
		return nil
	}
	posHost, posEndHost := pos[0], pos[1]

	// --dpi-desync-hostfakesplit-midhost: an extra cut inside the real host,
	// only honoured while it stays strictly within the hostname.
	midHost := segResolveMidHost(c, p, posHost, posEndHost)

	fakeHost := segFakeHost(posEndHost-posHost, prm.HostFakeHost)
	fakeSeg := segFakeSeg(fakeHost, posHost, prm)
	before := segDataSeg(c.Payload[:posHost], 0, prm)
	after := segDataSeg(c.Payload[posEndHost:n], posEndHost, prm)

	realHost := make([]Seg, 0, 2)
	if midHost != 0 {
		realHost = append(realHost,
			segDataSeg(c.Payload[posHost:midHost], posHost, prm),
			segDataSeg(c.Payload[midHost:posEndHost], midHost, prm),
		)
	} else {
		realHost = append(realHost, segDataSeg(c.Payload[posHost:posEndHost], posHost, prm))
	}

	segTakeOverData(p) // this op owns the payload's segmentation from here on
	p.Segs = append(p.Segs, before, fakeSeg)
	if prm.AltOrder == 1 {
		// altorder=1: the whole request with the faked host goes out first,
		// then the real host lands on top of the decoy's sequence range.
		p.Segs = append(p.Segs, after)
		p.Segs = append(p.Segs, realHost...)
	} else {
		p.Segs = append(p.Segs, realHost...)
		p.Segs = append(p.Segs, fakeSeg, after)
	}
	p.DropOriginal = true
	return nil
}

// Degrade implements Degrader: split at the hostname boundaries without any
// decoy, which is still a useful cut for a byte-stream transport.
func (o hostfakesplitOp) Degrade(c *Ctx, p *Plan) error {
	pos := segResolveMultiPos(c, []PosSpec{
		{Marker: proto.MarkerHost},
		{Marker: proto.MarkerEndHost},
	})
	if len(pos) != 2 {
		return nil
	}
	if m := segResolveMidHost(c, p, pos[0], pos[1]); m != 0 {
		pos = []int{pos[0], m, pos[1]}
	}
	segTakeOverAll(p)
	from := 0
	for _, to := range append(pos, len(c.Payload)) {
		p.Segs = append(p.Segs, segDataSeg(c.Payload[from:to], from, c.Params))
		from = to
	}
	p.DropOriginal = true
	return nil
}
