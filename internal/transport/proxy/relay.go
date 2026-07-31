package proxy

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
)

// This file turns a desync.Plan into writes on an ordinary TCP socket. It is the
// whole of the proxy transport's datapath: everything below the byte stream —
// sequence numbers, TTL per packet, injected decoys, IP identification — belongs
// to the divert transport and is filtered out by the engine's Caps gating before
// a plan ever reaches here (desync.ProxyCaps sets only Segment, TLSRec and
// DropOriginal).
//
// What survives that gating is exactly what tpws can do:
//
//   - one Write() per segment with TCP_NODELAY on, so every segment becomes its
//     own TCP segment (tpws --split-pos);
//   - a first segment sent with IP_TTL 1 so it dies in transit and the kernel's
//     retransmission arrives after the later segments, which makes the server
//     reassemble out of order (tpws --disorder);
//   - payload rewrites: TLS record splitting (tpws --tlsrec) and the
//     Host-header manglings, which reach us as ordinary segment bytes;
//   - closing the connection without forwarding anything (the `block` op).

// ErrPlanNotContiguous means the plan's data segments do not describe one
// gap-free byte stream. A byte stream cannot express a hole, so the relay
// forwards the original payload instead of guessing.
var ErrPlanNotContiguous = errors.New("proxy: plan segments do not form a contiguous stream")

// SegWriter is the upstream side of a relayed connection, as ApplyPlan needs it.
//
// Implementations must map one Write call to one TCP segment: TCP_NODELAY has to
// be set and the implementation must not coalesce or buffer. ConnWriter does
// both; the tests use a recorder with the same contract.
type SegWriter interface {
	// Write sends p as a single segment.
	Write(p []byte) (int, error)
	// SetTTL sets the outgoing IPv4 TTL (or IPv6 hop limit) for subsequent
	// writes. ttl == 0 restores the value the socket had when the relay took
	// it over.
	SetTTL(ttl int) error
}

// Drainer is implemented by a SegWriter that can wait until the kernel has
// handed everything already written to the network. ApplyPlan uses it to keep a
// TTL change from overtaking the write it belongs to; see the Darwin caveat on
// ApplyPlan.
type Drainer interface {
	Drain() error
}

// disorderTTL is the hop limit that makes a segment die before it reaches the
// server. tpws uses 1 for --disorder; the first router on the path decrements it
// to 0 and drops it.
const disorderTTL = 1

// Piece is one write ApplyPlan will perform, already trimmed of anything a
// socket cannot express.
type Piece struct {
	// Data is what to write, as one segment.
	Data []byte
	// SeqOff is where Data starts in the stream the relay writes, counted from
	// the first byte of the request. It is always >= 0: a socket cannot lower a
	// sequence number, so any sub-window prefix has been dropped by then.
	SeqOff int
	// LowTTL asks for the die-in-transit TTL (the tpws --disorder trick).
	LowTTL bool
}

// PlanInfo records everything that had to be given up while converting a plan
// into socket writes. It is the honest counterpart of Plan.Degraded: the engine
// records what it could not *plan*, this records what the relay could not *do*.
type PlanInfo struct {
	// OverlapDropped is the number of bytes removed from the front of segments
	// because they sat below the stream position already written — a
	// --dpi-desync-split-seqovl prefix, or a segment repeating bytes an earlier
	// one carried.
	OverlapDropped int
	// Reordered is true when the plan listed segments in a transmit order that
	// is not ascending stream order (a packet-level multidisorder). A byte
	// stream must be written in stream order, so the relay sorted them.
	Reordered bool
	// LowTTL is the number of segments that ask for the disorder trick.
	LowTTL int
	// Notes describes each of the above in words, for the log.
	Notes []string
}

// note appends a formatted note.
func (i *PlanInfo) note(format string, args ...any) {
	i.Notes = append(i.Notes, fmt.Sprintf(format, args...))
}

// Result is the outcome of applying a plan to a connection.
type Result struct {
	PlanInfo
	// Writes is how many Write calls were made, i.e. how many TCP segments the
	// request was cut into.
	Writes int
	// Bytes is how many bytes were handed to Write in total.
	Bytes int
	// Blocked reports that the plan asked for the payload to be dropped with
	// nothing put in its place (the `block` op): the caller must close the
	// connection without forwarding anything.
	Blocked bool
	// Verbatim reports that the original payload was forwarded unchanged,
	// either because there was no plan or because the plan was unusable.
	Verbatim bool
	// Rewritten is the signed change in payload length the plan performed
	// (tlsrec adds a 5-byte record header, the tamper knobs can add or remove
	// bytes). Zero means the bytes written reassemble to exactly the payload.
	Rewritten int
}

// segKindName spells a SegKind for a log message.
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
		return fmt.Sprintf("kind%d", int(k))
	}
}

// Segments converts a plan's segments into the ordered writes a socket must
// perform.
//
// Only SegData is actionable. Anything else needs packet injection, which
// desync.ProxyCaps does not claim, so the engine must have filtered it out
// already; the check here is defensive, and a leaked decoy is skipped rather
// than sent — putting a fake payload into the byte stream would corrupt the
// request.
//
// Segments are sorted by SeqOff (stably, so equal offsets keep plan order) and
// then trimmed: a segment starting below the position already covered has that
// prefix removed. That is what makes --dpi-desync-split-seqovl survive at all —
// its whole point is a segment sent *below* the current sequence number, which a
// socket cannot express, so the overlap bytes are dropped and counted.
//
// err is ErrPlanNotContiguous when what is left does not tile one gap-free
// stream; the caller then forwards the original payload.
func Segments(plan *desync.Plan) (pieces []Piece, info PlanInfo, err error) {
	if plan == nil {
		return nil, info, nil
	}

	// Collect the data segments, remembering their position in the plan so the
	// out-of-order check below can compare transmit order with stream order.
	type indexed struct {
		seg desync.Seg
		at  int
	}
	data := make([]indexed, 0, len(plan.Segs))
	skipped := make(map[string]int)
	for i, s := range plan.Segs {
		if s.Kind != desync.SegData {
			skipped[segKindName(s.Kind)]++
			continue
		}
		if len(s.Data) == 0 {
			continue
		}
		data = append(data, indexed{seg: s, at: i})
	}
	for kind, n := range skipped {
		info.note("dropped %d %s segment(s): a byte stream cannot inject packets "+
			"(the engine should have gated this op out under ProxyCaps)", n, kind)
	}
	if len(data) == 0 {
		return nil, info, nil
	}

	sorted := make([]indexed, len(data))
	copy(sorted, data)
	sort.SliceStable(sorted, func(a, b int) bool { return sorted[a].seg.SeqOff < sorted[b].seg.SeqOff })
	for i := range sorted {
		if sorted[i].at != data[i].at {
			info.Reordered = true
			break
		}
	}
	if info.Reordered {
		info.note("plan asked for out-of-order transmission; a byte stream is written in " +
			"stream order, so only the TTL-1 trick can emulate a disorder")
	}

	pieces = make([]Piece, 0, len(sorted))
	pos := 0 // next stream offset not yet covered
	for _, ix := range sorted {
		s := ix.seg
		// The segment covers the stream range [segStart, segEnd). segStart is
		// negative for --dpi-desync-split-seqovl: the segment deliberately
		// starts below the window so the server's TCP discards the prefix while
		// a naive DPI reassembler swallows it. A socket owns no sequence
		// numbers, so everything below pos (and everything below 0) has to go —
		// sending it would insert junk into the request.
		segStart := int(s.SeqOff)
		segEnd := segStart + len(s.Data)
		switch {
		case segEnd <= pos:
			if segEnd <= 0 {
				// Pure sub-window filler with no payload of its own.
				info.OverlapDropped += len(s.Data)
				continue
			}
			return nil, info, fmt.Errorf("%w: segment [%d,%d) repeats bytes the stream already "+
				"carries (%d written)", ErrPlanNotContiguous, segStart, segEnd, pos)
		case segStart > pos:
			return nil, info, fmt.Errorf("%w: gap of %d byte(s) before the segment at %d",
				ErrPlanNotContiguous, segStart-pos, segStart)
		}
		drop := pos - segStart // >= 0 here, since segStart <= pos
		if drop > 0 {
			info.OverlapDropped += drop
		}
		start := pos
		body := s.Data[drop:]
		low := s.TTL == disorderTTL
		if low {
			info.LowTTL++
		}
		pieces = append(pieces, Piece{Data: body, SeqOff: start, LowTTL: low})
		pos = start + len(body)

		// Things the plan may still carry that a socket cannot honour. They are
		// reported once per segment rather than silently ignored.
		if s.Repeats > 1 {
			info.note("segment at %d asks for %d transmissions; a byte stream would duplicate "+
				"request bytes, so it is written once", start, s.Repeats)
		}
		if s.TTL != 0 && !low {
			info.note("segment at %d asks for TTL %d; only TTL 1 (the disorder trick) is "+
				"meaningful on a socket", start, s.TTL)
		}
		if s.Fool != desync.FoolNone {
			info.note("segment at %d asks for fooling %#x; the kernel owns the TCP/IP header here",
				start, uint16(s.Fool))
		}
		if s.Frag > 0 {
			info.note("segment at %d asks for IP fragmentation at %d; the kernel owns the IP header here",
				start, s.Frag)
		}
		if s.Window != 0 {
			info.note("segment at %d asks for TCP window %d; a socket cannot set a per-write window",
				start, s.Window)
		}
		if s.IPID != desync.IPIDDefault {
			info.note("segment at %d asks for a chosen ip-id; the kernel owns the IP header here", start)
		}
	}
	if info.OverlapDropped > 0 {
		info.note("dropped %d byte(s) of sub-window overlap: a socket cannot lower a sequence number",
			info.OverlapDropped)
	}
	return pieces, info, nil
}

// Reconstruct returns the byte stream a piece list writes. It exists so callers
// (and the tests) can verify that segmentation is a pure re-cutting of the
// request and not an accidental rewrite.
func Reconstruct(pieces []Piece) []byte {
	n := 0
	for _, p := range pieces {
		n += len(p.Data)
	}
	out := make([]byte, 0, n)
	for _, p := range pieces {
		out = append(out, p.Data...)
	}
	return out
}

// ApplyPlan writes the request to the upstream connection according to plan.
//
// payload is the request as the client sent it, and is what gets forwarded
// verbatim whenever the plan is absent, empty or unusable — the relay never
// fails a connection because a desync could not be applied.
//
// # THE DISORDER TRICK AND ITS DARWIN CAVEAT
//
// A segment marked TTL 1 is written with setsockopt(IPPROTO_IP, IP_TTL, 1) —
// IPV6_UNICAST_HOPS for IPv6 — in force, and the real TTL is restored
// afterwards. Apple's Developer Technical Support has stated that setsockopt is
// synchronous while send is not: the option takes effect on the socket
// immediately, but bytes already queued may be transmitted later, so with
// several writes in flight a TTL change can be picked up by the wrong segment.
// Two mitigations are applied here, and neither is a guarantee:
//
//   - the low-TTL segment is written alone, with no other write outstanding;
//   - before the TTL is restored, Drain() waits for the socket's send queue to
//     empty (Darwin's SO_NWRITE), bounded by a short timeout.
//
// If the restore does slip past a later segment, that segment also dies in
// transit and the client's retransmission repairs it: the connection survives,
// the desync degrades. That is why the trick is acceptable at all.
func ApplyPlan(w SegWriter, plan *desync.Plan, payload []byte) (Result, error) {
	var res Result

	forward := func(reason string) (Result, error) {
		if reason != "" {
			res.note("%s", reason)
		}
		res.Verbatim = true
		if len(payload) == 0 {
			return res, nil
		}
		n, err := w.Write(payload)
		res.Writes++
		res.Bytes += n
		if err != nil {
			return res, fmt.Errorf("proxy: forwarding the request unchanged: %w", err)
		}
		return res, nil
	}

	if plan == nil {
		return forward("")
	}
	if len(plan.Segs) == 0 {
		if plan.DropOriginal {
			// The `block` op: drop the payload with nothing in its place.
			res.Blocked = true
			res.note("plan blocks the connection: closing without forwarding %d byte(s)", len(payload))
			return res, nil
		}
		return forward("")
	}

	pieces, info, err := Segments(plan)
	res.PlanInfo = info
	if err != nil {
		return forward(fmt.Sprintf("plan unusable (%v); request forwarded unchanged", err))
	}
	if len(pieces) == 0 {
		return forward("plan left no data segments; request forwarded unchanged")
	}
	if !plan.DropOriginal {
		res.note("plan carries segments but does not set DropOriginal; the segments are " +
			"authoritative, the original payload is not sent as well")
	}

	// Verify the reassembly. Equality with the payload is the common case
	// (pure segmentation); a difference is legitimate for tlsrec and the
	// tamper knobs, which rewrite the request on purpose. Either way the
	// plan's bytes are what goes on the wire — this only records what happened.
	stream := Reconstruct(pieces)
	if len(stream) != len(payload) {
		res.Rewritten = len(stream) - len(payload)
		res.note("plan rewrites the request: %d byte(s) in, %d out (%+d)",
			len(payload), len(stream), res.Rewritten)
	} else if !equalBytes(stream, payload) {
		res.note("plan rewrites %d byte(s) of the request in place", len(payload))
	}

	for i, p := range pieces {
		if p.LowTTL {
			if err := w.SetTTL(disorderTTL); err != nil {
				// Without the low TTL the segment would arrive normally and the
				// disorder would not happen; that is a degradation, not a
				// failure, so the write proceeds.
				res.note("segment %d: cannot set TTL %d (%v); written with the real TTL",
					i, disorderTTL, err)
				p.LowTTL = false
			}
		}
		n, werr := w.Write(p.Data)
		res.Writes++
		res.Bytes += n
		if p.LowTTL {
			// Restore only after the bytes have left the socket; see the caveat
			// in the doc comment.
			if d, ok := w.(Drainer); ok {
				if derr := d.Drain(); derr != nil {
					res.note("segment %d: waiting for the send queue to drain: %v", i, derr)
				}
			}
			if rerr := w.SetTTL(0); rerr != nil {
				return res, fmt.Errorf("proxy: restoring the real TTL after a low-TTL segment: %w", rerr)
			}
		}
		if werr != nil {
			return res, fmt.Errorf("proxy: writing segment %d of %d (%d bytes at offset %d): %w",
				i, len(pieces), len(p.Data), p.SeqOff, werr)
		}
	}
	return res, nil
}

// equalBytes compares two byte slices.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// ConnWriter — SegWriter over a real TCP connection
// ---------------------------------------------------------------------------

// drainTimeout bounds the SO_NWRITE wait after a low-TTL segment. It is short on
// purpose: the wait exists to stop a TTL restore from overtaking one small
// segment, and a slow or stalled peer must not hold up the request.
const drainTimeout = 50 * time.Millisecond

// drainPoll is how often the send queue is re-checked while draining.
const drainPoll = 500 * time.Microsecond

// ConnWriter is the SegWriter of a real upstream TCP connection.
//
// It sets TCP_NODELAY (so one Write is one segment, which is the entire point of
// the segmentation ops) and remembers the socket's real TTL at construction, so
// SetTTL(0) can put it back exactly instead of guessing 64.
type ConnWriter struct {
	c  *net.TCPConn
	rc syscall.RawConn
	// v6 selects between IP_TTL and IPV6_UNICAST_HOPS.
	v6 bool
	// realTTL is the value the socket had before the relay touched it.
	realTTL int
	// curTTL is the value currently in force, so a redundant setsockopt is
	// skipped.
	curTTL int
	// noDrain is set when SO_NWRITE turned out to be unavailable, so Drain
	// stops asking.
	noDrain bool
}

// NewConnWriter prepares c for segment-wise writing.
//
// The address family is taken from the connection's local address: the proxy
// always dials with an explicit "tcp4"/"tcp6" network, so the socket family is
// unambiguous and the right TTL option is known up front.
func NewConnWriter(c *net.TCPConn) (*ConnWriter, error) {
	if c == nil {
		return nil, errors.New("proxy: NewConnWriter needs a connection")
	}
	if err := c.SetNoDelay(true); err != nil {
		return nil, fmt.Errorf("proxy: TCP_NODELAY on the upstream socket: %w", err)
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("proxy: raw access to the upstream socket: %w", err)
	}
	w := &ConnWriter{c: c, rc: raw, v6: isV6Conn(c)}

	// Read the TTL the kernel picked so SetTTL(0) can restore it byte-exactly.
	// A failure here is not fatal: the relay simply falls back to the platform
	// default, which is what the socket had anyway.
	ttl, err := w.getTTL()
	if err != nil {
		w.realTTL = 0
	} else {
		w.realTTL = ttl
	}
	w.curTTL = w.realTTL
	return w, nil
}

// isV6Conn reports whether c's local address is a real IPv6 address. A 4-in-6
// mapped local address means the socket carries IPv4 traffic and wants IP_TTL.
func isV6Conn(c *net.TCPConn) bool {
	la, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok || la.IP == nil {
		return false
	}
	return la.IP.To4() == nil
}

// Write sends p as one segment.
func (w *ConnWriter) Write(p []byte) (int, error) { return w.c.Write(p) }

// Conn exposes the underlying connection, so the caller can splice it after the
// plan has been applied.
func (w *ConnWriter) Conn() *net.TCPConn { return w.c }

// ttlOption returns the (level, option) pair for this socket's family.
func (w *ConnWriter) ttlOption() (level, opt int, name string) {
	if w.v6 {
		return unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, "IPV6_UNICAST_HOPS"
	}
	return unix.IPPROTO_IP, unix.IP_TTL, "IP_TTL"
}

// getTTL reads the socket's current TTL / hop limit.
func (w *ConnWriter) getTTL() (int, error) {
	level, opt, name := w.ttlOption()
	var (
		val   int
		inner error
	)
	if err := w.rc.Control(func(fd uintptr) {
		val, inner = unix.GetsockoptInt(int(fd), level, opt)
	}); err != nil {
		return 0, fmt.Errorf("proxy: reaching the upstream socket: %w", err)
	}
	if inner != nil {
		return 0, fmt.Errorf("proxy: getsockopt(%s): %s", name, errnoName(inner))
	}
	return val, nil
}

// SetTTL implements SegWriter. ttl == 0 restores the socket's original TTL.
func (w *ConnWriter) SetTTL(ttl int) error {
	want := ttl
	if want == 0 {
		want = w.realTTL
	}
	if want == 0 {
		// The original value could not be read, so there is nothing to restore
		// to. Leave the socket alone rather than imposing a guessed TTL.
		return nil
	}
	if want == w.curTTL {
		return nil
	}
	level, opt, name := w.ttlOption()
	var inner error
	if err := w.rc.Control(func(fd uintptr) {
		inner = unix.SetsockoptInt(int(fd), level, opt, want)
	}); err != nil {
		return fmt.Errorf("proxy: reaching the upstream socket: %w", err)
	}
	if inner != nil {
		return fmt.Errorf("proxy: setsockopt(%s, %d): %s", name, want, errnoName(inner))
	}
	w.curTTL = want
	return nil
}

// Drain waits, briefly, until the socket's send queue is empty.
//
// Darwin exposes the queue depth as SO_NWRITE, which is exactly what is needed
// to keep a TTL restore from overtaking the low-TTL segment it belongs to. The
// wait is bounded by drainTimeout and any failure is reported rather than
// retried: a socket whose queue never empties has a stalled peer, which is the
// caller's problem, not the relay's.
func (w *ConnWriter) Drain() error {
	if w.noDrain {
		return nil
	}
	deadline := time.Now().Add(drainTimeout)
	for {
		var (
			queued int
			inner  error
		)
		if err := w.rc.Control(func(fd uintptr) {
			queued, inner = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_NWRITE)
		}); err != nil {
			return fmt.Errorf("proxy: reaching the upstream socket: %w", err)
		}
		if inner != nil {
			// No SO_NWRITE on this kernel: stop asking, and say so once.
			w.noDrain = true
			return fmt.Errorf("proxy: getsockopt(SO_NWRITE): %s", errnoName(inner))
		}
		if queued == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("proxy: %d byte(s) still queued after %v", queued, drainTimeout)
		}
		time.Sleep(drainPoll)
	}
}

// errnoName renders an error as its symbolic errno name plus the readable text.
// The symbolic name is what a bug report needs; the prose alone is ambiguous
// about which contract was violated.
func errnoName(err error) string {
	var errno unix.Errno
	if errors.As(err, &errno) {
		if name := unix.ErrnoName(errno); name != "" {
			return fmt.Sprintf("%s (%v)", name, errno)
		}
		return fmt.Sprintf("errno %d (%v)", int(errno), errno)
	}
	return err.Error()
}
