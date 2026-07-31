package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/engine"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
	"github.com/naladwepo/zapret-for-mac/internal/transport"
)

// Everything in this file runs without root and without network access: the
// "server" and the "client" are loopback sockets, and the original-destination
// lookup that normally needs /dev/pf is injected. The one test that does need
// root skips with a reason.

// ---------------------------------------------------------------------------
// test doubles
// ---------------------------------------------------------------------------

// recorder is a SegWriter that records exactly what the relay did, so segment
// boundaries and TTL ordering can be asserted deterministically. A real socket
// cannot prove where one segment ended and the next began; this can.
type recorder struct {
	// events is the ordered log: "ttl=N", "write:<bytes>", "drain".
	events []string
	writes [][]byte
	// ttls is the TTL in force for each write, in write order.
	ttls []int
	cur  int

	// failWriteAt makes the n-th (0-based) Write fail, to exercise the error
	// path. -1 disables it.
	failWriteAt int
	// setTTLErr makes SetTTL fail.
	setTTLErr error
	// drainErr makes Drain fail.
	drainErr error
}

func newRecorder() *recorder { return &recorder{failWriteAt: -1, cur: 64} }

func (r *recorder) Write(p []byte) (int, error) {
	r.events = append(r.events, "write:"+string(p))
	r.writes = append(r.writes, append([]byte(nil), p...))
	r.ttls = append(r.ttls, r.cur)
	if r.failWriteAt >= 0 && len(r.writes)-1 == r.failWriteAt {
		return 0, errors.New("recorder: injected write failure")
	}
	return len(p), nil
}

func (r *recorder) SetTTL(ttl int) error {
	if r.setTTLErr != nil {
		return r.setTTLErr
	}
	if ttl == 0 {
		ttl = 64
	}
	r.cur = ttl
	r.events = append(r.events, fmt.Sprintf("ttl=%d", ttl))
	return nil
}

func (r *recorder) Drain() error {
	r.events = append(r.events, "drain")
	return r.drainErr
}

// plainRecorder is a recorder without Drain, to check ApplyPlan does not require
// it.
type plainRecorder struct{ r *recorder }

func (p plainRecorder) Write(b []byte) (int, error) { return p.r.Write(b) }
func (p plainRecorder) SetTTL(ttl int) error        { return p.r.SetTTL(ttl) }

// recordingServer is a fake upstream: it accepts connections, records every read
// separately, optionally greets the client first, and echoes nothing.
type recordingServer struct {
	ln    *net.TCPListener
	addr  netip.AddrPort
	greet []byte

	mu     sync.Mutex
	chunks [][]byte
	done   chan struct{}
	once   sync.Once
}

// startRecordingServer starts a fake server on 127.0.0.1 and returns it. greet,
// when non-empty, is sent to the client as soon as the connection is accepted —
// that is how the "server speaks first" case is reproduced.
func startRecordingServer(t *testing.T, greet []byte) *recordingServer {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("fake server listen: %v", err)
	}
	ta := ln.Addr().(*net.TCPAddr)
	s := &recordingServer{
		ln:    ln,
		addr:  netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(ta.Port)),
		greet: greet,
		done:  make(chan struct{}),
	}
	t.Cleanup(func() { _ = ln.Close() })
	go s.accept()
	return s
}

func (s *recordingServer) accept() {
	for {
		c, err := s.ln.AcceptTCP()
		if err != nil {
			return
		}
		go s.serve(c)
	}
}

func (s *recordingServer) serve(c *net.TCPConn) {
	defer c.Close()
	if len(s.greet) > 0 {
		_, _ = c.Write(s.greet)
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.chunks = append(s.chunks, append([]byte(nil), buf[:n]...))
			s.mu.Unlock()
		}
		if err != nil {
			s.once.Do(func() { close(s.done) })
			return
		}
	}
}

// received returns everything the server read, concatenated.
func (s *recordingServer) received() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []byte
	for _, c := range s.chunks {
		out = append(out, c...)
	}
	return out
}

// waitBytes waits until the server has received exactly want.
//
// Polling rather than waiting for a close: the relay opens one upstream
// connection per client connection, and a test may produce more than one, so
// "somebody closed" is not the same as "the bytes arrived".
func (s *recordingServer) waitBytes(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := string(s.received())
		if got == want {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("upstream received %q, want %q", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// expectNothing gives the relay a moment to misbehave and then asserts the
// server saw no bytes at all.
func (s *recordingServer) expectNothing(t *testing.T) {
	t.Helper()
	time.Sleep(200 * time.Millisecond)
	if got := s.received(); len(got) != 0 {
		t.Fatalf("upstream received %q, want nothing", got)
	}
}

// dialTo opens a client connection to addr.
func dialTo(t *testing.T, addr netip.AddrPort) *net.TCPConn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", addr.String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial %v: %v", addr, err)
	}
	tc := c.(*net.TCPConn)
	t.Cleanup(func() { _ = tc.Close() })
	return tc
}

// dataSeg builds a real-payload segment the way the desync ops do.
func dataSeg(data string, seqOff int) desync.Seg {
	return desync.Seg{Kind: desync.SegData, Data: []byte(data), SeqOff: int32(seqOff), Repeats: 1}
}

// ---------------------------------------------------------------------------
// Segments / Reconstruct
// ---------------------------------------------------------------------------

func TestSegmentsReconstruction(t *testing.T) {
	payload := "ABCDEFGHIJ"

	cases := []struct {
		name string
		plan *desync.Plan
		// want is the stream the pieces must reassemble to.
		want string
		// wantOffsets is the stream offset of each piece.
		wantOffsets []int
		wantOverlap int
		wantErr     error
		wantReorder bool
	}{
		{
			name:        "nil plan",
			plan:        nil,
			want:        "",
			wantOffsets: nil,
		},
		{
			name:        "single segment is the whole payload",
			plan:        &desync.Plan{Segs: []desync.Seg{dataSeg(payload, 0)}},
			want:        payload,
			wantOffsets: []int{0},
		},
		{
			name: "multisplit at 2 and 5",
			plan: &desync.Plan{Segs: []desync.Seg{
				dataSeg("AB", 0), dataSeg("CDE", 2), dataSeg("FGHIJ", 5),
			}},
			want:        payload,
			wantOffsets: []int{0, 2, 5},
		},
		{
			name: "multidisorder plan order is rewritten into stream order",
			plan: &desync.Plan{Segs: []desync.Seg{
				dataSeg("FGHIJ", 5), dataSeg("CDE", 2), dataSeg("AB", 0),
			}},
			want:        payload,
			wantOffsets: []int{0, 2, 5},
			wantReorder: true,
		},
		{
			name: "seqovl prefix below the window is dropped",
			plan: &desync.Plan{Segs: []desync.Seg{
				// nfqws' seqovl: three filler bytes below the window, then the
				// real first part. SeqOff = 0 - 3.
				dataSeg("\x00\x00\x00AB", -3), dataSeg("CDEFGHIJ", 2),
			}},
			want:        payload,
			wantOffsets: []int{0, 2},
			wantOverlap: 3,
		},
		{
			name: "overlap of bytes an earlier segment carried is dropped",
			plan: &desync.Plan{Segs: []desync.Seg{
				dataSeg("ABCDE", 0), dataSeg("DEFGHIJ", 3),
			}},
			want:        payload,
			wantOffsets: []int{0, 5},
			wantOverlap: 2,
		},
		{
			name: "tlsrec-style growth is passed through",
			plan: &desync.Plan{Segs: []desync.Seg{
				dataSeg("ABCDE", 0), dataSeg("!!CDEFGHIJ", 5),
			}},
			want:        "ABCDE" + "!!CDEFGHIJ",
			wantOffsets: []int{0, 5},
		},
		{
			name: "injected segments are skipped",
			plan: &desync.Plan{Segs: []desync.Seg{
				{Kind: desync.SegFake, Data: []byte("XXXX"), SeqOff: 0, Repeats: 3},
				{Kind: desync.SegRST, Data: nil},
				dataSeg(payload, 0),
			}},
			want:        payload,
			wantOffsets: []int{0},
		},
		{
			name: "a gap is refused",
			plan: &desync.Plan{Segs: []desync.Seg{
				dataSeg("AB", 0), dataSeg("FGHIJ", 5),
			}},
			wantErr: ErrPlanNotContiguous,
		},
		{
			name: "a plan that does not start at 0 is refused",
			plan: &desync.Plan{Segs: []desync.Seg{
				dataSeg("CDEFGHIJ", 2),
			}},
			wantErr: ErrPlanNotContiguous,
		},
		{
			name: "a fully duplicated segment is refused",
			plan: &desync.Plan{Segs: []desync.Seg{
				dataSeg("ABCDE", 0), dataSeg("BCD", 1), dataSeg("FGHIJ", 5),
			}},
			wantErr: ErrPlanNotContiguous,
		},
		{
			name:        "empty segments are ignored",
			plan:        &desync.Plan{Segs: []desync.Seg{dataSeg("", 0), dataSeg(payload, 0)}},
			want:        payload,
			wantOffsets: []int{0},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pieces, info, err := Segments(c.plan)
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("Segments err = %v, want %v", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Segments: %v", err)
			}
			if got := string(Reconstruct(pieces)); got != c.want {
				t.Errorf("Reconstruct = %q, want %q", got, c.want)
			}
			if len(pieces) != len(c.wantOffsets) {
				t.Fatalf("got %d piece(s), want %d (%v)", len(pieces), len(c.wantOffsets), pieces)
			}
			for i, off := range c.wantOffsets {
				if pieces[i].SeqOff != off {
					t.Errorf("piece %d: SeqOff = %d, want %d", i, pieces[i].SeqOff, off)
				}
			}
			if info.OverlapDropped != c.wantOverlap {
				t.Errorf("OverlapDropped = %d, want %d", info.OverlapDropped, c.wantOverlap)
			}
			if info.Reordered != c.wantReorder {
				t.Errorf("Reordered = %v, want %v", info.Reordered, c.wantReorder)
			}
			// Whatever happens, the pieces must tile the stream without gaps.
			pos := 0
			for i, p := range pieces {
				if p.SeqOff != pos {
					t.Errorf("piece %d starts at %d, expected %d: pieces must be contiguous", i, p.SeqOff, pos)
				}
				pos += len(p.Data)
			}
		})
	}
}

// TestSegmentsNegativeSeqOffIsNoted is the specific requirement that a leaked
// sequence overlap is dropped AND reported: silently sending the filler bytes
// would corrupt the request, and silently dropping them would hide a
// misconfiguration.
func TestSegmentsNegativeSeqOffIsNoted(t *testing.T) {
	plan := &desync.Plan{
		DropOriginal: true,
		Segs: []desync.Seg{
			dataSeg("\xde\xad\xbe\xefGET", -4),
			dataSeg(" / HTTP/1.1", 3),
		},
	}
	pieces, info, err := Segments(plan)
	if err != nil {
		t.Fatalf("Segments: %v", err)
	}
	if got, want := string(Reconstruct(pieces)), "GET / HTTP/1.1"; got != want {
		t.Fatalf("Reconstruct = %q, want %q", got, want)
	}
	if info.OverlapDropped != 4 {
		t.Errorf("OverlapDropped = %d, want 4", info.OverlapDropped)
	}
	if pieces[0].SeqOff != 0 {
		t.Errorf("first piece SeqOff = %d, want 0: a socket cannot lower a sequence number", pieces[0].SeqOff)
	}
	found := false
	for _, n := range info.Notes {
		if strings.Contains(n, "sub-window overlap") {
			found = true
		}
	}
	if !found {
		t.Errorf("no note about the dropped overlap; notes = %q", info.Notes)
	}
}

// TestSegmentsPassesLowTTLThrough checks the disorder marker survives conversion.
func TestSegmentsPassesLowTTLThrough(t *testing.T) {
	first := dataSeg("AB", 0)
	first.TTL = 1
	second := dataSeg("CDEF", 2)
	second.TTL = 7 // a packet-level TTL a socket cannot express meaningfully
	pieces, info, err := Segments(&desync.Plan{Segs: []desync.Seg{first, second}})
	if err != nil {
		t.Fatalf("Segments: %v", err)
	}
	if !pieces[0].LowTTL {
		t.Error("the TTL 1 segment did not come out as LowTTL")
	}
	if pieces[1].LowTTL {
		t.Error("a TTL 7 segment must not be treated as the disorder trick")
	}
	if info.LowTTL != 1 {
		t.Errorf("PlanInfo.LowTTL = %d, want 1", info.LowTTL)
	}
	if len(info.Notes) == 0 {
		t.Error("a TTL a socket cannot honour must be reported")
	}
}

// ---------------------------------------------------------------------------
// ApplyPlan
// ---------------------------------------------------------------------------

func TestApplyPlanWritesOneSegmentPerWrite(t *testing.T) {
	payload := []byte("ABCDEFGHIJ")
	plan := &desync.Plan{
		DropOriginal: true,
		Segs:         []desync.Seg{dataSeg("AB", 0), dataSeg("CDE", 2), dataSeg("FGHIJ", 5)},
	}
	r := newRecorder()
	res, err := ApplyPlan(r, plan, payload)
	if err != nil {
		t.Fatalf("ApplyPlan: %v", err)
	}
	if res.Writes != 3 || res.Bytes != len(payload) {
		t.Errorf("Writes/Bytes = %d/%d, want 3/%d", res.Writes, res.Bytes, len(payload))
	}
	if res.Verbatim || res.Blocked {
		t.Errorf("Verbatim=%v Blocked=%v, want both false", res.Verbatim, res.Blocked)
	}
	want := []string{"write:AB", "write:CDE", "write:FGHIJ"}
	if got := strings.Join(r.events, ","); got != strings.Join(want, ",") {
		t.Errorf("events = %v, want %v", r.events, want)
	}
}

// TestApplyPlanDisorderTTLSequence pins the exact syscall order the disorder
// trick needs: set TTL 1, write that segment alone, wait for it to leave the
// socket, restore the real TTL, then write the rest.
func TestApplyPlanDisorderTTLSequence(t *testing.T) {
	payload := []byte("ABCDEFGHIJ")
	first := dataSeg("AB", 0)
	first.TTL = 1
	plan := &desync.Plan{
		DropOriginal: true,
		Segs:         []desync.Seg{first, dataSeg("CDEFGHIJ", 2)},
	}
	r := newRecorder()
	res, err := ApplyPlan(r, plan, payload)
	if err != nil {
		t.Fatalf("ApplyPlan: %v", err)
	}
	want := []string{"ttl=1", "write:AB", "drain", "ttl=64", "write:CDEFGHIJ"}
	if got := strings.Join(r.events, ","); got != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", r.events, want)
	}
	if r.ttls[0] != 1 {
		t.Errorf("the first segment went out with TTL %d, want 1", r.ttls[0])
	}
	if r.ttls[1] != 64 {
		t.Errorf("the second segment went out with TTL %d, want the real one restored", r.ttls[1])
	}
	if res.LowTTL != 1 {
		t.Errorf("Result.LowTTL = %d, want 1", res.LowTTL)
	}
}

// TestApplyPlanWithoutDrainer checks that a SegWriter which cannot drain still
// works — the drain is a mitigation, not a requirement.
func TestApplyPlanWithoutDrainer(t *testing.T) {
	first := dataSeg("AB", 0)
	first.TTL = 1
	r := newRecorder()
	if _, err := ApplyPlan(plainRecorder{r}, &desync.Plan{
		DropOriginal: true,
		Segs:         []desync.Seg{first, dataSeg("CD", 2)},
	}, []byte("ABCD")); err != nil {
		t.Fatalf("ApplyPlan: %v", err)
	}
	want := []string{"ttl=1", "write:AB", "ttl=64", "write:CD"}
	if got := strings.Join(r.events, ","); got != strings.Join(want, ",") {
		t.Errorf("events = %v, want %v", r.events, want)
	}
}

// TestApplyPlanTTLFailureDegrades: if the TTL cannot be set the segment must
// still be sent. Losing the desync is acceptable; losing the request is not.
func TestApplyPlanTTLFailureDegrades(t *testing.T) {
	first := dataSeg("AB", 0)
	first.TTL = 1
	r := newRecorder()
	r.setTTLErr = errors.New("EPERM")
	res, err := ApplyPlan(r, &desync.Plan{
		DropOriginal: true,
		Segs:         []desync.Seg{first, dataSeg("CD", 2)},
	}, []byte("ABCD"))
	if err != nil {
		t.Fatalf("ApplyPlan: %v", err)
	}
	if res.Writes != 2 || res.Bytes != 4 {
		t.Errorf("Writes/Bytes = %d/%d, want 2/4", res.Writes, res.Bytes)
	}
	if len(res.Notes) == 0 {
		t.Error("a failed TTL change must be reported")
	}
}

func TestApplyPlanBlock(t *testing.T) {
	r := newRecorder()
	res, err := ApplyPlan(r, &desync.Plan{DropOriginal: true}, []byte("GET / HTTP/1.1\r\n"))
	if err != nil {
		t.Fatalf("ApplyPlan: %v", err)
	}
	if !res.Blocked {
		t.Fatal("a plan with no segments and DropOriginal must block the connection")
	}
	if res.Writes != 0 {
		t.Errorf("Writes = %d, want 0: the block op must forward nothing", res.Writes)
	}
	if len(r.writes) != 0 {
		t.Errorf("the writer saw %d write(s), want none", len(r.writes))
	}
}

func TestApplyPlanForwardsVerbatim(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\n")

	cases := []struct {
		name string
		plan *desync.Plan
	}{
		{"no plan", nil},
		{"empty plan", &desync.Plan{}},
		{"plan with a gap", &desync.Plan{DropOriginal: true, Segs: []desync.Seg{
			dataSeg("GET", 0), dataSeg("1.1\r\n", 11),
		}}},
		{"plan with only injected segments", &desync.Plan{DropOriginal: true, Segs: []desync.Seg{
			{Kind: desync.SegFake, Data: []byte("XX")},
		}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRecorder()
			res, err := ApplyPlan(r, c.plan, payload)
			if err != nil {
				t.Fatalf("ApplyPlan: %v", err)
			}
			if !res.Verbatim {
				t.Error("Verbatim = false, want true")
			}
			if len(r.writes) != 1 || string(r.writes[0]) != string(payload) {
				t.Errorf("writes = %q, want one write of %q", r.writes, payload)
			}
		})
	}
}

func TestApplyPlanReportsRewrites(t *testing.T) {
	payload := []byte("ABCDEFGHIJ")
	// tlsrec-style: the same request plus an extra record header.
	plan := &desync.Plan{DropOriginal: true, Segs: []desync.Seg{
		dataSeg("ABCDE", 0), dataSeg("!!FGHIJ", 5),
	}}
	r := newRecorder()
	res, err := ApplyPlan(r, plan, payload)
	if err != nil {
		t.Fatalf("ApplyPlan: %v", err)
	}
	if res.Rewritten != 2 {
		t.Errorf("Rewritten = %d, want +2", res.Rewritten)
	}
	if res.Bytes != 12 {
		t.Errorf("Bytes = %d, want 12", res.Bytes)
	}
}

func TestApplyPlanWriteErrorIsReported(t *testing.T) {
	r := newRecorder()
	r.failWriteAt = 1
	res, err := ApplyPlan(r, &desync.Plan{DropOriginal: true, Segs: []desync.Seg{
		dataSeg("AB", 0), dataSeg("CD", 2), dataSeg("EF", 4),
	}}, []byte("ABCDEF"))
	if err == nil {
		t.Fatal("ApplyPlan must report a failed write")
	}
	if res.Writes != 2 {
		t.Errorf("Writes = %d, want 2 (it must stop at the failure)", res.Writes)
	}
}

func TestApplyPlanEmptyPayload(t *testing.T) {
	r := newRecorder()
	res, err := ApplyPlan(r, nil, nil)
	if err != nil {
		t.Fatalf("ApplyPlan: %v", err)
	}
	if res.Writes != 0 {
		t.Errorf("Writes = %d, want 0 for an empty payload", res.Writes)
	}
}

// ---------------------------------------------------------------------------
// ConnWriter over a real socket
// ---------------------------------------------------------------------------

func TestConnWriterOverLoopback(t *testing.T) {
	srv := startRecordingServer(t, nil)
	c := dialTo(t, srv.addr)

	w, err := NewConnWriter(c)
	if err != nil {
		t.Fatalf("NewConnWriter: %v", err)
	}
	if w.Conn() != c {
		t.Error("Conn() must return the connection it was built from")
	}

	payload := []byte("ABCDEFGHIJKLMNOPQRST")
	first := dataSeg("ABCDE", 0)
	first.TTL = 1 // exercise the real setsockopt path too
	plan := &desync.Plan{DropOriginal: true, Segs: []desync.Seg{
		first, dataSeg("FGHIJ", 5), dataSeg("KLMNOPQRST", 10),
	}}
	res, err := ApplyPlan(w, plan, payload)
	if err != nil {
		t.Fatalf("ApplyPlan over a real socket: %v", err)
	}
	if res.Writes != 3 {
		t.Errorf("Writes = %d, want 3", res.Writes)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// The low-TTL segment does die in transit on a real path; over loopback
	// there is no hop to decrement the TTL, so everything arrives. That is what
	// makes this assertion possible at all, and it is the point: the relay must
	// deliver the exact request bytes.
	srv.waitBytes(t, string(payload))
}

func TestConnWriterTTLRoundTrip(t *testing.T) {
	srv := startRecordingServer(t, nil)
	c := dialTo(t, srv.addr)
	w, err := NewConnWriter(c)
	if err != nil {
		t.Fatalf("NewConnWriter: %v", err)
	}
	real0, err := w.getTTL()
	if err != nil {
		t.Skipf("cannot read IP_TTL on this kernel: %v", err)
	}
	if real0 <= 1 {
		t.Skipf("the socket's TTL is already %d; nothing to distinguish", real0)
	}
	if err := w.SetTTL(disorderTTL); err != nil {
		t.Fatalf("SetTTL(1): %v", err)
	}
	if got, err := w.getTTL(); err != nil || got != disorderTTL {
		t.Fatalf("after SetTTL(1): TTL = %d, err = %v; want 1", got, err)
	}
	if err := w.SetTTL(0); err != nil {
		t.Fatalf("SetTTL(0): %v", err)
	}
	if got, err := w.getTTL(); err != nil || got != real0 {
		t.Fatalf("after SetTTL(0): TTL = %d, err = %v; want the original %d", got, err, real0)
	}
	// A redundant restore must not issue a syscall or fail.
	if err := w.SetTTL(0); err != nil {
		t.Fatalf("second SetTTL(0): %v", err)
	}
	if err := w.Drain(); err != nil {
		t.Errorf("Drain on an idle socket: %v", err)
	}
}

func TestConnWriterRejectsNil(t *testing.T) {
	if _, err := NewConnWriter(nil); err == nil {
		t.Error("NewConnWriter(nil) must fail")
	}
}

// ---------------------------------------------------------------------------
// original-destination validation
// ---------------------------------------------------------------------------

func TestValidateDest(t *testing.T) {
	client := netip.MustParseAddrPort("192.168.1.10:54321")
	local := netip.MustParseAddrPort("127.0.0.1:10800")
	good := netip.MustParseAddrPort("142.250.185.78:443")

	if err := validateDest(good, client, local); err != nil {
		t.Errorf("validateDest on a good answer: %v", err)
	}
	if err := validateDest(netip.AddrPort{}, client, local); err == nil {
		t.Error("an invalid destination must be rejected")
	}
	if err := validateDest(netip.MustParseAddrPort("142.250.185.78:0"), client, local); err == nil {
		t.Error("port 0 must be rejected")
	}
	if err := validateDest(local, client, local); !errors.Is(err, ErrNotRedirected) {
		t.Errorf("the listener's own address must be ErrNotRedirected, got %v", err)
	}
	if err := validateDest(client, client, local); err == nil {
		t.Error("the client's own address must be rejected")
	}
	if err := validateDest(netip.MustParseAddrPort("[2001:db8::1]:443"), client, local); err == nil {
		t.Error("a family mismatch must be rejected")
	}
}

func TestLookupFuncAdapter(t *testing.T) {
	want := netip.MustParseAddrPort("203.0.113.9:443")
	var l DestLookup = LookupFunc(func(client, local netip.AddrPort) (netip.AddrPort, error) {
		return want, nil
	})
	got, err := l.OrigDst(netip.MustParseAddrPort("127.0.0.1:1"), netip.MustParseAddrPort("127.0.0.1:2"))
	if err != nil || got != want {
		t.Fatalf("OrigDst = %v, %v; want %v, nil", got, err, want)
	}
	if err := l.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestOpenPFLookupNeedsRoot covers the real /dev/pf path. DIOCNATLOOK is a
// privileged query and /dev/pf is 0600 root:wheel, so without root there is
// nothing to test but the failure.
func TestOpenPFLookupNeedsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skipf("needs root: /dev/pf is 0600 root:wheel (uid %d)", os.Geteuid())
	}
	l, err := OpenPFLookup()
	if err != nil {
		t.Fatalf("OpenPFLookup: %v", err)
	}
	pl, ok := l.(*pfLookup)
	if !ok {
		t.Fatalf("OpenPFLookup returned %T", l)
	}
	if pl.FD() < 0 {
		t.Error("the /dev/pf descriptor is not open")
	}
	// A tuple with no pf state must be reported as "not redirected", never as a
	// destination.
	_, err = l.OrigDst(netip.MustParseAddrPort("192.0.2.123:54321"), netip.MustParseAddrPort("203.0.113.45:65001"))
	if !errors.Is(err, ErrNotRedirected) {
		t.Errorf("OrigDst for an unknown tuple: err = %v, want ErrNotRedirected", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if pl.FD() >= 0 {
		t.Error("Close must invalidate the descriptor")
	}
	if _, err := l.OrigDst(netip.MustParseAddrPort("192.0.2.1:1"), netip.MustParseAddrPort("192.0.2.2:2")); err == nil {
		t.Error("OrigDst after Close must fail")
	}
}

// ---------------------------------------------------------------------------
// ruleset generation
// ---------------------------------------------------------------------------

func TestRulesFor(t *testing.T) {
	tr := &Transport{port: 10800, opts: Options{}}
	s := &strategy.Strategy{
		Name:      "t",
		WindowTCP: strategy.PortSet{{Lo: 80, Hi: 80}, {Lo: 443, Hi: 443}, {Lo: 2053, Hi: 2096}},
	}
	rs, err := tr.rulesFor(s)
	if err != nil {
		t.Fatalf("rulesFor: %v", err)
	}
	for _, want := range []string{
		"rdr pass on lo0 inet proto tcp from ! 127.0.0.0/8 to any port { 80 443 2053:2096 } -> 127.0.0.1 port 10800",
		"route-to (lo0 127.0.0.1)",
		"user { > root }",
	} {
		if !strings.Contains(rs.v4, want) {
			t.Errorf("ruleset is missing %q:\n%s", want, rs.v4)
		}
	}
	if rs.both != rs.v4 {
		t.Error("without Options.IPv6 the combined ruleset must equal the IPv4 one")
	}

	// The `user { > root }` clause is not optional: without it the relay's own
	// upstream connections are redirected back into itself.
	if !strings.Contains(rs.v4, "user { > root }") {
		t.Error("the route-to rule must exempt root, or the relay loops on itself")
	}

	if _, err := tr.rulesFor(&strategy.Strategy{Name: "empty"}); err == nil {
		t.Error("an empty TCP window must be refused, not turned into an empty ruleset")
	}
	if _, err := tr.rulesFor(nil); err == nil {
		t.Error("a nil strategy must be refused")
	}

	// With IPv6 on, the redirect target must be the address the listener really
	// binds. Before listen() has run that is zapret's own choice, fe80::1 —
	// upstream's pf.sh redirects there, not to ::1.
	tr6 := &Transport{port: 10800, opts: Options{IPv6: true}}
	rs6, err := tr6.rulesFor(s)
	if err != nil {
		t.Fatalf("rulesFor with IPv6: %v", err)
	}
	if !strings.Contains(rs6.both, "rdr pass on lo0 inet6 proto tcp from ! ::1 to any port { 80 443 2053:2096 } -> fe80::1 port 10800") {
		t.Errorf("the combined ruleset lacks the expected inet6 redirect:\n%s", rs6.both)
	}
	if !strings.Contains(rs6.both, "route-to (lo0 fe80::1) inet6") {
		t.Errorf("the combined ruleset lacks the inet6 route-to:\n%s", rs6.both)
	}
	if strings.Contains(rs6.v4, "inet6") {
		t.Error("the IPv4 fallback ruleset must not contain inet6 rules")
	}

	// Once a listener has bound ::1 instead, the rule must follow it there.
	tr6.v6Target = "::1"
	rs6b, err := tr6.rulesFor(s)
	if err != nil {
		t.Fatalf("rulesFor with IPv6 and a ::1 listener: %v", err)
	}
	if !strings.Contains(rs6b.both, "-> ::1 port 10800") {
		t.Errorf("the inet6 redirect must point at the address that was bound:\n%s", rs6b.both)
	}

	// And if listen() bound no IPv6 loopback at all, no inet6 rules are emitted.
	tr6.v6Target = ""
	tr6.started = true
	rs6c, err := tr6.rulesFor(s)
	if err != nil {
		t.Fatalf("rulesFor with IPv6 and no v6 listener: %v", err)
	}
	if strings.Contains(rs6c.both, "inet6") {
		t.Errorf("no IPv6 listener means no inet6 rules:\n%s", rs6c.both)
	}
}

// TestListenBindsIPv6Target checks the listener/rule agreement that the inet6
// redirect depends on: whichever loopback address bound is the one the rule
// points at.
func TestListenBindsIPv6Target(t *testing.T) {
	strat := testStrategy(t, splitStrategy)
	eng := engine.New(strat, desync.ProxyCaps(), desync.FakeSet{})
	tr, err := NewWithOptions(transport.Config{
		Strategy: strat, Engine: eng, ProxyPort: freePort(t),
	}, Options{NoPF: true, IPv6: true, Logf: t.Logf,
		Lookup: LookupFunc(func(client, local netip.AddrPort) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("203.0.113.1:443"), nil
		}),
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	if err := tr.listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		if err := tr.unwind(); err != nil {
			t.Errorf("unwind: %v", err)
		}
	}()
	if len(tr.lns) < 2 {
		t.Fatalf("bound %d listener(s), want at least the IPv4 one and an IPv6 one", len(tr.lns))
	}
	switch tr.v6Target {
	case "fe80::1", "::1":
		rs, err := tr.rulesFor(strat)
		if err != nil {
			t.Fatalf("rulesFor: %v", err)
		}
		if !strings.Contains(rs.both, "-> "+tr.v6Target+" port ") {
			t.Errorf("the inet6 rule does not point at the bound address %s:\n%s", tr.v6Target, rs.both)
		}
	case "":
		t.Log("no IPv6 loopback could be bound; the inet6 redirect is correctly omitted")
	default:
		t.Errorf("unexpected v6 target %q", tr.v6Target)
	}
}

func TestMergeRulesets(t *testing.T) {
	a := "table <zmx> persist\nrdr pass on lo0 inet ...\n"
	b := "table <zmx> persist\nrdr pass on lo0 inet6 ...\n"
	got := mergeRulesets(a, b)
	if n := strings.Count(got, "table <zmx> persist"); n != 1 {
		t.Errorf("table declared %d times, want 1:\n%s", n, got)
	}
	if !strings.Contains(got, "inet ...") || !strings.Contains(got, "inet6 ...") {
		t.Errorf("both halves must survive:\n%s", got)
	}
	if got != "" && !strings.HasSuffix(got, "\n") {
		t.Error("a ruleset must end with a newline")
	}
	if mergeRulesets("", "") != "" {
		t.Error("merging two empty rulesets must give an empty one")
	}
}

// ---------------------------------------------------------------------------
// the whole transport, without root
// ---------------------------------------------------------------------------

// testStrategy compiles a strategy from TOML text, exactly as the daemon does.
func testStrategy(t *testing.T, text string) *strategy.Strategy {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("write strategy: %v", err)
	}
	s, err := strategy.Load(path, strategy.LoadOpts{Caps: desync.ProxyCaps()})
	if err != nil {
		t.Fatalf("compile strategy: %v", err)
	}
	return s
}

// splitStrategy cuts every TCP request at absolute offsets 2 and 5. The filter
// deliberately has no port list so the fake upstream's ephemeral port matches.
const splitStrategy = `
name = "test-split"

[window]
tcp = ["443"]

[[profile]]
name = "p1"

[profile.filter]
proto = "tcp"

[[profile.ops]]
op = "multisplit"
pos = ["2", "5"]
`

// blockStrategy drops every TCP request.
const blockStrategy = `
name = "test-block"

[window]
tcp = ["443"]

[[profile]]
name = "p1"

[profile.filter]
proto = "tcp"

[[profile.ops]]
op = "block"
`

// freePort returns a loopback TCP port that was free a moment ago. The listener
// is closed before returning, so there is a small race with anything else on the
// machine; the transport reports a bind failure clearly if it loses it.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}
	return port
}

// startTransport wires a Transport to a fake upstream and starts it. pf is off,
// so nothing here needs root.
func startTransport(t *testing.T, strat *strategy.Strategy, upstream netip.AddrPort) (*Transport, netip.AddrPort) {
	t.Helper()
	eng := engine.New(strat, desync.ProxyCaps(), desync.FakeSet{})
	port := freePort(t)
	tr, err := NewWithOptions(transport.Config{
		Strategy:   strat,
		Engine:     eng,
		ProxyPort:  port,
		ExemptRoot: true,
		Verbose:    2,
	}, Options{
		NoPF: true,
		Logf: t.Logf,
		Lookup: LookupFunc(func(client, local netip.AddrPort) (netip.AddrPort, error) {
			return upstream, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := tr.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Start returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Start did not return after Close")
		}
	})

	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port))
	waitListening(t, addr)
	return tr, addr
}

// waitListening blocks until the transport has bound addr.
//
// It probes by trying to bind the same address itself instead of dialling:
// dialling would be relayed, which would open an upstream connection and pollute
// what the fake server recorded.
func waitListening(t *testing.T, addr netip.AddrPort) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: addr.Addr().AsSlice(), Port: int(addr.Port())})
		if err != nil {
			return // the port is taken, i.e. the transport got there first
		}
		_ = ln.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("nothing bound %v", addr)
}

// TestTransportRelaysAndSegments is the end-to-end case: a client connects to
// the listener, the injected lookup plays the part of pf's rdr, and the fake
// upstream must receive the request byte-for-byte — cut into the three segments
// the strategy asks for.
func TestTransportRelaysAndSegments(t *testing.T) {
	srv := startRecordingServer(t, nil)
	strat := testStrategy(t, splitStrategy)
	tr, addr := startTransport(t, strat, srv.addr)

	payload := []byte("ABCDEFGHIJKLMNOPQRST")
	c := dialTo(t, addr)
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	srv.waitBytes(t, string(payload))

	// Drain the (empty) response so the relay finishes before Stats is read.
	_, _ = io.ReadAll(c)

	st := tr.Stats()
	if st.Transport != "proxy" {
		t.Errorf("Stats.Transport = %q, want proxy", st.Transport)
	}
	if st.FlowsTotal < 1 {
		t.Errorf("FlowsTotal = %d, want at least 1", st.FlowsTotal)
	}
	if st.PktsIn < 1 {
		t.Errorf("PktsIn = %d, want at least 1 intercepted payload", st.PktsIn)
	}
	if st.PktsOut < 3 {
		t.Errorf("PktsOut = %d, want at least 3 (the request was to be cut in three)", st.PktsOut)
	}
	if st.Matched < 1 {
		t.Errorf("Matched = %d, want at least 1", st.Matched)
	}
	if st.Desyncs < 1 {
		t.Errorf("Desyncs = %d, want at least 1", st.Desyncs)
	}
	if st.PktsInject != 0 {
		t.Errorf("PktsInject = %d, want 0: this transport injects nothing", st.PktsInject)
	}
}

// TestTransportBlocks checks the kill switch: the `block` op must close the
// connection with nothing forwarded.
func TestTransportBlocks(t *testing.T) {
	srv := startRecordingServer(t, nil)
	strat := testStrategy(t, blockStrategy)
	tr, addr := startTransport(t, strat, srv.addr)

	c := dialTo(t, addr)
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	// The relay closes both sockets, so the client's next read must end.
	if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 16)
	if n, err := c.Read(buf); err == nil {
		t.Fatalf("read returned %d byte(s) and no error; the connection should be closed", n)
	} else if isTimeout(err) {
		t.Fatalf("the blocked connection was not closed: %v", err)
	}
	srv.expectNothing(t)
	if st := tr.Stats(); st.PktsDropped < 1 {
		t.Errorf("Stats.PktsDropped = %d, want at least 1", st.PktsDropped)
	}
}

// TestTransportServerSpeaksFirst covers the deadline on the first read: a
// protocol whose server greets first must not be stalled waiting for a request
// that will never come.
func TestTransportServerSpeaksFirst(t *testing.T) {
	greet := []byte("220 mail.example.com ESMTP\r\n")
	srv := startRecordingServer(t, greet)
	strat := testStrategy(t, splitStrategy)
	_, addr := startTransport(t, strat, srv.addr)

	c := dialTo(t, addr)
	// Say nothing at all, and wait a little longer than firstPayloadTimeout.
	if err := c.SetReadDeadline(time.Now().Add(firstPayloadTimeout + 3*time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, len(greet))
	n, err := io.ReadFull(c, buf)
	if err != nil {
		t.Fatalf("reading the server greeting through the relay: %v (got %d byte(s))", err, n)
	}
	if string(buf) != string(greet) {
		t.Errorf("greeting = %q, want %q", buf, greet)
	}
	// And the connection is still usable afterwards.
	if _, err := c.Write([]byte("EHLO test\r\n")); err != nil {
		t.Fatalf("write after the greeting: %v", err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	srv.waitBytes(t, "EHLO test\r\n")
}

// TestTransportRefusesSelfDial is the loop breaker: if the lookup ever hands
// back our own listener the connection must die instead of recursing.
func TestTransportRefusesSelfDial(t *testing.T) {
	strat := testStrategy(t, splitStrategy)
	port := freePort(t)
	self := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port))
	eng := engine.New(strat, desync.ProxyCaps(), desync.FakeSet{})
	tr, err := NewWithOptions(transport.Config{Strategy: strat, Engine: eng, ProxyPort: port}, Options{
		NoPF:   true,
		Logf:   t.Logf,
		Lookup: LookupFunc(func(client, local netip.AddrPort) (netip.AddrPort, error) { return self, nil }),
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tr.Start(ctx) }()
	defer tr.Close()
	waitListening(t, self)

	c := dialTo(t, self)
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if n, err := c.Read(make([]byte, 8)); err == nil {
		t.Fatalf("read returned %d byte(s); the relay must refuse to talk to itself", n)
	} else if isTimeout(err) {
		t.Fatal("the self-dial was neither served nor refused; it hung")
	}
	if st := tr.Stats(); st.Errors < 1 {
		t.Errorf("Stats.Errors = %d, want at least 1", st.Errors)
	}
}

// TestTransportNotRedirected covers a connection that reached the listener
// without a pf redirect: there is nowhere to send it, so it must be dropped
// rather than guessed at.
func TestTransportNotRedirected(t *testing.T) {
	strat := testStrategy(t, splitStrategy)
	_, addr := startTransportWithLookup(t, strat, LookupFunc(
		func(client, local netip.AddrPort) (netip.AddrPort, error) {
			return netip.AddrPort{}, fmt.Errorf("%w: test", ErrNotRedirected)
		}))
	c := dialTo(t, addr)
	if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if n, err := c.Read(make([]byte, 8)); err == nil {
		t.Fatalf("read returned %d byte(s); the connection should have been dropped", n)
	} else if isTimeout(err) {
		t.Fatal("a connection with no recoverable destination was left hanging")
	}
}

// startTransportWithLookup is startTransport with a caller-supplied lookup.
func startTransportWithLookup(t *testing.T, strat *strategy.Strategy, lookup DestLookup) (*Transport, netip.AddrPort) {
	t.Helper()
	eng := engine.New(strat, desync.ProxyCaps(), desync.FakeSet{})
	port := freePort(t)
	tr, err := NewWithOptions(transport.Config{Strategy: strat, Engine: eng, ProxyPort: port}, Options{
		NoPF: true, Logf: t.Logf, Lookup: lookup,
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = tr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = tr.Close()
	})
	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port))
	waitListening(t, addr)
	return tr, addr
}

// ---------------------------------------------------------------------------
// construction, reload and teardown
// ---------------------------------------------------------------------------

func TestNewValidates(t *testing.T) {
	strat := testStrategy(t, splitStrategy)
	eng := engine.New(strat, desync.ProxyCaps(), desync.FakeSet{})

	if _, err := New(transport.Config{Strategy: strat}); err == nil {
		t.Error("a missing engine must be refused")
	}
	if _, err := New(transport.Config{Engine: eng}); err == nil {
		t.Error("a missing strategy must be refused")
	}
	if _, err := New(transport.Config{Strategy: strat, Engine: eng, ProxyPort: 70000}); err == nil {
		t.Error("an out-of-range port must be refused")
	}
	tr, err := New(transport.Config{Strategy: strat, Engine: eng})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if tr.Port() != DefaultProxyPort {
		t.Errorf("Port() = %d, want the default %d", tr.Port(), DefaultProxyPort)
	}
	if tr.Name() != "proxy" {
		t.Errorf("Name() = %q, want proxy", tr.Name())
	}
	if caps := tr.Caps(); caps != desync.ProxyCaps() {
		t.Errorf("Caps() = %+v, want desync.ProxyCaps() %+v", caps, desync.ProxyCaps())
	}
	if caps := tr.Caps(); caps.Inject || caps.Seq || caps.UDP || caps.Fooling || caps.PerPacketTTL {
		t.Errorf("Caps() claims something a socket cannot do: %+v", caps)
	}

	// A strategy with no TCP window has nothing to redirect.
	empty := &strategy.Strategy{Name: "empty"}
	if _, err := New(transport.Config{Strategy: empty, Engine: eng}); err == nil {
		t.Error("a strategy with an empty TCP window must be refused at construction")
	}
}

func TestReloadSwapsStrategy(t *testing.T) {
	srv := startRecordingServer(t, nil)
	strat := testStrategy(t, splitStrategy)
	tr, addr := startTransport(t, strat, srv.addr)

	blocking := testStrategy(t, blockStrategy)
	if err := tr.Reload(blocking); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if err := tr.Reload(nil); err == nil {
		t.Error("Reload(nil) must fail")
	}

	// The new strategy blocks, so a fresh connection must be dropped.
	c := dialTo(t, addr)
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if n, err := c.Read(make([]byte, 8)); err == nil {
		t.Fatalf("read returned %d byte(s); the reloaded strategy should block", n)
	} else if isTimeout(err) {
		t.Fatal("the reloaded strategy did not take effect")
	}
	srv.expectNothing(t)
}

func TestCloseIsIdempotentAndUnwinds(t *testing.T) {
	strat := testStrategy(t, splitStrategy)
	eng := engine.New(strat, desync.ProxyCaps(), desync.FakeSet{})
	port := freePort(t)
	tr, err := NewWithOptions(transport.Config{Strategy: strat, Engine: eng, ProxyPort: port}, Options{
		NoPF: true, Logf: t.Logf,
		Lookup: LookupFunc(func(client, local netip.AddrPort) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("203.0.113.1:443"), nil
		}),
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- tr.Start(ctx) }()
	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port))
	waitListening(t, addr)

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start returned %v after Close", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Close")
	}
	// The listener must be gone, i.e. the port is free again.
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatalf("the listener was not closed: %v", err)
	}
	_ = ln.Close()

	// Starting again after Close must be refused rather than half-work.
	if err := tr.Start(context.Background()); err == nil {
		t.Error("Start after Close must fail")
	}
}

func TestStartRefusesABusyPort(t *testing.T) {
	strat := testStrategy(t, splitStrategy)
	eng := engine.New(strat, desync.ProxyCaps(), desync.FakeSet{})
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	tr, err := NewWithOptions(transport.Config{Strategy: strat, Engine: eng, ProxyPort: port}, Options{
		NoPF: true, Logf: t.Logf,
		Lookup: LookupFunc(func(client, local netip.AddrPort) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("203.0.113.1:443"), nil
		}),
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	err = tr.Start(context.Background())
	if err == nil {
		t.Fatal("Start must fail when the port is taken")
	}
	if !errors.Is(err, unix.EADDRINUSE) {
		t.Logf("Start failed with %v (EADDRINUSE not wrapped, which is acceptable)", err)
	}
	// A failed Start must have unwound: closing afterwards stays clean.
	if err := tr.Close(); err != nil {
		t.Errorf("Close after a failed Start: %v", err)
	}
}

func TestNoPFWithoutLookupIsRefused(t *testing.T) {
	strat := testStrategy(t, splitStrategy)
	eng := engine.New(strat, desync.ProxyCaps(), desync.FakeSet{})
	tr, err := NewWithOptions(transport.Config{
		Strategy: strat, Engine: eng, ProxyPort: freePort(t),
	}, Options{NoPF: true, Logf: t.Logf})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	if err := tr.Start(context.Background()); err == nil {
		t.Error("NoPF without a lookup must be refused: nothing could recover a destination")
	}
	if err := tr.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestEndpointsUnmaps checks the address plumbing on a real connection: pf keeps
// IPv4 state, so a 4-in-6 address from a dual-stack socket would look up a tuple
// that does not exist.
func TestEndpointsUnmaps(t *testing.T) {
	srv := startRecordingServer(t, nil)
	c := dialTo(t, srv.addr)
	from, to, err := endpoints(c)
	if err != nil {
		t.Fatalf("endpoints: %v", err)
	}
	if !from.Addr().Is4() || !to.Addr().Is4() {
		t.Errorf("endpoints = %v -> %v; both must be unmapped IPv4", from, to)
	}
	// endpoints() is called here on the *client* side, so the peer ("from") is
	// the server and the local end ("to") is the client's ephemeral port.
	if from != srv.addr {
		t.Errorf("peer endpoint = %v, want the server's %v", from, srv.addr)
	}
	if to.Port() == 0 {
		t.Error("the local port must be known")
	}
}

func TestIsSelf(t *testing.T) {
	tr := &Transport{port: 10800}
	if !tr.isSelf(netip.MustParseAddrPort("127.0.0.1:10800")) {
		t.Error("127.0.0.1:10800 is the listener")
	}
	if !tr.isSelf(netip.MustParseAddrPort("[::1]:10800")) {
		t.Error("[::1]:10800 is the listener too")
	}
	if tr.isSelf(netip.MustParseAddrPort("127.0.0.1:443")) {
		t.Error("a different port is not the listener")
	}
	if tr.isSelf(netip.MustParseAddrPort("203.0.113.1:10800")) {
		t.Error("a remote address is not the listener")
	}
}

func TestPortRanges(t *testing.T) {
	got := portRanges(strategy.PortSet{{Lo: 80, Hi: 80}, {Lo: 19294, Hi: 19344}})
	if len(got) != 2 || got[0] != [2]uint16{80, 80} || got[1] != [2]uint16{19294, 19344} {
		t.Errorf("portRanges = %v", got)
	}
	if len(portRanges(nil)) != 0 {
		t.Error("an empty port set must convert to an empty slice")
	}
}
