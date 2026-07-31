//go:build darwin

package proxy

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/engine"
	"github.com/naladwepo/zapret-for-mac/internal/transport"
)

// TestRelayIdleTimeoutFreesThePoolSlot is the regression test for the relay that
// had no deadline of any kind.
//
// BEFORE: splice ran two io.CopyBuffer goroutines with no read deadline, no write
// deadline and no idle timeout. A peer that completed the TCP handshake, waited out
// firstPayloadTimeout and then sent nothing held two descriptors, two goroutines and
// one slot in the MaxConns pool for ever. MaxConns such peers — any local process,
// or a remote peer that half-opens and stalls — made every new connection on the
// redirected ports fail, permanently, with no root needed.
//
// The test uses a 1-connection pool so "the slot came back" is observable, and a
// short RelayIdleTimeout so it runs in well under a second.
func TestRelayIdleTimeoutFreesThePoolSlot(t *testing.T) {
	srv := startSilentServer(t)
	strat := testStrategy(t, splitStrategy)
	eng := engine.New(strat, desync.ProxyCaps(), desync.FakeSet{})
	port := freePort(t)

	tr, err := NewWithOptions(transport.Config{
		Strategy: strat, Engine: eng, ProxyPort: port, ExemptRoot: true,
	}, Options{
		NoPF:                true,
		Logf:                t.Logf,
		MaxConns:            1,
		FirstPayloadTimeout: 100 * time.Millisecond,
		RelayIdleTimeout:    400 * time.Millisecond,
		Lookup: LookupFunc(func(client, local netip.AddrPort) (netip.AddrPort, error) {
			return srv, nil
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
		_ = tr.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Start did not return after Close")
		}
	})
	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port))
	waitListening(t, addr)

	// The stalling peer: connect, say nothing, never close.
	stalled := dialTo(t, addr)
	defer stalled.Close()

	waitFlows(t, tr, 1, 3*time.Second, "the relay never started")
	// It must eventually be reclaimed. Before the fix this loop timed out.
	waitFlows(t, tr, 0, 6*time.Second, "the stalled relay was never reclaimed")
	if got := tr.Stats().QueueDrop; got == 0 {
		t.Error("the idle teardown was not counted, so an operator cannot tell why the pool filled up")
	}

	// And the freed slot is usable: a second connection is accepted, not refused.
	second := dialTo(t, addr)
	defer second.Close()
	if _, err := second.Write([]byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")); err != nil {
		t.Fatalf("the pool slot was not released: %v", err)
	}
	if err := second.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	// The upstream never answers, so a timeout here means the relay is live (an
	// immediate EOF would mean the connection had been refused).
	if _, err := second.Read(make([]byte, 1)); err != nil && !isTimeout(err) {
		t.Fatalf("the second connection was dropped instead of relayed: %v", err)
	}
}

// TestSpliceStopsOnContextCancel: shutdown must not depend on the peers
// cooperating. Close cancels the serve context, which has to unblock the copy
// goroutines even though neither side ever sends anything.
func TestSpliceStopsOnContextCancel(t *testing.T) {
	srv := startSilentServer(t)
	strat := testStrategy(t, splitStrategy)
	eng := engine.New(strat, desync.ProxyCaps(), desync.FakeSet{})
	port := freePort(t)

	tr, err := NewWithOptions(transport.Config{
		Strategy: strat, Engine: eng, ProxyPort: port, ExemptRoot: true,
	}, Options{
		NoPF:                true,
		Logf:                t.Logf,
		FirstPayloadTimeout: 100 * time.Millisecond,
		// Long enough that only ctx cancellation can end the relay.
		RelayIdleTimeout: time.Hour,
		Lookup: LookupFunc(func(client, local netip.AddrPort) (netip.AddrPort, error) {
			return srv, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Start(ctx) }()
	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port))
	waitListening(t, addr)

	stalled := dialTo(t, addr)
	defer stalled.Close()
	// Let the relay reach the splice.
	waitFlows(t, tr, 1, 3*time.Second, "the relay never started")

	cancel()
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return: the splice goroutines outlived the cancelled context")
	}
	if got := tr.Stats().FlowsActive; got != 0 {
		t.Errorf("FlowsActive = %d after Close, want 0", got)
	}
}

// startSilentServer accepts connections and never says anything, which is the
// upstream half of a stalled relay.
func startSilentServer(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold it open, read nothing, write nothing.
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// waitFlows blocks until the transport reports exactly want active flows.
func waitFlows(t *testing.T, tr *Transport, want int64, budget time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if tr.Stats().FlowsActive == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: FlowsActive = %d, want %d", msg, tr.Stats().FlowsActive, want)
}
