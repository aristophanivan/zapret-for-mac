package diag_test

// REGRESSION TEST for what used to be a data race in internal/engine: the
// engine's statistics were plain int64 fields incremented with no lock, and
// Engine.flow handed out a *desync.Flow after releasing flowsMu.
//
// WHY IT BIT. The divert transport reads its utun from a single goroutine, so
// its writes were serialised by accident. The proxy transport is not: it runs
// one goroutine per accepted connection, each calling PlanStream. Two concurrent
// connections therefore did a read-modify-write on the same word, and the daemon
// read the same words from the control-socket goroutine for `zaprctl status`.
// It was lossy, not merely detector-visible: with 32 goroutines this test was
// observed reporting Matched=31 against FlowsTotal=32.
//
// THE FIX. engine.Engine keeps its statistics in atomics behind
// Engine.Counters(), and every flow's desync.Flow is guarded by a per-entry
// mutex held for the whole handler call. This test is the proof; run it with
// -race, which the repository's verification step does.

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/engine"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// TestEngineCountersRace drives PlanStream concurrently the way the proxy
// transport does, with a concurrent Stats()-style reader alongside.
func TestEngineCountersRace(t *testing.T) {
	root := filepath.Join("..", "..")
	s, err := strategy.Load(filepath.Join(root, "strategies", "general.toml"), strategy.LoadOpts{
		ListsDir: filepath.Join(root, "lists"),
		FakesDir: filepath.Join(root, "fakes"),
		Caps:     desync.ProxyCaps(),
	})
	if err != nil {
		t.Fatalf("load general.toml: %v", err)
	}
	hello, err := os.ReadFile(filepath.Join(root, "fakes", "tls_clienthello_www_google_com.bin"))
	if err != nil {
		t.Fatalf("read ClientHello fixture: %v", err)
	}

	eng := engine.New(s, desync.ProxyCaps(), desync.FakeSet{})

	const workers = 32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// A distinct 4-tuple per goroutine: the race is on the shared
			// counters, not on per-flow state, so nothing here is aliased.
			key := desync.FlowKey{
				Src:     netip.MustParseAddr("192.168.3.50"),
				Dst:     netip.MustParseAddr("142.250.185.100"),
				SrcPort: uint16(40000 + i),
				DstPort: 443,
				Proto:   proto.IPProtoTCP,
			}
			for n := 0; n < 50; n++ {
				_, _ = eng.PlanStream(key, hello)
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; n < 500; n++ {
			_ = eng.Counters() // what transport.Stats() and the daemon do
			_ = eng.FlowCount()
		}
	}()
	wg.Wait()

	// Every goroutine used a distinct key and general.toml has a profile for
	// TLS/443, so each flow must have been counted exactly once. A short count is
	// the lost-update half of the race, visible even without -race.
	if got, want := eng.Counters().Matched, int64(workers); got != want {
		t.Errorf("Matched = %d, want %d (FlowsTotal=%d): a counter increment was lost",
			got, want, eng.Counters().FlowsTotal)
	}
}
