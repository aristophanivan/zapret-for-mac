//go:build darwin

package divert

import (
	"net/netip"
	"os"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/engine"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// TestWireDump is a diagnostic: it prints every packet a strategy
// would emit for one ClientHello, so a "the strategy broke all traffic" report
// can be checked against the actual bytes.
func TestWireDump(t *testing.T) {
	for _, name := range []string{"general", "general-alt"} {
		t.Run(name, func(t *testing.T) {
			s, err := strategy.Load("../../../strategies/"+name+".toml", strategy.LoadOpts{
				ListsDir: "../../../lists", FakesDir: "../../../fakes", Caps: desync.FullCaps(),
			})
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			hello, err := os.ReadFile("../../../fakes/tls_clienthello_www_google_com.bin")
			if err != nil {
				t.Fatal(err)
			}
			fakes := desync.FakeSet{
				TLS:  mustRead(t, "../../../fakes/tls_clienthello_www_google_com.bin"),
				HTTP: mustRead(t, "../../../fakes/tls_clienthello_max_ru.bin"),
				QUIC: mustRead(t, "../../../fakes/quic_initial_www_google_com.bin"),
			}
			eng := engine.New(s, desync.FullCaps(), fakes)

			// A ClientHello to an address inside ipset-all, port 443, WITH a TCP
			// timestamp option present (that is what macOS sends).
			opts := []byte{
				1, 1, 8, 10, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0,
			}
			tm := &proto.Tmpl{
				Src: netip.MustParseAddr("192.168.0.99"), Dst: netip.MustParseAddr("142.250.185.198"),
				SrcPort: 54321, DstPort: 443, Seq: 1000, Ack: 2000,
				Flags: proto.TCPPsh | proto.TCPAck, Window: 65535, TTL: 64,
				TCPOpts: opts, Payload: hello,
			}
			raw, err := tm.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			pkt, err := proto.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := eng.OnTCP(pkt)
			if err != nil {
				t.Fatalf("OnTCP: %v", err)
			}
			if plan == nil {
				t.Fatalf("%s: no plan (no profile matched)", name)
			}
			t.Logf("%s: %d seg(s), drop-original=%v, degraded=%v", name, len(plan.Segs), plan.DropOriginal, plan.Degraded)
			for i, sg := range plan.Segs {
				t.Logf("  seg[%d] kind=%v seqoff=%d len=%d ttl=%d repeats=%d fool=%#x",
					i, sg.Kind, sg.SeqOff, len(sg.Data), sg.TTL, sg.Repeats, sg.Fool)
			}
			out, err := BuildPlanPackets(pkt, plan, BuildOpts{IPIDStart: 0x1000})
			if err != nil {
				t.Fatalf("BuildPlanPackets: %v", err)
			}
			t.Logf("%s: %d packet(s) on the wire", name, len(out))
			for i, b := range out {
				p, perr := proto.Parse(b)
				if perr != nil {
					t.Errorf("  pkt[%d] unparseable: %v", i, perr)
					continue
				}
				ts, echo, hasTS := proto.TCPTimestamps(p.TCPOpts)
				l4 := append([]byte(nil), b[p.L3Len:]...)
				got := uint16(l4[16])<<8 | uint16(l4[17])
				l4[16], l4[17] = 0, 0
				sumOK := proto.L4Checksum(p.Src, p.Dst, p.Proto, l4) == got
				t.Logf("  pkt[%d] seq=%d len=%d ttl=%d ipid=%#x ts=%v(%d,%d) l4sum_valid=%v",
					i, p.Seq, len(p.Payload()), p.TTL, p.IPID, hasTS, ts, echo, sumOK)
			}
		})
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
