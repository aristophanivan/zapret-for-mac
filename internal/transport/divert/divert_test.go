//go:build darwin

package divert

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/engine"
	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
	"github.com/naladwepo/zapret-for-mac/internal/transport"
)

// requireRoot skips a test that needs euid 0 (a utun control socket, /dev/bpf).
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: creating a utun and opening /dev/bpf are both privileged")
	}
}

// ---------------------------------------------------------------------------
// utun framing
// ---------------------------------------------------------------------------

func TestUtunPrefixRoundTrip(t *testing.T) {
	cases := []struct {
		ver  uint8
		want uint32
	}{
		{4, uint32(unix.AF_INET)},
		{6, uint32(unix.AF_INET6)},
		{0, uint32(unix.AF_INET)}, // anything not 6 frames as IPv4
	}
	for _, tc := range cases {
		p := utunPrefix(tc.ver)
		if got := binary.BigEndian.Uint32(p[:]); got != tc.want {
			t.Errorf("utunPrefix(%d) = %#x, want %#x", tc.ver, got, tc.want)
		}
		if p[0] != 0 || p[1] != 0 || p[2] != 0 {
			t.Errorf("utunPrefix(%d) = %#x, the family must be big-endian in 4 bytes", tc.ver, p)
		}
	}

	body := []byte{0x45, 0x00, 0x00, 0x14}
	for _, ver := range []uint8{4, 6} {
		p := utunPrefix(ver)
		buf := append(append([]byte(nil), p[:]...), body...)
		gotVer, gotPkt, ok := utunDecode(buf)
		if !ok {
			t.Fatalf("utunDecode rejected a %d-byte framed packet", len(buf))
		}
		if gotVer != ver {
			t.Errorf("utunDecode reported version %d, want %d", gotVer, ver)
		}
		if string(gotPkt) != string(body) {
			t.Errorf("utunDecode returned %#x, want %#x", gotPkt, body)
		}
	}

	if _, _, ok := utunDecode([]byte{0, 0, 0}); ok {
		t.Errorf("utunDecode accepted a buffer shorter than the 4-byte prefix")
	}
	// An unknown address family must not be guessed at.
	unknown := []byte{0, 0, 0, 99, 0x45}
	if ver, _, ok := utunDecode(unknown); !ok || ver != 0 {
		t.Errorf("utunDecode(AF 99) = ver %d ok %v, want ver 0 ok true", ver, ok)
	}
}

// ---------------------------------------------------------------------------
// Ethernet framing
// ---------------------------------------------------------------------------

func TestBuildEthFrame(t *testing.T) {
	dstMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	srcMAC := net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	payload := make([]byte, 80)
	for i := range payload {
		payload[i] = byte(i)
	}

	for _, tc := range []struct {
		ver  uint8
		want uint16
	}{{4, 0x0800}, {6, 0x86dd}} {
		frame, err := buildEthFrame(nil, dstMAC, srcMAC, ethTypeFor(tc.ver), payload)
		if err != nil {
			t.Fatalf("buildEthFrame: %v", err)
		}
		if len(frame) != ethHdrLen+len(payload) {
			t.Fatalf("frame is %d bytes, want %d", len(frame), ethHdrLen+len(payload))
		}
		if string(frame[0:6]) != string(dstMAC) {
			t.Errorf("destination MAC = %x, want %x", frame[0:6], dstMAC)
		}
		if string(frame[6:12]) != string(srcMAC) {
			t.Errorf("source MAC = %x, want %x", frame[6:12], srcMAC)
		}
		if got := binary.BigEndian.Uint16(frame[12:14]); got != tc.want {
			t.Errorf("ethertype for IPv%d = %#x, want %#x", tc.ver, got, tc.want)
		}
		if string(frame[14:]) != string(payload) {
			t.Errorf("the payload was not copied verbatim")
		}
	}

	// A short packet is padded to the Ethernet minimum.
	short := []byte{0x45, 1, 2, 3}
	frame, err := buildEthFrame(nil, dstMAC, srcMAC, ethTypeIPv4, short)
	if err != nil {
		t.Fatalf("buildEthFrame(short): %v", err)
	}
	if len(frame) != ethMinFrame {
		t.Errorf("short frame is %d bytes, want the %d-byte minimum", len(frame), ethMinFrame)
	}
	for i := ethHdrLen + len(short); i < len(frame); i++ {
		if frame[i] != 0 {
			t.Errorf("padding byte %d = %#x, want 0", i, frame[i])
		}
	}

	// The scratch buffer is reused, so a second call must not leak the first
	// call's bytes past the new length.
	buf := make([]byte, 0, 256)
	f1, _ := buildEthFrame(buf, dstMAC, srcMAC, ethTypeIPv4, payload)
	f2, err := buildEthFrame(f1[:0], srcMAC, dstMAC, ethTypeIPv6, short)
	if err != nil {
		t.Fatalf("buildEthFrame(reuse): %v", err)
	}
	if len(f2) != ethMinFrame {
		t.Errorf("reused frame is %d bytes, want %d", len(f2), ethMinFrame)
	}
	if string(f2[0:6]) != string(srcMAC) {
		t.Errorf("reused frame kept the old destination MAC")
	}

	if _, err := buildEthFrame(nil, dstMAC[:5], srcMAC, ethTypeIPv4, payload); err == nil {
		t.Errorf("a 5-byte MAC must be rejected")
	}
	if _, err := buildEthFrame(nil, dstMAC, srcMAC, ethTypeIPv4, nil); err == nil {
		t.Errorf("an empty payload must be rejected")
	}
}

func TestIPVersionAndDest(t *testing.T) {
	v4 := origTCP(t, []byte("x"), nil)
	if ipVersionOf(v4.Raw) != 4 {
		t.Errorf("ipVersionOf(IPv4) = %d", ipVersionOf(v4.Raw))
	}
	if dst, ok := ipDestOf(v4.Raw); !ok || dst != testDst4 {
		t.Errorf("ipDestOf(IPv4) = %s ok %v, want %s", dst, ok, testDst4)
	}

	v6 := origTCP6(t, []byte("x"), nil)
	if ipVersionOf(v6.Raw) != 6 {
		t.Errorf("ipVersionOf(IPv6) = %d", ipVersionOf(v6.Raw))
	}
	if dst, ok := ipDestOf(v6.Raw); !ok || dst != testDst6 {
		t.Errorf("ipDestOf(IPv6) = %s ok %v, want %s", dst, ok, testDst6)
	}

	if _, ok := ipDestOf(nil); ok {
		t.Errorf("ipDestOf(nil) reported success")
	}
	if _, ok := ipDestOf([]byte{0x45, 0, 0}); ok {
		t.Errorf("ipDestOf on a truncated IPv4 header reported success")
	}
	if _, ok := ipDestOf([]byte{0x60, 0, 0}); ok {
		t.Errorf("ipDestOf on a truncated IPv6 header reported success")
	}
}

// ---------------------------------------------------------------------------
// the inbound BPF filter, run through a miniature BPF machine
// ---------------------------------------------------------------------------

// runBPF interprets the subset of BPF that inboundFilter emits and returns the
// program's verdict (the accepted byte count, 0 for a reject). An out-of-range
// load rejects the packet, which is what the kernel machine does too.
func runBPF(t *testing.T, prog []unix.BpfInsn, pkt []byte) uint32 {
	t.Helper()
	var a, x uint32
	for pc, steps := 0, 0; pc < len(prog); steps++ {
		if steps > 4096 {
			t.Fatalf("BPF program did not terminate")
		}
		in := prog[pc]
		switch in.Code {
		case bpfLDHAbs:
			if int(in.K)+2 > len(pkt) {
				return 0
			}
			a = uint32(binary.BigEndian.Uint16(pkt[in.K : in.K+2]))
			pc++
		case bpfLDBAbs:
			if int(in.K)+1 > len(pkt) {
				return 0
			}
			a = uint32(pkt[in.K])
			pc++
		case bpfLDHInd:
			off := int(x) + int(in.K)
			if off < 0 || off+2 > len(pkt) {
				return 0
			}
			a = uint32(binary.BigEndian.Uint16(pkt[off : off+2]))
			pc++
		case bpfLDXMsh:
			if int(in.K)+1 > len(pkt) {
				return 0
			}
			x = uint32(pkt[in.K]&0x0f) * 4
			pc++
		case bpfJEQ, bpfJGT, bpfJGE, bpfJSET:
			var take bool
			switch in.Code {
			case bpfJEQ:
				take = a == in.K
			case bpfJGT:
				take = a > in.K
			case bpfJGE:
				take = a >= in.K
			case bpfJSET:
				take = a&in.K != 0
			}
			if take {
				pc += 1 + int(in.Jt)
			} else {
				pc += 1 + int(in.Jf)
			}
		case bpfJA:
			pc += 1 + int(in.K)
		case bpfRET:
			return in.K
		default:
			t.Fatalf("runBPF: unsupported opcode %#x at %d", in.Code, pc)
		}
	}
	t.Fatalf("BPF program ran off the end without a ret")
	return 0
}

// ethFrameFor wraps an IP packet in an Ethernet header for the filter tests.
func ethFrameFor(t *testing.T, etherType uint16, ip []byte) []byte {
	t.Helper()
	mac := net.HardwareAddr{1, 2, 3, 4, 5, 6}
	frame, err := buildEthFrame(nil, mac, mac, etherType, ip)
	if err != nil {
		t.Fatalf("buildEthFrame: %v", err)
	}
	return frame
}

// inboundIP builds a server->client packet with the given source port.
func inboundIP(t *testing.T, v6, udp bool, srcPort uint16) []byte {
	t.Helper()
	tm := proto.Tmpl{
		Src: testDst4, Dst: testSrc4,
		SrcPort: srcPort, DstPort: testSrcPort,
		Seq: 77, Ack: 88, Flags: proto.TCPSyn | proto.TCPAck,
		Window: 65535, TTL: 55, UDP: udp, Payload: []byte("reply"),
	}
	if v6 {
		tm.Src, tm.Dst = testDst6, testSrc6
	}
	raw, err := tm.Marshal()
	if err != nil {
		t.Fatalf("building the inbound fixture: %v", err)
	}
	return raw
}

func TestInboundFilterAcceptsWindowPortsOnly(t *testing.T) {
	ports := []netcfg.PortRange{{443, 443}, {80, 80}, {19294, 19344}}
	prog, filtered, err := inboundFilter(ports)
	if err != nil {
		t.Fatalf("inboundFilter: %v", err)
	}
	if !filtered {
		t.Fatalf("a 3-range window must be enforced by the kernel program")
	}
	if len(prog) > 512 {
		t.Fatalf("program is %d instructions, over BPF_MAXINSNS", len(prog))
	}

	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"ipv4 tcp from 443", ethFrameFor(t, ethTypeIPv4, inboundIP(t, false, false, 443)), true},
		{"ipv4 tcp from 80", ethFrameFor(t, ethTypeIPv4, inboundIP(t, false, false, 80)), true},
		{"ipv4 tcp from 8080", ethFrameFor(t, ethTypeIPv4, inboundIP(t, false, false, 8080)), false},
		{"ipv4 udp from 443", ethFrameFor(t, ethTypeIPv4, inboundIP(t, false, true, 443)), true},
		{"ipv4 udp inside the discord range", ethFrameFor(t, ethTypeIPv4, inboundIP(t, false, true, 19300)), true},
		{"ipv4 udp just below the range", ethFrameFor(t, ethTypeIPv4, inboundIP(t, false, true, 19293)), false},
		{"ipv4 udp just above the range", ethFrameFor(t, ethTypeIPv4, inboundIP(t, false, true, 19345)), false},
		{"ipv6 tcp from 443", ethFrameFor(t, ethTypeIPv6, inboundIP(t, true, false, 443)), true},
		{"ipv6 udp from 19294", ethFrameFor(t, ethTypeIPv6, inboundIP(t, true, true, 19294)), true},
		{"ipv6 tcp from 8080", ethFrameFor(t, ethTypeIPv6, inboundIP(t, true, false, 8080)), false},
		{"arp", ethFrameFor(t, 0x0806, make([]byte, 28)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runBPF(t, prog, tc.frame)
			if (got > 0) != tc.want {
				t.Errorf("verdict = %d, want accepted=%v", got, tc.want)
			}
			if tc.want && got != observeSnapLen {
				t.Errorf("accepted with a snapshot length of %d, want %d", got, observeSnapLen)
			}
		})
	}
}

func TestInboundFilterRejectsNonInitialFragments(t *testing.T) {
	prog, _, err := inboundFilter([]netcfg.PortRange{{443, 443}})
	if err != nil {
		t.Fatalf("inboundFilter: %v", err)
	}
	ip := inboundIP(t, false, false, 443)
	// Set a non-zero fragment offset: the bytes at the "source port" position are
	// then payload, so reading them would be nonsense.
	binary.BigEndian.PutUint16(ip[6:8], 0x0001)
	if got := runBPF(t, prog, ethFrameFor(t, ethTypeIPv4, ip)); got != 0 {
		t.Errorf("a non-initial fragment was accepted (verdict %d)", got)
	}
}

func TestInboundFilterHandlesIPv4Options(t *testing.T) {
	// ihl = 6 words: a 24-byte header. The source port then sits 4 bytes further
	// in, which is exactly what the BPF_MSH indirection is for.
	prog, _, err := inboundFilter([]netcfg.PortRange{{443, 443}})
	if err != nil {
		t.Fatalf("inboundFilter: %v", err)
	}
	ip := make([]byte, 24+20)
	ip[0] = 0x46 // version 4, ihl 6
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 55
	ip[9] = proto.IPProtoTCP
	copy(ip[12:16], testDst4.AsSlice())
	copy(ip[16:20], testSrc4.AsSlice())
	ip[20], ip[21], ip[22], ip[23] = 1, 1, 1, 1 // NOP IP options
	binary.BigEndian.PutUint16(ip[24:26], 443)  // source port
	binary.BigEndian.PutUint16(ip[26:28], 51000)

	if got := runBPF(t, prog, ethFrameFor(t, ethTypeIPv4, ip)); got == 0 {
		t.Errorf("a packet with IP options was rejected; the ihl indirection is wrong")
	}
	binary.BigEndian.PutUint16(ip[24:26], 8080)
	if got := runBPF(t, prog, ethFrameFor(t, ethTypeIPv4, ip)); got != 0 {
		t.Errorf("an out-of-window port with IP options was accepted (verdict %d)", got)
	}
}

func TestInboundFilterWithoutAWindowAcceptsAllTCPUDP(t *testing.T) {
	prog, filtered, err := inboundFilter(nil)
	if err != nil {
		t.Fatalf("inboundFilter: %v", err)
	}
	if filtered {
		t.Errorf("an empty window cannot be enforced in the kernel")
	}
	if got := runBPF(t, prog, ethFrameFor(t, ethTypeIPv4, inboundIP(t, false, false, 9999))); got == 0 {
		t.Errorf("an unfiltered program must accept every TCP packet")
	}
	if got := runBPF(t, prog, ethFrameFor(t, 0x0806, make([]byte, 28))); got != 0 {
		t.Errorf("even an unfiltered program must reject ARP")
	}
}

func TestInboundFilterFallsBackPastTheRangeCap(t *testing.T) {
	var many []netcfg.PortRange
	for i := 0; i < maxFilterRanges+5; i++ {
		p := uint16(1000 + i*10) // spaced out so they never merge
		many = append(many, netcfg.PortRange{p, p})
	}
	prog, filtered, err := inboundFilter(many)
	if err != nil {
		t.Fatalf("inboundFilter: %v", err)
	}
	if filtered {
		t.Errorf("more than %d ranges must degrade to a userspace check", maxFilterRanges)
	}
	if got := runBPF(t, prog, ethFrameFor(t, ethTypeIPv4, inboundIP(t, false, false, 1))); got == 0 {
		t.Errorf("the fallback program must accept every TCP packet")
	}
}

func TestNormalisePortRanges(t *testing.T) {
	got := normalisePortRanges([]netcfg.PortRange{
		{443, 443}, {80, 80}, {444, 500}, {90, 85}, {0, 0}, {443, 443}, {501, 510},
	})
	want := []netcfg.PortRange{{80, 80}, {85, 90}, {443, 510}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("range %d = %v, want %v", i, got[i], want[i])
		}
	}
	// The 0xffff edge must not wrap when merging.
	if got := normalisePortRanges([]netcfg.PortRange{{65535, 65535}, {1, 1}}); len(got) != 2 {
		t.Errorf("normalisePortRanges lost a range at the 65535 edge: %v", got)
	}
}

func TestBPFAsmRejectsBadPrograms(t *testing.T) {
	a := newBPFAsm()
	a.jump(bpfJEQ, 1, "nowhere", "drop")
	a.label("drop")
	a.op(bpfRET, 0)
	if _, err := a.assemble(); err == nil || !strings.Contains(err.Error(), "undefined") {
		t.Errorf("an undefined label must be reported, got %v", err)
	}

	b := newBPFAsm()
	b.label("back")
	b.op(bpfRET, 0)
	b.jump(bpfJEQ, 1, "back", "back")
	if _, err := b.assemble(); err == nil || !strings.Contains(err.Error(), "backward") {
		t.Errorf("a backward jump must be reported, got %v", err)
	}

	c := newBPFAsm()
	c.jump(bpfJEQ, 1, "far", "far")
	for i := 0; i < 300; i++ {
		c.op(bpfRET, 0)
	}
	c.label("far")
	c.op(bpfRET, 0)
	if _, err := c.assemble(); err == nil || !strings.Contains(err.Error(), "field holds") {
		t.Errorf("an unencodable displacement must be reported, got %v", err)
	}

	d := newBPFAsm()
	d.label("dup")
	d.label("dup")
	d.op(bpfRET, 0)
	if _, err := d.assemble(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("a duplicate label must be reported, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// truncated-capture parsing
// ---------------------------------------------------------------------------

func TestParseTruncatedIP(t *testing.T) {
	full := inboundIP(t, false, false, 443)
	// Cut the packet short, the way a 128-byte BPF snapshot would.
	for _, n := range []int{len(full), 40, 24} {
		p, ok := parseTruncatedIP(full[:n])
		if !ok {
			t.Fatalf("a %d-byte prefix of a 40-byte packet was rejected", n)
		}
		if p.TTL != 55 {
			t.Errorf("TTL = %d, want 55", p.TTL)
		}
		if p.SrcPort != 443 || p.DstPort != testSrcPort {
			t.Errorf("ports = %d -> %d, want 443 -> %d", p.SrcPort, p.DstPort, testSrcPort)
		}
		if p.Src != testDst4 || p.Dst != testSrc4 {
			t.Errorf("addresses = %s -> %s", p.Src, p.Dst)
		}
		if !p.IsTCP() {
			t.Errorf("protocol = %d, want TCP", p.Proto)
		}
	}

	v6 := inboundIP(t, true, true, 443)
	p, ok := parseTruncatedIP(v6[:48])
	if !ok {
		t.Fatalf("a truncated IPv6/UDP capture was rejected")
	}
	if !p.IsUDP() || p.SrcPort != 443 || p.TTL != 55 {
		t.Errorf("IPv6 parse gave proto %d port %d ttl %d", p.Proto, p.SrcPort, p.TTL)
	}

	// Hostile and useless inputs must be rejected, never panic.
	for _, bad := range [][]byte{
		nil,
		{0x45},
		{0x45, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}, // no L4 bytes
		{0x60},
		{0x35, 0, 0, 0}, // version 3
	} {
		if _, ok := parseTruncatedIP(bad); ok {
			t.Errorf("parseTruncatedIP(%#x) reported success", bad)
		}
	}

	// An IPv4 header claiming ihl 15 with only 20 captured bytes.
	short := append([]byte(nil), full...)
	short[0] = 0x4f
	if _, ok := parseTruncatedIP(short[:20]); ok {
		t.Errorf("a header longer than the capture reported success")
	}

	// A non-initial fragment has no ports to read.
	frag := append([]byte(nil), full...)
	binary.BigEndian.PutUint16(frag[6:8], 0x0002)
	if _, ok := parseTruncatedIP(frag); ok {
		t.Errorf("a non-initial fragment reported success")
	}
}

func TestPortInRanges(t *testing.T) {
	r := []netcfg.PortRange{{443, 443}, {19344, 19294}} // reversed pair must be tolerated
	for _, tc := range []struct {
		p    uint16
		want bool
	}{{443, true}, {442, false}, {19294, true}, {19344, true}, {19345, false}} {
		if got := portInRanges(tc.p, r); got != tc.want {
			t.Errorf("portInRanges(%d) = %v, want %v", tc.p, got, tc.want)
		}
	}
	if !portInRanges(1, nil) {
		t.Errorf("an empty window must match everything")
	}
}

// ---------------------------------------------------------------------------
// pf rule generation
// ---------------------------------------------------------------------------

// testStrategy is a two-window strategy standing in for a converted .bat.
func testStrategy() *strategy.Strategy {
	return &strategy.Strategy{
		Name:      "unit",
		WindowTCP: strategy.PortSet{{Lo: 80, Hi: 80}, {Lo: 443, Hi: 443}},
		WindowUDP: strategy.PortSet{{Lo: 443, Hi: 443}, {Lo: 19294, Hi: 19344}},
	}
}

// testUtun is a utunHandle with no kernel object behind it: enough for the rule
// generators, which only read the name and the addresses.
func testUtun() *utunHandle {
	return &utunHandle{
		fd:    -1,
		Name:  "utun9",
		Local: netip.MustParseAddr(DefaultTunLocal),
		Peer:  netip.MustParseAddr(DefaultTunPeer),
		MTU:   1500,
	}
}

// newTestTransport builds a Transport that never touches the kernel.
func newTestTransport(t *testing.T, cfg transport.Config) *Transport {
	t.Helper()
	strat := testStrategy()
	if cfg.Strategy == nil {
		cfg.Strategy = strat
	}
	if cfg.Engine == nil {
		cfg.Engine = engine.New(cfg.Strategy, desync.FullCaps(), desync.FakeSet{})
	}
	tr, err := New(cfg, Options{Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tr.utun = testUtun()
	return tr
}

func TestSteerRulesForAStrategyWindow(t *testing.T) {
	tr := newTestTransport(t, transport.Config{ExemptRoot: true, BlockQUIC: true})
	rules, err := tr.steerRules()
	if err != nil {
		t.Fatalf("steerRules: %v", err)
	}
	for _, want := range []string{
		"pass quick on lo0 all",
		"route-to (utun9 198.18.0.2)",
		"inet proto tcp",
		"inet proto udp",
		"port { 80 443 }",
		"port { 443 19294:19344 }",
		"user { > root }",
		"no state",
		"block return-icmp out quick inet proto udp",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("the ruleset is missing %q:\n%s", want, rules)
		}
	}
	// The block rule has to precede the UDP steering rule, or `quick` would make
	// it unreachable for every port both rules cover.
	if i, j := strings.Index(rules, "block return-icmp"), strings.Index(rules, "proto udp from any to any port { 443"); i < 0 || j < 0 || i > j {
		t.Errorf("BlockQUIC must come before the UDP steering rule:\n%s", rules)
	}
}

func TestSteerRulesForceExemptRootOnTheRawInjector(t *testing.T) {
	tr := newTestTransport(t, transport.Config{ExemptRoot: false})
	tr.inj = &rawInjector{fd: -1}

	rules, err := tr.steerRules()
	if err != nil {
		t.Fatalf("steerRules: %v", err)
	}
	if !strings.Contains(rules, "user { > root }") {
		t.Fatalf("the raw injector goes through pf, so `user { > root }` is mandatory:\n%s", rules)
	}
	found := false
	for _, w := range tr.Warnings() {
		if strings.Contains(w, "ExemptRoot") && strings.Contains(w, "loop") {
			found = true
		}
	}
	if !found {
		t.Errorf("forcing ExemptRoot must be reported as a warning, got %v", tr.Warnings())
	}
}

func TestSteerRulesIPv6Merge(t *testing.T) {
	tr := newTestTransport(t, transport.Config{ExemptRoot: true})
	tr.opts.IPv6 = true
	tr.utun.HaveIPv6 = true
	tr.utun.Peer6 = netip.MustParseAddr(DefaultTunPeer6)

	rules, err := tr.steerRules()
	if err != nil {
		t.Fatalf("steerRules: %v", err)
	}
	if !strings.Contains(rules, "inet proto tcp") || !strings.Contains(rules, "inet6 proto tcp") {
		t.Errorf("both families must be steered:\n%s", rules)
	}
	if !strings.Contains(rules, "route-to (utun9 2001:2::2)") {
		t.Errorf("the inet6 rule must use the IPv6 peer:\n%s", rules)
	}
	if n := strings.Count(rules, "pass quick on lo0 all"); n != 1 {
		t.Errorf("the loopback pass appears %d times, want exactly 1:\n%s", n, rules)
	}
}

func TestSteerRulesNeedsAWindow(t *testing.T) {
	tr := newTestTransport(t, transport.Config{})
	tr.strat = &strategy.Strategy{Name: "empty"}
	rules, err := tr.steerRules()
	if err != nil {
		t.Fatalf("steerRules: %v", err)
	}
	if strings.Contains(rules, "route-to") {
		t.Errorf("a strategy with no window must not produce a steering rule:\n%s", rules)
	}
}

func TestMergeRulesets(t *testing.T) {
	a := "table <zmx> persist\npass quick on lo0 all\npass out quick route-to (utun9 198.18.0.2) inet proto tcp\n"
	b := "table <zmx> persist\npass out quick route-to (utun9 2001:2::2) inet6 proto tcp\n"
	got := mergeRulesets(a, b)
	if n := strings.Count(got, "table <zmx> persist"); n != 1 {
		t.Errorf("the table declaration appears %d times, want 1:\n%s", n, got)
	}
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("want 4 lines, got %d:\n%s", len(lines), got)
	}
	if lines[0] != "table <zmx> persist" {
		t.Errorf("the table declaration must stay first, got %q", lines[0])
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("a pf ruleset must end with a newline")
	}
	if mergeRulesets("", "") != "" {
		t.Errorf("two empty rulesets must merge to nothing")
	}
}

func TestPortRangesAndWindowUnion(t *testing.T) {
	s := testStrategy()
	tcp := portRanges(s.WindowTCP)
	if len(tcp) != 2 || tcp[0] != (netcfg.PortRange{80, 80}) || tcp[1] != (netcfg.PortRange{443, 443}) {
		t.Errorf("portRanges(WindowTCP) = %v", tcp)
	}
	if portRanges(nil) != nil {
		t.Errorf("an empty PortSet must convert to nil, not to an empty non-nil slice")
	}
	if got := len(windowUnion(s)); got != 4 {
		t.Errorf("windowUnion covers %d ranges, want 4 (2 TCP + 2 UDP)", got)
	}
	if windowUnion(nil) != nil {
		t.Errorf("windowUnion(nil) must be nil")
	}
}

// ---------------------------------------------------------------------------
// lifecycle without root
// ---------------------------------------------------------------------------

func TestNewValidatesItsInput(t *testing.T) {
	if _, err := New(transport.Config{}, Options{}); err == nil {
		t.Errorf("New must reject a Config with no Engine")
	}
	strat := testStrategy()
	eng := engine.New(strat, desync.FullCaps(), desync.FakeSet{})
	if _, err := New(transport.Config{Engine: eng}, Options{}); err == nil {
		t.Errorf("New must reject a Config with no Strategy")
	}
	tr, err := New(transport.Config{Engine: eng, Strategy: strat}, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if tr.opts.Anchor != DefaultAnchor {
		t.Errorf("anchor = %q, want the default %q", tr.opts.Anchor, DefaultAnchor)
	}
	if tr.Name() != "divert" {
		t.Errorf("Name() = %q", tr.Name())
	}
	if tr.Caps() != desync.FullCaps() {
		t.Errorf("Caps() before Start must be the full set, got %+v", tr.Caps())
	}

	// A table with contents but no name gets the default name, so the prefixes
	// cannot silently go nowhere.
	tr2, err := New(transport.Config{Engine: eng, Strategy: strat}, Options{
		ExcludePrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if tr2.opts.ExcludeTable != DefaultExcludeTable {
		t.Errorf("exclude table = %q, want %q", tr2.opts.ExcludeTable, DefaultExcludeTable)
	}
}

func TestCapsFollowTheInjector(t *testing.T) {
	tr := newTestTransport(t, transport.Config{})
	raw := &rawInjector{fd: -1}
	tr.caps = raw.Caps()

	got := tr.Caps()
	if got.IPID {
		t.Errorf("the raw injector cannot honour ip_id=zero, Caps.IPID must be false")
	}
	if got.IPv6ExtHdr {
		t.Errorf("the raw injector cannot emit IPv6, Caps.IPv6ExtHdr must be false")
	}
	if !got.Inject || !got.Seq || !got.Frag || !got.PerPacketTTL || !got.Fooling {
		t.Errorf("the raw injector still owns the IPv4 header, got %+v", got)
	}
	if raw.Limits() == "" {
		t.Errorf("a degraded injector must describe its limits")
	}
	if (&bpfInjector{}).Limits() != "" {
		t.Errorf("the BPF injector imposes no limits")
	}
	if (&bpfInjector{}).Caps() != desync.FullCaps() {
		t.Errorf("the BPF injector must report the full capability set")
	}
}

func TestCloseAndTeardownAreIdempotent(t *testing.T) {
	tr := newTestTransport(t, transport.Config{})
	tr.utun = nil // nothing was ever created
	if err := tr.Close(); err != nil {
		t.Errorf("Close without Start = %v, want nil", err)
	}
	if err := tr.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
	if err := tr.teardown(); err != nil {
		t.Errorf("teardown after Close = %v, want nil", err)
	}
}

func TestStatsShape(t *testing.T) {
	tr := newTestTransport(t, transport.Config{})
	tr.st.pktsIn.Store(10)
	tr.st.pktsOut.Store(7)
	tr.st.pktsInject.Store(21)
	tr.st.pktsDropped.Store(3)
	tr.st.tapDrop.Store(5)
	tr.st.utunDrop.Store(2)
	tr.st.errs.Store(1)

	s := tr.Stats()
	if s.Transport != "divert" {
		t.Errorf("Transport = %q, want \"divert\" before an injector exists", s.Transport)
	}
	if s.PktsIn != 10 || s.PktsOut != 7 || s.PktsInject != 21 || s.PktsDropped != 3 {
		t.Errorf("packet counters did not survive: %+v", s)
	}
	if s.QueueDrop != 7 {
		t.Errorf("QueueDrop = %d, want the sum of the tap (5) and utun (2) drops", s.QueueDrop)
	}
	if s.Errors != 1 {
		t.Errorf("Errors = %d, want 1", s.Errors)
	}

	tr.inj = &rawInjector{fd: -1}
	if got := tr.Stats().Transport; got != "divert/raw" {
		t.Errorf("Transport = %q, want \"divert/raw\"", got)
	}
}

func TestReloadWithoutAPFHandle(t *testing.T) {
	tr := newTestTransport(t, transport.Config{})
	if err := tr.Reload(nil); err == nil {
		t.Errorf("Reload(nil) must be rejected")
	}
	next := &strategy.Strategy{Name: "next", WindowTCP: strategy.PortSet{{Lo: 8443, Hi: 8443}}}
	if err := tr.Reload(next); err != nil {
		t.Errorf("Reload before Start = %v, want nil", err)
	}
	if tr.strategyName() != "next" {
		t.Errorf("the strategy was not swapped: %q", tr.strategyName())
	}
}

func TestParseAddrDefault(t *testing.T) {
	if a, err := parseAddrDefault("", DefaultTunLocal); err != nil || a.String() != DefaultTunLocal {
		t.Errorf("an empty string must fall back to %s, got %s / %v", DefaultTunLocal, a, err)
	}
	if a, err := parseAddrDefault("  10.1.2.3 ", ""); err != nil || a.String() != "10.1.2.3" {
		t.Errorf("surrounding whitespace must be tolerated, got %s / %v", a, err)
	}
	if _, err := parseAddrDefault("not-an-ip", ""); err == nil {
		t.Errorf("a malformed address must be rejected")
	}
	// An IPv4-mapped IPv6 literal must come back as plain IPv4, or the utun
	// configuration ioctl would get the wrong family.
	if a, err := parseAddrDefault("::ffff:198.18.0.1", ""); err != nil || !a.Is4() {
		t.Errorf("an IPv4-mapped address must unmap to IPv4, got %s / %v", a, err)
	}
}

func TestPickTunPairAvoidsConfiguredAddresses(t *testing.T) {
	ifaces, err := netcfg.Interfaces()
	if err != nil {
		t.Skipf("cannot read the interface table: %v", err)
	}
	// The default pair must be free on any sane machine, and pickTunPair must say
	// so without moving.
	def4, def4peer := netip.MustParseAddr(DefaultTunLocal), netip.MustParseAddr(DefaultTunPeer)
	local, peer, moved, err := pickTunPair(def4, def4peer)
	if err != nil {
		t.Fatalf("pickTunPair: %v", err)
	}
	if !local.IsValid() || !peer.IsValid() {
		t.Fatalf("pickTunPair returned an invalid pair: %s / %s", local, peer)
	}
	if !moved && (local != def4 || peer != def4peer) {
		t.Errorf("pickTunPair reported no move but changed the pair to %s / %s", local, peer)
	}

	// Feeding it an address that IS configured must move it away.
	var taken netip.Addr
	for _, inf := range ifaces {
		for _, a := range inf.Addrs {
			if a.Is4() && !a.IsLoopback() {
				taken = a
			}
		}
	}
	if !taken.IsValid() {
		t.Skip("no IPv4 interface address to collide with")
	}
	local2, peer2, moved2, err := pickTunPair(taken, def4peer)
	if err != nil {
		t.Fatalf("pickTunPair: %v", err)
	}
	if !moved2 {
		t.Errorf("pickTunPair kept %s, which is configured on an interface", taken)
	}
	if local2 == taken {
		t.Errorf("pickTunPair returned the colliding address %s", taken)
	}
	if !local2.Is4() || !peer2.Is4() {
		t.Errorf("the replacement pair is not IPv4: %s / %s", local2, peer2)
	}
}

func TestForgetIfClosingOnlyOnFinOrRst(t *testing.T) {
	strat := testStrategy()
	eng := engine.New(strat, desync.FullCaps(), desync.FakeSet{})
	tr := newTestTransport(t, transport.Config{Engine: eng, Strategy: strat})

	// Prime a flow, then close it: the entry must be gone afterwards.
	syn := mkPkt(t, proto.Tmpl{
		Src: testSrc4, Dst: testDst4, SrcPort: testSrcPort, DstPort: 443,
		Seq: testSeq, Flags: proto.TCPSyn, Window: testWindow, TTL: testTTL,
	})
	if _, err := eng.OnTCP(syn); err != nil {
		t.Fatalf("OnTCP(SYN): %v", err)
	}
	if eng.FlowCount() != 1 {
		t.Fatalf("the flow was not tracked (count %d)", eng.FlowCount())
	}

	data := mkPkt(t, proto.Tmpl{
		Src: testSrc4, Dst: testDst4, SrcPort: testSrcPort, DstPort: 443,
		Seq: testSeq + 1, Flags: proto.TCPPsh | proto.TCPAck, Window: testWindow,
		TTL: testTTL, Payload: []byte("x"),
	})
	tr.forgetIfClosing(data)
	if eng.FlowCount() != 1 {
		t.Errorf("a plain data packet must not drop the flow state")
	}

	fin := mkPkt(t, proto.Tmpl{
		Src: testSrc4, Dst: testDst4, SrcPort: testSrcPort, DstPort: 443,
		Seq: testSeq + 2, Flags: proto.TCPFin | proto.TCPAck, Window: testWindow, TTL: testTTL,
	})
	tr.forgetIfClosing(fin)
	if eng.FlowCount() != 0 {
		t.Errorf("FIN must drop the flow state (count %d)", eng.FlowCount())
	}
}

func TestInjectorsHonourTheUtunAddressFamily(t *testing.T) {
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}

	// The BPF injector must frame a packet it cannot parse using the family the
	// utun reported, so "forward everything verbatim" really holds. With no
	// descriptor behind it the call gets as far as the write and fails with EBADF,
	// which is precisely the proof that the framing step accepted the buffer.
	bpf := &bpfInjector{srcMAC: mac, gwMAC: mac, mtu: 1500}
	garbage := []byte{0x99, 0x01, 0x02, 0x03}
	if err := bpf.Inject(4, garbage); !errors.Is(err, unix.EBADF) {
		t.Errorf("Inject(AF_INET, garbage) = %v, want it framed and then EBADF from the write", err)
	}
	if err := bpf.Inject(6, garbage); !errors.Is(err, unix.EBADF) {
		t.Errorf("Inject(AF_INET6, garbage) = %v, want it framed and then EBADF", err)
	}
	// With no hint at all there is nothing to frame with, and refusing is right.
	if err := bpf.Inject(0, garbage); err == nil || errors.Is(err, unix.EBADF) {
		t.Errorf("Inject(0, garbage) = %v, want a refusal", err)
	}

	// The raw injector cannot forward what it cannot parse: sendto needs a
	// destination address.
	raw := &rawInjector{fd: -1, mtu: 1500}
	if err := raw.Inject(4, garbage); err == nil {
		t.Errorf("the raw injector accepted a malformed packet")
	}
	v4 := origTCP(t, []byte("x"), nil)
	if err := raw.Inject(6, v4.Raw); err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Errorf("the raw injector must refuse IPv6 explicitly, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// the datapath, with the injector mocked out
// ---------------------------------------------------------------------------

// mockInjector records what the datapath decided to put on the wire.
type mockInjector struct {
	pkts [][]byte
	err  error
}

func (m *mockInjector) Inject(ver uint8, pkt []byte) error {
	if ver != 4 && ver != 6 {
		return fmt.Errorf("mock injector got address family %d", ver)
	}
	if m.err != nil {
		return m.err
	}
	m.pkts = append(m.pkts, append([]byte(nil), pkt...))
	return nil
}
func (m *mockInjector) Name() string      { return "mock" }
func (m *mockInjector) Caps() desync.Caps { return desync.FullCaps() }
func (m *mockInjector) Limits() string    { return "" }
func (m *mockInjector) Close() error      { return nil }
func (m *mockInjector) reset()            { m.pkts = nil; m.err = nil }
func (m *mockInjector) count() int        { return len(m.pkts) }
func (m *mockInjector) last() []byte      { return m.pkts[len(m.pkts)-1] }
func (m *mockInjector) at(i int) []byte   { return m.pkts[i] }

// splitStrategy is a strategy that multisplits every TCP/443 payload at offset 2.
func splitStrategy(t *testing.T) *strategy.Strategy {
	t.Helper()
	op, err := desync.Lookup("multisplit")
	if err != nil {
		t.Fatalf("looking up multisplit: %v", err)
	}
	return &strategy.Strategy{
		Name:      "split-443",
		WindowTCP: strategy.PortSet{{Lo: 443, Hi: 443}},
		Profiles: []*strategy.Profile{{
			Name: "p1",
			Filter: strategy.Filter{
				Proto: proto.IPProtoTCP,
				Ports: strategy.PortSet{{Lo: 443, Hi: 443}},
			},
			Ops: []strategy.CompiledOp{{
				Op: op,
				Params: desync.OpParams{
					SplitPos: []desync.PosSpec{{Marker: proto.MarkerAbs, Offset: 2}},
				},
			}},
		}},
	}
}

func TestDatapathForwardsWhatItDoesNotUnderstand(t *testing.T) {
	strat := splitStrategy(t)
	eng := engine.New(strat, desync.FullCaps(), desync.FakeSet{})
	tr := newTestTransport(t, transport.Config{Engine: eng, Strategy: strat})
	inj := &mockInjector{}
	tr.inj = inj

	// An ICMP packet: no L4 view, and definitely not ours to desync.
	icmp := make([]byte, 28)
	icmp[0] = 0x45
	binary.BigEndian.PutUint16(icmp[2:4], uint16(len(icmp)))
	icmp[8] = 64
	icmp[9] = proto.IPProtoICMP
	copy(icmp[12:16], testSrc4.AsSlice())
	copy(icmp[16:20], testDst4.AsSlice())

	// A non-initial IPv4 fragment: proto.Parse refuses it, and dropping it would
	// break every fragmented datagram on the machine.
	fragged := append([]byte(nil), origTCP(t, []byte("0123456789"), nil).Raw...)
	binary.BigEndian.PutUint16(fragged[6:8], 0x0002)

	// Outright garbage.
	garbage := []byte{0x99, 0x01, 0x02}

	for name, raw := range map[string][]byte{
		"icmp": icmp, "non-initial fragment": fragged, "garbage": garbage,
	} {
		t.Run(name, func(t *testing.T) {
			inj.reset()
			before := tr.st.pktsOut.Load()
			tr.handle(4, raw)
			if inj.count() != 1 {
				t.Fatalf("want the packet forwarded exactly once, got %d injections", inj.count())
			}
			if name != "garbage" && !bytes.Equal(inj.last(), raw) {
				t.Errorf("the forwarded packet was modified")
			}
			if tr.st.pktsOut.Load() != before+1 {
				t.Errorf("PktsOut was not incremented")
			}
		})
	}
	if tr.st.pktsDropped.Load() != 0 {
		t.Errorf("nothing should have been dropped, got %d", tr.st.pktsDropped.Load())
	}
}

func TestDatapathDesyncsAMatchingPayload(t *testing.T) {
	strat := splitStrategy(t)
	eng := engine.New(strat, desync.FullCaps(), desync.FakeSet{})
	tr := newTestTransport(t, transport.Config{Engine: eng, Strategy: strat})
	inj := &mockInjector{}
	tr.inj = inj

	// A bare SYN carries no payload, so no op fires and it must pass through.
	syn := mkPkt(t, proto.Tmpl{
		Src: testSrc4, Dst: testDst4, SrcPort: testSrcPort, DstPort: 443,
		Seq: testSeq, Flags: proto.TCPSyn, Window: testWindow, TTL: testTTL, DF: true,
	})
	tr.handle(4, syn.Raw)
	if inj.count() != 1 || !bytes.Equal(inj.last(), syn.Raw) {
		t.Fatalf("the SYN was not forwarded unchanged (%d injections)", inj.count())
	}

	// The request itself: the profile matches, multisplit cuts at offset 2, and
	// the original must NOT also go out or the server would see it twice.
	inj.reset()
	payload := []byte("hello there, dpi")
	data := mkPkt(t, proto.Tmpl{
		Src: testSrc4, Dst: testDst4, SrcPort: testSrcPort, DstPort: 443,
		Seq: testSeq + 1, Ack: testAck, Flags: proto.TCPPsh | proto.TCPAck,
		Window: testWindow, TTL: testTTL, DF: true, Payload: payload,
	})
	before := tr.st.pktsOut.Load()
	tr.handle(4, data.Raw)

	if inj.count() != 2 {
		t.Fatalf("want 2 injected segments, got %d", inj.count())
	}
	if tr.st.pktsOut.Load() != before {
		t.Errorf("the original packet was forwarded as well as the split segments")
	}
	if tr.st.pktsDropped.Load() != 1 {
		t.Errorf("PktsDropped = %d, want 1", tr.st.pktsDropped.Load())
	}
	if tr.st.pktsInject.Load() != 2 {
		t.Errorf("PktsInject = %d, want 2", tr.st.pktsInject.Load())
	}

	first := decode(t, inj.at(0))
	second := decode(t, inj.at(1))
	if got := string(first.pkt.Payload()); got != string(payload[:2]) {
		t.Errorf("first segment payload = %q, want %q", got, payload[:2])
	}
	if got := string(second.pkt.Payload()); got != string(payload[2:]) {
		t.Errorf("second segment payload = %q, want %q", got, payload[2:])
	}
	if first.pkt.Seq != testSeq+1 || second.pkt.Seq != testSeq+1+2 {
		t.Errorf("segment sequence numbers = %d, %d; want %d, %d",
			first.pkt.Seq, second.pkt.Seq, testSeq+1, testSeq+3)
	}
	if !l4ChecksumOK(t, inj.at(0)) || !l4ChecksumOK(t, inj.at(1)) {
		t.Errorf("a split segment has a broken TCP checksum")
	}

	// A FIN must clear the flow state.
	inj.reset()
	fin := mkPkt(t, proto.Tmpl{
		Src: testSrc4, Dst: testDst4, SrcPort: testSrcPort, DstPort: 443,
		Seq: testSeq + 1 + uint32(len(payload)), Ack: testAck,
		Flags: proto.TCPFin | proto.TCPAck, Window: testWindow, TTL: testTTL, DF: true,
	})
	tr.handle(4, fin.Raw)
	if eng.FlowCount() != 0 {
		t.Errorf("the flow survived the FIN (count %d)", eng.FlowCount())
	}
}

func TestDatapathCountsInjectionFailures(t *testing.T) {
	strat := splitStrategy(t)
	eng := engine.New(strat, desync.FullCaps(), desync.FakeSet{})
	tr := newTestTransport(t, transport.Config{Engine: eng, Strategy: strat})
	inj := &mockInjector{err: unix.ENOBUFS}
	tr.inj = inj

	pkt := mkPkt(t, proto.Tmpl{
		Src: testSrc4, Dst: testDst4, SrcPort: testSrcPort, DstPort: 8080,
		Seq: testSeq, Flags: proto.TCPPsh | proto.TCPAck, Window: testWindow,
		TTL: testTTL, DF: true, Payload: []byte("out of window"),
	})
	tr.handle(4, pkt.Raw)
	if tr.st.errs.Load() != 1 {
		t.Errorf("Errors = %d, want 1 after a failed write", tr.st.errs.Load())
	}
	if tr.st.pktsOut.Load() != 0 {
		t.Errorf("PktsOut counted a write that failed")
	}
	if tr.st.pktsIn.Load() != 1 {
		t.Errorf("PktsIn = %d, want 1", tr.st.pktsIn.Load())
	}
}

func TestDatapathHasNoInjector(t *testing.T) {
	strat := splitStrategy(t)
	eng := engine.New(strat, desync.FullCaps(), desync.FakeSet{})
	tr := newTestTransport(t, transport.Config{Engine: eng, Strategy: strat})
	// tr.inj is nil: every write must fail loudly instead of panicking.
	pkt := origTCP(t, []byte("x"), nil)
	tr.handle(4, pkt.Raw)
	if tr.st.errs.Load() == 0 {
		t.Errorf("a missing injector must be counted as an error")
	}
}

// ---------------------------------------------------------------------------
// privileged paths
// ---------------------------------------------------------------------------

func TestCreateUTUNAsRoot(t *testing.T) {
	requireRoot(t)
	local, peer, _, err := pickTunPair(netip.MustParseAddr(DefaultTunLocal), netip.MustParseAddr(DefaultTunPeer))
	if err != nil {
		t.Fatalf("pickTunPair: %v", err)
	}
	h, err := createUTUN(-1, local, peer, 1500)
	if err != nil {
		t.Fatalf("createUTUN: %v", err)
	}
	defer h.Close()

	if !strings.HasPrefix(h.Name, "utun") {
		t.Errorf("interface name = %q, want utunN", h.Name)
	}
	for _, n := range h.Notes {
		t.Logf("utun configuration note: %s", n)
	}
	ifaces, err := netcfg.Interfaces()
	if err != nil {
		t.Fatalf("netcfg.Interfaces: %v", err)
	}
	inf, ok := ifaces[h.Name]
	if !ok {
		t.Fatalf("%s does not appear in the interface table", h.Name)
	}
	if !inf.Up() {
		t.Errorf("%s is not IFF_UP; pf route-to would not use it", h.Name)
	}
	found := false
	for _, a := range inf.Addrs {
		if a.Unmap() == local {
			found = true
		}
	}
	if !found {
		t.Errorf("%s does not carry %s (addresses: %v)", h.Name, local, inf.Addrs)
	}

	// Closing the control socket must destroy the interface.
	name := h.Name
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if ifaces, err := netcfg.Interfaces(); err == nil {
		if _, still := ifaces[name]; still {
			t.Errorf("%s survived closing its control socket", name)
		}
	}
}

func TestOpenBPFAsRoot(t *testing.T) {
	requireRoot(t)
	r, err := netcfg.DefaultRoute4()
	if err != nil {
		t.Skipf("no IPv4 default route: %v", err)
	}
	if r.IsTunnel {
		t.Skipf("the default route is the tunnel %s; a BPF Ethernet write needs a real link", r.Iface)
	}
	h, err := openBPF(r.Iface, 65536, true, false, nil)
	if err != nil {
		t.Fatalf("openBPF(%s): %v", r.Iface, err)
	}
	defer h.Close()

	if h.Datalink != dltEN10MB {
		t.Errorf("datalink = %d, want DLT_EN10MB (%d)", h.Datalink, dltEN10MB)
	}
	if h.BufLen <= 0 {
		t.Errorf("buffer length = %d", h.BufLen)
	}
	if _, _, err := h.stats(); err != nil {
		t.Errorf("BIOCGSTATS: %v", err)
	}
}

func TestObserverFilterLoadsAsRoot(t *testing.T) {
	requireRoot(t)
	r, err := netcfg.DefaultRoute4()
	if err != nil {
		t.Skipf("no IPv4 default route: %v", err)
	}
	obs, err := newObserver(r.Iface, windowUnion(testStrategy()))
	if err != nil {
		t.Fatalf("newObserver(%s): %v", r.Iface, err)
	}
	defer obs.Close()
	if !obs.Filtered() {
		t.Errorf("the kernel must have accepted the port filter for a 4-range window")
	}
}
