//go:build darwin

package divert

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// The observer is a second, read-only BPF handle on the uplink. Inbound traffic
// is never steered into the utun — that is the design's core simplification —
// so without this tap the engine would never see a server->client packet and
// autottl would have no hop count to work from.
//
// It is strictly optional: if it cannot start, the engine falls back to the
// midpoint of the configured autottl range (see engine.applyTTL).

// observeSnapLen is the BPF snapshot length. A hop count needs the IP header and
// the port pair, nothing else, and the ideal sample — the SYN-ACK — fits well
// inside this, so there is no reason to copy full-MSS data packets through the
// kernel buffer.
const observeSnapLen = 128

// observeBufLen is the kernel read buffer requested via BIOCSBLEN. 256 KiB is
// inside BPF_MAXBUFSIZE (512 KiB on this kernel) and large enough that a busy
// Wi-Fi link does not drop the frames we care about.
const observeBufLen = 256 * 1024

// observePollInterval bounds how long a read waits before the loop rechecks ctx.
const observePollInterval = 250 * time.Millisecond

// observeStatsInterval is how often BIOCGSTATS is sampled into Stats.QueueDrop.
const observeStatsInterval = time.Second

// maxFilterRanges caps how many port ranges are compiled into the BPF program.
// Jump displacements in a BPF instruction are 8 bits, so an unbounded range list
// could produce an unencodable program; past the cap the filter degrades to
// "every inbound TCP/UDP packet" and the port check happens in userspace, which
// is free anyway because engine.OnInbound only touches flows we already track.
const maxFilterRanges = 24

// observer taps inbound traffic on the uplink and feeds it to engine.OnInbound.
type observer struct {
	h     *bpfHandle
	ports []netcfg.PortRange
	// filtered reports whether the kernel program does the port check.
	filtered bool
}

// newObserver opens the read-only tap. ports is the union of the strategy's TCP
// and UDP windows.
func newObserver(iface string, ports []netcfg.PortRange) (*observer, error) {
	prog, filtered, err := inboundFilter(ports)
	if err != nil {
		return nil, err
	}
	// seeSent = false: the tap must never see our own injections, or every
	// re-emitted client packet would be fed back as if it were inbound.
	h, err := openBPF(iface, observeBufLen, false, false, prog)
	if err != nil {
		return nil, err
	}
	return &observer{h: h, ports: ports, filtered: filtered}, nil
}

// Device reports which /dev/bpfN the tap holds.
func (o *observer) Device() string { return o.h.Device }

// Filtered reports whether the port window is enforced by the kernel program.
func (o *observer) Filtered() bool { return o.filtered }

// Run drains the tap until ctx is done. onPkt receives every inbound packet that
// parses; onDrop receives the running BIOCGSTATS drop count.
func (o *observer) Run(ctx context.Context, onPkt func(*proto.Pkt), onDrop func(total uint64)) error {
	buf := make([]byte, o.h.BufLen)
	hdrSize := int(unsafe.Sizeof(unix.BpfHdr{}))
	lastStats := time.Now()

	for {
		if ctx.Err() != nil {
			return nil
		}
		ready, err := waitReadable(o.h.fd, observePollInterval)
		if err != nil {
			return err
		}
		if now := time.Now(); now.Sub(lastStats) >= observeStatsInterval {
			lastStats = now
			if _, drop, serr := o.h.stats(); serr == nil && onDrop != nil {
				onDrop(uint64(drop))
			}
		}
		if !ready {
			continue
		}
		n, err := unix.Read(o.h.fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			return syscallError("read(bpf tap)", err)
		}
		for off := 0; off+hdrSize <= n; {
			hdr := (*unix.BpfHdr)(unsafe.Pointer(&buf[off]))
			hdrLen, capLen := int(hdr.Hdrlen), int(hdr.Caplen)
			if hdrLen < hdrSize || capLen < 0 || off+hdrLen+capLen > n {
				break
			}
			// The frame aliases buf and is consumed before the next read, so no
			// copy is needed: the callback only reads header fields.
			o.handleFrame(buf[off+hdrLen:off+hdrLen+capLen], onPkt)
			step := bpfWordAlign(hdrLen + capLen)
			if step <= 0 {
				break
			}
			off += step
		}
	}
}

// handleFrame parses one captured Ethernet frame and hands the packet on.
func (o *observer) handleFrame(frame []byte, onPkt func(*proto.Pkt)) {
	if onPkt == nil || len(frame) < ethHdrLen {
		return
	}
	switch binary.BigEndian.Uint16(frame[2*ethAddrLen : ethHdrLen]) {
	case ethTypeIPv4, ethTypeIPv6:
	default:
		return
	}
	body := frame[ethHdrLen:]

	// A complete capture (a SYN-ACK, an ACK, a small response) parses fully.
	// Anything longer than the snapshot length is deliberately truncated, so fall
	// back to reading just the fields OnInbound needs.
	pkt, err := proto.Parse(body)
	if err != nil {
		p, ok := parseTruncatedIP(body)
		if !ok {
			return
		}
		pkt = p
	}
	if !pkt.IsTCP() && !pkt.IsUDP() {
		return
	}
	if !o.filtered && !portInRanges(pkt.SrcPort, o.ports) {
		return
	}
	onPkt(pkt)
}

// Close releases the tap.
func (o *observer) Close() error {
	if o == nil {
		return nil
	}
	return o.h.Close()
}

// portInRanges reports whether p falls inside any range. An empty list matches
// everything, which is what "no window configured" means for the tap.
func portInRanges(p uint16, ranges []netcfg.PortRange) bool {
	if len(ranges) == 0 {
		return true
	}
	for _, r := range ranges {
		lo, hi := r[0], r[1]
		if lo > hi {
			lo, hi = hi, lo
		}
		if p >= lo && p <= hi {
			return true
		}
	}
	return false
}

// parseTruncatedIP reads the header fields engine.OnInbound needs — addresses,
// ports, protocol and TTL — out of a capture that may be shorter than the packet
// claims to be. Every access is bounds checked, so a hostile or malformed frame
// yields ok=false rather than a panic.
//
// The returned Pkt has no usable Payload: L3Len/L4Len describe the real packet,
// not the captured prefix. Nothing downstream of OnInbound looks at it.
func parseTruncatedIP(b []byte) (*proto.Pkt, bool) {
	if len(b) < 1 {
		return nil, false
	}
	p := &proto.Pkt{Raw: b}
	var l4 []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return nil, false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 {
			return nil, false
		}
		p.Ver, p.Proto, p.TTL = 4, b[9], b[8]
		p.IPID = binary.BigEndian.Uint16(b[4:6])
		p.DF = binary.BigEndian.Uint16(b[6:8])&0x4000 != 0
		p.Src = netip.AddrFrom4([4]byte(b[12:16]))
		p.Dst = netip.AddrFrom4([4]byte(b[16:20]))
		p.L3Len = ihl
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return nil, false // non-initial fragment: no ports to read
		}
		if len(b) < ihl {
			return nil, false
		}
		l4 = b[ihl:]
	case 6:
		if len(b) < 40 {
			return nil, false
		}
		p.Ver, p.Proto, p.TTL = 6, b[6], b[7]
		p.DF = true
		p.Src = netip.AddrFrom16([16]byte(b[8:24]))
		p.Dst = netip.AddrFrom16([16]byte(b[24:40]))
		p.L3Len = 40
		l4 = b[40:]
		// Walk a bounded extension-header chain; give up rather than guess.
		for hops := 0; hops < 8; hops++ {
			switch p.Proto {
			case proto.IPProtoHopOpt, proto.IPProtoDstOpt, 43:
				if len(l4) < 2 {
					return nil, false
				}
				hlen := (int(l4[1]) + 1) * 8
				if hlen > len(l4) {
					return nil, false
				}
				p.Proto = l4[0]
				p.L3Len += hlen
				l4 = l4[hlen:]
				continue
			}
			break
		}
	default:
		return nil, false
	}

	// Only the port pair is mandatory. A capture can end anywhere, and the hop
	// count plus the 4-tuple is all OnInbound reads, so the rest of the transport
	// header is filled in only as far as the bytes reach.
	if p.Proto != proto.IPProtoTCP && p.Proto != proto.IPProtoUDP {
		return nil, false
	}
	if len(l4) < 4 {
		return nil, false
	}
	p.SrcPort = binary.BigEndian.Uint16(l4[0:2])
	p.DstPort = binary.BigEndian.Uint16(l4[2:4])
	if p.Proto == proto.IPProtoUDP {
		p.L4Len = 8
		return p, true
	}
	if len(l4) >= 20 {
		p.Seq = binary.BigEndian.Uint32(l4[4:8])
		p.Ack = binary.BigEndian.Uint32(l4[8:12])
		p.Flags = l4[13]
		p.Window = binary.BigEndian.Uint16(l4[14:16])
		if dataOff := int(l4[12]>>4) * 4; dataOff >= 20 {
			p.L4Len = dataOff
			if dataOff <= len(l4) {
				p.TCPOpts = l4[20:dataOff]
			}
		} else {
			p.L4Len = 20
		}
	} else {
		p.L4Len = 20
	}
	return p, true
}

// ---------------------------------------------------------------------------
// BPF filter assembly
// ---------------------------------------------------------------------------

// BPF instruction encodings from <net/bpf.h>, composed from the class, size and
// mode bit fields so each line is checkable against the header.
const (
	bpfLDHAbs = 0x00 | 0x08 | 0x20 // BPF_LD  | BPF_H | BPF_ABS
	bpfLDBAbs = 0x00 | 0x10 | 0x20 // BPF_LD  | BPF_B | BPF_ABS
	bpfLDHInd = 0x00 | 0x08 | 0x40 // BPF_LD  | BPF_H | BPF_IND
	bpfLDXMsh = 0x01 | 0x10 | 0xa0 // BPF_LDX | BPF_B | BPF_MSH
	bpfJEQ    = 0x05 | 0x10        // BPF_JMP | BPF_JEQ  | BPF_K
	bpfJGT    = 0x05 | 0x20        // BPF_JMP | BPF_JGT  | BPF_K
	bpfJGE    = 0x05 | 0x30        // BPF_JMP | BPF_JGE  | BPF_K
	bpfJSET   = 0x05 | 0x40        // BPF_JMP | BPF_JSET | BPF_K
	bpfJA     = 0x05 | 0x00        // BPF_JMP | BPF_JA
	bpfRET    = 0x06 | 0x00        // BPF_RET | BPF_K
)

// bpfAsm assembles a BPF program with symbolic jump targets, because hand-counted
// displacements are exactly the kind of thing that silently filters out all
// traffic instead of failing loudly.
type bpfAsm struct {
	ins    []unix.BpfInsn
	jt, jf []string // per-instruction target labels, "" for a literal offset
	labels map[string]int
	err    error
}

func newBPFAsm() *bpfAsm { return &bpfAsm{labels: map[string]int{}} }

// label marks the current position with a name.
func (a *bpfAsm) label(name string) {
	if _, dup := a.labels[name]; dup && a.err == nil {
		a.err = fmt.Errorf("divert: duplicate BPF label %q", name)
	}
	a.labels[name] = len(a.ins)
}

// op appends a non-jump instruction.
func (a *bpfAsm) op(code uint16, k uint32) {
	a.ins = append(a.ins, unix.BpfInsn{Code: code, K: k})
	a.jt = append(a.jt, "")
	a.jf = append(a.jf, "")
}

// jump appends a conditional jump to two labels.
func (a *bpfAsm) jump(code uint16, k uint32, jt, jf string) {
	a.ins = append(a.ins, unix.BpfInsn{Code: code, K: k})
	a.jt = append(a.jt, jt)
	a.jf = append(a.jf, jf)
}

// ja appends an unconditional jump; BPF_JA keeps its displacement in K, not in
// Jt, so it is resolved separately.
func (a *bpfAsm) ja(target string) {
	a.ins = append(a.ins, unix.BpfInsn{Code: bpfJA})
	a.jt = append(a.jt, "\x00ja"+target) // sentinel: resolve into K
	a.jf = append(a.jf, "")
}

// assemble resolves every label into a displacement.
func (a *bpfAsm) assemble() ([]unix.BpfInsn, error) {
	if a.err != nil {
		return nil, a.err
	}
	for i := range a.ins {
		next := i + 1
		if t := a.jt[i]; t != "" {
			if raw, isJA := trimJASentinel(t); isJA {
				off, err := a.displacement(raw, next, 0xffff)
				if err != nil {
					return nil, err
				}
				a.ins[i].K = uint32(off)
				continue
			}
			off, err := a.displacement(t, next, 0xff)
			if err != nil {
				return nil, err
			}
			a.ins[i].Jt = uint8(off)
		}
		if t := a.jf[i]; t != "" {
			off, err := a.displacement(t, next, 0xff)
			if err != nil {
				return nil, err
			}
			a.ins[i].Jf = uint8(off)
		}
	}
	return a.ins, nil
}

// trimJASentinel recognises the marker ja() leaves on its target label.
func trimJASentinel(s string) (string, bool) {
	const pfx = "\x00ja"
	if len(s) > len(pfx) && s[:len(pfx)] == pfx {
		return s[len(pfx):], true
	}
	return s, false
}

// displacement computes a forward jump distance and rejects anything the field
// cannot hold. Only forward jumps are legal in BPF, which the check enforces.
func (a *bpfAsm) displacement(label string, next, max int) (int, error) {
	at, ok := a.labels[label]
	if !ok {
		return 0, fmt.Errorf("divert: undefined BPF label %q", label)
	}
	off := at - next
	if off < 0 {
		return 0, fmt.Errorf("divert: backward BPF jump to %q (%d -> %d)", label, next, at)
	}
	if off > max {
		return 0, fmt.Errorf("divert: BPF jump to %q is %d instructions away, field holds %d", label, off, max)
	}
	return off, nil
}

// inboundFilter builds the tap's kernel filter: Ethernet frames carrying IPv4 or
// IPv6 TCP/UDP whose SOURCE port is inside the steered window (a reply comes back
// from the port we steered towards).
//
// filtered reports whether the port check made it into the program; when it did
// not, the caller must repeat it in userspace.
func inboundFilter(ports []netcfg.PortRange) (prog []unix.BpfInsn, filtered bool, err error) {
	ranges := normalisePortRanges(ports)
	filtered = len(ranges) > 0 && len(ranges) <= maxFilterRanges
	if !filtered {
		ranges = nil
	}

	a := newBPFAsm()
	a.op(bpfLDHAbs, 2*ethAddrLen) // A = ethertype
	a.jump(bpfJEQ, ethTypeIPv4, "ip4", "chk6")
	a.label("chk6")
	// A still holds the ethertype: a jump does not touch the accumulator.
	a.jump(bpfJEQ, ethTypeIPv6, "ip6", "drop")

	a.label("ip4")
	a.op(bpfLDBAbs, ethHdrLen+9) // A = ip_p
	a.jump(bpfJEQ, proto.IPProtoTCP, "ip4frag", "ip4udp")
	a.label("ip4udp")
	a.jump(bpfJEQ, proto.IPProtoUDP, "ip4frag", "drop")
	a.label("ip4frag")
	a.op(bpfLDHAbs, ethHdrLen+6) // A = flags + fragment offset
	// A non-initial fragment carries no transport header, so its "source port"
	// bytes are payload. Drop it: the observer only wants a hop count, and the
	// initial fragment of the same datagram delivers one.
	a.jump(bpfJSET, 0x1fff, "drop", "ip4port")
	a.label("ip4port")
	a.op(bpfLDXMsh, ethHdrLen) // X = 4 * (ip_vhl & 0xf), the IP header length
	a.op(bpfLDHInd, ethHdrLen) // A = *(u16*)(frame + X + 14) = source port
	a.ja("ports")

	a.label("ip6")
	a.op(bpfLDBAbs, ethHdrLen+6) // A = ip6_nxt
	a.jump(bpfJEQ, proto.IPProtoTCP, "ip6port", "ip6udp")
	a.label("ip6udp")
	// An extension-header chain falls through to drop: walking one needs a loop
	// BPF does not have, and the hop count arrives on the plain packets anyway.
	a.jump(bpfJEQ, proto.IPProtoUDP, "ip6port", "drop")
	a.label("ip6port")
	a.op(bpfLDHAbs, ethHdrLen+ipv6HdrLen) // A = source port

	a.label("ports")
	for i, r := range ranges {
		next := "drop"
		if i+1 < len(ranges) {
			next = fmt.Sprintf("r%d", i+1)
		}
		if i > 0 {
			a.label(fmt.Sprintf("r%d", i))
		}
		if r[0] == r[1] {
			a.jump(bpfJEQ, uint32(r[0]), "accept", next)
			continue
		}
		hi := fmt.Sprintf("r%dhi", i)
		a.jump(bpfJGE, uint32(r[0]), hi, next)
		a.label(hi)
		a.jump(bpfJGT, uint32(r[1]), next, "accept")
	}
	a.label("accept")
	a.op(bpfRET, observeSnapLen)
	a.label("drop")
	a.op(bpfRET, 0)

	prog, err = a.assemble()
	if err != nil {
		return nil, false, err
	}
	return prog, filtered, nil
}

// normalisePortRanges sorts, merges and caps a port window so the generated
// program is deterministic and as short as possible.
func normalisePortRanges(in []netcfg.PortRange) []netcfg.PortRange {
	out := make([]netcfg.PortRange, 0, len(in))
	for _, r := range in {
		lo, hi := r[0], r[1]
		if lo > hi {
			lo, hi = hi, lo
		}
		if lo == 0 {
			continue
		}
		out = append(out, netcfg.PortRange{lo, hi})
	}
	slices.SortFunc(out, func(a, b netcfg.PortRange) int {
		if a[0] != b[0] {
			return int(a[0]) - int(b[0])
		}
		return int(a[1]) - int(b[1])
	})
	merged := out[:0]
	for _, r := range out {
		if n := len(merged); n > 0 && r[0] <= merged[n-1][1]+1 && merged[n-1][1] != 0xffff {
			if r[1] > merged[n-1][1] {
				merged[n-1][1] = r[1]
			}
			continue
		}
		merged = append(merged, r)
	}
	return merged
}
