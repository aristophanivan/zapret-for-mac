//go:build darwin

package divert

import (
	"fmt"
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// rawInjector is the degraded write side: AF_INET/SOCK_RAW with IP_HDRINCL, the
// classic BSD path for handing the kernel a fully formed IPv4 packet.
//
// It exists for machines where /dev/bpf cannot be opened (another capture
// process holds every clone, or a security product blocks the device). Three
// things are honestly worse than the BPF path, and Caps reports each of them:
//
//   - ip_id == 0 is impossible. Darwin's rip_output() fills in a random
//     identification whenever the field it is handed is zero, so --ip-id=zero
//     silently becomes --ip-id=random. Caps.IPID is therefore false.
//   - IPv6 cannot be emitted at all. Darwin has no IPV6_HDRINCL; an AF_INET6 raw
//     socket makes the kernel build the header, which loses the extension-header
//     chain and the per-packet hop limit. Caps.IPv6ExtHdr is false and an IPv6
//     packet handed to Inject is refused rather than sent wrong.
//   - The send goes through ip_output(), so it is subject to pf. That means the
//     steering ruleset MUST carry `user { > root }` (transport.Config.ExemptRoot),
//     or our own injections would match the route-to rule and loop straight back
//     into the utun. Start enforces this.
//
// IPv4 fragmentation, per-packet TTL, sub-window sequence numbers and a
// deliberately wrong L4 checksum all still work: the kernel only ever rewrites
// ip_len, ip_off, ip_sum and a zero ip_id.
type rawInjector struct {
	fd  int
	mtu int

	mu  sync.Mutex
	buf []byte
}

// newRawInjector creates the raw socket and enables IP_HDRINCL.
func newRawInjector(mtu int) (*rawInjector, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, syscallError("socket(AF_INET, SOCK_RAW, IPPROTO_RAW)", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return nil, syscallError("setsockopt(IP_HDRINCL, 1)", err)
	}
	// A larger send buffer keeps a burst of repeats from failing with ENOBUFS.
	// Purely an optimisation: the default buffer works, so the error is ignored.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<20)
	return &rawInjector{fd: fd, mtu: mtu, buf: make([]byte, 0, 2048)}, nil
}

// Name implements injector.
func (i *rawInjector) Name() string { return "raw" }

// Caps implements injector: the honest reduction described on the type.
func (i *rawInjector) Caps() desync.Caps {
	c := desync.FullCaps()
	c.IPID = false       // rip_output() replaces a zero ip_id
	c.IPv6ExtHdr = false // no IPV6_HDRINCL on Darwin
	return c
}

// Limits implements injector.
func (i *rawInjector) Limits() string {
	return "SOCK_RAW+IP_HDRINCL fallback: ip_id=zero is overwritten by the kernel, " +
		"IPv6 cannot be emitted, and injections pass through pf (ExemptRoot is mandatory)"
}

// Inject implements injector.
//
// Unlike the BPF path this one cannot forward a packet it does not understand:
// sendto(2) needs a destination address, which only a well-formed IPv4 header
// carries. A malformed packet is therefore reported rather than sent, and the
// datapath counts it.
func (i *rawInjector) Inject(ver uint8, pkt []byte) error {
	if ver == 0 {
		ver = ipVersionOf(pkt)
	}
	switch ver {
	case 4:
	case 6:
		return fmt.Errorf("divert: the raw-socket injector cannot emit IPv6 (no IPV6_HDRINCL on Darwin)")
	default:
		return fmt.Errorf("divert: refusing to inject a non-IP buffer (first nibble %d)", ipVersionOf(pkt))
	}
	if ipVersionOf(pkt) != 4 {
		return fmt.Errorf("divert: the utun reported AF_INET but the packet's version nibble is %d",
			ipVersionOf(pkt))
	}
	dst, ok := ipDestOf(pkt)
	if !ok {
		return fmt.Errorf("divert: cannot read the destination address of a %d-byte packet", len(pkt))
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	for _, part := range fragmentForMTU(pkt, i.mtu) {
		// Darwin's rip_output() byte-swaps ip_len and ip_off itself, so those two
		// fields must be handed over in HOST order while everything else stays in
		// wire order. Work on a copy: the caller's buffer may alias the utun read
		// buffer, and the packet must stay a valid wire image for the caller.
		if cap(i.buf) < len(part) {
			i.buf = make([]byte, len(part))
		}
		wire := i.buf[:len(part)]
		copy(wire, part)
		proto.HostOrderIPHeaderInPlace(wire)
		// A zero header checksum makes the kernel compute it; ours was correct
		// for the network-order header, and the kernel swaps the two fields back
		// before transmitting, so either value would do. Zeroing is the
		// documented contract, so use it.
		wire[10], wire[11] = 0, 0
		if err := i.sendto(wire, dst); err != nil {
			return err
		}
	}
	return nil
}

// sendto pushes one packet out, retrying on EINTR.
func (i *rawInjector) sendto(wire []byte, dst netip.Addr) error {
	sa := &unix.SockaddrInet4{Addr: dst.As4()}
	for {
		err := unix.Sendto(i.fd, wire, 0, sa)
		if err == nil {
			return nil
		}
		if err == unix.EINTR {
			continue
		}
		return syscallError(fmt.Sprintf("sendto(%s, %d bytes)", dst, len(wire)), err)
	}
}

// Close implements injector.
func (i *rawInjector) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.fd < 0 {
		return nil
	}
	err := unix.Close(i.fd)
	i.fd = -1
	if err != nil {
		return syscallError("close(raw socket)", err)
	}
	return nil
}
