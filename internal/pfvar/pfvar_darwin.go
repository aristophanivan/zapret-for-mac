//go:build darwin

// Package pfvar vendors the small part of the pf(4) userland ABI that macOS no
// longer ships, so the proxy transport can ask the packet filter where a
// redirected connection was originally headed.
//
// # WHY THIS FILE EXISTS
//
// Apple removed <net/pfvar.h> from the macOS SDK — verified on this machine:
//
//	$ ls $(xcrun --show-sdk-path)/usr/include/net | grep -i pf
//	pfkeyv2.h
//
// (only bpf.h and pfkeyv2.h are left; /usr/include/net/pfvar.h does not exist
// either). The kernel interface itself is unchanged: /dev/pf still answers
// DIOCNATLOOK, and that ioctl is the only way a userspace listener can recover
// the pre-translation destination of a connection an `rdr` rule redirected to
// it. zapret's tpws does exactly this on macOS/BSD. So the structure has to be
// restated here, by hand.
//
// # WHY BEING WRONG HERE IS WORSE THAN ELSEWHERE
//
// A wrong *field offset* is silent: the ioctl succeeds and returns 16 bytes read
// from the wrong place, i.e. a plausible-but-wrong IP address, and the proxy
// would faithfully connect to the wrong server. Three defences:
//
//  1. The request number encodes sizeof(struct pfioc_natlook) (see DIOCNATLOOK
//     below). XNU's pfioctl() switches on the complete request number, so if our
//     total size is wrong the kernel does not recognise the command at all and
//     fails the call with ENOTTY. A size mistake is therefore loud, not silent.
//  2. The Go declaration's size and every field offset are asserted at compile
//     time in this file and, with readable messages, in pfvar_test.go. Go cannot
//     see the kernel's layout, so these assertions pin our *transcription*: they
//     fail the moment somebody edits the struct without updating the documented
//     numbers.
//  3. Natlook validates what came back (address family echoed unchanged, a
//     non-zero port, a valid address) instead of trusting the buffer.
//
// # THE LAYOUT THAT IS ASSUMED
//
// From xnu bsd/net/pfvar.h (Apple's pf, which is a fork of OpenBSD 4.x pf and
// deviates from it here — upstream OpenBSD/FreeBSD have plain u_int16_t
// sport/dport fields and no proto_variant):
//
//	struct pf_addr {
//	        union {
//	                struct in_addr          v4;      /*  4 bytes */
//	                struct in6_addr         v6;      /* 16 bytes */
//	                u_int8_t                addr8[16];
//	                u_int16_t               addr16[8];
//	                u_int32_t               addr32[4];
//	        } pfa;                                   /* 16 bytes, align 4 */
//	};
//
//	union pf_state_xport {
//	        u_int16_t       port;                    /* network byte order   */
//	        u_int16_t       call_id;
//	        u_int32_t       spi;
//	};                                               /*  4 bytes, align 4    */
//
//	struct pfioc_natlook {
//	        struct pf_addr          saddr;           /* @ 0  */
//	        struct pf_addr          daddr;           /* @ 16 */
//	        struct pf_addr          rsaddr;          /* @ 32 */
//	        struct pf_addr          rdaddr;          /* @ 48 */
//	        union pf_state_xport    sxport;          /* @ 64 */
//	        union pf_state_xport    dxport;          /* @ 68 */
//	        union pf_state_xport    rsxport;         /* @ 72 */
//	        union pf_state_xport    rdxport;         /* @ 76 */
//	        sa_family_t             af;              /* @ 80, __uint8_t      */
//	        u_int8_t                proto;           /* @ 81 */
//	        u_int8_t                proto_variant;   /* @ 82 */
//	        u_int8_t                direction;       /* @ 83 */
//	};                                               /* sizeof = 84, align 4 */
//
// sa_family_t is __uint8_t on Darwin (<sys/_types/_sa_family_t.h>), so the tail
// is four single bytes, the widest member anywhere in the structure is 4 bytes,
// 84 is already a multiple of 4 and there is no tail padding.
//
// # HOW THAT WAS CHECKED
//
// The numbers above are not from memory. zapret vendors the relevant slice of an
// older Apple SDK's pfvar.h, and an installed zapret leaves it on disk at
// /opt/zapret/tpws/macos/net/pfvar.h. It is present on the development machine,
// so the layout was measured by compiling this against it with the system clang
// and SDK (macOS 26.5.1, Darwin 25.5.0, arm64):
//
//	#include "/opt/zapret/tpws/macos/net/pfvar.h"
//	printf("%zu %zu ...", sizeof(struct pfioc_natlook), offsetof(...));
//
// which printed exactly:
//
//	sizeof(struct pf_addr)=16 alignof=4
//	sizeof(union pf_state_xport)=4 alignof=4
//	sizeof(struct pfioc_natlook)=84 alignof=4
//	sizeof(sa_family_t)=1
//	saddr=0 daddr=16 rsaddr=32 rdaddr=48
//	sxport=64 dxport=68 rsxport=72 rdxport=76
//	af=80 proto=81 proto_variant=82 direction=83
//	DIOCNATLOOK=0xc0544417
//	PF_OUT=2 PF_IN=1 PF_INOUT=0 PF_FWD=3
//
// Every one of those values is asserted in this file and in pfvar_test.go.
//
// Two caveats remain, and they are the reason for Natlook's result validation:
//
//   - the header is a vendored copy of an *older* SDK, and the kernel this runs
//     on is not obliged to agree with it. A change in total size is caught
//     immediately (the request number would no longer be one the kernel knows,
//     giving ENOTTY); a hypothetical re-ordering of fields at the same total size
//     would not be.
//   - cmd/zapret-probe/pf_darwin.go carries an equivalent hand-verified
//     definition. This package is now the authoritative copy; the probe's is a
//     standalone duplicate on purpose, because the probe must build and run with
//     no dependency on internal/.
package pfvar

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// DevicePath is the pf character device. It is 0600 root:wheel, so Open needs
// euid 0.
const DevicePath = "/dev/pf"

// Direction values, from the anonymous enum in xnu bsd/net/pfvar.h:
//
//	enum { PF_INOUT, PF_IN, PF_OUT, PF_FWD };
//
// A redirected inbound connection is looked up from the translator's point of
// view, which is why DirOut is the value to pass for an `rdr` lookup — the same
// choice zapret's tpws makes.
const (
	DirInOut uint8 = 0
	DirIn    uint8 = 1
	DirOut   uint8 = 2
	DirFwd   uint8 = 3
)

// ioctl request encoding, from <sys/ioccom.h>:
//
//	#define IOC_VOID        0x20000000
//	#define IOC_OUT         0x40000000
//	#define IOC_IN          0x80000000
//	#define IOC_INOUT       (IOC_IN|IOC_OUT)
//	#define IOCPARM_MASK    0x1fff
//	#define _IOC(inout,group,num,len) \
//	        (inout | ((len & IOCPARM_MASK) << 16) | ((group) << 8) | (num))
const (
	iocIn       = uint32(0x80000000)
	iocOut      = uint32(0x40000000)
	iocInOut    = iocIn | iocOut
	iocParmMask = uint32(0x1fff)
)

// Errors callers match with errors.Is.
var (
	// ErrNoState means pf holds no state for the queried tuple: the
	// connection was not translated by our rdr rule (or its state already
	// expired). It is the expected outcome for a connection that reached the
	// listener directly, so it must be distinguishable from a real failure.
	ErrNoState = errors.New("pfvar: no pf state matches the queried tuple")
	// ErrClosed means the /dev/pf descriptor is not open.
	ErrClosed = errors.New("pfvar: /dev/pf descriptor is not open")
	// ErrFamily means the addresses handed in do not agree with each other or
	// with the requested address family.
	ErrFamily = errors.New("pfvar: address family mismatch")
)

// addr mirrors "struct pf_addr": a 16-byte union whose widest member is
// u_int32_t, so its C alignment is 4. The zero-length [0]uint32 reproduces that
// alignment in Go without contributing any bytes. Contents are in network byte
// order, exactly like the in_addr/in6_addr they overlay.
type addr struct {
	_   [0]uint32
	Raw [16]byte
}

// set stores an IPv4 or IPv6 address into the union. The caller has already
// unmapped 4-in-6 addresses; a 4-in-6 value here would be written as 16 bytes
// and pf would never match it.
func (a *addr) set(ip netip.Addr) {
	if ip.Is4() {
		b := ip.As4()
		copy(a.Raw[:4], b[:])
		return
	}
	b := ip.As16()
	copy(a.Raw[:], b[:])
}

// get reads the address back out for the given family.
func (a addr) get(af uint8) (netip.Addr, bool) {
	switch af {
	case unix.AF_INET:
		return netip.AddrFrom4([4]byte{a.Raw[0], a.Raw[1], a.Raw[2], a.Raw[3]}), true
	case unix.AF_INET6:
		var b [16]byte
		copy(b[:], a.Raw[:])
		return netip.AddrFrom16(b), true
	}
	return netip.Addr{}, false
}

// xport mirrors "union pf_state_xport". The u_int16_t port member overlays the
// first two bytes and holds the port in NETWORK byte order, so it is modelled as
// raw bytes with explicit big-endian access rather than as a uint16 whose
// meaning would depend on the host's endianness.
type xport struct {
	_   [0]uint32
	Raw [4]byte
}

// port returns the port the union holds, converted to host order.
func (x xport) port() uint16 { return binary.BigEndian.Uint16(x.Raw[:2]) }

// setPort stores p (host order) into the union.
func (x *xport) setPort(p uint16) { binary.BigEndian.PutUint16(x.Raw[:2], p) }

// natlook mirrors "struct pfioc_natlook" from xnu bsd/net/pfvar.h. See the
// package comment for the C declaration this transcribes and for how it was
// checked.
type natlook struct {
	Saddr        addr
	Daddr        addr
	Rsaddr       addr
	Rdaddr       addr
	Sxport       xport
	Dxport       xport
	Rsxport      xport
	Rdxport      xport
	Af           uint8
	Proto        uint8
	ProtoVariant uint8
	Direction    uint8
}

// SizeofNatlook is sizeof(struct pfioc_natlook) as this package declares it. It
// must be 84; see the compile-time assertions below.
const SizeofNatlook = unsafe.Sizeof(natlook{})

// DIOCNATLOOK is _IOWR('D', 23, struct pfioc_natlook) == 0xc0544417.
//
// It is derived from SizeofNatlook rather than written as a literal, so a change
// to the Go struct changes the request number and is caught by the assertions
// below instead of silently turning into a kernel-side ENOTTY at runtime.
const DIOCNATLOOK = iocInOut | ((uint32(SizeofNatlook) & iocParmMask) << 16) | (uint32('D') << 8) | 23

// Compile-time ABI assertions. Each pair of unsigned subtractions fails to
// compile unless the two sides are equal, because a negative constant cannot be
// converted to uint. The expected numbers are the ones the C compiler printed;
// see "HOW THAT WAS CHECKED" in the package comment.
const (
	_ = uint(SizeofNatlook - 84)
	_ = uint(84 - SizeofNatlook)

	_ = uint(unsafe.Offsetof(natlook{}.Saddr) - 0)
	_ = uint(0 - unsafe.Offsetof(natlook{}.Saddr))
	_ = uint(unsafe.Offsetof(natlook{}.Daddr) - 16)
	_ = uint(16 - unsafe.Offsetof(natlook{}.Daddr))
	_ = uint(unsafe.Offsetof(natlook{}.Rsaddr) - 32)
	_ = uint(32 - unsafe.Offsetof(natlook{}.Rsaddr))
	_ = uint(unsafe.Offsetof(natlook{}.Rdaddr) - 48)
	_ = uint(48 - unsafe.Offsetof(natlook{}.Rdaddr))

	_ = uint(unsafe.Offsetof(natlook{}.Sxport) - 64)
	_ = uint(64 - unsafe.Offsetof(natlook{}.Sxport))
	_ = uint(unsafe.Offsetof(natlook{}.Dxport) - 68)
	_ = uint(68 - unsafe.Offsetof(natlook{}.Dxport))
	_ = uint(unsafe.Offsetof(natlook{}.Rsxport) - 72)
	_ = uint(72 - unsafe.Offsetof(natlook{}.Rsxport))
	_ = uint(unsafe.Offsetof(natlook{}.Rdxport) - 76)
	_ = uint(76 - unsafe.Offsetof(natlook{}.Rdxport))

	_ = uint(unsafe.Offsetof(natlook{}.Af) - 80)
	_ = uint(80 - unsafe.Offsetof(natlook{}.Af))
	_ = uint(unsafe.Offsetof(natlook{}.Proto) - 81)
	_ = uint(81 - unsafe.Offsetof(natlook{}.Proto))
	_ = uint(unsafe.Offsetof(natlook{}.ProtoVariant) - 82)
	_ = uint(82 - unsafe.Offsetof(natlook{}.ProtoVariant))
	_ = uint(unsafe.Offsetof(natlook{}.Direction) - 83)
	_ = uint(83 - unsafe.Offsetof(natlook{}.Direction))

	_ = uint(DIOCNATLOOK - 0xc0544417)
	_ = uint(0xc0544417 - DIOCNATLOOK)
)

// Layout returns a one-line description of the ABI this package assumes, for
// `zaprctl doctor` to print. Nothing branches on it; it exists so an operator
// debugging a wrong-destination report can see the exact numbers in use.
func Layout() string {
	return fmt.Sprintf("xnu/Apple struct pfioc_natlook: sizeof=%d align=4; "+
		"saddr@%d daddr@%d rsaddr@%d rdaddr@%d sxport@%d dxport@%d rsxport@%d rdxport@%d "+
		"af@%d proto@%d proto_variant@%d direction@%d; DIOCNATLOOK=_IOWR('D',23,%d)=%#08x",
		SizeofNatlook,
		unsafe.Offsetof(natlook{}.Saddr), unsafe.Offsetof(natlook{}.Daddr),
		unsafe.Offsetof(natlook{}.Rsaddr), unsafe.Offsetof(natlook{}.Rdaddr),
		unsafe.Offsetof(natlook{}.Sxport), unsafe.Offsetof(natlook{}.Dxport),
		unsafe.Offsetof(natlook{}.Rsxport), unsafe.Offsetof(natlook{}.Rdxport),
		unsafe.Offsetof(natlook{}.Af), unsafe.Offsetof(natlook{}.Proto),
		unsafe.Offsetof(natlook{}.ProtoVariant), unsafe.Offsetof(natlook{}.Direction),
		SizeofNatlook, DIOCNATLOOK)
}

// Open opens /dev/pf read-only, which is all DIOCNATLOOK needs: xnu's pfioctl()
// permits a small set of query commands — DIOCNATLOOK among them — on a
// descriptor without FWRITE, and rejects everything else with EACCES. Opening
// read-only means a bug in this daemon can never modify the packet filter
// through this descriptor.
//
// O_CLOEXEC matters because netcfg shells out to pfctl: without it every child
// process would inherit an open handle on the packet filter.
func Open() (fd int, err error) {
	fd, err = unix.Open(DevicePath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.Geteuid() != 0 && (errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM)) {
			return -1, fmt.Errorf("pfvar: open %s: %s (it is 0600 root:wheel and this process runs as uid %d)",
				DevicePath, errnoName(err), os.Geteuid())
		}
		return -1, fmt.Errorf("pfvar: open %s: %s", DevicePath, errnoName(err))
	}
	return fd, nil
}

// Close closes a descriptor returned by Open. A negative fd is a no-op so
// teardown paths need no guard of their own.
func Close(fd int) error {
	if fd < 0 {
		return nil
	}
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("pfvar: close %s: %s", DevicePath, errnoName(err))
	}
	return nil
}

// AddrFamily returns the AF_* value describing ip, or 0 when ip is invalid.
// 4-in-6 addresses count as AF_INET, because that is the family pf keeps state
// for and the family the socket really used.
func AddrFamily(ip netip.Addr) uint8 {
	switch {
	case !ip.IsValid():
		return 0
	case ip.Is4() || ip.Is4In6():
		return unix.AF_INET
	default:
		return unix.AF_INET6
	}
}

// Natlook asks pf for the pre-translation destination of a translated
// connection.
//
// pfFd must come from Open. af is AF_INET or AF_INET6 (pass 0 to derive it from
// src). proto is an IPPROTO_* value — IPPROTO_TCP for everything the proxy
// transport handles. src is the peer address of the accepted connection and dst
// the local address it was accepted on, i.e. the post-translation tuple as the
// listener sees it; both ports are in host order, as netip.AddrPort always is.
//
// The returned AddrPort is the address the client originally connected to.
//
// A connection that pf never translated yields ErrNoState (the kernel's ENOENT),
// which callers must treat as "not ours" rather than as a failure.
func Natlook(pfFd int, af uint8, proto uint8, src, dst netip.AddrPort) (netip.AddrPort, error) {
	if pfFd < 0 {
		return netip.AddrPort{}, ErrClosed
	}
	if !src.IsValid() || !dst.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("pfvar: natlook needs two valid address/port pairs, got src=%v dst=%v", src, dst)
	}
	// Unmap 4-in-6 (::ffff:a.b.c.d): the Go runtime hands those out for IPv4
	// connections accepted on a dual-stack socket, and pf keeps IPv4 state for
	// them. Passing 16 bytes would look up an address that has no state.
	srcIP, dstIP := src.Addr().Unmap(), dst.Addr().Unmap()
	if af == 0 {
		af = AddrFamily(srcIP)
	}
	switch af {
	case unix.AF_INET:
		if !srcIP.Is4() || !dstIP.Is4() {
			return netip.AddrPort{}, fmt.Errorf("%w: af=AF_INET but src=%v dst=%v", ErrFamily, srcIP, dstIP)
		}
	case unix.AF_INET6:
		if srcIP.Is4() || dstIP.Is4() {
			return netip.AddrPort{}, fmt.Errorf("%w: af=AF_INET6 but src=%v dst=%v", ErrFamily, srcIP, dstIP)
		}
	default:
		return netip.AddrPort{}, fmt.Errorf("%w: unsupported af=%d (want AF_INET=%d or AF_INET6=%d)",
			ErrFamily, af, unix.AF_INET, unix.AF_INET6)
	}

	nl := natlook{Af: af, Proto: proto, Direction: DirOut}
	nl.Saddr.set(srcIP)
	nl.Daddr.set(dstIP)
	nl.Sxport.setPort(src.Port())
	nl.Dxport.setPort(dst.Port())

	if err := ioctlPtr(pfFd, DIOCNATLOOK, unsafe.Pointer(&nl)); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return netip.AddrPort{}, fmt.Errorf("%w (src=%v dst=%v proto=%d)", ErrNoState, src, dst, proto)
		}
		if errors.Is(err, unix.ENOTTY) {
			// The kernel did not recognise the request number, which means the
			// size encoded in it disagrees with the kernel's struct: our ABI
			// transcription is wrong, not the caller's arguments.
			return netip.AddrPort{}, fmt.Errorf("pfvar: ioctl(DIOCNATLOOK=%#08x): %s — the kernel does not know this request, "+
				"so struct pfioc_natlook is no longer %d bytes; %s", DIOCNATLOOK, errnoName(err), SizeofNatlook, Layout())
		}
		return netip.AddrPort{}, fmt.Errorf("pfvar: ioctl(DIOCNATLOOK): %s", errnoName(err))
	}

	// Validate what came back instead of trusting the buffer: pf leaves af and
	// proto alone, so a mismatch means something wrote over the structure.
	if nl.Af != af {
		return netip.AddrPort{}, fmt.Errorf("pfvar: DIOCNATLOOK returned af=%d, asked for %d; %s", nl.Af, af, Layout())
	}
	if nl.Proto != proto {
		return netip.AddrPort{}, fmt.Errorf("pfvar: DIOCNATLOOK returned proto=%d, asked for %d; %s", nl.Proto, proto, Layout())
	}
	ip, ok := nl.Rdaddr.get(af)
	if !ok || !ip.IsValid() || ip.IsUnspecified() {
		return netip.AddrPort{}, fmt.Errorf("pfvar: DIOCNATLOOK returned an unusable destination address (%v); %s", ip, Layout())
	}
	port := nl.Rdxport.port()
	if port == 0 {
		return netip.AddrPort{}, fmt.Errorf("pfvar: DIOCNATLOOK returned destination port 0 for %v; %s", ip, Layout())
	}
	return netip.AddrPortFrom(ip.Unmap(), port), nil
}

// ioctlPtr issues an ioctl with a pointer argument.
//
// unix.IoctlSetInt and friends cannot express a request that both reads and
// writes a caller-owned struct, so the syscall is made directly. The argument
// must be obtained as unsafe.Pointer(&x) at the call site: that makes escape
// analysis heap-allocate x, and heap objects do not move, so handing the kernel
// a uintptr of it stays valid for the duration of the call.
func ioctlPtr(fd int, req uint32, arg unsafe.Pointer) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

// errnoName renders an error as its symbolic errno name ("ENOENT") plus the
// human-readable text, falling back to the text alone for non-errno errors. The
// symbolic name is what a bug report needs; the prose alone ("no such file or
// directory") is ambiguous about which syscall contract was violated.
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
