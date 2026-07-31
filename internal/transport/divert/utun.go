//go:build darwin

package divert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// syscall plumbing shared by every file in this package
// ---------------------------------------------------------------------------

// sysprotoControl is SYSPROTO_CONTROL from <sys/sys_domain.h> and utunOptIfname
// is UTUN_OPT_IFNAME from <net/if_utun.h>. golang.org/x/sys/unix exports
// neither; both values are read from the SDK headers and are stable ABI (the
// kernel control socket protocol number and the utun getsockopt index).
const (
	sysprotoControl = 2
	utunOptIfname   = 2
)

// utunControlName is the kernel control the utun driver registers.
const utunControlName = "com.apple.net.utun_control"

// ioctl request numbers used to configure an interface. Values verified against
// <sys/sockio.h> and golang.org/x/sys/unix's generated darwin/arm64 constants:
//
//	SIOCAIFADDR   _IOW ('i', 26, struct ifaliasreq)  == 0x8040691a (sizeof 64)
//	SIOCSIFMTU    _IOW ('i', 52, struct ifreq)       == 0x80206934 (sizeof 32)
//	SIOCSIFFLAGS  _IOW ('i', 16, struct ifreq)       == 0x80206910
//	SIOCGIFFLAGS  _IOWR('i', 17, struct ifreq)       == 0xc0206911
//	SIOCAIFADDR_IN6 _IOW('i', 26, struct in6_aliasreq) == 0x8080691a (sizeof 128)
//
// SIOCAIFADDR_IN6 shares the 'i',26 pair with its IPv4 sibling and is told apart
// only by the encoded struct size, which is why ifAliasReq6 carries a
// compile-time size assertion of its own.
const (
	siocAIfAddr    = 0x8040691a
	siocAIfAddrIn6 = 0x8080691a
	siocSIfMTU     = 0x80206934
	siocSIfFlags   = 0x80206910
	siocGIfFlags   = 0xc0206911
)

// ioctlPtr issues ioctl(fd, req, arg). golang.org/x/sys/unix keeps its own
// version of this unexported, so it is restated here. Callers must pass a
// pointer obtained with unsafe.Pointer(&x) so escape analysis heap-allocates x:
// heap objects do not move, which is what makes handing the kernel a uintptr of
// one safe.
func ioctlPtr(fd int, req uint32, arg unsafe.Pointer) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

// errnoNames maps the errnos this package can plausibly observe to their
// symbolic name. A slice, not a map literal, because Darwin aliases some values
// (EWOULDBLOCK == EAGAIN) and duplicate map keys do not compile.
var errnoNames = []struct {
	e    unix.Errno
	name string
}{
	{unix.EPERM, "EPERM"}, {unix.ENOENT, "ENOENT"}, {unix.EINTR, "EINTR"},
	{unix.EIO, "EIO"}, {unix.ENXIO, "ENXIO"}, {unix.EBADF, "EBADF"},
	{unix.ENOMEM, "ENOMEM"}, {unix.EACCES, "EACCES"}, {unix.EFAULT, "EFAULT"},
	{unix.EBUSY, "EBUSY"}, {unix.EEXIST, "EEXIST"}, {unix.ENODEV, "ENODEV"},
	{unix.EINVAL, "EINVAL"}, {unix.ENFILE, "ENFILE"}, {unix.EMFILE, "EMFILE"},
	{unix.ENOTTY, "ENOTTY"}, {unix.ENOSPC, "ENOSPC"}, {unix.EPIPE, "EPIPE"},
	{unix.EAGAIN, "EAGAIN"}, {unix.ENOTSOCK, "ENOTSOCK"},
	{unix.EDESTADDRREQ, "EDESTADDRREQ"}, {unix.EMSGSIZE, "EMSGSIZE"},
	{unix.EPROTOTYPE, "EPROTOTYPE"}, {unix.ENOPROTOOPT, "ENOPROTOOPT"},
	{unix.EPROTONOSUPPORT, "EPROTONOSUPPORT"}, {unix.ENOTSUP, "ENOTSUP"},
	{unix.EAFNOSUPPORT, "EAFNOSUPPORT"}, {unix.EADDRINUSE, "EADDRINUSE"},
	{unix.EADDRNOTAVAIL, "EADDRNOTAVAIL"}, {unix.ENETDOWN, "ENETDOWN"},
	{unix.ENETUNREACH, "ENETUNREACH"}, {unix.ECONNRESET, "ECONNRESET"},
	{unix.ENOBUFS, "ENOBUFS"}, {unix.EISCONN, "EISCONN"},
	{unix.ENOTCONN, "ENOTCONN"}, {unix.ESHUTDOWN, "ESHUTDOWN"},
	{unix.ETIMEDOUT, "ETIMEDOUT"}, {unix.EHOSTDOWN, "EHOSTDOWN"},
	{unix.EHOSTUNREACH, "EHOSTUNREACH"}, {unix.ENOSYS, "ENOSYS"},
	{unix.EOPNOTSUPP, "EOPNOTSUPP"}, {unix.ERANGE, "ERANGE"},
	{unix.EOVERFLOW, "EOVERFLOW"}, {unix.ENOLCK, "ENOLCK"},
}

var errnoNameByValue = func() map[unix.Errno]string {
	m := make(map[unix.Errno]string, len(errnoNames))
	for _, en := range errnoNames {
		if _, dup := m[en.e]; !dup {
			m[en.e] = en.name
		}
	}
	return m
}()

// errnoName renders err as "ENAME (message)" when it carries an errno and as the
// plain message otherwise. Every syscall failure this package reports goes
// through it, so an operator always sees the symbolic errno.
func errnoName(err error) string {
	if err == nil {
		return "OK"
	}
	var e unix.Errno
	if errors.As(err, &e) {
		if name, ok := errnoNameByValue[e]; ok {
			return fmt.Sprintf("%s (%v)", name, e)
		}
		return fmt.Sprintf("errno %d (%v)", int(e), e)
	}
	return err.Error()
}

// syscallError annotates a failing syscall with its name and symbolic errno,
// keeping the errno wrapped so callers can still errors.Is it.
func syscallError(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %s: %w", op, errnoName(err), err)
}

// waitReadable blocks until fd is readable or the timeout expires, retrying on
// EINTR. poll(2) rather than SO_RCVTIMEO because a utun is an AF_SYSTEM socket
// and a BPF descriptor is a character device; neither honours the socket option
// reliably.
func waitReadable(fd int, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return false, nil
		}
		ms := int(remain / time.Millisecond)
		if ms < 1 {
			ms = 1
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, ms)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return false, syscallError("poll", err)
		}
		if n == 0 {
			return false, nil
		}
		if fds[0].Revents&(unix.POLLIN|unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return true, nil
		}
	}
}

// ---------------------------------------------------------------------------
// interface request structs
// ---------------------------------------------------------------------------

// ifAliasReq mirrors "struct ifaliasreq" from <net/if.h>: a 16-byte interface
// name followed by three sockaddrs (addr, broadaddr, mask), 64 bytes total. On a
// point-to-point interface the kernel treats ifra_broadaddr as the destination
// (peer) address, which is how "ifconfig utunN A B" works.
type ifAliasReq struct {
	Name      [unix.IFNAMSIZ]byte
	Addr      unix.RawSockaddrInet4
	Broadaddr unix.RawSockaddrInet4
	Mask      unix.RawSockaddrInet4
}

// in6AddrLifetime mirrors "struct in6_addrlifetime" from <netinet6/in6_var.h>:
// two time_t plus two uint32, 24 bytes on arm64.
type in6AddrLifetime struct {
	Expire    int64
	Preferred int64
	VLTime    uint32
	PLTime    uint32
}

// ifAliasReq6 mirrors "struct in6_aliasreq": name, three sockaddr_in6, an int
// flags field and the lifetime. 16 + 3*28 = 100, flags at 100, and the
// 8-byte-aligned lifetime lands at 104 with no padding, so the total is exactly
// the 128 bytes SIOCAIFADDR_IN6 encodes.
type ifAliasReq6 struct {
	Name       [unix.IFNAMSIZ]byte
	Addr       unix.RawSockaddrInet6
	Dstaddr    unix.RawSockaddrInet6
	Prefixmask unix.RawSockaddrInet6
	Flags      int32
	Lifetime   in6AddrLifetime
}

// ifReqInt mirrors "struct ifreq" when the union member in use is the int
// ifr_mtu: a 16-byte name plus a 16-byte union, 32 bytes total.
type ifReqInt struct {
	Name [unix.IFNAMSIZ]byte
	Val  int32
	_    [12]byte
}

// ifReqFlags mirrors "struct ifreq" when the union member in use is the
// "short ifru_flags".
type ifReqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags int16
	_     [14]byte
}

// Compile-time guards on the struct sizes the ioctl request numbers encode. A
// mismatch would make the kernel reject the call with ENOTTY, so it is caught at
// build time instead: one of the two conversions overflows uint if the size is
// wrong in either direction.
const (
	_ = uint(unsafe.Sizeof(ifAliasReq{}) - 64)
	_ = uint(64 - unsafe.Sizeof(ifAliasReq{}))
	_ = uint(unsafe.Sizeof(ifAliasReq6{}) - 128)
	_ = uint(128 - unsafe.Sizeof(ifAliasReq6{}))
	_ = uint(unsafe.Sizeof(ifReqInt{}) - 32)
	_ = uint(32 - unsafe.Sizeof(ifReqInt{}))
	_ = uint(unsafe.Sizeof(ifReqFlags{}) - 32)
	_ = uint(32 - unsafe.Sizeof(ifReqFlags{}))
)

// ---------------------------------------------------------------------------
// utun framing
// ---------------------------------------------------------------------------

// utunAFPrefixLen is the length of the framing header on every read from and
// write to a utun control socket: the address family as a 32-bit big-endian
// value, i.e. {0,0,0,2} for AF_INET and {0,0,0,30} for AF_INET6.
const utunAFPrefixLen = 4

// utunPrefix returns the 4-byte framing header for an IP version (4 or 6).
func utunPrefix(ver uint8) [utunAFPrefixLen]byte {
	af := uint32(unix.AF_INET)
	if ver == 6 {
		af = uint32(unix.AF_INET6)
	}
	var p [utunAFPrefixLen]byte
	binary.BigEndian.PutUint32(p[:], af)
	return p
}

// utunDecode strips the framing header from a utun read and reports the IP
// version the header announced (4, 6, or 0 for anything else).
func utunDecode(buf []byte) (ver uint8, pkt []byte, ok bool) {
	if len(buf) < utunAFPrefixLen {
		return 0, nil, false
	}
	switch binary.BigEndian.Uint32(buf[:utunAFPrefixLen]) {
	case uint32(unix.AF_INET):
		ver = 4
	case uint32(unix.AF_INET6):
		ver = 6
	default:
		ver = 0
	}
	return ver, buf[utunAFPrefixLen:], true
}

// ---------------------------------------------------------------------------
// utun lifecycle
// ---------------------------------------------------------------------------

// DefaultTunLocal and DefaultTunPeer are the point-to-point pair the steering
// rule's route-to target lives on. 198.18.0.0/15 is the RFC 2544 benchmarking
// range: deliberately not RFC 1918, so it cannot collide with the user's LAN,
// their VPN, or a container bridge.
const (
	DefaultTunLocal = "198.18.0.1"
	DefaultTunPeer  = "198.18.0.2"
	// DefaultTunLocal6 / DefaultTunPeer6 are the IPv6 equivalents from RFC 5180
	// (2001:2::/48, reserved for benchmarking).
	DefaultTunLocal6 = "2001:2::1"
	DefaultTunPeer6  = "2001:2::2"
)

// utunHandle owns a utun control socket and therefore the interface itself:
// closing the socket destroys utunN, which is what makes cleanup complete even
// after SIGKILL.
type utunHandle struct {
	fd   int
	Name string
	Unit int
	// FellBack reports that the requested unit was taken and the kernel picked
	// one instead.
	FellBack bool

	Local, Peer   netip.Addr
	Local6, Peer6 netip.Addr
	// HaveIPv6 reports whether the IPv6 pair could be assigned; when false only
	// inet steering rules may be installed.
	HaveIPv6 bool

	MTU int
	// Notes collects non-fatal configuration problems for the operator.
	Notes []string
}

// createUTUN opens a utun control socket, attaches it to a unit, reads back the
// kernel-assigned interface name and configures addresses, MTU and flags with
// ioctls only — never by shelling out to ifconfig.
//
// The kernel's sc_unit numbering is 1-based: sc_unit == unit+1 selects utun<unit>
// and sc_unit == 0 asks for the lowest free unit.
func createUTUN(unit int, local, peer netip.Addr, mtu int) (*utunHandle, error) {
	if !local.Is4() || !peer.Is4() {
		return nil, fmt.Errorf("divert: utun needs an IPv4 point-to-point pair, got %s -> %s", local, peer)
	}
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, syscallError("socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)", err)
	}
	h := &utunHandle{fd: fd, Local: local, Peer: peer, MTU: mtu}

	var ci unix.CtlInfo
	copy(ci.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, &ci); err != nil {
		unix.Close(fd)
		return nil, syscallError(`ioctl(CTLIOCGINFO, "`+utunControlName+`")`, err)
	}

	if unit < 0 {
		unit = 0
	}
	connectErr := unix.Connect(fd, &unix.SockaddrCtl{ID: ci.Id, Unit: uint32(unit) + 1})
	if connectErr != nil {
		// The requested unit is busy or otherwise unusable; sc_unit == 0 asks the
		// kernel for the lowest free one.
		if err2 := unix.Connect(fd, &unix.SockaddrCtl{ID: ci.Id, Unit: 0}); err2 != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("divert: %v; falling back to a kernel-chosen unit also failed: %s",
				syscallError(fmt.Sprintf("connect(utun unit %d)", unit), connectErr), errnoName(err2))
		}
		h.FellBack = true
	}

	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		unix.Close(fd)
		return nil, syscallError("getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)", err)
	}
	h.Name = name
	h.Unit = -1
	if n, perr := fmt.Sscanf(name, "utun%d", &h.Unit); perr != nil || n != 1 {
		h.Unit = -1
	}

	if err := h.configure(); err != nil {
		unix.Close(fd)
		h.fd = -1
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		h.fd = -1
		return nil, syscallError("SetNonblock(utun)", err)
	}
	return h, nil
}

// configure assigns the point-to-point addresses, sets the MTU and brings the
// interface up through ioctls on a scratch datagram socket.
func (h *utunHandle) configure() error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return syscallError("socket(AF_INET, SOCK_DGRAM) for ioctl", err)
	}
	defer unix.Close(s)

	var aif ifAliasReq
	copy(aif.Name[:], h.Name)
	aif.Addr = sockaddrInet4Raw(h.Local)
	// On a point-to-point interface ifra_broadaddr carries the peer address.
	aif.Broadaddr = sockaddrInet4Raw(h.Peer)
	aif.Mask = sockaddrInet4Raw(netip.AddrFrom4([4]byte{255, 255, 255, 255}))
	if err := ioctlPtr(s, siocAIfAddr, unsafe.Pointer(&aif)); err != nil {
		return syscallError(fmt.Sprintf("ioctl(SIOCAIFADDR, %s %s->%s/32)", h.Name, h.Local, h.Peer), err)
	}

	if h.MTU > 0 {
		var mtu ifReqInt
		copy(mtu.Name[:], h.Name)
		mtu.Val = int32(h.MTU)
		if err := ioctlPtr(s, siocSIfMTU, unsafe.Pointer(&mtu)); err != nil {
			// The default utun MTU still carries traffic, so this is a warning:
			// the only cost is that a full-size packet may be split by the
			// kernel before we ever see it.
			h.Notes = append(h.Notes,
				syscallError(fmt.Sprintf("ioctl(SIOCSIFMTU, %s, %d)", h.Name, h.MTU), err).Error())
		}
	}

	var fl ifReqFlags
	copy(fl.Name[:], h.Name)
	if err := ioctlPtr(s, siocGIfFlags, unsafe.Pointer(&fl)); err != nil {
		return syscallError(fmt.Sprintf("ioctl(SIOCGIFFLAGS, %s)", h.Name), err)
	}
	// The bit that matters for pf's route-to is IFF_UP; IFF_RUNNING is
	// driver-owned on most interfaces but utun honours it.
	fl.Flags |= int16(unix.IFF_UP | unix.IFF_RUNNING)
	if err := ioctlPtr(s, siocSIfFlags, unsafe.Pointer(&fl)); err != nil {
		return syscallError(fmt.Sprintf("ioctl(SIOCSIFFLAGS, %s, UP)", h.Name), err)
	}
	return nil
}

// ConfigureIPv6 adds the IPv6 point-to-point pair, which an inet6 steering rule
// needs as its route-to next hop. Failure is not fatal: HaveIPv6 stays false and
// the caller installs IPv4-only rules.
func (h *utunHandle) ConfigureIPv6(local, peer netip.Addr) error {
	if h == nil || h.fd < 0 {
		return unix.EBADF
	}
	if !local.Is6() || !peer.Is6() || local.Is4In6() || peer.Is4In6() {
		return fmt.Errorf("divert: utun IPv6 pair must be real IPv6 addresses, got %s -> %s", local, peer)
	}
	s, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return syscallError("socket(AF_INET6, SOCK_DGRAM) for ioctl", err)
	}
	defer unix.Close(s)

	var aif ifAliasReq6
	copy(aif.Name[:], h.Name)
	aif.Addr = sockaddrInet6Raw(local)
	aif.Dstaddr = sockaddrInet6Raw(peer)
	aif.Prefixmask = sockaddrInet6Raw(netip.AddrFrom16([16]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}))
	// ND6_INFINITE_LIFETIME: without it the kernel expires the address.
	aif.Lifetime.VLTime = 0xffffffff
	aif.Lifetime.PLTime = 0xffffffff
	if err := ioctlPtr(s, siocAIfAddrIn6, unsafe.Pointer(&aif)); err != nil {
		return syscallError(fmt.Sprintf("ioctl(SIOCAIFADDR_IN6, %s %s->%s/128)", h.Name, local, peer), err)
	}
	h.Local6, h.Peer6, h.HaveIPv6 = local, peer, true
	return nil
}

// sockaddrInet4Raw builds a filled-in sockaddr_in for the ifaliasreq slots.
func sockaddrInet4Raw(ip netip.Addr) unix.RawSockaddrInet4 {
	return unix.RawSockaddrInet4{
		Len:    unix.SizeofSockaddrInet4,
		Family: unix.AF_INET,
		Addr:   ip.As4(),
	}
}

// sockaddrInet6Raw builds a filled-in sockaddr_in6 for the in6_aliasreq slots.
func sockaddrInet6Raw(ip netip.Addr) unix.RawSockaddrInet6 {
	return unix.RawSockaddrInet6{
		Len:    unix.SizeofSockaddrInet6,
		Family: unix.AF_INET6,
		Addr:   ip.As16(),
	}
}

// Read waits up to timeout for one packet and returns the IP version and the IP
// packet with the framing header stripped. The returned slice aliases buf.
//
// ok is false on a timeout, which the datapath uses as its ctx-cancellation
// check point.
func (h *utunHandle) Read(buf []byte, timeout time.Duration) (ver uint8, pkt []byte, ok bool, err error) {
	if h == nil || h.fd < 0 {
		return 0, nil, false, unix.EBADF
	}
	ready, err := waitReadable(h.fd, timeout)
	if err != nil || !ready {
		return 0, nil, false, err
	}
	n, err := unix.Read(h.fd, buf)
	if err != nil {
		if err == unix.EAGAIN || err == unix.EINTR {
			return 0, nil, false, nil
		}
		return 0, nil, false, syscallError("read(utun)", err)
	}
	if n < utunAFPrefixLen {
		return 0, nil, false, fmt.Errorf("divert: short utun read: %d byte(s)", n)
	}
	ver, pkt, _ = utunDecode(buf[:n])
	return ver, pkt, true, nil
}

// Write sends an IP packet into the utun, prepending the framing header. It is
// only used by the diagnostics path: the datapath re-emits through the injector,
// because writing back into the utun would hand the packet to the routing table
// again and loop.
func (h *utunHandle) Write(ver uint8, pkt []byte) (int, error) {
	if h == nil || h.fd < 0 {
		return 0, unix.EBADF
	}
	prefix := utunPrefix(ver)
	buf := make([]byte, utunAFPrefixLen+len(pkt))
	copy(buf, prefix[:])
	copy(buf[utunAFPrefixLen:], pkt)
	n, err := unix.Write(h.fd, buf)
	if err != nil {
		return n, syscallError("write(utun)", err)
	}
	return n, nil
}

// Close destroys the interface by closing its control socket.
func (h *utunHandle) Close() error {
	if h == nil || h.fd < 0 {
		return nil
	}
	err := unix.Close(h.fd)
	h.fd = -1
	if err != nil {
		return syscallError("close(utun)", err)
	}
	return nil
}

// pickTunPair returns a point-to-point pair that collides with no interface,
// starting from the requested one.
//
// Collision is judged against interface PREFIXES, not just their addresses.
// Checking addresses alone is not enough and the difference is not theoretical:
// AmneziaVPN configures 198.18.0.1 with a /16 netmask, so it owns the whole of
// 198.18.0.0/16. An address-only check would accept 198.18.1.2 as a free next
// hop while the kernel routes that address into the VPN's utun — our steering
// rule would name our interface but the peer address would belong to somebody
// else, which is exactly the kind of half-working state that is miserable to
// diagnose.
func pickTunPair(local, peer netip.Addr) (netip.Addr, netip.Addr, bool, error) {
	claimed, err := claimedPrefixes()
	if err != nil {
		// Without the interface table we cannot check; use the request as-is
		// rather than refusing to start.
		return local, peer, false, err
	}
	free := func(a netip.Addr) bool {
		a = a.Unmap()
		for _, p := range claimed {
			if p.Contains(a) {
				return false
			}
		}
		return true
	}
	if local.IsValid() && peer.IsValid() && free(local) && free(peer) {
		return local, peer, false, nil
	}
	// Walk 198.18.k.1 / 198.18.k.2, then 198.19.k.1 / 198.19.k.2.
	for hi := 18; hi <= 19; hi++ {
		for k := 0; k < 256; k++ {
			l := netip.AddrFrom4([4]byte{198, byte(hi), byte(k), 1})
			p := netip.AddrFrom4([4]byte{198, byte(hi), byte(k), 2})
			if free(l) && free(p) {
				return l, p, true, nil
			}
		}
	}
	return local, peer, false, fmt.Errorf(
		"divert: every address in 198.18.0.0/15 is inside a prefix some interface already owns " +
			"(a VPN using that range, e.g. AmneziaVPN's 198.18.0.1/16, is the usual cause); " +
			"stop it or set --tun-local/--tun-peer to a free pair")
}

// claimedPrefixes lists the networks currently configured on interfaces.
//
// net.Interfaces is used rather than netcfg.Interfaces because the netmask is
// what matters here and netcfg's routing-socket view exposes addresses only.
// A /32 or /128 (a point-to-point peer, a loopback alias) claims just itself.
func claimedPrefixes() ([]netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, inf := range ifaces {
		addrs, aerr := inf.Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			ip = ip.Unmap()
			if ip.Is4() && ones > 32 {
				// A 4-in-6 address carrying a 128-bit mask; normalise.
				ones -= 96
			}
			if p, perr := ip.Prefix(ones); perr == nil {
				out = append(out, p)
			}
		}
	}
	return out, nil
}
