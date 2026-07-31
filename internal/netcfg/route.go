package netcfg

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// routing table access
//
// Everything here goes through the route sysctl (CTL_NET.AF_ROUTE.*), never
// through route(8)/netstat(1): shelling out to parse localised, version-drifting
// human output is exactly the kind of fragility this daemon cannot afford, and
// the divert transport needs the gateway's link-layer address, which netstat
// does not print reliably.
//
// x/sys/unix does not export RouteRIB/ParseRoutingMessage (they exist only in
// the deprecated stdlib syscall package, and its Darwin parser mis-handles some
// message types), so the messages are decoded by hand. The offsets and the
// ROUNDUP() stepping below are the same ones cmd/zapret-probe/net_darwin.go
// verified against xnu on this machine.
// ---------------------------------------------------------------------------

// Sizes and field offsets of the routing message headers, from xnu's
// <net/route.h> and <net/if.h> on darwin/arm64.
const (
	sizeofRtMsghdr  = 92
	sizeofIfMsghdr  = 112
	sizeofIfaMsghdr = 20

	offRtIndex = 4
	offRtFlags = 8
	offRtAddrs = 12

	offIfAddrs = 4
	offIfFlags = 8
	offIfIndex = 12

	offIfaAddrs = 4
	offIfaIndex = 12

	rtaxMax = 8 // RTAX_MAX
)

// tunnelPrefixes are the interface-name prefixes of point-to-point/VPN devices.
// A default route on one of these means a VPN owns the uplink.
var tunnelPrefixes = []string{"utun", "ipsec", "ppp", "gif", "stf", "tun", "tap", "wg"}

// IsTunnelInterface reports whether name belongs to a tunnel/VPN-style
// interface. The divert transport re-emits packets with a BPF Ethernet write,
// which needs a real link layer, so a tunnel uplink is a hard warning.
func IsTunnelInterface(name string) bool {
	for _, p := range tunnelPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Route describes one route as read from the kernel routing table, enriched
// with the outgoing interface's identity.
type Route struct {
	// Iface is the outgoing interface name ("en0"), IfIndex its ifindex.
	Iface   string
	IfIndex int
	// Flags is the RTF_* bitmask.
	Flags uint32
	// Gateway is the next hop, invalid when the route is link-scoped or the
	// gateway was expressed only as a link-layer address.
	Gateway netip.Addr
	// GatewayMAC is set when RTAX_GATEWAY carried a sockaddr_dl instead of a
	// sockaddr_in (a directly attached next hop).
	GatewayMAC net.HardwareAddr
	// Local is the source address the kernel would use on this route.
	Local netip.Addr
	// MAC is the outgoing interface's own link-layer address — the Ethernet
	// source the divert transport writes.
	MAC net.HardwareAddr
	// MTU is the outgoing interface's MTU, 0 when it could not be read.
	MTU int
	// IsTunnel mirrors IsTunnelInterface(Iface).
	IsTunnel bool
}

// Interface describes one network interface from NET_RT_IFLIST.
type Interface struct {
	// Index is the ifindex, Name the interface name.
	Index int
	Name  string
	// Flags is the IFF_* bitmask.
	Flags uint32
	// MAC is the link-layer address, nil for interfaces without one.
	MAC net.HardwareAddr
	// Addrs are the interface's IPv4 and IPv6 addresses.
	Addrs []netip.Addr
}

// Up reports whether IFF_UP is set.
func (i Interface) Up() bool { return i.Flags&unix.IFF_UP != 0 }

// DefaultRoute returns the interface, gateway, local address and interface MAC
// of the IPv4 default route the divert transport should attach to.
//
// mac is the OUTGOING INTERFACE's hardware address (the Ethernet source for a
// BPF re-emit), not the gateway's. Use DefaultRoute4 or ResolveGatewayMAC when
// the Ethernet destination is needed too.
//
// Non-tunnel routes are preferred over tunnel ones, so an active VPN does not
// hide the physical uplink; check IsTunnelInterface on the result to detect
// that the VPN is nonetheless the active default.
func DefaultRoute() (iface string, gateway netip.Addr, local netip.Addr, mac net.HardwareAddr, err error) {
	r, err := DefaultRoute4()
	if err != nil {
		return "", netip.Addr{}, netip.Addr{}, nil, err
	}
	return r.Iface, r.Gateway, r.Local, r.MAC, nil
}

// DefaultRoute4 returns the preferred IPv4 default route.
func DefaultRoute4() (Route, error) {
	routes, err := DefaultRoutes4()
	if err != nil {
		return Route{}, err
	}
	if len(routes) == 0 {
		return Route{}, fmt.Errorf("netcfg: no IPv4 default route")
	}
	return routes[0], nil
}

// DefaultRoutes4 returns every usable IPv4 default route (destination
// 0.0.0.0/0), non-tunnel first and then by ifindex, so the result is
// deterministic across calls.
func DefaultRoutes4() ([]Route, error) {
	ifaces, err := interfaceTable()
	if err != nil {
		return nil, err
	}
	buf, err := sysctlMIB([]int32{unix.CTL_NET, unix.AF_ROUTE, 0, unix.AF_INET, unix.NET_RT_DUMP, 0})
	if err != nil {
		return nil, fmt.Errorf("netcfg: sysctl net.route.0.inet.dump: %w", err)
	}
	var out []Route
	forEachRouteMessage(buf, func(msg []byte) {
		flags := binary.LittleEndian.Uint32(msg[offRtFlags : offRtFlags+4])
		if flags&unix.RTF_UP == 0 {
			return
		}
		addrs := binary.LittleEndian.Uint32(msg[offRtAddrs : offRtAddrs+4])
		sas := splitSockaddrs(msg[sizeofRtMsghdr:], addrs)
		dst, _, ok := sockaddrInet4(sas[unix.RTAX_DST])
		if !ok || dst != netip.AddrFrom4([4]byte{}) {
			return
		}
		// A default route must have an all-zero (or absent) netmask; without
		// this check host routes to 0.0.0.0 would slip through.
		if !sockaddrMaskIsZero(sas[unix.RTAX_NETMASK]) {
			return
		}
		r := Route{
			IfIndex: int(binary.LittleEndian.Uint16(msg[offRtIndex : offRtIndex+2])),
			Flags:   flags,
		}
		if gw := sas[unix.RTAX_GATEWAY]; gw != nil {
			if ip, _, ok := sockaddrInet4(gw); ok {
				r.Gateway = ip
			} else if _, _, mac, ok := parseLinkAddr(gw); ok {
				r.GatewayMAC = mac
			}
		}
		if ifa := sas[unix.RTAX_IFA]; ifa != nil {
			if ip, _, ok := sockaddrInet4(ifa); ok {
				r.Local = ip
			}
		}
		fillRouteIface(&r, ifaces)
		out = append(out, r)
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].IsTunnel != out[j].IsTunnel {
			return !out[i].IsTunnel
		}
		return out[i].IfIndex < out[j].IfIndex
	})
	return out, nil
}

// RouteForIface returns the first usable IPv4 gateway route on the named
// interface. The daemon needs it when the operator pins --iface to something
// that is not currently the system default route.
func RouteForIface(name string) (Route, error) {
	ifaces, err := interfaceTable()
	if err != nil {
		return Route{}, err
	}
	want := -1
	for idx, inf := range ifaces {
		if inf.Name == name {
			want = idx
			break
		}
	}
	if want < 0 {
		return Route{}, fmt.Errorf("netcfg: no interface named %q", name)
	}
	buf, err := sysctlMIB([]int32{unix.CTL_NET, unix.AF_ROUTE, 0, unix.AF_INET, unix.NET_RT_DUMP, 0})
	if err != nil {
		return Route{}, fmt.Errorf("netcfg: sysctl net.route.0.inet.dump: %w", err)
	}
	var found *Route
	forEachRouteMessage(buf, func(msg []byte) {
		if found != nil {
			return
		}
		flags := binary.LittleEndian.Uint32(msg[offRtFlags : offRtFlags+4])
		if flags&unix.RTF_UP == 0 || flags&unix.RTF_GATEWAY == 0 {
			return
		}
		if int(binary.LittleEndian.Uint16(msg[offRtIndex:offRtIndex+2])) != want {
			return
		}
		addrs := binary.LittleEndian.Uint32(msg[offRtAddrs : offRtAddrs+4])
		sas := splitSockaddrs(msg[sizeofRtMsghdr:], addrs)
		gw, _, ok := sockaddrInet4(sas[unix.RTAX_GATEWAY])
		if !ok {
			return
		}
		r := Route{IfIndex: want, Flags: flags, Gateway: gw}
		if ifa := sas[unix.RTAX_IFA]; ifa != nil {
			if ip, _, ok := sockaddrInet4(ifa); ok {
				r.Local = ip
			}
		}
		fillRouteIface(&r, ifaces)
		found = &r
	})
	if found == nil {
		return Route{}, fmt.Errorf("netcfg: no IPv4 gateway route on %s", name)
	}
	return *found, nil
}

// fillRouteIface copies the outgoing interface's identity into r.
func fillRouteIface(r *Route, ifaces map[int]*Interface) {
	if inf := ifaces[r.IfIndex]; inf != nil {
		r.Iface = inf.Name
		r.MAC = inf.MAC
		if !r.Local.IsValid() {
			for _, a := range inf.Addrs {
				if a.Is4() {
					r.Local = a
					break
				}
			}
		}
	}
	r.IsTunnel = IsTunnelInterface(r.Iface)
	if r.Iface != "" {
		if mtu, err := InterfaceMTU(r.Iface); err == nil {
			r.MTU = mtu
		}
	}
}

// Interfaces returns every interface the kernel reports, keyed by name.
func Interfaces() (map[string]Interface, error) {
	tbl, err := interfaceTable()
	if err != nil {
		return nil, err
	}
	out := make(map[string]Interface, len(tbl))
	for _, inf := range tbl {
		if inf.Name == "" {
			continue
		}
		out[inf.Name] = *inf
	}
	return out, nil
}

// interfaceTable dumps NET_RT_IFLIST into a map keyed by ifindex.
func interfaceTable() (map[int]*Interface, error) {
	buf, err := sysctlMIB([]int32{unix.CTL_NET, unix.AF_ROUTE, 0, 0, unix.NET_RT_IFLIST, 0})
	if err != nil {
		return nil, fmt.Errorf("netcfg: sysctl net.route.0.0.iflist: %w", err)
	}
	out := make(map[int]*Interface)
	get := func(idx int) *Interface {
		if inf := out[idx]; inf != nil {
			return inf
		}
		inf := &Interface{Index: idx}
		out[idx] = inf
		return inf
	}
	for b := buf; len(b) >= 4; {
		msglen := int(binary.LittleEndian.Uint16(b[0:2]))
		if msglen < 4 || msglen > len(b) {
			break
		}
		msg := b[:msglen]
		b = b[msglen:]
		if msg[2] != unix.RTM_VERSION {
			continue
		}
		switch msg[3] {
		case unix.RTM_IFINFO:
			if msglen <= sizeofIfMsghdr {
				continue
			}
			idx := int(binary.LittleEndian.Uint16(msg[offIfIndex : offIfIndex+2]))
			inf := get(idx)
			inf.Flags = binary.LittleEndian.Uint32(msg[offIfFlags : offIfFlags+4])
			addrs := binary.LittleEndian.Uint32(msg[offIfAddrs : offIfAddrs+4])
			sas := splitSockaddrs(msg[sizeofIfMsghdr:], addrs)
			if sa := sas[unix.RTAX_IFP]; sa != nil {
				if _, name, mac, ok := parseLinkAddr(sa); ok {
					if name != "" {
						inf.Name = name
					}
					if len(mac) > 0 {
						inf.MAC = mac
					}
				}
			}
		case unix.RTM_NEWADDR:
			if msglen <= sizeofIfaMsghdr {
				continue
			}
			idx := int(binary.LittleEndian.Uint16(msg[offIfaIndex : offIfaIndex+2]))
			addrs := binary.LittleEndian.Uint32(msg[offIfaAddrs : offIfaAddrs+4])
			sas := splitSockaddrs(msg[sizeofIfaMsghdr:], addrs)
			if sa := sas[unix.RTAX_IFA]; sa != nil {
				if ip, ok := sockaddrIP(sa); ok {
					inf := get(idx)
					inf.Addrs = append(inf.Addrs, ip)
				}
			}
		}
	}
	return out, nil
}

// routeMessageTypes are the RTM_* types whose payload is a struct rt_msghdr.
// A NET_RT_DUMP only ever reports RTM_GET, but accepting the family keeps the
// parser from being brittle across releases.
var routeMessageTypes = [256]bool{
	unix.RTM_ADD: true, unix.RTM_DELETE: true, unix.RTM_CHANGE: true,
	unix.RTM_GET: true, unix.RTM_LOSING: true, unix.RTM_REDIRECT: true,
	unix.RTM_MISS: true, unix.RTM_LOCK: true, unix.RTM_RESOLVE: true,
}

// forEachRouteMessage walks a routing-socket dump, invoking fn for each
// rt_msghdr-shaped message. It never reads past the end of buf.
func forEachRouteMessage(buf []byte, fn func(msg []byte)) {
	for b := buf; len(b) >= 4; {
		msglen := int(binary.LittleEndian.Uint16(b[0:2]))
		if msglen < 4 || msglen > len(b) {
			return
		}
		msg := b[:msglen]
		b = b[msglen:]
		if msg[2] != unix.RTM_VERSION || !routeMessageTypes[msg[3]] || msglen <= sizeofRtMsghdr {
			continue
		}
		fn(msg)
	}
}

// ARPTable dumps the IPv4 neighbour cache (NET_RT_FLAGS filtered by RTF_LLINFO)
// and returns each neighbour's link-layer address.
func ARPTable() (map[netip.Addr]net.HardwareAddr, error) {
	buf, err := sysctlMIB([]int32{unix.CTL_NET, unix.AF_ROUTE, 0, unix.AF_INET, unix.NET_RT_FLAGS, unix.RTF_LLINFO})
	if err != nil {
		return nil, fmt.Errorf("netcfg: sysctl net.route.0.inet.flags(RTF_LLINFO): %w", err)
	}
	out := make(map[netip.Addr]net.HardwareAddr)
	forEachRouteMessage(buf, func(msg []byte) {
		addrs := binary.LittleEndian.Uint32(msg[offRtAddrs : offRtAddrs+4])
		sas := splitSockaddrs(msg[sizeofRtMsghdr:], addrs)
		ip, _, ok := sockaddrInet4(sas[unix.RTAX_DST])
		if !ok {
			return
		}
		gw := sas[unix.RTAX_GATEWAY]
		if gw == nil {
			return
		}
		if _, _, mac, ok := parseLinkAddr(gw); ok && len(mac) == 6 {
			out[ip] = mac
		}
	})
	return out, nil
}

// ResolveGatewayMAC returns the next hop's link-layer address — the Ethernet
// destination the divert transport writes with BPF.
//
// If the neighbour is not cached yet, one UDP datagram is sent to its discard
// port to make the kernel do the ARP exchange, and the cache is polled for up
// to 1.5s. Nothing is expected in reply; the point is only the ARP request the
// send triggers.
func ResolveGatewayMAC(gw netip.Addr) (net.HardwareAddr, error) {
	if !gw.IsValid() {
		return nil, fmt.Errorf("netcfg: invalid gateway address")
	}
	tbl, err := ARPTable()
	if err != nil {
		return nil, err
	}
	if mac, ok := tbl[gw]; ok && len(mac) == 6 {
		return mac, nil
	}
	if err := primeARP(gw); err != nil {
		return nil, fmt.Errorf("netcfg: priming ARP for %s: %w", gw, err)
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		tbl, err = ARPTable()
		if err != nil {
			return nil, err
		}
		if mac, ok := tbl[gw]; ok && len(mac) == 6 {
			return mac, nil
		}
	}
	return nil, fmt.Errorf("netcfg: no ARP entry for %s after one probe", gw)
}

// primeARP sends a single UDP datagram to gw's discard port so the kernel
// resolves its link-layer address.
func primeARP(gw netip.Addr) error {
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: gw.AsSlice(), Port: 9})
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = c.Write([]byte{0})
	return err
}

// ifreqMTU mirrors the `struct ifreq` variant SIOCGIFMTU uses: a 16-byte
// interface name followed by the 16-byte union whose first member is an int.
// sizeof(struct ifreq) is 32 on Darwin, so the tail must be padded explicitly
// or the kernel writes past the Go value.
type ifreqMTU struct {
	Name [unix.IFNAMSIZ]byte
	MTU  int32
	_    [12]byte
}

// InterfaceMTU returns the named interface's MTU via ioctl(SIOCGIFMTU), which
// needs no privileges and works for a utun the daemon has just created.
func InterfaceMTU(name string) (int, error) {
	if name == "" || len(name) >= unix.IFNAMSIZ {
		return 0, fmt.Errorf("netcfg: invalid interface name %q", name)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, fmt.Errorf("netcfg: socket(AF_INET, SOCK_DGRAM): %w", err)
	}
	defer unix.Close(fd)

	var req ifreqMTU
	copy(req.Name[:], name)
	if err := ioctlPtr(fd, unix.SIOCGIFMTU, unsafe.Pointer(&req)); err != nil {
		return 0, fmt.Errorf("netcfg: ioctl(SIOCGIFMTU, %s): %w", name, err)
	}
	if req.MTU <= 0 {
		return 0, fmt.Errorf("netcfg: ioctl(SIOCGIFMTU, %s) returned %d", name, req.MTU)
	}
	return int(req.MTU), nil
}

// ---------------------------------------------------------------------------
// syscall plumbing
// ---------------------------------------------------------------------------

// ioctlPtr issues ioctl(fd, req, arg). It mirrors the unexported helper in
// x/sys/unix. arg must come from unsafe.Pointer(&x) so escape analysis
// heap-allocates x: heap objects do not move, so handing the kernel a uintptr
// of one is safe.
func ioctlPtr(fd int, req uint32, arg unsafe.Pointer) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

// sysctlMIB performs sysctl(3) with a numeric MIB, sizing the buffer with a
// probe call first. unix.SysctlRaw only accepts symbolic names and the routing
// table has none, so the MIB has to be numeric.
func sysctlMIB(mib []int32) ([]byte, error) {
	if len(mib) == 0 {
		return nil, unix.EINVAL
	}
	n := uintptr(0)
	if _, _, e := unix.Syscall6(unix.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
		0, uintptr(unsafe.Pointer(&n)), 0, 0); e != 0 {
		return nil, e
	}
	if n == 0 {
		return nil, nil
	}
	// The table can grow between the sizing call and the read, so retry on
	// ENOMEM with a slightly larger buffer each time.
	for attempt := 0; attempt < 4; attempt++ {
		buf := make([]byte, n)
		got := n
		_, _, e := unix.Syscall6(unix.SYS___SYSCTL,
			uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&got)), 0, 0)
		if e == 0 {
			if got > uintptr(len(buf)) {
				got = uintptr(len(buf))
			}
			return buf[:got], nil
		}
		if e != unix.ENOMEM {
			return nil, e
		}
		n = n + n/4 + 1024
	}
	return nil, unix.ENOMEM
}

// roundup4 implements the ROUNDUP() macro the Darwin routing code uses to step
// between sockaddrs: lengths round up to 4 bytes, and a zero length still
// consumes one 4-byte slot.
func roundup4(n int) int {
	if n == 0 {
		return 4
	}
	return (n + 3) &^ 3
}

// splitSockaddrs slices the sockaddr array following a routing message header
// into one entry per RTAX_* slot present in addrs. Absent slots are nil. It
// never reads past the end of b, which is what makes it safe on a truncated or
// hostile dump.
func splitSockaddrs(b []byte, addrs uint32) [][]byte {
	out := make([][]byte, rtaxMax)
	for i := 0; i < rtaxMax; i++ {
		if addrs&(1<<uint(i)) == 0 {
			continue
		}
		if len(b) < 2 {
			return out
		}
		salen := int(b[0])
		step := roundup4(salen)
		if salen == 0 || salen > len(b) {
			salen = min(step, len(b))
		}
		out[i] = b[:salen]
		if step >= len(b) {
			return out
		}
		b = b[step:]
	}
	return out
}

// sockaddrInet4 extracts the IPv4 address and port from a sockaddr_in the
// routing socket produced. Netmask slots are frequently truncated (sa_len < 16),
// so missing trailing bytes are read as zero, exactly as the kernel intends.
func sockaddrInet4(b []byte) (netip.Addr, uint16, bool) {
	if len(b) < 2 || b[1] != unix.AF_INET {
		return netip.Addr{}, 0, false
	}
	var a [4]byte
	if len(b) > 4 {
		copy(a[:], b[4:min(len(b), 8)])
	}
	var port uint16
	if len(b) >= 4 {
		port = binary.BigEndian.Uint16(b[2:4])
	}
	return netip.AddrFrom4(a), port, true
}

// sockaddrIP decodes either a sockaddr_in or a sockaddr_in6. The IPv6 scope id
// lives at offset 24 and is folded into the returned address as its zone so
// link-local addresses stay distinguishable.
func sockaddrIP(b []byte) (netip.Addr, bool) {
	if len(b) < 2 {
		return netip.Addr{}, false
	}
	switch b[1] {
	case unix.AF_INET:
		ip, _, ok := sockaddrInet4(b)
		return ip, ok
	case unix.AF_INET6:
		if len(b) < 24 {
			return netip.Addr{}, false
		}
		var a [16]byte
		copy(a[:], b[8:24])
		addr := netip.AddrFrom16(a)
		// Darwin stashes the scope id inside bytes 2-3 of a link-local
		// address instead of sin6_scope_id; normalise it away so the address
		// compares equal to what userspace configured.
		if addr.IsLinkLocalUnicast() {
			a[2], a[3] = 0, 0
			addr = netip.AddrFrom16(a)
		}
		return addr, true
	default:
		return netip.Addr{}, false
	}
}

// sockaddrMaskIsZero reports whether an RTAX_NETMASK slot denotes /0. The
// kernel encodes a default route's mask either by omitting the slot or by
// emitting a truncated sockaddr whose address bytes are all zero.
func sockaddrMaskIsZero(b []byte) bool {
	if len(b) <= 4 {
		return true
	}
	for _, c := range b[4:] {
		if c != 0 {
			return false
		}
	}
	return true
}

// parseLinkAddr decodes a sockaddr_dl. Layout from <net/if_dl.h>:
// sdl_len@0 sdl_family@1 sdl_index@2 sdl_type@4 sdl_nlen@5 sdl_alen@6
// sdl_slen@7 sdl_data@8.
func parseLinkAddr(b []byte) (index int, name string, mac net.HardwareAddr, ok bool) {
	if len(b) < 8 || b[1] != unix.AF_LINK {
		return 0, "", nil, false
	}
	index = int(binary.LittleEndian.Uint16(b[2:4]))
	nlen := int(b[5])
	alen := int(b[6])
	if 8+nlen > len(b) {
		return index, "", nil, false
	}
	name = string(b[8 : 8+nlen])
	if alen > 0 && 8+nlen+alen <= len(b) {
		mac = net.HardwareAddr(append([]byte(nil), b[8+nlen:8+nlen+alen]...))
	}
	return index, name, mac, true
}
