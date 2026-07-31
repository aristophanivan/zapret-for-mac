//go:build darwin

package pfvar

import (
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestNatlookLayout is the loud failure the package comment promises: it pins
// every offset of our transcription of struct pfioc_natlook against the numbers
// the C compiler printed for zapret's vendored pfvar.h on this machine (see the
// package comment). Apple ships no pfvar.h in the SDK, so nothing else in a
// normal build can catch a mistake here — a wrong offset does not fail the
// ioctl, it returns a plausible-but-wrong address.
func TestNatlookLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(natlook{}), uintptr(84); got != want {
		t.Fatalf("sizeof(struct pfioc_natlook) = %d, want %d; the size is encoded in "+
			"DIOCNATLOOK, so the kernel will reject the ioctl with ENOTTY", got, want)
	}
	if got, want := unsafe.Sizeof(addr{}), uintptr(16); got != want {
		t.Errorf("sizeof(struct pf_addr) = %d, want %d", got, want)
	}
	if got, want := unsafe.Alignof(addr{}), uintptr(4); got != want {
		t.Errorf("alignof(struct pf_addr) = %d, want %d (widest union member is u_int32_t)", got, want)
	}
	if got, want := unsafe.Sizeof(xport{}), uintptr(4); got != want {
		t.Errorf("sizeof(union pf_state_xport) = %d, want %d", got, want)
	}
	if got, want := unsafe.Alignof(xport{}), uintptr(4); got != want {
		t.Errorf("alignof(union pf_state_xport) = %d, want %d (widest union member is u_int32_t spi)", got, want)
	}
	if got, want := unsafe.Alignof(natlook{}), uintptr(4); got != want {
		t.Errorf("alignof(struct pfioc_natlook) = %d, want %d", got, want)
	}

	for _, c := range []struct {
		field string
		got   uintptr
		want  uintptr
	}{
		{"saddr", unsafe.Offsetof(natlook{}.Saddr), 0},
		{"daddr", unsafe.Offsetof(natlook{}.Daddr), 16},
		{"rsaddr", unsafe.Offsetof(natlook{}.Rsaddr), 32},
		{"rdaddr", unsafe.Offsetof(natlook{}.Rdaddr), 48},
		{"sxport", unsafe.Offsetof(natlook{}.Sxport), 64},
		{"dxport", unsafe.Offsetof(natlook{}.Dxport), 68},
		{"rsxport", unsafe.Offsetof(natlook{}.Rsxport), 72},
		{"rdxport", unsafe.Offsetof(natlook{}.Rdxport), 76},
		{"af", unsafe.Offsetof(natlook{}.Af), 80},
		{"proto", unsafe.Offsetof(natlook{}.Proto), 81},
		{"proto_variant", unsafe.Offsetof(natlook{}.ProtoVariant), 82},
		{"direction", unsafe.Offsetof(natlook{}.Direction), 83},
	} {
		if c.got != c.want {
			t.Errorf("offsetof(struct pfioc_natlook.%s) = %d, want %d — see the layout in the package comment",
				c.field, c.got, c.want)
		}
	}
}

// TestDIOCNATLOOKNumber checks the request number (0xc0544417, as printed by
// _IOWR('D', 23, struct pfioc_natlook) on this machine) and, separately, the way
// it is built: an error in the _IOWR encoding is as fatal as one in the struct.
func TestDIOCNATLOOKNumber(t *testing.T) {
	const want = uint32(0xc0544417)
	if DIOCNATLOOK != want {
		t.Fatalf("DIOCNATLOOK = %#08x, want %#08x", uint32(DIOCNATLOOK), want)
	}
	// Decompose the value the way <sys/ioccom.h> composes it.
	if got := DIOCNATLOOK & iocInOut; got != iocInOut {
		t.Errorf("direction bits = %#08x, want IOC_INOUT %#08x (_IOWR)", got, iocInOut)
	}
	if got := (DIOCNATLOOK >> 16) & iocParmMask; got != 84 {
		t.Errorf("encoded parameter length = %d, want 84", got)
	}
	if got := (DIOCNATLOOK >> 8) & 0xff; got != uint32('D') {
		t.Errorf("group = %#x, want 'D' = %#x", got, 'D')
	}
	if got := DIOCNATLOOK & 0xff; got != 23 {
		t.Errorf("command number = %d, want 23", got)
	}
}

// TestXportIsNetworkOrder guards the one field whose byte order is not implied by
// its Go type: pf_state_xport.port is stored big-endian regardless of the host.
func TestXportIsNetworkOrder(t *testing.T) {
	var x xport
	x.setPort(443)
	if x.Raw[0] != 0x01 || x.Raw[1] != 0xbb {
		t.Errorf("setPort(443) wrote % x, want 01 bb (network order)", x.Raw[:2])
	}
	if x.Raw[2] != 0 || x.Raw[3] != 0 {
		t.Errorf("setPort must not touch the spi tail, got % x", x.Raw[:])
	}
	if got := x.port(); got != 443 {
		t.Errorf("port() = %d, want 443", got)
	}
	x = xport{}
	x.setPort(65535)
	if got := x.port(); got != 65535 {
		t.Errorf("port() = %d, want 65535", got)
	}
}

// TestAddrUnion checks that an address lands in the union the way in_addr and
// in6_addr overlay it.
func TestAddrUnion(t *testing.T) {
	var a addr
	a.set(netip.MustParseAddr("198.51.100.7"))
	if a.Raw[0] != 198 || a.Raw[1] != 51 || a.Raw[2] != 100 || a.Raw[3] != 7 {
		t.Errorf("IPv4 stored as % x, want c6 33 64 07 in the first four bytes", a.Raw[:4])
	}
	for i := 4; i < 16; i++ {
		if a.Raw[i] != 0 {
			t.Errorf("IPv4 must leave byte %d of the union zero, got %#x", i, a.Raw[i])
		}
	}
	if got, ok := a.get(unix.AF_INET); !ok || got != netip.MustParseAddr("198.51.100.7") {
		t.Errorf("get(AF_INET) = %v, %v; want 198.51.100.7, true", got, ok)
	}

	var b addr
	v6 := netip.MustParseAddr("2001:db8::dead:beef")
	b.set(v6)
	if got, ok := b.get(unix.AF_INET6); !ok || got != v6 {
		t.Errorf("get(AF_INET6) = %v, %v; want %v, true", got, ok, v6)
	}
	if _, ok := b.get(99); ok {
		t.Error("get() accepted an unknown address family")
	}
}

// TestAddrFamily covers the 4-in-6 case, which is the form the Go runtime hands
// out for IPv4 connections accepted on a dual-stack listener.
func TestAddrFamily(t *testing.T) {
	cases := []struct {
		in   string
		want uint8
	}{
		{"127.0.0.1", unix.AF_INET},
		{"::ffff:127.0.0.1", unix.AF_INET},
		{"::1", unix.AF_INET6},
		{"2001:db8::1", unix.AF_INET6},
	}
	for _, c := range cases {
		if got := AddrFamily(netip.MustParseAddr(c.in)); got != c.want {
			t.Errorf("AddrFamily(%s) = %d, want %d", c.in, got, c.want)
		}
	}
	if got := AddrFamily(netip.Addr{}); got != 0 {
		t.Errorf("AddrFamily(invalid) = %d, want 0", got)
	}
}

// TestNatlookRejectsBadInput exercises every validation Natlook does before it
// reaches the kernel. None of these needs root, because none of them issues the
// ioctl.
func TestNatlookRejectsBadInput(t *testing.T) {
	v4 := netip.MustParseAddrPort("192.0.2.10:12345")
	v4b := netip.MustParseAddrPort("203.0.113.1:443")
	v6 := netip.MustParseAddrPort("[2001:db8::1]:443")

	if _, err := Natlook(-1, unix.AF_INET, unix.IPPROTO_TCP, v4, v4b); !errors.Is(err, ErrClosed) {
		t.Errorf("Natlook with fd -1: err = %v, want ErrClosed", err)
	}
	if _, err := Natlook(3, unix.AF_INET, unix.IPPROTO_TCP, netip.AddrPort{}, v4b); err == nil {
		t.Error("Natlook accepted an invalid src")
	}
	if _, err := Natlook(3, unix.AF_INET, unix.IPPROTO_TCP, v4, netip.AddrPort{}); err == nil {
		t.Error("Natlook accepted an invalid dst")
	}
	if _, err := Natlook(3, unix.AF_INET, unix.IPPROTO_TCP, v4, v6); !errors.Is(err, ErrFamily) {
		t.Errorf("Natlook with mixed families: err = %v, want ErrFamily", err)
	}
	if _, err := Natlook(3, unix.AF_INET6, unix.IPPROTO_TCP, v4, v4b); !errors.Is(err, ErrFamily) {
		t.Errorf("Natlook(AF_INET6) with IPv4 addresses: err = %v, want ErrFamily", err)
	}
	if _, err := Natlook(3, 42, unix.IPPROTO_TCP, v4, v4b); !errors.Is(err, ErrFamily) {
		t.Errorf("Natlook with af=42: err = %v, want ErrFamily", err)
	}
}

// TestLayoutMentionsTheNumbers keeps the diagnostic string useful: an operator
// reading a wrong-destination report must be able to see the ABI in use.
func TestLayoutMentionsTheNumbers(t *testing.T) {
	s := Layout()
	for _, want := range []string{"sizeof=84", "rdaddr@48", "rdxport@76", "0xc0544417"} {
		if !strings.Contains(s, want) {
			t.Errorf("Layout() = %q, missing %q", s, want)
		}
	}
}

// TestCloseIsSafeOnNegativeFd keeps teardown paths guard-free.
func TestCloseIsSafeOnNegativeFd(t *testing.T) {
	if err := Close(-1); err != nil {
		t.Errorf("Close(-1) = %v, want nil", err)
	}
}

// TestOpenAndNatlookLive is the only check that involves the kernel, and the
// only one that can confirm the request number is one the kernel recognises: a
// tuple that certainly has no pf state must come back as ErrNoState (ENOENT)
// rather than ENOTTY (unknown request => our struct size is wrong).
//
// /dev/pf is 0600 root:wheel, so this needs uid 0.
func TestOpenAndNatlookLive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skipf("needs root: %s is 0600 root:wheel and DIOCNATLOOK is a privileged query (uid %d)",
			DevicePath, os.Geteuid())
	}
	if _, err := os.Stat(DevicePath); err != nil {
		t.Skipf("needs %s: %v", DevicePath, err)
	}
	fd, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() {
		if err := Close(fd); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	// TEST-NET-1 to TEST-NET-3 with an ephemeral-looking source: no state can
	// exist for this, so pf must answer ENOENT.
	src := netip.MustParseAddrPort("192.0.2.123:54321")
	dst := netip.MustParseAddrPort("203.0.113.45:65001")
	if _, err := Natlook(fd, unix.AF_INET, unix.IPPROTO_TCP, src, dst); !errors.Is(err, ErrNoState) {
		t.Fatalf("Natlook for a tuple with no state: err = %v, want ErrNoState; "+
			"an ENOTTY here means struct pfioc_natlook is no longer %d bytes", err, SizeofNatlook)
	}
}
