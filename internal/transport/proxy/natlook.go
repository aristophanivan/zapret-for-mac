package proxy

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/naladwepo/zapret-for-mac/internal/pfvar"
)

// This file is the one thing that makes a userspace relay possible at all on
// macOS: recovering where a redirected connection was originally going.
//
// pf's `rdr` rewrites the destination before the kernel delivers the SYN, so by
// the time accept(2) returns, the socket's local address is the listener's
// (127.0.0.1:10800) and the original destination exists only inside pf's state
// table. ioctl(DIOCNATLOOK) on /dev/pf asks for it back. There is no
// SO_ORIGINAL_DST on Darwin, and no alternative that does not need a kernel
// extension.
//
// The call shape is cross-checked against zapret's own implementation,
// tpws/redirect.c destination_from_pf(), which on an installed zapret is at
// /opt/zapret/tpws/redirect.c and was read while writing this:
//
//	saddr/sxport  = the accepted socket's PEER address   (our `client`)
//	daddr/dxport  = the accepted socket's LOCAL address  (our `local`)
//	proto         = IPPROTO_TCP
//	direction     = PF_OUT
//	result        = rdaddr + rdxport, with nl.af re-checked afterwards
//
// It also converts 4-in-6 mapped addresses to plain IPv4 before the lookup and
// refuses a family mismatch between the two addresses — both of which pfvar.Natlook
// does. /dev/pf is opened O_RDONLY there too.

// ErrNotRedirected means the connection did not come through our rdr rule, so
// there is no original destination to recover. Somebody connected to the
// listener directly.
var ErrNotRedirected = errors.New("proxy: connection was not redirected by pf")

// DestLookup recovers the original (pre-translation) destination of a connection
// that arrived at the local listener.
//
// It is an interface for two reasons: the tests drive the whole relay without
// root by supplying their own, and a future transport that learns the
// destination some other way (a SOCKS/HTTP CONNECT front end, say) can slot in
// without touching the datapath.
type DestLookup interface {
	// OrigDst maps an accepted connection's (peer, local) pair to the address
	// the client originally connected to. client is the socket's peer address,
	// local the address it was accepted on. Both ports are in host order.
	OrigDst(client, local netip.AddrPort) (netip.AddrPort, error)
	// Close releases whatever the lookup holds.
	Close() error
}

// LookupFunc adapts a plain function to DestLookup.
type LookupFunc func(client, local netip.AddrPort) (netip.AddrPort, error)

// OrigDst implements DestLookup.
func (f LookupFunc) OrigDst(client, local netip.AddrPort) (netip.AddrPort, error) {
	return f(client, local)
}

// Close implements DestLookup and does nothing.
func (f LookupFunc) Close() error { return nil }

// pfLookup answers from pf's state table via ioctl(DIOCNATLOOK) on /dev/pf.
type pfLookup struct {
	// mu guards fd against a Close racing with in-flight lookups: without it a
	// closed descriptor number could be reused by another part of the process
	// and this ioctl would be aimed at an unrelated file.
	mu sync.RWMutex
	fd int
}

// OpenPFLookup opens /dev/pf for original-destination queries.
//
// The descriptor is read-only, which is all DIOCNATLOOK needs and all this
// process should ever have: it cannot be used to change the packet filter.
// /dev/pf is 0600 root:wheel, so this requires euid 0.
func OpenPFLookup() (DestLookup, error) {
	fd, err := pfvar.Open()
	if err != nil {
		return nil, fmt.Errorf("proxy: the relay cannot recover original destinations: %w", err)
	}
	return &pfLookup{fd: fd}, nil
}

// OrigDst implements DestLookup.
func (l *pfLookup) OrigDst(client, local netip.AddrPort) (netip.AddrPort, error) {
	l.mu.RLock()
	fd := l.fd
	l.mu.RUnlock()
	if fd < 0 {
		return netip.AddrPort{}, fmt.Errorf("proxy: %w", pfvar.ErrClosed)
	}

	// pf keeps the state under the tuple as it exists after translation: source
	// = the client, destination = the rdr target (our listener). Direction
	// PF_OUT is the translator's point of view, which is what an rdr lookup
	// needs — the same choice tpws makes.
	dst, err := pfvar.Natlook(fd, 0, unix.IPPROTO_TCP, client, local)
	if err != nil {
		if errors.Is(err, pfvar.ErrNoState) {
			return netip.AddrPort{}, fmt.Errorf("%w: %v -> %v has no pf state (%v)",
				ErrNotRedirected, client, local, err)
		}
		return netip.AddrPort{}, err
	}
	if err := validateDest(dst, client, local); err != nil {
		return netip.AddrPort{}, err
	}
	return dst, nil
}

// Close implements DestLookup.
func (l *pfLookup) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	fd := l.fd
	l.fd = -1
	return pfvar.Close(fd)
}

// FD exposes the /dev/pf descriptor for diagnostics. It is -1 after Close.
func (l *pfLookup) FD() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.fd
}

// validateDest rejects a recovered destination that cannot be right.
//
// A wrong answer here is the failure mode the pfvar package warns about: the
// ioctl succeeds and hands back a plausible address read from the wrong offset.
// These checks cannot prove the ABI is right, but they catch the cases that
// would otherwise turn into a connection to the wrong server or a relay talking
// to itself.
func validateDest(dst, client, local netip.AddrPort) error {
	if !dst.IsValid() || dst.Port() == 0 {
		return fmt.Errorf("proxy: pf returned an unusable original destination %v for %v -> %v; %s",
			dst, client, local, pfvar.Layout())
	}
	if dst == local {
		// pf answered with the post-translation tuple, i.e. no translation was
		// recorded. Relaying would connect us to our own listener.
		return fmt.Errorf("%w: pf returned the listener's own address %v for %v",
			ErrNotRedirected, dst, client)
	}
	if dst == client {
		return fmt.Errorf("proxy: pf returned the client's own address %v as the original "+
			"destination; the DIOCNATLOOK result is being read from the wrong offset. %s",
			dst, pfvar.Layout())
	}
	if dst.Addr().Unmap().Is4() != client.Addr().Unmap().Is4() {
		return fmt.Errorf("proxy: pf returned a %s destination (%v) for a %s client (%v); "+
			"the DIOCNATLOOK result is being read from the wrong offset. %s",
			family(dst.Addr()), dst, family(client.Addr()), client, pfvar.Layout())
	}
	return nil
}

// family names an address family for an error message.
func family(a netip.Addr) string {
	if a.Unmap().Is4() {
		return "IPv4"
	}
	return "IPv6"
}
