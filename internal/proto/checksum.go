package proto

import (
	"encoding/binary"
	"net/netip"
)

// Checksum16 returns the RFC 1071 internet checksum of data: the ones'
// complement of the ones'-complement sum of its 16-bit big-endian words, with a
// final odd byte padded by a zero byte.
//
// This is the value that goes into the header field, so the field itself must be
// zero while summing. Summing a buffer that already carries its correct checksum
// yields 0, which is the usual way to verify one.
func Checksum16(data []byte) uint16 {
	return ^fold32(sum16(0, data))
}

// sum16 adds the 16-bit big-endian words of b into acc. A trailing odd byte is
// treated as the high half of a word, per RFC 1071. Only the last chunk of a
// multi-chunk sum may have odd length, otherwise the words would misalign.
func sum16(acc uint32, b []byte) uint32 {
	i := 0
	for ; i+1 < len(b); i += 2 {
		acc += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if i < len(b) {
		acc += uint32(b[i]) << 8
	}
	return acc
}

// fold32 folds the carries of a 32-bit accumulator into 16 bits.
func fold32(acc uint32) uint16 {
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return uint16(acc)
}

// L4Checksum computes the TCP/UDP checksum of l4 (header plus payload, with its
// own checksum field zeroed) over the IPv4 or IPv6 pseudo-header, chosen from
// the address family of src/dst.
//
// A computed zero is returned as 0xffff: for UDP a zero field means "no
// checksum", so the ones'-complement -0 must be sent as +0 (RFC 768 / RFC 8200
// 8.1). Doing it for TCP as well is harmless, since 0 and 0xffff are the same
// value in ones'-complement arithmetic.
func L4Checksum(src, dst netip.Addr, ipproto uint8, l4 []byte) uint16 {
	src, dst = src.Unmap(), dst.Unmap()

	var acc uint32
	if src.Is4() && dst.Is4() {
		s, d := src.As4(), dst.As4()
		acc = sum16(acc, s[:])
		acc = sum16(acc, d[:])
		// zero byte + protocol byte form one word, then the 16-bit L4 length.
		acc += uint32(ipproto)
		acc += uint32(uint16(len(l4)))
	} else {
		// As16 is defined for every valid address (and returns zeros for the
		// invalid zero value), so a family mismatch degrades to an IPv6
		// pseudo-header instead of panicking.
		s, d := src.As16(), dst.As16()
		acc = sum16(acc, s[:])
		acc = sum16(acc, d[:])
		// The IPv6 pseudo-header carries a 32-bit upper-layer length and puts
		// the next-header value in the last byte of a 4-byte word.
		n := uint32(len(l4))
		acc += n >> 16
		acc += n & 0xffff
		acc += uint32(ipproto)
	}

	acc = sum16(acc, l4)
	sum := ^fold32(acc)
	if sum == 0 {
		return 0xffff
	}
	return sum
}

// ipv4HeaderChecksumInPlace recomputes the header checksum of an IPv4 header of
// ihl bytes at the start of hdr.
func ipv4HeaderChecksumInPlace(hdr []byte) {
	if len(hdr) < ipv4MinHdrLen {
		return
	}
	ihl := int(hdr[0]&0x0f) * 4
	if ihl < ipv4MinHdrLen || ihl > len(hdr) {
		return
	}
	binary.BigEndian.PutUint16(hdr[10:12], 0)
	binary.BigEndian.PutUint16(hdr[10:12], Checksum16(hdr[:ihl]))
}
