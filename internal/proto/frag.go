package proto

import (
	"encoding/binary"
	"fmt"
)

// ipv6EmptyExtHdr is the body of an "empty" IPv6 option header: after the
// NextHeader/HdrExtLen pair the remaining 6 bytes must still be valid TLV
// options, so they hold one PadN (kind 1) option of length 4.
var ipv6EmptyExtHdr = [6]byte{1, 4, 0, 0, 0, 0}

// IPFragment splits an IPv4 packet into exactly two fragments at pos bytes of
// L4 content (pos counts from the first byte after the IP header, i.e. the TCP
// or UDP header is part of the first fragment).
//
// pos is rounded down to a multiple of 8 because an IPv4 fragment offset counts
// 8-byte units. The first fragment gets MF set, the second gets the rounded
// offset; both keep the original IPID so the peer reassembles them, and both get
// a freshly computed header checksum. The L4 checksum is not touched: it was
// computed over the whole datagram and stays valid after reassembly.
//
// DF is cleared on both fragments (a fragment that forbids fragmentation is a
// contradiction middleboxes drop), and IP options, if any, are copied verbatim.
func IPFragment(pkt []byte, pos int) ([][]byte, error) {
	if len(pkt) < 1 {
		return nil, fmt.Errorf("%w: empty buffer", ErrTruncated)
	}
	if pkt[0]>>4 == 6 {
		return nil, fmt.Errorf("proto: cannot fragment IPv6 in place, use AddIPv6ExtHdr + a fragment header")
	}
	if pkt[0]>>4 != 4 {
		return nil, fmt.Errorf("%w: %d", ErrIPVersion, pkt[0]>>4)
	}
	if len(pkt) < ipv4MinHdrLen {
		return nil, fmt.Errorf("%w: ipv4 header wants %d bytes, have %d", ErrTruncated, ipv4MinHdrLen, len(pkt))
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4MinHdrLen || ihl > len(pkt) {
		return nil, fmt.Errorf("%w: ipv4 ihl %d, buffer %d", ErrMalformedHeader, ihl, len(pkt))
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total == 0 {
		total = len(pkt)
	}
	if total < ihl {
		return nil, fmt.Errorf("%w: ipv4 total length %d < ihl %d", ErrMalformedHeader, total, ihl)
	}
	if total > len(pkt) {
		return nil, fmt.Errorf("%w: ipv4 total length %d, have %d", ErrTruncated, total, len(pkt))
	}

	l4len := total - ihl
	// Round down to the 8-byte granularity of the fragment offset field.
	fpos := pos &^ 7
	if fpos < 8 || fpos >= l4len {
		return nil, fmt.Errorf("proto: cannot fragment %d L4 bytes at position %d (rounded %d): need 8 <= pos < %d",
			l4len, pos, fpos, l4len)
	}

	// The original may already be a fragment: keep its base offset and its MF.
	fragField := binary.BigEndian.Uint16(pkt[6:8])
	baseOff := int(fragField & 0x1fff)
	origMF := fragField & 0x2000
	if (baseOff+fpos/8)&^0x1fff != 0 {
		return nil, fmt.Errorf("proto: fragment offset %d overflows the 13-bit field", baseOff+fpos/8)
	}

	first := make([]byte, ihl+fpos)
	copy(first, pkt[:ihl])
	copy(first[ihl:], pkt[ihl:ihl+fpos])
	binary.BigEndian.PutUint16(first[2:4], uint16(len(first)))
	binary.BigEndian.PutUint16(first[6:8], uint16(baseOff)|0x2000) // MF, DF cleared
	ipv4HeaderChecksumInPlace(first)

	second := make([]byte, ihl+l4len-fpos)
	copy(second, pkt[:ihl])
	copy(second[ihl:], pkt[ihl+fpos:total])
	binary.BigEndian.PutUint16(second[2:4], uint16(len(second)))
	binary.BigEndian.PutUint16(second[6:8], uint16(baseOff+fpos/8)|origMF)
	ipv4HeaderChecksumInPlace(second)

	return [][]byte{first, second}, nil
}

// AddIPv6ExtHdr inserts count empty extension headers of the given kind
// (IPProtoHopOpt = 0 hop-by-hop, IPProtoDstOpt = 60 destination options) between
// the fixed IPv6 header and whatever follows it, rewriting the NextHeader chain
// and the payload length. The input is not modified; a fresh buffer is returned.
//
// count == 2 is --dpi-desync-fooling=hopbyhop2, which deliberately violates
// RFC 8200 (at most one hop-by-hop header, and only first): DPI stacks that
// re-walk the chain give up while the peer's IPv6 stack still accepts it. The
// duplicate is therefore produced faithfully, not normalised away.
//
// L4 checksums are unaffected: the IPv6 pseudo-header covers the addresses, the
// upper-layer length and the final next-header value, none of which change.
func AddIPv6ExtHdr(pkt []byte, count int, kind uint8) ([]byte, error) {
	if len(pkt) < ipv6FixedHdrLen {
		return nil, fmt.Errorf("%w: ipv6 header wants %d bytes, have %d", ErrTruncated, ipv6FixedHdrLen, len(pkt))
	}
	if pkt[0]>>4 != 6 {
		return nil, fmt.Errorf("%w: %d (AddIPv6ExtHdr is IPv6 only)", ErrIPVersion, pkt[0]>>4)
	}
	if kind != IPProtoHopOpt && kind != IPProtoDstOpt {
		return nil, fmt.Errorf("proto: extension header kind %d is not hop-by-hop (%d) or destination options (%d)",
			kind, IPProtoHopOpt, IPProtoDstOpt)
	}
	if count < 0 {
		return nil, fmt.Errorf("proto: negative extension header count %d", count)
	}

	plen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if plen == 0 {
		// Offload/jumbogram: the buffer length is the only truth available.
		plen = len(pkt) - ipv6FixedHdrLen
	} else if ipv6FixedHdrLen+plen > len(pkt) {
		return nil, fmt.Errorf("%w: ipv6 payload length %d, have %d", ErrTruncated, plen, len(pkt)-ipv6FixedHdrLen)
	}
	body := pkt[ipv6FixedHdrLen : ipv6FixedHdrLen+plen]

	if count == 0 {
		out := make([]byte, ipv6FixedHdrLen+plen)
		copy(out, pkt[:ipv6FixedHdrLen])
		binary.BigEndian.PutUint16(out[4:6], uint16(plen))
		copy(out[ipv6FixedHdrLen:], body)
		return out, nil
	}

	added := count * 8
	if plen+added > 0xffff {
		return nil, fmt.Errorf("proto: %d extension headers overflow the ipv6 payload length (%d + %d)", count, plen, added)
	}

	out := make([]byte, ipv6FixedHdrLen+added+plen)
	copy(out, pkt[:ipv6FixedHdrLen])
	binary.BigEndian.PutUint16(out[4:6], uint16(plen+added))

	origNext := pkt[6]
	out[6] = kind // the fixed header now points at the first inserted header
	for i := 0; i < count; i++ {
		off := ipv6FixedHdrLen + i*8
		if i == count-1 {
			out[off] = origNext // last one hands over to the original payload
		} else {
			out[off] = kind
		}
		out[off+1] = 0 // HdrExtLen 0 == this header is 8 bytes long
		copy(out[off+2:off+8], ipv6EmptyExtHdr[:])
	}
	copy(out[ipv6FixedHdrLen+added:], body)
	return out, nil
}
