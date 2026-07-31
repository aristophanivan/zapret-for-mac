package proto

import (
	"bytes"
	"encoding/binary"
)

// stunMagicCookie is the fixed value at offset 4 of every RFC 5389 STUN message.
const stunMagicCookie uint32 = 0x2112a442

// stunHeaderLen is the fixed STUN header size (type, length, cookie, txid).
const stunHeaderLen = 20

// IsSTUN reports whether payload is a STUN message (RFC 5389): the two most
// significant bits of the first byte are zero, the magic cookie is present, and
// the length field — which excludes the header and is always a multiple of 4 —
// fits inside the datagram.
//
// The two zero bits are what keeps STUN distinguishable from QUIC and other
// media protocols multiplexed on the same UDP port; a QUIC packet always has at
// least the fixed bit (0x40) set.
func IsSTUN(payload []byte) bool {
	if len(payload) < stunHeaderLen {
		return false
	}
	if payload[0]&0xc0 != 0 {
		return false
	}
	if binary.BigEndian.Uint32(payload[4:8]) != stunMagicCookie {
		return false
	}
	msgLen := int(binary.BigEndian.Uint16(payload[2:4]))
	if msgLen&3 != 0 {
		return false
	}
	return stunHeaderLen+msgLen <= len(payload)
}

// discordIPDiscoveryLen is the exact size of a Discord voice IP-discovery
// datagram: type(2) + length(2) + ssrc(4) + address(64) + port(2).
const discordIPDiscoveryLen = 74

// discordIPDiscoveryBodyLen is the value of its length field: everything after
// the type and length fields (4 + 64 + 2).
const discordIPDiscoveryBodyLen = 70

// IsDiscordIPDiscovery reports whether payload is a Discord voice IP-discovery
// message — type 0x0001 (request) or 0x0002 (response) with the fixed 70-byte
// body. It is the first datagram a Discord voice client sends, which is why
// zapret keys its Discord voice desync on it.
func IsDiscordIPDiscovery(payload []byte) bool {
	if len(payload) != discordIPDiscoveryLen {
		return false
	}
	switch binary.BigEndian.Uint16(payload[0:2]) {
	case 1, 2:
	default:
		return false
	}
	return binary.BigEndian.Uint16(payload[2:4]) == discordIPDiscoveryBodyLen
}

// WireGuard message sizes (protocol spec §5.4): the handshake messages are
// fixed-length, transport data is a 16-byte header plus a padded AEAD payload.
const (
	wgInitiationLen = 148
	wgResponseLen   = 92
	wgDataMinLen    = 32 // 16-byte header + 16-byte tag (a keepalive)
)

// IsWireGuard reports whether payload looks like a WireGuard message. Every
// message starts with a one-byte type followed by three reserved zero bytes, and
// each type has a fixed (or, for transport data, a 16-byte-quantised) size:
// handshake initiation 148 B, handshake response 92 B, transport data
// 16 + 16k + 16 B.
func IsWireGuard(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	if payload[1] != 0 || payload[2] != 0 || payload[3] != 0 {
		return false
	}
	switch payload[0] {
	case 1:
		return len(payload) == wgInitiationLen
	case 2:
		return len(payload) == wgResponseLen
	case 4:
		// counter(8) + receiver(4) + type(4) = 16 header bytes, then ChaCha20
		// Poly1305 output: plaintext padded to a multiple of 16 plus the tag.
		return len(payload) >= wgDataMinLen && len(payload)%16 == 0
	}
	return false
}

// BitTorrent DHT queries and responses are bencoded dictionaries that always
// open with the transaction/type keys in the same order, giving a stable prefix.
var (
	dhtQueryPrefix    = []byte("d1:ad2:id20:")
	dhtResponsePrefix = []byte("d1:rd2:id20:")
)

// IsDHT reports whether payload is a BitTorrent DHT (KRPC) query or response.
func IsDHT(payload []byte) bool {
	// The prefix is followed by the 20-byte node ID it announces.
	if len(payload) < len(dhtQueryPrefix)+20 {
		return false
	}
	return bytes.HasPrefix(payload, dhtQueryPrefix) || bytes.HasPrefix(payload, dhtResponsePrefix)
}
