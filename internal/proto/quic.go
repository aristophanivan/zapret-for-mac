package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
)

// QUIC versions whose Initial packets we can decrypt. The salt and the
// long-header packet-type numbering are version specific, so an unknown version
// is unparseable by construction.
const (
	quicVer1       uint32 = 0x00000001 // RFC 9000
	quicVer2       uint32 = 0x6b3343cf // RFC 9369
	quicVerDraft29 uint32 = 0xff00001d // draft-ietf-quic-transport-29
)

// Per-version Initial salts (RFC 9001 §5.2, RFC 9369 §3.3, draft-29 §5.2).
var (
	quicSaltV1 = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
	}
	quicSaltV2 = []byte{
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
	}
	quicSaltDraft29 = []byte{
		0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
		0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
	}
)

const (
	quicMaxCIDLen = 20 // RFC 9000 §17.2: connection IDs are at most 20 bytes
	quicSampleLen = 16 // header-protection sample size
	quicHPKeyLen  = 16 // Initial keys are always AES-128
	quicKeyLen    = 16
	quicIVLen     = 12
	quicTagLen    = 16 // AES-GCM authentication tag
	// quicMaxCrypto caps CRYPTO-frame reassembly. A ClientHello that matters for
	// SNI extraction is a couple of kilobytes; the cap keeps a hostile frame
	// offset from asking for a huge allocation.
	quicMaxCrypto = 1 << 16
)

// quicHeader is a decoded QUIC Initial long header. Its slices alias the input.
type quicHeader struct {
	ver   uint32
	dcid  []byte
	pnOff int // offset of the (still header-protected) packet number field
	end   int // offset just past this packet: pnOff + Length
}

// quicVarint decodes a QUIC variable-length integer (RFC 9000 §16). The top two
// bits of the first byte select a 1, 2, 4 or 8 byte encoding; the remaining 6
// bits are the most significant bits of the value.
func quicVarint(b []byte) (v uint64, n int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, false
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, true
}

// quicInitialTypeBits returns the value of the two long-header type bits that
// means "Initial" for a version. RFC 9369 renumbered the packet types in v2
// (Initial moved from 0 to 1) specifically so v1-aware middleboxes stop
// recognising it, so the check has to be version-dependent.
func quicInitialTypeBits(ver uint32) (uint8, bool) {
	switch ver {
	case quicVer1, quicVerDraft29:
		return 0, true
	case quicVer2:
		return 1, true
	}
	return 0, false
}

// parseQUICInitial decodes the long header of a client Initial packet. It fails
// unless every length in the header is self-consistent and the packet's declared
// Length fits inside the datagram, which is what makes truncated captures and
// random payloads fall through instead of being taken for QUIC.
func parseQUICInitial(p []byte) (quicHeader, bool) {
	var h quicHeader
	// Shortest conceivable prefix: flags + version + dcidlen + scidlen.
	if len(p) < 7 {
		return h, false
	}
	// 0x80 = long header, 0x40 = fixed ("QUIC") bit.
	if p[0]&0xc0 != 0xc0 {
		return h, false
	}
	h.ver = binary.BigEndian.Uint32(p[1:5])
	initType, ok := quicInitialTypeBits(h.ver)
	if !ok || (p[0]>>4)&0x03 != initType {
		return h, false
	}

	off := 5
	dl := int(p[off])
	off++
	if dl > quicMaxCIDLen || off+dl >= len(p) {
		return h, false
	}
	h.dcid = p[off : off+dl]
	off += dl

	sl := int(p[off])
	off++
	if sl > quicMaxCIDLen || off+sl > len(p) {
		return h, false
	}
	off += sl

	tokLen, n, ok := quicVarint(p[off:])
	if !ok {
		return h, false
	}
	off += n
	if tokLen > uint64(len(p)-off) {
		return h, false
	}
	off += int(tokLen)

	plen, n, ok := quicVarint(p[off:])
	if !ok {
		return h, false
	}
	off += n
	// Length covers the packet number, the protected payload and the AEAD tag.
	if plen < 1+quicTagLen || plen > uint64(len(p)-off) {
		return h, false
	}
	h.pnOff = off
	h.end = off + int(plen)
	return h, true
}

// IsQUICInitial reports whether payload starts with a QUIC Initial packet of a
// version we know how to decrypt (v1, v2 or draft-29).
func IsQUICInitial(payload []byte) bool {
	_, ok := parseQUICInitial(payload)
	return ok
}

// quicExpandLabel is HKDF-Expand-Label from TLS 1.3 (RFC 8446 §7.1) with an
// empty context, which is what QUIC key derivation uses.
func quicExpandLabel(secret []byte, label string, n int) ([]byte, bool) {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = append(info, byte(n>>8), byte(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // zero-length context
	out, err := hkdf.Expand(sha256.New, secret, string(info), n)
	if err != nil {
		return nil, false
	}
	return out, true
}

// quicInitialKeys derives the client Initial header-protection key, AEAD key and
// IV from the packet's Destination Connection ID (RFC 9001 §5.2).
func quicInitialKeys(ver uint32, dcid []byte) (hp, key, iv []byte, ok bool) {
	var salt []byte
	// v2 changed the labels as well as the salt (RFC 9369 §3.3).
	hpLabel, keyLabel, ivLabel := "quic hp", "quic key", "quic iv"
	switch ver {
	case quicVer1:
		salt = quicSaltV1
	case quicVerDraft29:
		salt = quicSaltDraft29
	case quicVer2:
		salt = quicSaltV2
		hpLabel, keyLabel, ivLabel = "quicv2 hp", "quicv2 key", "quicv2 iv"
	default:
		return nil, nil, nil, false
	}

	// initial_secret = HKDF-Extract(salt, client_dst_connection_id)
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, nil, nil, false
	}
	client, ok := quicExpandLabel(initial, "client in", sha256.Size)
	if !ok {
		return nil, nil, nil, false
	}
	if hp, ok = quicExpandLabel(client, hpLabel, quicHPKeyLen); !ok {
		return nil, nil, nil, false
	}
	if key, ok = quicExpandLabel(client, keyLabel, quicKeyLen); !ok {
		return nil, nil, nil, false
	}
	if iv, ok = quicExpandLabel(client, ivLabel, quicIVLen); !ok {
		return nil, nil, nil, false
	}
	return hp, key, iv, true
}

// quicDecryptInitial removes header protection and decrypts the payload of a
// QUIC Initial packet, returning the frame bytes. The input is never modified.
func quicDecryptInitial(p []byte) ([]byte, bool) {
	h, ok := parseQUICInitial(p)
	if !ok {
		return nil, false
	}
	hp, key, iv, ok := quicInitialKeys(h.ver, h.dcid)
	if !ok {
		return nil, false
	}

	// Header protection (RFC 9001 §5.4.2): the mask is AES-ECB over the 16 bytes
	// starting 4 bytes past the packet number field — the sample position assumes
	// the maximum 4-byte packet number, whatever its real length turns out to be.
	sampleOff := h.pnOff + 4
	if sampleOff+quicSampleLen > h.end {
		return nil, false
	}
	hpBlk, err := aes.NewCipher(hp)
	if err != nil {
		return nil, false
	}
	var mask [aes.BlockSize]byte
	hpBlk.Encrypt(mask[:], p[sampleOff:sampleOff+quicSampleLen])

	// Long header: only the low 4 bits of the first byte are protected.
	first := p[0] ^ (mask[0] & 0x0f)
	pnLen := int(first&0x03) + 1
	if h.pnOff+pnLen+quicTagLen > h.end {
		return nil, false
	}

	// The AAD is the header with protection removed. Copy it: payload aliases the
	// live packet buffer and must stay byte-identical for the transport.
	aad := make([]byte, h.pnOff+pnLen)
	copy(aad, p[:h.pnOff+pnLen])
	aad[0] = first
	var pn uint64
	for i := 0; i < pnLen; i++ {
		b := p[h.pnOff+i] ^ mask[1+i]
		aad[h.pnOff+i] = b
		pn = pn<<8 | uint64(b)
	}

	// Nonce = IV XOR the packet number, right-aligned (RFC 9001 §5.3). Initial
	// packet numbers are small, so no reconstruction of a truncated PN is needed.
	nonce := make([]byte, quicIVLen)
	copy(nonce, iv)
	var pnb [8]byte
	binary.BigEndian.PutUint64(pnb[:], pn)
	for i := 0; i < 8; i++ {
		nonce[quicIVLen-8+i] ^= pnb[i]
	}

	ct := p[h.pnOff+pnLen : h.end]
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, false
	}
	if plain, err := aead.Open(nil, nonce, ct, aad); err == nil {
		return plain, true
	}

	// Tag mismatch. zapret's quic.c deliberately does not authenticate: a fake
	// blob that was re-padded, clipped or partially rewritten on its way here
	// still carries a perfectly readable CRYPTO frame, and the frame plus TLS
	// parsers reject actual garbage anyway. AES-GCM encryption is AES-CTR with
	// the counter starting at 2 (block 1 is reserved for the GHASH key stream),
	// so decrypt without the tag by hand.
	if len(ct) <= quicTagLen {
		return nil, false
	}
	ctr := make([]byte, aes.BlockSize)
	copy(ctr, nonce)
	ctr[aes.BlockSize-1] = 2
	body := ct[:len(ct)-quicTagLen]
	out := make([]byte, len(body))
	cipher.NewCTR(blk, ctr).XORKeyStream(out, body)
	return out, true
}

// quicSkipACK returns the byte length of an ACK frame body (RFC 9000 §19.3).
// A client's second Initial (after a Retry or a server Initial) carries one
// ahead of the CRYPTO frames, so skipping it correctly matters.
func quicSkipACK(b []byte, ecn bool) (int, bool) {
	off := 0
	var rangeCount uint64
	// Largest Acknowledged, ACK Delay, ACK Range Count, First ACK Range.
	for i := 0; i < 4; i++ {
		v, n, ok := quicVarint(b[off:])
		if !ok {
			return 0, false
		}
		if i == 2 {
			rangeCount = v
		}
		off += n
	}
	// Every range costs at least two bytes, so a count beyond the remaining
	// bytes is a malformed frame; bail out instead of looping on a huge number.
	if rangeCount > uint64(len(b)) {
		return 0, false
	}
	for i := uint64(0); i < rangeCount; i++ {
		for j := 0; j < 2; j++ { // Gap, ACK Range Length
			_, n, ok := quicVarint(b[off:])
			if !ok {
				return 0, false
			}
			off += n
		}
	}
	if ecn {
		for i := 0; i < 3; i++ { // ECT0, ECT1, ECN-CE counts
			_, n, ok := quicVarint(b[off:])
			if !ok {
				return 0, false
			}
			off += n
		}
	}
	return off, true
}

// quicCryptoStream walks the frames of a decrypted Initial payload and
// reassembles the CRYPTO frames, honouring their stream offsets. It returns the
// contiguous prefix of the handshake stream that is actually covered.
func quicCryptoStream(plain []byte) ([]byte, bool) {
	type span struct{ start, end int }
	var (
		buf   []byte
		spans []span
	)

frames:
	for off := 0; off < len(plain); {
		typ, n, ok := quicVarint(plain[off:])
		if !ok {
			break
		}
		off += n
		switch typ {
		case 0x00, 0x01: // PADDING, PING: no body
		case 0x02, 0x03: // ACK, ACK with ECN counts
			n, ok := quicSkipACK(plain[off:], typ == 0x03)
			if !ok {
				break frames
			}
			off += n
		case 0x06: // CRYPTO
			cOff, n, ok := quicVarint(plain[off:])
			if !ok {
				break frames
			}
			off += n
			cLen, n, ok := quicVarint(plain[off:])
			if !ok {
				break frames
			}
			off += n
			if cLen > uint64(len(plain)-off) {
				break frames
			}
			end := cOff + cLen
			if end > quicMaxCrypto {
				break frames
			}
			if int(end) > len(buf) {
				buf = append(buf, make([]byte, int(end)-len(buf))...)
			}
			copy(buf[cOff:end], plain[off:off+int(cLen)])
			spans = append(spans, span{start: int(cOff), end: int(end)})
			off += int(cLen)
		default:
			// Any other frame type: we cannot know its body length, so we cannot
			// find the next frame boundary. Use what we have collected so far.
			break frames
		}
	}

	// Only the prefix reachable from offset 0 is usable; frames may arrive out
	// of order inside one packet.
	total := 0
	for grew := true; grew; {
		grew = false
		for _, s := range spans {
			if s.start <= total && s.end > total {
				total = s.end
				grew = true
			}
		}
	}
	if total == 0 {
		return nil, false
	}
	return buf[:total], true
}

// quicHostFromHandshake extracts the SNI from a bare TLS handshake stream (no
// record layer, which is how QUIC carries it) by wrapping it in a synthetic
// TLSPlaintext record and handing it to the regular ClientHello parser.
func quicHostFromHandshake(hs []byte) (string, bool) {
	const maxRecord = 1 << 14 // RFC 8446 §5.1 record size limit
	if len(hs) < 4 {
		return "", false
	}
	if len(hs) > maxRecord {
		hs = hs[:maxRecord]
	}
	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16 // handshake
	rec[1], rec[2] = 0x03, 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)

	info, ok := ParseTLSClientHello(rec)
	if !ok || info.Host == "" {
		return "", false
	}
	return info.Host, true
}

// QUICSNI decrypts a QUIC Initial packet and returns the SNI hostname from the
// ClientHello inside its CRYPTO frames. It returns ("", false) on any parse or
// decrypt failure and never modifies or retains payload.
func QUICSNI(payload []byte) (string, bool) {
	plain, ok := quicDecryptInitial(payload)
	if !ok {
		return "", false
	}
	hs, ok := quicCryptoStream(plain)
	if !ok {
		return "", false
	}
	return quicHostFromHandshake(hs)
}
