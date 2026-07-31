package proto

import (
	"encoding/binary"
	"fmt"
)

// TLS wire constants used by the ClientHello parser and the record splitter.
const (
	// tlsRecHdrLen is the TLS record header: type(1) + legacy version(2) + len(2).
	tlsRecHdrLen = 5
	// tlsHSHdrLen is the handshake header: msg type(1) + len(3).
	tlsHSHdrLen = 4
	// tlsHelloBodyOff is where the ClientHello body starts (legacy_version).
	tlsHelloBodyOff = tlsRecHdrLen + tlsHSHdrLen

	// tlsRecLenOff / tlsHSLenOff are the offsets of the two outermost length
	// fields, at fixed positions in every ClientHello record.
	tlsRecLenOff = 3
	tlsHSLenOff  = 6

	tlsRecChangeCipher = 0x14
	tlsRecAlert        = 0x15
	tlsRecHandshake    = 0x16
	tlsRecAppData      = 0x17
	tlsRecHeartbeat    = 0x18

	tlsHSClientHello = 0x01

	tlsExtServerName = 0x0000 // RFC 6066 server_name
	tlsExtECH        = 0xfe0d // draft-ietf-tls-esni encrypted_client_hello

	tlsSNITypeHostName = 0x00

	// tlsMaxHostLen is the longest hostname accepted as an SNI value; longer
	// values are treated as garbage rather than a name.
	tlsMaxHostLen = 253
)

// tlsHelloLayout is the offset map of one ClientHello, produced by
// tlsParseHello. Offsets are absolute inside the payload; a zero offset means
// "the walk never reached this field" (no real field can live at offset 0,
// which is the record content type).
type tlsHelloLayout struct {
	// complete reports that the payload holds exactly one whole record whose
	// handshake message fills it edge to edge. Length rewriting (ModifyTLSFake)
	// is only safe when this holds.
	complete bool

	recLen int // value of the 16-bit record length field
	hsLen  int // value of the 24-bit handshake length field

	randomOff int // 32-byte ClientHello.random
	sidLenOff int // 1-byte legacy_session_id length
	sidLen    int

	cipherLenOff int // 2-byte cipher_suites length
	compLenOff   int // 1-byte compression_methods length

	extsLenOff int // 2-byte extensions total length
	extsOff    int // first extension
	extsEnd    int // end of the extensions block (clamped to available bytes)

	sniExtOff     int // server_name extension type field
	sniExtLenOff  int
	sniExtEnd     int
	sniListLenOff int // 2-byte server_name_list length
	sniNameLenOff int // 2-byte host_name length
	nameOff       int // hostname bytes
	nameLen       int

	echExtOff    int // encrypted_client_hello extension type field
	echExtLenOff int
	echBodyOff   int
	echBodyLen   int
}

// tlsParseHello walks a ClientHello, filling in every offset it can reach.
//
// It returns ok as soon as the record and handshake headers say "this is a
// ClientHello", even when the message is cut short: nfqws classifies a flow as
// TLS from the first segment, and a hello whose SNI needs reassembly must still
// be recognised. Callers that rewrite lengths must additionally check complete.
func tlsParseHello(p []byte) (tlsHelloLayout, bool) {
	var l tlsHelloLayout
	if len(p) < tlsRecHdrLen+tlsHSHdrLen {
		return l, false
	}
	// Record header: handshake, legacy version 0x03 0x0X.
	if p[0] != tlsRecHandshake || p[1] != 0x03 || p[2] > 0x04 {
		return l, false
	}
	l.recLen = int(binary.BigEndian.Uint16(p[tlsRecLenOff:]))
	if l.recLen < tlsHSHdrLen {
		return l, false
	}
	if p[tlsRecHdrLen] != tlsHSClientHello {
		return l, false
	}
	l.hsLen = int(p[tlsHSLenOff])<<16 | int(p[tlsHSLenOff+1])<<8 | int(p[tlsHSLenOff+2])
	l.complete = len(p) == tlsRecHdrLen+l.recLen && l.hsLen+tlsHSHdrLen == l.recLen

	// Never walk past the record or the handshake message: a payload may carry
	// further records (or garbage) whose bytes must not be mistaken for
	// extensions of this hello.
	limit := len(p)
	if e := tlsRecHdrLen + l.recLen; e < limit {
		limit = e
	}
	if e := tlsHelloBodyOff + l.hsLen; e < limit {
		limit = e
	}

	off := tlsHelloBodyOff
	if off+2 > limit {
		return l, true
	}
	off += 2 // legacy_version
	if off+32 > limit {
		return l, true
	}
	l.randomOff = off
	off += 32

	if off+1 > limit {
		return l, true
	}
	l.sidLenOff = off
	l.sidLen = int(p[off])
	off += 1 + l.sidLen

	if off < 0 || off+2 > limit {
		return l, true
	}
	l.cipherLenOff = off
	off += 2 + int(binary.BigEndian.Uint16(p[off:]))

	if off < 0 || off+1 > limit {
		return l, true
	}
	l.compLenOff = off
	off += 1 + int(p[off])

	if off < 0 || off+2 > limit {
		return l, true
	}
	l.extsLenOff = off
	l.extsOff = off + 2
	l.extsEnd = l.extsOff + int(binary.BigEndian.Uint16(p[off:]))
	if l.extsEnd > limit {
		l.extsEnd = limit
	}

	for e := l.extsOff; e+4 <= l.extsEnd; {
		typ := int(binary.BigEndian.Uint16(p[e:]))
		bodyLen := int(binary.BigEndian.Uint16(p[e+2:]))
		body := e + 4
		if body+bodyLen > l.extsEnd {
			break // truncated extension: stop, keep what we have
		}
		switch typ {
		case tlsExtServerName:
			if l.sniExtOff == 0 {
				tlsParseSNIExt(p, e, body, bodyLen, &l)
			}
		case tlsExtECH:
			if l.echExtOff == 0 {
				l.echExtOff, l.echExtLenOff = e, e+2
				l.echBodyOff, l.echBodyLen = body, bodyLen
			}
		}
		e = body + bodyLen
	}
	return l, true
}

// tlsParseSNIExt fills the server_name sub-offsets of l from one extension.
func tlsParseSNIExt(p []byte, extOff, body, bodyLen int, l *tlsHelloLayout) {
	l.sniExtOff = extOff
	l.sniExtLenOff = extOff + 2
	l.sniExtEnd = body + bodyLen
	if bodyLen < 2 {
		return
	}
	l.sniListLenOff = body
	end := body + 2 + int(binary.BigEndian.Uint16(p[body:]))
	if end > l.sniExtEnd {
		end = l.sniExtEnd
	}
	// ServerNameList: repeated { name_type(1), length(2), name }.
	for q := body + 2; q+3 <= end; {
		nameLen := int(binary.BigEndian.Uint16(p[q+1:]))
		if q+3+nameLen > end {
			return
		}
		if p[q] == tlsSNITypeHostName {
			l.sniNameLenOff = q + 1
			l.nameOff = q + 3
			l.nameLen = nameLen
			return
		}
		q += 3 + nameLen
	}
}

// ParseTLSClientHello recognises a TLS ClientHello and locates its SNI.
//
// It fills Proto, Host (lowercased), HostOff/HostLen (the hostname bytes),
// SNIExtOff (the server_name extension's type field) and SLDOff/SLDLen (the
// second-level label, "google" in "www.google.com"). MethodOff stays 0.
//
// ok is false only when the payload is not a ClientHello at all. A hello with
// no server_name extension, or one truncated before it, returns ok=true with an
// empty Host — the flow is TLS either way.
func ParseTLSClientHello(payload []byte) (L7Info, bool) {
	var info L7Info
	l, ok := tlsParseHello(payload)
	if !ok {
		return info, false
	}
	info.Proto = L7TLS
	info.SNIExtOff = l.sniExtOff
	if l.nameOff <= 0 || l.nameLen <= 0 {
		return info, true
	}
	name := payload[l.nameOff : l.nameOff+l.nameLen]
	if !tlsValidHostName(name) {
		// Structurally a host_name entry, semantically junk: keep the flow
		// classified as TLS but do not feed garbage to the hostlists.
		return info, true
	}
	info.Host = tlsLowerASCII(name)
	info.HostOff, info.HostLen = l.nameOff, l.nameLen
	if off, n := hostSLDSpan(name); n > 0 {
		info.SLDOff, info.SLDLen = l.nameOff+off, n
	}
	return info, true
}

// tlsValidHostName reports whether b looks like a DNS name: printable ASCII
// hostname characters only, no spaces, no dot at the start.
func tlsValidHostName(b []byte) bool {
	if len(b) == 0 || len(b) > tlsMaxHostLen {
		return false
	}
	if b[0] == '.' || b[0] == '-' {
		return false
	}
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// tlsLowerASCII returns b as a string with A-Z folded to lower case.
func tlsLowerASCII(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

// TLSRecordSplit re-wraps one complete TLS record into two records carrying the
// same content type and legacy version, cutting the body so that the first
// record ends at pos.
//
// pos is an offset into payload and therefore includes the 5-byte record
// header; it is clamped to the payload before the body cut is derived. This is
// tpws' --tlsrec: a TLS handshake message may span records, so a DPI engine
// that only inspects the first record never sees the SNI, and no packet-level
// privilege is needed to do it.
func TLSRecordSplit(payload []byte, pos int) ([]byte, error) {
	if len(payload) < tlsRecHdrLen+2 {
		return nil, fmt.Errorf("tlsrec: payload of %d bytes is too short for a splittable record", len(payload))
	}
	ct := payload[0]
	if ct < tlsRecChangeCipher || ct > tlsRecHeartbeat || payload[1] != 0x03 {
		return nil, fmt.Errorf("tlsrec: not a TLS record (type %#02x version %#02x%02x)", ct, payload[1], payload[2])
	}
	recLen := int(binary.BigEndian.Uint16(payload[tlsRecLenOff:]))
	if recLen+tlsRecHdrLen != len(payload) {
		return nil, fmt.Errorf("tlsrec: payload is not a single complete record (header says %d, have %d bytes of body)",
			recLen, len(payload)-tlsRecHdrLen)
	}
	body := payload[tlsRecHdrLen:]

	if pos > len(payload) {
		pos = len(payload)
	}
	if pos < 0 {
		pos = 0
	}
	cut := pos - tlsRecHdrLen
	if cut <= 0 || cut >= len(body) {
		return nil, fmt.Errorf("tlsrec: split position %d leaves an empty record (body is %d bytes)", pos, len(body))
	}

	out := make([]byte, 0, len(payload)+tlsRecHdrLen)
	out = append(out, ct, payload[1], payload[2], byte(cut>>8), byte(cut))
	out = append(out, body[:cut]...)
	rest := len(body) - cut
	out = append(out, ct, payload[1], payload[2], byte(rest>>8), byte(rest))
	out = append(out, body[cut:]...)
	return out, nil
}
