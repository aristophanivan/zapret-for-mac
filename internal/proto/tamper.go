package proto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
)

// TLSMod is --dpi-desync-fake-tls-mod: how a fake ClientHello is mutated before
// it goes on the wire.
//
// The field set is deliberately identical (names, types, order) to
// desync.TLSMod, so a caller can convert between the two with a plain struct
// conversion — proto cannot import desync, which owns the strategy-side type.
type TLSMod struct {
	None     bool
	Rnd      bool   // randomise the ClientHello random + session id
	RndSNI   bool   // randomise the SNI hostname, keeping its length
	SNI      string // force this SNI
	DupSID   bool   // duplicate the session id
	PadEncap bool   // append/extend an ECH-shaped padding extension
}

// Padding geometry for TLSMod.PadEncap.
const (
	// tlsPadTarget is the size Chrome pads its GREASE-ECH ClientHello to; a fake
	// that lands on the same number keeps the "big padded hello" fingerprint.
	tlsPadTarget = 517
	// tlsPadMin is the least amount of padding worth adding when the hello is
	// already at or beyond the target.
	tlsPadMin = 16
	// tlsECHMinBody is the fixed overhead of an ECH "outer" extension body:
	// client_hello_type(1) + cipher_suite(4) + config_id(1) + enc len(2) +
	// payload len(2).
	tlsECHMinBody = 10
)

// ParseTLSMod parses a --dpi-desync-fake-tls-mod list such as
// "rnd,dupsid,sni=www.google.com", "none" or "rnd,rndsni". Tokens are
// case-insensitive and may be padded with spaces; an empty string yields a zero
// TLSMod (no mutation). "none" wins over any other token in ModifyTLSFake.
func ParseTLSMod(s string) (TLSMod, error) {
	var m TLSMod
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if i := strings.IndexByte(tok, '='); i >= 0 {
			key := strings.ToLower(strings.TrimSpace(tok[:i]))
			val := strings.TrimSpace(tok[i+1:])
			if key != "sni" {
				return TLSMod{}, fmt.Errorf("tls-mod: unknown key %q", key)
			}
			if err := tlsCheckSNI(val); err != nil {
				return TLSMod{}, err
			}
			m.SNI = val
			continue
		}
		switch strings.ToLower(tok) {
		case "none":
			m.None = true
		case "rnd":
			m.Rnd = true
		case "rndsni":
			m.RndSNI = true
		case "dupsid":
			m.DupSID = true
		case "padencap":
			m.PadEncap = true
		default:
			return TLSMod{}, fmt.Errorf("tls-mod: unknown value %q", tok)
		}
	}
	return m, nil
}

// tlsCheckSNI validates a forced SNI hostname.
func tlsCheckSNI(h string) error {
	if h == "" {
		return fmt.Errorf("tls-mod: sni= needs a hostname")
	}
	if len(h) > tlsMaxHostLen {
		return fmt.Errorf("tls-mod: sni %q is longer than %d bytes", h, tlsMaxHostLen)
	}
	if !tlsValidHostName([]byte(h)) {
		return fmt.Errorf("tls-mod: sni %q is not a valid hostname", h)
	}
	return nil
}

// ModifyTLSFake applies a TLSMod to a fake ClientHello, returning a new slice;
// hello is never written to.
//
// Mutations run in a fixed order (rnd, sni/rndsni, dupsid, padencap) and each
// length-changing step re-derives the offset map from the bytes it is handed, so
// they compose. A step that cannot be represented (a length field would
// overflow, the hello is truncated or not a ClientHello at all) is skipped: the
// result is always a structurally valid hello, at worst an unmodified copy.
func ModifyTLSFake(hello []byte, mod TLSMod) []byte {
	out := make([]byte, len(hello))
	copy(out, hello)
	if mod.None {
		return out
	}
	if !mod.Rnd && !mod.RndSNI && mod.SNI == "" && !mod.DupSID && !mod.PadEncap {
		return out
	}
	l, ok := tlsParseHello(out)
	if !ok {
		return out
	}
	if mod.Rnd {
		// No length change: random and session_id are fixed-size fields.
		tlsApplyRnd(out, l)
	}
	if !l.complete {
		// Everything below rewrites length fields, which is only meaningful for a
		// whole record.
		return out
	}
	if mod.SNI != "" {
		if nb := tlsSetSNI(out, mod.SNI); nb != nil {
			out = nb
		}
	} else if mod.RndSNI {
		tlsApplyRndSNI(out)
	}
	if mod.DupSID {
		if nb := tlsDupSessionID(out); nb != nil {
			out = nb
		}
	}
	if mod.PadEncap {
		if nb := tlsPadEncap(out); nb != nil {
			out = nb
		}
	}
	return out
}

// tlsApplyRnd randomises ClientHello.random and legacy_session_id in place.
func tlsApplyRnd(b []byte, l tlsHelloLayout) {
	if l.randomOff > 0 && l.randomOff+32 <= len(b) {
		tamperRandBytes(b[l.randomOff : l.randomOff+32])
	}
	if l.sidLenOff > 0 && l.sidLen > 0 && l.sidLenOff+1+l.sidLen <= len(b) {
		tamperRandBytes(b[l.sidLenOff+1 : l.sidLenOff+1+l.sidLen])
	}
}

// tlsApplyRndSNI overwrites the SNI hostname with a random name of the same
// length, in place (no length field changes).
func tlsApplyRndSNI(b []byte) {
	l, ok := tlsParseHello(b)
	if !ok || l.nameOff <= 0 || l.nameLen <= 0 || l.nameOff+l.nameLen > len(b) {
		return
	}
	tlsRandName(b[l.nameOff : l.nameOff+l.nameLen])
}

// tlsRandName rewrites dst with a random hostname of exactly len(dst) bytes,
// keeping the dots where they are and the last label (the TLD) untouched, so the
// result still looks like a real name.
func tlsRandName(dst []byte) {
	if len(dst) == 0 {
		return
	}
	end := len(dst)
	for i := len(dst) - 1; i >= 0; i-- {
		if dst[i] == '.' {
			end = i
			break
		}
	}
	if end <= 0 {
		return
	}
	const letters = "abcdefghijklmnopqrstuvwxyz"
	const alnum = "abcdefghijklmnopqrstuvwxyz0123456789"
	r := make([]byte, end)
	tamperRandBytes(r)
	labelStart := true
	for i := 0; i < end; i++ {
		if dst[i] == '.' {
			labelStart = true
			continue
		}
		if labelStart {
			// A label may not start with a digit in a plausible hostname.
			dst[i] = letters[int(r[i])%len(letters)]
			labelStart = false
			continue
		}
		dst[i] = alnum[int(r[i])%len(alnum)]
	}
}

// tlsSetSNI forces the hostname of a complete ClientHello, adjusting every
// enclosing length field. Returns nil when the change cannot be represented.
func tlsSetSNI(b []byte, name string) []byte {
	if name == "" || len(name)+5 > 0xffff {
		return nil
	}
	l, ok := tlsParseHello(b)
	if !ok || !l.complete || l.extsLenOff == 0 {
		return nil
	}

	// Common case: a host_name entry exists, so only the name bytes move.
	if l.nameOff > 0 {
		delta := len(name) - l.nameLen
		nb := protoSplice(b, l.nameOff, l.nameLen, []byte(name))
		binary.BigEndian.PutUint16(nb[l.sniNameLenOff:], uint16(len(name)))
		if delta != 0 && !tlsGrowEnclosing(nb, l, delta) {
			return nil
		}
		return nb
	}

	body := tlsBuildSNIBody(name)

	// A server_name extension with no host_name entry: replace its whole body.
	if l.sniExtOff > 0 {
		bodyOff := l.sniExtOff + 4
		oldLen := l.sniExtEnd - bodyOff
		if oldLen < 0 || bodyOff+oldLen > len(b) {
			return nil
		}
		nb := protoSplice(b, bodyOff, oldLen, body)
		binary.BigEndian.PutUint16(nb[l.sniExtLenOff:], uint16(len(body)))
		if delta := len(body) - oldLen; delta != 0 {
			if !tlsAddLen16(nb, l.extsLenOff, delta) ||
				!tlsAddLen24(nb, tlsHSLenOff, delta) ||
				!tlsAddLen16(nb, tlsRecLenOff, delta) {
				return nil
			}
		}
		return nb
	}

	// No server_name at all: append a complete extension after the last one.
	if l.extsEnd != len(b) {
		return nil
	}
	ext := make([]byte, 0, 4+len(body))
	ext = append(ext, byte(tlsExtServerName>>8), byte(tlsExtServerName),
		byte(len(body)>>8), byte(len(body)))
	ext = append(ext, body...)
	nb := protoSplice(b, l.extsEnd, 0, ext)
	if !tlsAddLen16(nb, l.extsLenOff, len(ext)) ||
		!tlsAddLen24(nb, tlsHSLenOff, len(ext)) ||
		!tlsAddLen16(nb, tlsRecLenOff, len(ext)) {
		return nil
	}
	return nb
}

// tlsBuildSNIBody builds a server_name extension body carrying one host_name:
// server_name_list length(2) + name_type(1) + host_name length(2) + name.
func tlsBuildSNIBody(name string) []byte {
	body := make([]byte, 5+len(name))
	binary.BigEndian.PutUint16(body, uint16(3+len(name)))
	body[2] = tlsSNITypeHostName
	binary.BigEndian.PutUint16(body[3:], uint16(len(name)))
	copy(body[5:], name)
	return body
}

// tlsGrowEnclosing adds delta to every length field enclosing the SNI hostname,
// innermost first: server_name_list, extension, extensions total, handshake,
// record. Reports false (leaving b half-patched, which is why the caller
// discards the buffer) when a field would not fit.
func tlsGrowEnclosing(b []byte, l tlsHelloLayout, delta int) bool {
	return tlsAddLen16(b, l.sniListLenOff, delta) &&
		tlsAddLen16(b, l.sniExtLenOff, delta) &&
		tlsAddLen16(b, l.extsLenOff, delta) &&
		tlsAddLen24(b, tlsHSLenOff, delta) &&
		tlsAddLen16(b, tlsRecLenOff, delta)
}

// tlsDupSessionID appends a second copy of legacy_session_id inside the same
// field, doubling its length byte.
func tlsDupSessionID(b []byte) []byte {
	l, ok := tlsParseHello(b)
	if !ok || !l.complete || l.sidLenOff == 0 || l.sidLen == 0 {
		return nil
	}
	// The session id length is a single byte.
	if l.sidLen*2 > 0xff {
		return nil
	}
	sidOff := l.sidLenOff + 1
	if sidOff+l.sidLen > len(b) {
		return nil
	}
	dup := make([]byte, l.sidLen)
	copy(dup, b[sidOff:sidOff+l.sidLen])
	nb := protoSplice(b, sidOff+l.sidLen, 0, dup)
	nb[l.sidLenOff] = byte(l.sidLen * 2)
	if !tlsAddLen24(nb, tlsHSLenOff, l.sidLen) || !tlsAddLen16(nb, tlsRecLenOff, l.sidLen) {
		return nil
	}
	return nb
}

// tlsPadEncap pads the hello with encrypted_client_hello-shaped zeros: it grows
// an existing 0xfe0d extension's ECH payload when there is one, otherwise it
// appends a fresh 0xfe0d extension. Target size is tlsPadTarget.
func tlsPadEncap(b []byte) []byte {
	l, ok := tlsParseHello(b)
	if !ok || !l.complete || l.extsLenOff == 0 {
		return nil
	}
	pad := tlsPadTarget - len(b)

	if l.echExtOff > 0 {
		if plOff, okECH := tlsECHPayloadLenOff(b, l); okECH {
			if pad < tlsPadMin {
				pad = tlsPadMin
			}
			nb := protoSplice(b, l.echBodyOff+l.echBodyLen, 0, make([]byte, pad))
			// Every field between the ECH payload and the record header grows.
			if !tlsAddLen16(nb, plOff, pad) ||
				!tlsAddLen16(nb, l.echExtLenOff, pad) ||
				!tlsAddLen16(nb, l.extsLenOff, pad) ||
				!tlsAddLen24(nb, tlsHSLenOff, pad) ||
				!tlsAddLen16(nb, tlsRecLenOff, pad) {
				return nil
			}
			return nb
		}
	}

	if l.extsEnd != len(b) {
		return nil
	}
	total := pad
	if total < 4+tlsECHMinBody {
		total = 4 + tlsECHMinBody
	}
	body := tlsBuildECHBody(total - 4)
	ext := make([]byte, 0, 4+len(body))
	ext = append(ext, byte(tlsExtECH>>8), byte(tlsExtECH&0xff), byte(len(body)>>8), byte(len(body)))
	ext = append(ext, body...)
	nb := protoSplice(b, l.extsEnd, 0, ext)
	if !tlsAddLen16(nb, l.extsLenOff, len(ext)) ||
		!tlsAddLen24(nb, tlsHSLenOff, len(ext)) ||
		!tlsAddLen16(nb, tlsRecLenOff, len(ext)) {
		return nil
	}
	return nb
}

// tlsECHPayloadLenOff locates the 2-byte ECHClientHello payload length of an
// existing 0xfe0d extension, but only when that length reaches exactly to the
// end of the extension — otherwise growing it would not be padding.
func tlsECHPayloadLenOff(b []byte, l tlsHelloLayout) (int, bool) {
	p, end := l.echBodyOff, l.echBodyOff+l.echBodyLen
	if end > len(b) {
		return 0, false
	}
	// client_hello_type(1) cipher_suite(4) config_id(1) enc<2+n> payload<2+n>
	if p+8 > end {
		return 0, false
	}
	p += 6
	encLen := int(binary.BigEndian.Uint16(b[p:]))
	p += 2 + encLen
	if p+2 > end {
		return 0, false
	}
	if p+2+int(binary.BigEndian.Uint16(b[p:])) != end {
		return 0, false
	}
	return p, true
}

// tlsBuildECHBody returns an n-byte ECH "outer" extension body: zero-filled key
// material and payload, with only the two internal length prefixes set so the
// extension still parses as ECH.
func tlsBuildECHBody(n int) []byte {
	if n < tlsECHMinBody {
		n = tlsECHMinBody
	}
	b := make([]byte, n)
	rem := n - tlsECHMinBody
	encLen := rem
	if encLen > 32 {
		encLen = 32 // X25519 KEM share size
	}
	binary.BigEndian.PutUint16(b[6:], uint16(encLen))
	binary.BigEndian.PutUint16(b[8+encLen:], uint16(rem-encLen))
	return b
}

// tlsAddLen16 adds delta to the 16-bit big-endian field at off.
func tlsAddLen16(b []byte, off, delta int) bool {
	if off <= 0 || off+2 > len(b) {
		return false
	}
	v := int(binary.BigEndian.Uint16(b[off:])) + delta
	if v < 0 || v > 0xffff {
		return false
	}
	binary.BigEndian.PutUint16(b[off:], uint16(v))
	return true
}

// tlsAddLen24 adds delta to the 24-bit big-endian field at off.
func tlsAddLen24(b []byte, off, delta int) bool {
	if off <= 0 || off+3 > len(b) {
		return false
	}
	v := int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2])
	v += delta
	if v < 0 || v > 0xffffff {
		return false
	}
	b[off] = byte(v >> 16)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v)
	return true
}

// protoSplice returns a fresh slice with b[at:at+remove] replaced by ins. b is
// left untouched; out-of-range arguments are clamped.
func protoSplice(b []byte, at, remove int, ins []byte) []byte {
	if at < 0 {
		at = 0
	}
	if at > len(b) {
		at = len(b)
	}
	if remove < 0 {
		remove = 0
	}
	if at+remove > len(b) {
		remove = len(b) - at
	}
	out := make([]byte, 0, len(b)-remove+len(ins))
	out = append(out, b[:at]...)
	out = append(out, ins...)
	return append(out, b[at+remove:]...)
}

// tamperRandBytes fills b with cryptographic randomness. crypto/rand.Read is
// documented never to fail, so there is nothing to report.
func tamperRandBytes(b []byte) { _, _ = rand.Read(b) }

// tamperRandCase flips the case of every ASCII letter in b at random.
func tamperRandCase(b []byte) {
	if len(b) == 0 {
		return
	}
	r := make([]byte, len(b))
	tamperRandBytes(r)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			if r[i]&1 == 0 {
				b[i] = c - ('a' - 'A')
			}
		case c >= 'A' && c <= 'Z':
			if r[i]&1 == 1 {
				b[i] = c + ('a' - 'A')
			}
		}
	}
}

// tamperPadHeaders builds exactly n bytes of junk "X-Pad: ..." header lines
// (CRLF terminated). It returns nil when n is too small to hold one well-formed
// line, in which case the caller pads nothing rather than emitting a broken
// request.
func tamperPadHeaders(n int) []byte {
	const name = "X-Pad"
	const overhead = len(name) + 2 + 2 // ": " and CRLF
	const maxFill = 200
	if n < overhead+1 {
		return nil
	}
	// Spread the padding over as few lines as the per-line cap allows, then
	// distribute the bytes evenly so every line stays well formed.
	lines := (n + overhead + maxFill - 1) / (overhead + maxFill)
	base, extra := n/lines, n%lines
	out := make([]byte, 0, n)
	fill := make([]byte, maxFill)
	for i := 0; i < lines; i++ {
		size := base
		if i < extra {
			size++
		}
		out = append(out, name...)
		out = append(out, ':', ' ')
		k := size - overhead
		tamperRandBytes(fill[:k])
		for j := 0; j < k; j++ {
			out = append(out, 'a'+fill[j]%26)
		}
		out = append(out, '\r', '\n')
	}
	return out
}

// tamperCRLFToLF drops every CR that is part of a CRLF pair.
func tamperCRLFToLF(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '\r' && i+1 < len(b) && b[i+1] == '\n' {
			continue
		}
		out = append(out, b[i])
	}
	return out
}

// TamperHost applies zapret's L7 mangling knobs to a copy of payload.
//
// For an HTTP request: HostCase/HostSpell respell the "Host" header name
// (HostCase alone means "host"), HostNoSpace drops the whitespace after the
// colon, HostDot and HostTab append a '.' / '\t' to the hostname, HostPad
// inserts N bytes of junk headers ahead of the Host line, DomCase randomises the
// case of the domain, MethodSpace adds a second space after the method,
// MethodEOL prepends a bare LF and UnixEOL turns every CRLF into a bare LF.
//
// For a TLS ClientHello only DomCase applies, rewriting the SNI in place (a
// same-length edit, so no TLS length field moves). Anything else — and an empty
// TamperOpts — returns the unchanged copy.
func TamperHost(payload []byte, info L7Info, o TamperOpts) []byte {
	out := make([]byte, len(payload))
	copy(out, payload)

	if info.Proto == L7TLS {
		if o.DomCase && info.HostOff > 0 && info.HostLen > 0 && info.HostOff+info.HostLen <= len(out) {
			tamperRandCase(out[info.HostOff : info.HostOff+info.HostLen])
		}
		return out
	}
	if info.Proto != L7HTTP {
		return out
	}

	// Every step re-locates the Host header, because the ones that change the
	// length invalidate the offsets the previous step used.
	spell := o.HostSpell
	if spell == "" && o.HostCase {
		spell = "host"
	}
	if spell != "" {
		out = httpRewriteHostName(out, spell)
	}
	if o.DomCase {
		if loc, ok := httpFindHost(out); ok && loc.hostEnd > loc.valOff {
			tamperRandCase(out[loc.valOff:loc.hostEnd])
		}
	}
	if o.HostNoSpace {
		out = httpHostNoSpace(out)
	}
	if o.HostDot {
		out = httpInsertAfterHost(out, '.')
	}
	if o.HostTab {
		out = httpInsertAfterHost(out, '\t')
	}
	if o.HostPad > 0 {
		out = httpHostPad(out, o.HostPad)
	}
	if o.MethodSpace {
		out = httpMethodSpace(out)
	}
	if o.MethodEOL {
		// A bare LF before the request line: RFC 7230 servers ignore it, many DPI
		// parsers lose the method.
		out = protoSplice(out, 0, 0, []byte{'\n'})
	}
	if o.UnixEOL {
		out = tamperCRLFToLF(out)
	}
	return out
}

// httpRewriteHostName replaces the Host header's name with spell.
func httpRewriteHostName(b []byte, spell string) []byte {
	loc, ok := httpFindHost(b)
	if !ok {
		return b
	}
	if len(spell) == loc.nameLen {
		copy(b[loc.lineOff:], spell)
		return b
	}
	return protoSplice(b, loc.lineOff, loc.nameLen, []byte(spell))
}

// httpHostNoSpace removes the whitespace between "Host:" and its value.
func httpHostNoSpace(b []byte) []byte {
	loc, ok := httpFindHost(b)
	if !ok || loc.valOff <= loc.colonOff+1 {
		return b
	}
	return protoSplice(b, loc.colonOff+1, loc.valOff-(loc.colonOff+1), nil)
}

// httpInsertAfterHost inserts c right after the hostname (before any ":port").
func httpInsertAfterHost(b []byte, c byte) []byte {
	loc, ok := httpFindHost(b)
	if !ok || loc.hostEnd <= loc.valOff {
		return b
	}
	return protoSplice(b, loc.hostEnd, 0, []byte{c})
}

// httpHostPad inserts n bytes of junk headers immediately before the Host line.
func httpHostPad(b []byte, n int) []byte {
	loc, ok := httpFindHost(b)
	if !ok {
		return b
	}
	pad := tamperPadHeaders(n)
	if len(pad) == 0 {
		return b
	}
	return protoSplice(b, loc.lineOff, 0, pad)
}

// httpMethodSpace inserts an extra space between the method and the target.
func httpMethodSpace(b []byte) []byte {
	n := httpMethodLen(b)
	if n == 0 {
		return b
	}
	return protoSplice(b, n, 0, []byte{' '})
}
