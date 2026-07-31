package proto

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tlsFakeVectors are the real winws fake ClientHellos shipped in fakes/.
// NOTE: tls_clienthello_max_ru.bin keeps upstream's file name but the blob on
// disk carries the SNI www.onetrust.com — the test asserts the bytes, not the
// file name.
var tlsFakeVectors = []struct {
	file string
	host string
	sld  string
}{
	{"tls_clienthello_www_google_com.bin", "www.google.com", "google"},
	{"tls_clienthello_max_ru.bin", "www.onetrust.com", "onetrust"},
	{"tls_clienthello_4pda_to.bin", "4pda.to", "4pda"},
}

func tlsLoadFake(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "fakes", name))
	if err != nil {
		t.Fatalf("read fake %s: %v", name, err)
	}
	return b
}

// tlsCheckHello re-walks a ClientHello from scratch and fails the test unless
// every length field is exactly consistent with the bytes. It returns the SNI it
// found ("" if none). This is the independent check on ModifyTLSFake's length
// arithmetic.
func tlsCheckHello(t *testing.T, b []byte) string {
	t.Helper()
	if len(b) < 9 {
		t.Fatalf("hello is %d bytes, too short", len(b))
	}
	if b[0] != 0x16 || b[1] != 0x03 {
		t.Fatalf("bad record header % x", b[:3])
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen+5 != len(b) {
		t.Fatalf("record length %d does not match payload of %d bytes", recLen, len(b))
	}
	if b[5] != 0x01 {
		t.Fatalf("handshake type %#02x is not client_hello", b[5])
	}
	hsLen := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
	if hsLen+4 != recLen {
		t.Fatalf("handshake length %d does not fill record of %d", hsLen, recLen)
	}
	off := 9 + 2 + 32
	if off+1 > len(b) {
		t.Fatalf("hello truncated before session id")
	}
	sidLen := int(b[off])
	off += 1 + sidLen
	if off+2 > len(b) {
		t.Fatalf("hello truncated before cipher suites (session id %d)", sidLen)
	}
	csLen := int(binary.BigEndian.Uint16(b[off:]))
	if csLen == 0 || csLen%2 != 0 {
		t.Fatalf("cipher suites length %d is not a positive multiple of 2", csLen)
	}
	off += 2 + csLen
	if off+1 > len(b) {
		t.Fatalf("hello truncated before compression methods")
	}
	off += 1 + int(b[off])
	if off+2 > len(b) {
		t.Fatalf("hello truncated before extensions")
	}
	extsLen := int(binary.BigEndian.Uint16(b[off:]))
	extsOff := off + 2
	if extsOff+extsLen != len(b) {
		t.Fatalf("extensions length %d ends at %d, hello ends at %d", extsLen, extsOff+extsLen, len(b))
	}
	host := ""
	e := extsOff
	for e < extsOff+extsLen {
		if e+4 > extsOff+extsLen {
			t.Fatalf("extension header at %d overruns the extensions block", e)
		}
		typ := int(binary.BigEndian.Uint16(b[e:]))
		bl := int(binary.BigEndian.Uint16(b[e+2:]))
		body := e + 4
		if body+bl > extsOff+extsLen {
			t.Fatalf("extension %#06x at %d claims %d bytes, block ends at %d", typ, e, bl, extsOff+extsLen)
		}
		switch typ {
		case tlsExtServerName:
			if bl < 5 {
				t.Fatalf("server_name extension body of %d bytes is too short", bl)
			}
			listLen := int(binary.BigEndian.Uint16(b[body:]))
			if listLen != bl-2 {
				t.Fatalf("server_name_list length %d does not fill the %d byte extension body", listLen, bl)
			}
			q := body + 2
			for q < body+2+listLen {
				if q+3 > body+2+listLen {
					t.Fatalf("server_name entry at %d overruns the list", q)
				}
				nl := int(binary.BigEndian.Uint16(b[q+1:]))
				if q+3+nl > body+2+listLen {
					t.Fatalf("host_name length %d overruns the list", nl)
				}
				if b[q] == tlsSNITypeHostName && host == "" {
					host = string(b[q+3 : q+3+nl])
				}
				q += 3 + nl
			}
		case tlsExtECH:
			// The padding path must keep the ECH body self-describing.
			if bl >= tlsECHMinBody {
				p := body + 6
				encLen := int(binary.BigEndian.Uint16(b[p:]))
				p += 2 + encLen
				if p+2 > body+bl {
					t.Fatalf("ech enc length %d overruns the extension", encLen)
				}
				if pl := int(binary.BigEndian.Uint16(b[p:])); p+2+pl != body+bl {
					t.Fatalf("ech payload length %d does not reach the end of the extension", pl)
				}
			}
		}
		e = body + bl
	}
	if e != extsOff+extsLen {
		t.Fatalf("extension walk ended at %d, block ends at %d", e, extsOff+extsLen)
	}
	return host
}

// tlsBuildTestHello builds a minimal but well-formed ClientHello. When sni is
// empty the hello carries no server_name extension at all; when sniExt is
// supplied it replaces the generated server_name extension verbatim.
func tlsBuildTestHello(sni string, sniExt []byte) []byte {
	var exts []byte
	switch {
	case sniExt != nil:
		exts = append(exts, sniExt...)
	case sni != "":
		body := tlsBuildSNIBody(sni)
		exts = append(exts, 0x00, 0x00, byte(len(body)>>8), byte(len(body)))
		exts = append(exts, body...)
	}
	// supported_versions, so even a hello without SNI has an extensions block.
	exts = append(exts, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 32)
	body = append(body, make([]byte, 32)...) // session id
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func TestParseTLSClientHelloVectors(t *testing.T) {
	for _, v := range tlsFakeVectors {
		t.Run(v.file, func(t *testing.T) {
			p := tlsLoadFake(t, v.file)
			if got := tlsCheckHello(t, p); got != v.host {
				t.Fatalf("vector SNI = %q, want %q", got, v.host)
			}
			info, ok := ParseTLSClientHello(p)
			if !ok {
				t.Fatal("ParseTLSClientHello reported not a ClientHello")
			}
			if info.Proto != L7TLS {
				t.Errorf("Proto = %d, want L7TLS", info.Proto)
			}
			if info.Host != v.host {
				t.Errorf("Host = %q, want %q", info.Host, v.host)
			}
			if got := string(p[info.HostOff : info.HostOff+info.HostLen]); got != v.host {
				t.Errorf("payload[HostOff:+HostLen] = %q, want %q", got, v.host)
			}
			if got := string(p[info.SLDOff : info.SLDOff+info.SLDLen]); got != v.sld {
				t.Errorf("payload[SLDOff:+SLDLen] = %q, want %q", got, v.sld)
			}
			if info.MethodOff != 0 {
				t.Errorf("MethodOff = %d, want 0", info.MethodOff)
			}
			if info.SNIExtOff <= 0 || info.SNIExtOff+4 > len(p) {
				t.Fatalf("SNIExtOff = %d out of range", info.SNIExtOff)
			}
			if typ := binary.BigEndian.Uint16(p[info.SNIExtOff:]); typ != tlsExtServerName {
				t.Errorf("payload[SNIExtOff:] extension type = %#06x, want 0x0000", typ)
			}
			// The extension must enclose the hostname it points at.
			extLen := int(binary.BigEndian.Uint16(p[info.SNIExtOff+2:]))
			if info.HostOff < info.SNIExtOff+4 || info.HostOff+info.HostLen > info.SNIExtOff+4+extLen {
				t.Errorf("hostname [%d,%d) is not inside the SNI extension [%d,%d)",
					info.HostOff, info.HostOff+info.HostLen, info.SNIExtOff+4, info.SNIExtOff+4+extLen)
			}
		})
	}
}

func TestParseTLSClientHelloNoSNI(t *testing.T) {
	p := tlsBuildTestHello("", nil)
	tlsCheckHello(t, p)
	info, ok := ParseTLSClientHello(p)
	if !ok {
		t.Fatal("a ClientHello without SNI must still be recognised")
	}
	if info.Proto != L7TLS || info.Host != "" || info.HostOff != 0 || info.HostLen != 0 {
		t.Fatalf("unexpected info %+v", info)
	}
	if info.SNIExtOff != 0 {
		t.Errorf("SNIExtOff = %d, want 0", info.SNIExtOff)
	}
}

func TestParseTLSClientHelloRejects(t *testing.T) {
	good := tlsLoadFake(t, "tls_clienthello_www_google_com.bin")
	bad := func(mut func(b []byte)) []byte {
		c := append([]byte(nil), good...)
		mut(c)
		return c
	}
	tests := []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"one byte", []byte{0x16}},
		{"header only", []byte{0x16, 0x03, 0x01, 0x00}},
		{"http request", []byte("GET / HTTP/1.1\r\nHost: a.com\r\n\r\n")},
		{"app data record", bad(func(b []byte) { b[0] = 0x17 })},
		{"bad major version", bad(func(b []byte) { b[1] = 0x02 })},
		{"bad minor version", bad(func(b []byte) { b[2] = 0x77 })},
		{"not client_hello", bad(func(b []byte) { b[5] = 0x02 })},
		{"record len too small", bad(func(b []byte) { b[3], b[4] = 0, 3 })},
		{"zeroes", make([]byte, 64)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if info, ok := ParseTLSClientHello(tc.in); ok {
				t.Fatalf("accepted non-ClientHello, info %+v", info)
			}
		})
	}
}

func TestParseTLSClientHelloTruncated(t *testing.T) {
	for _, v := range tlsFakeVectors {
		p := tlsLoadFake(t, v.file)
		for n := 0; n <= len(p); n++ {
			in := p[:n]
			info, ok := ParseTLSClientHello(in)
			if !ok {
				continue
			}
			if info.Proto != L7TLS {
				t.Fatalf("%s[:%d]: Proto = %d", v.file, n, info.Proto)
			}
			// Every offset must stay inside the bytes we were given.
			for _, x := range [][2]int{
				{info.HostOff, info.HostLen}, {info.SLDOff, info.SLDLen}, {info.SNIExtOff, 0},
			} {
				if x[0] < 0 || x[0]+x[1] > n {
					t.Fatalf("%s[:%d]: offset %d len %d out of range", v.file, n, x[0], x[1])
				}
			}
			if info.Host != "" && info.Host != v.host {
				t.Fatalf("%s[:%d]: Host = %q", v.file, n, info.Host)
			}
			// The tamper and split paths must survive a truncated hello too.
			for _, m := range []HostlistMarker{
				MarkerAbs, MarkerMethod, MarkerHost, MarkerEndHost,
				MarkerSLD, MarkerEndSLD, MarkerMidSLD, MarkerSNIExt,
			} {
				if pos := FindSplitPos(in, info, m, 1); pos < 0 || pos > n {
					t.Fatalf("%s[:%d]: marker %d -> %d", v.file, n, m, pos)
				}
			}
			_, _ = TLSRecordSplit(in, n/2)
			if out := ModifyTLSFake(in, TLSMod{Rnd: true, SNI: "x.example.com", DupSID: true, PadEncap: true}); len(out) < n {
				t.Fatalf("%s[:%d]: ModifyTLSFake shrank the hello to %d", v.file, n, len(out))
			}
			_ = TamperHost(in, info, TamperOpts{DomCase: true})
		}
	}
}

func TestFindSplitPosMarkers(t *testing.T) {
	p := tlsLoadFake(t, "tls_clienthello_www_google_com.bin")
	info, ok := ParseTLSClientHello(p)
	if !ok {
		t.Fatal("vector did not parse")
	}
	tests := []struct {
		name string
		m    HostlistMarker
		off  int
		want int
	}{
		{"abs 0", MarkerAbs, 0, 0},
		{"abs 10", MarkerAbs, 10, 10},
		{"abs -1", MarkerAbs, -1, len(p) - 1},
		{"abs huge", MarkerAbs, 1 << 20, len(p)},
		{"abs very negative", MarkerAbs, -(1 << 20), 0},
		{"host", MarkerHost, 0, info.HostOff},
		{"host+1", MarkerHost, 1, info.HostOff + 1},
		{"endhost", MarkerEndHost, 0, info.HostOff + info.HostLen},
		{"endhost-2", MarkerEndHost, -2, info.HostOff + info.HostLen - 2},
		{"sld", MarkerSLD, 0, info.SLDOff},
		{"endsld", MarkerEndSLD, 0, info.SLDOff + info.SLDLen},
		{"midsld", MarkerMidSLD, 0, info.SLDOff + info.SLDLen/2},
		{"midsld+1", MarkerMidSLD, 1, info.SLDOff + info.SLDLen/2 + 1},
		{"sniext", MarkerSNIExt, 0, info.SNIExtOff},
		{"sniext+4", MarkerSNIExt, 4, info.SNIExtOff + 4},
		{"method on tls", MarkerMethod, 3, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FindSplitPos(p, info, tc.m, tc.off)
			if got != tc.want {
				t.Fatalf("FindSplitPos(%d, %+d) = %d, want %d", tc.m, tc.off, got, tc.want)
			}
			if got < 0 || got > len(p) {
				t.Fatalf("position %d outside payload of %d bytes", got, len(p))
			}
		})
	}
	// Sanity: the SLD really is "google" and midsld lands inside it.
	mid := FindSplitPos(p, info, MarkerMidSLD, 0)
	if mid <= info.SLDOff || mid >= info.SLDOff+info.SLDLen {
		t.Fatalf("midsld %d is not strictly inside the SLD [%d,%d)", mid, info.SLDOff, info.SLDOff+info.SLDLen)
	}
}

func TestFindSplitPosUnknownAnchor(t *testing.T) {
	p := []byte("some opaque payload")
	var empty L7Info
	for _, m := range []HostlistMarker{
		MarkerMethod, MarkerHost, MarkerEndHost, MarkerSLD, MarkerEndSLD, MarkerMidSLD, MarkerSNIExt,
		HostlistMarker(200),
	} {
		if got := FindSplitPos(p, empty, m, 5); got != 0 {
			t.Errorf("marker %d with no anchor = %d, want 0", m, got)
		}
	}
	// An HTTP payload anchors the method marker at offset 0.
	info, ok := ParseHTTPRequest([]byte("GET /x HTTP/1.1\r\nHost: a.example.com\r\n\r\n"))
	if !ok {
		t.Fatal("request did not parse")
	}
	if got := FindSplitPos(p, info, MarkerMethod, 3); got != 3 {
		t.Errorf("method+3 = %d, want 3", got)
	}
}

func TestTLSRecordSplitVectors(t *testing.T) {
	for _, v := range tlsFakeVectors {
		p := tlsLoadFake(t, v.file)
		info, ok := ParseTLSClientHello(p)
		if !ok {
			t.Fatalf("%s: did not parse", v.file)
		}
		positions := []int{
			tlsRecHdrLen + 1,
			len(p) - 1,
			FindSplitPos(p, info, MarkerSNIExt, 0),
			FindSplitPos(p, info, MarkerHost, 0),
			FindSplitPos(p, info, MarkerMidSLD, 0),
			len(p) / 2,
		}
		for _, pos := range positions {
			t.Run(v.file+"@"+itoa(pos), func(t *testing.T) {
				out, err := TLSRecordSplit(p, pos)
				if err != nil {
					t.Fatalf("TLSRecordSplit(%d): %v", pos, err)
				}
				if len(out) != len(p)+tlsRecHdrLen {
					t.Fatalf("output is %d bytes, want %d", len(out), len(p)+tlsRecHdrLen)
				}
				// Two well-formed records, same type/version, bodies concatenating
				// back to the original handshake message.
				var bodies []byte
				off, records := 0, 0
				for off < len(out) {
					if off+tlsRecHdrLen > len(out) {
						t.Fatalf("record header at %d is truncated", off)
					}
					if out[off] != p[0] || out[off+1] != p[1] || out[off+2] != p[2] {
						t.Fatalf("record %d header % x, want % x", records, out[off:off+3], p[:3])
					}
					n := int(binary.BigEndian.Uint16(out[off+3:]))
					if n == 0 {
						t.Fatalf("record %d is empty", records)
					}
					if off+tlsRecHdrLen+n > len(out) {
						t.Fatalf("record %d length %d overruns the output", records, n)
					}
					bodies = append(bodies, out[off+tlsRecHdrLen:off+tlsRecHdrLen+n]...)
					off += tlsRecHdrLen + n
					records++
				}
				if records != 2 {
					t.Fatalf("output holds %d records, want 2", records)
				}
				if !bytes.Equal(bodies, p[tlsRecHdrLen:]) {
					t.Fatal("concatenated record bodies differ from the original body")
				}
				if first := int(binary.BigEndian.Uint16(out[3:])); first != pos-tlsRecHdrLen {
					t.Fatalf("first record carries %d bytes, want %d", first, pos-tlsRecHdrLen)
				}
			})
		}
	}
}

func TestTLSRecordSplitErrors(t *testing.T) {
	p := tlsLoadFake(t, "tls_clienthello_4pda_to.bin")
	tests := []struct {
		name string
		in   []byte
		pos  int
	}{
		{"pos at header start", p, 0},
		{"pos inside header", p, 3},
		{"pos at header end", p, tlsRecHdrLen},
		{"pos at payload end", p, len(p)},
		{"pos past payload end", p, len(p) + 100},
		{"negative pos", p, -5},
		{"too short", p[:4], 2},
		{"truncated record", p[:len(p)-1], 20},
		{"trailing bytes", append(append([]byte(nil), p...), 0, 1, 2), 20},
		{"not a record", []byte("GET / HTTP/1.1\r\n\r\n"), 8},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if out, err := TLSRecordSplit(tc.in, tc.pos); err == nil {
				t.Fatalf("expected an error, got %d bytes", len(out))
			}
		})
	}
}

func TestModifyTLSFakeForcedSNI(t *testing.T) {
	names := []string{
		"a.io",                               // shorter than every vector
		"x.co",                               // shorter, different labels
		"www.google.com",                     // same length as one vector
		"very-long-subdomain.example.museum", // longer
		strings.Repeat("a", 60) + ".example.travel", // much longer
		"UPPER.Example.COM",                         // case is preserved on the wire
	}
	for _, v := range tlsFakeVectors {
		p := tlsLoadFake(t, v.file)
		for _, name := range names {
			t.Run(v.file+"/"+name, func(t *testing.T) {
				out := ModifyTLSFake(p, TLSMod{SNI: name})
				if got := tlsCheckHello(t, out); got != name {
					t.Fatalf("hello carries SNI %q, want %q", got, name)
				}
				if len(out) != len(p)+len(name)-len(v.host) {
					t.Fatalf("output is %d bytes, want %d", len(out), len(p)+len(name)-len(v.host))
				}
				info, ok := ParseTLSClientHello(out)
				if !ok {
					t.Fatal("modified hello no longer parses")
				}
				if info.Host != strings.ToLower(name) {
					t.Fatalf("ParseTLSClientHello Host = %q, want %q", info.Host, strings.ToLower(name))
				}
				if got := string(out[info.HostOff : info.HostOff+info.HostLen]); got != name {
					t.Fatalf("host bytes = %q, want %q", got, name)
				}
				if !bytes.Equal(p, tlsLoadFake(t, v.file)) {
					t.Fatal("ModifyTLSFake modified its input")
				}
			})
		}
	}
}

func TestModifyTLSFakeSNIOnSyntheticHellos(t *testing.T) {
	t.Run("no sni extension", func(t *testing.T) {
		in := tlsBuildTestHello("", nil)
		out := ModifyTLSFake(in, TLSMod{SNI: "added.example.org"})
		if got := tlsCheckHello(t, out); got != "added.example.org" {
			t.Fatalf("SNI = %q, want added.example.org", got)
		}
		info, ok := ParseTLSClientHello(out)
		if !ok || info.Host != "added.example.org" {
			t.Fatalf("reparse: ok=%v info=%+v", ok, info)
		}
	})
	t.Run("sni extension without host_name", func(t *testing.T) {
		// A server_name list holding a single non-host_name entry.
		body := []byte{0x00, 0x06, 0x02, 0x00, 0x03, 'a', 'b', 'c'}
		ext := append([]byte{0x00, 0x00, byte(len(body) >> 8), byte(len(body))}, body...)
		in := tlsBuildTestHello("", ext)
		if info, ok := ParseTLSClientHello(in); !ok || info.Host != "" || info.SNIExtOff == 0 {
			t.Fatalf("precondition: ok=%v info=%+v", ok, info)
		}
		out := ModifyTLSFake(in, TLSMod{SNI: "forced.example.net"})
		if got := tlsCheckHello(t, out); got != "forced.example.net" {
			t.Fatalf("SNI = %q, want forced.example.net", got)
		}
	})
}

func TestModifyTLSFakeRnd(t *testing.T) {
	for _, v := range tlsFakeVectors {
		t.Run(v.file, func(t *testing.T) {
			p := tlsLoadFake(t, v.file)
			out := ModifyTLSFake(p, TLSMod{Rnd: true})
			if len(out) != len(p) {
				t.Fatalf("rnd changed the length: %d -> %d", len(p), len(out))
			}
			if got := tlsCheckHello(t, out); got != v.host {
				t.Fatalf("rnd changed the SNI to %q", got)
			}
			l, ok := tlsParseHello(out)
			if !ok {
				t.Fatal("modified hello does not parse")
			}
			if bytes.Equal(out[l.randomOff:l.randomOff+32], p[l.randomOff:l.randomOff+32]) {
				t.Error("ClientHello.random was not randomised")
			}
			sid := l.sidLenOff + 1
			if bytes.Equal(out[sid:sid+l.sidLen], p[sid:sid+l.sidLen]) {
				t.Error("session id was not randomised")
			}
			// Everything after the session id must be untouched.
			if !bytes.Equal(out[sid+l.sidLen:], p[sid+l.sidLen:]) {
				t.Error("rnd touched bytes past the session id")
			}
		})
	}
}

func TestModifyTLSFakeRndSNI(t *testing.T) {
	for _, v := range tlsFakeVectors {
		t.Run(v.file, func(t *testing.T) {
			p := tlsLoadFake(t, v.file)
			out := ModifyTLSFake(p, TLSMod{RndSNI: true})
			if len(out) != len(p) {
				t.Fatalf("rndsni changed the length: %d -> %d", len(p), len(out))
			}
			got := tlsCheckHello(t, out)
			if got == v.host {
				t.Fatalf("rndsni left the SNI at %q", got)
			}
			if len(got) != len(v.host) {
				t.Fatalf("rndsni produced %q (%d bytes), want %d bytes", got, len(got), len(v.host))
			}
			// Label structure and TLD are preserved.
			gl, wl := strings.Split(got, "."), strings.Split(v.host, ".")
			if len(gl) != len(wl) {
				t.Fatalf("label count changed: %q vs %q", got, v.host)
			}
			for i := range gl {
				if len(gl[i]) != len(wl[i]) {
					t.Fatalf("label %d length changed: %q vs %q", i, got, v.host)
				}
			}
			if gl[len(gl)-1] != wl[len(wl)-1] {
				t.Errorf("TLD changed: %q vs %q", got, v.host)
			}
			info, ok := ParseTLSClientHello(out)
			if !ok || info.Host != got {
				t.Fatalf("reparse: ok=%v Host=%q want %q", ok, info.Host, got)
			}
		})
	}
}

func TestModifyTLSFakeDupSID(t *testing.T) {
	for _, v := range tlsFakeVectors {
		t.Run(v.file, func(t *testing.T) {
			p := tlsLoadFake(t, v.file)
			l0, _ := tlsParseHello(p)
			out := ModifyTLSFake(p, TLSMod{DupSID: true})
			if len(out) != len(p)+l0.sidLen {
				t.Fatalf("output is %d bytes, want %d", len(out), len(p)+l0.sidLen)
			}
			if got := tlsCheckHello(t, out); got != v.host {
				t.Fatalf("dupsid changed the SNI to %q", got)
			}
			l1, ok := tlsParseHello(out)
			if !ok {
				t.Fatal("modified hello does not parse")
			}
			if l1.sidLen != 2*l0.sidLen {
				t.Fatalf("session id length %d, want %d", l1.sidLen, 2*l0.sidLen)
			}
			orig := p[l0.sidLenOff+1 : l0.sidLenOff+1+l0.sidLen]
			first := out[l1.sidLenOff+1 : l1.sidLenOff+1+l0.sidLen]
			second := out[l1.sidLenOff+1+l0.sidLen : l1.sidLenOff+1+l1.sidLen]
			if !bytes.Equal(first, orig) || !bytes.Equal(second, orig) {
				t.Fatal("session id is not the original repeated twice")
			}
			if info, okp := ParseTLSClientHello(out); !okp || info.Host != v.host {
				t.Fatalf("reparse: ok=%v Host=%q", okp, info.Host)
			}
		})
	}
}

func TestModifyTLSFakePadEncap(t *testing.T) {
	for _, v := range tlsFakeVectors {
		t.Run(v.file, func(t *testing.T) {
			p := tlsLoadFake(t, v.file)
			l0, _ := tlsParseHello(p)
			out := ModifyTLSFake(p, TLSMod{PadEncap: true})
			if len(out) <= len(p) {
				t.Fatalf("padencap did not grow the hello (%d -> %d)", len(p), len(out))
			}
			if got := tlsCheckHello(t, out); got != v.host {
				t.Fatalf("padencap changed the SNI to %q", got)
			}
			l1, ok := tlsParseHello(out)
			if !ok {
				t.Fatal("padded hello does not parse")
			}
			if l1.echExtOff == 0 {
				t.Fatal("no encrypted_client_hello extension in the padded hello")
			}
			if l0.echExtOff != 0 {
				// The existing 0xfe0d extension must have grown, not been duplicated.
				if l1.echBodyLen <= l0.echBodyLen {
					t.Fatalf("ech body did not grow: %d -> %d", l0.echBodyLen, l1.echBodyLen)
				}
				n := 0
				for e := l1.extsOff; e+4 <= l1.extsEnd; {
					bl := int(binary.BigEndian.Uint16(out[e+2:]))
					if binary.BigEndian.Uint16(out[e:]) == tlsExtECH {
						n++
					}
					e += 4 + bl
				}
				if n != 1 {
					t.Fatalf("padded hello holds %d ech extensions, want 1", n)
				}
			} else if len(out) < tlsPadTarget {
				t.Errorf("padded hello is %d bytes, want at least %d", len(out), tlsPadTarget)
			}
			plOff, okECH := tlsECHPayloadLenOff(out, l1)
			if !okECH {
				t.Fatal("the padded ech extension does not parse as ECH")
			}
			end := l1.echBodyOff + l1.echBodyLen
			if l0.echExtOff != 0 {
				// Grown extension: only the appended tail is ours, the original
				// ECH key material and payload stay as they were.
				for i, b := range out[l1.echBodyOff+l0.echBodyLen : end] {
					if b != 0 {
						t.Fatalf("appended padding byte %d is %#02x, want 0", i, b)
					}
				}
			} else {
				// Freshly appended extension: everything except the two internal
				// length prefixes is zero.
				for i := l1.echBodyOff; i < end; i++ {
					if i == l1.echBodyOff+6 || i == l1.echBodyOff+7 || i == plOff || i == plOff+1 {
						continue
					}
					if out[i] != 0 {
						t.Fatalf("ech body byte %d is %#02x, want 0", i-l1.echBodyOff, out[i])
					}
				}
			}
			if info, okp := ParseTLSClientHello(out); !okp || info.Host != v.host {
				t.Fatalf("reparse: ok=%v Host=%q", okp, info.Host)
			}
			// Padding twice must stay valid.
			tlsCheckHello(t, ModifyTLSFake(out, TLSMod{PadEncap: true}))
		})
	}
}

func TestModifyTLSFakeCombined(t *testing.T) {
	p := tlsLoadFake(t, "tls_clienthello_www_google_com.bin")
	mod, err := ParseTLSMod("rnd,dupsid,padencap,sni=short.io")
	if err != nil {
		t.Fatalf("ParseTLSMod: %v", err)
	}
	out := ModifyTLSFake(p, mod)
	if got := tlsCheckHello(t, out); got != "short.io" {
		t.Fatalf("SNI = %q, want short.io", got)
	}
	l0, _ := tlsParseHello(p)
	l1, ok := tlsParseHello(out)
	if !ok {
		t.Fatal("combined output does not parse")
	}
	if l1.sidLen != 2*l0.sidLen {
		t.Errorf("session id length %d, want %d", l1.sidLen, 2*l0.sidLen)
	}
	if l1.echBodyLen <= l0.echBodyLen {
		t.Errorf("ech body did not grow: %d -> %d", l0.echBodyLen, l1.echBodyLen)
	}
	if info, okp := ParseTLSClientHello(out); !okp || info.Host != "short.io" {
		t.Fatalf("reparse: ok=%v Host=%q", okp, info.Host)
	}
}

func TestModifyTLSFakeNoneAndGarbage(t *testing.T) {
	p := tlsLoadFake(t, "tls_clienthello_max_ru.bin")
	out := ModifyTLSFake(p, TLSMod{None: true, Rnd: true, SNI: "ignored.example"})
	if !bytes.Equal(out, p) {
		t.Fatal("mod.None must return an unchanged copy")
	}
	out[0] = 0xff
	if p[0] == 0xff {
		t.Fatal("ModifyTLSFake returned a slice aliasing its input")
	}
	if got := ModifyTLSFake(p, TLSMod{}); !bytes.Equal(got, p) {
		t.Fatal("an empty TLSMod must return an unchanged copy")
	}
	for _, in := range [][]byte{nil, {}, []byte("not tls at all"), p[:20]} {
		got := ModifyTLSFake(in, TLSMod{Rnd: true, DupSID: true, PadEncap: true, SNI: "a.b"})
		if len(got) < len(in) {
			t.Fatalf("garbage input shrank: %d -> %d", len(in), len(got))
		}
	}
}

func TestParseTLSMod(t *testing.T) {
	tests := []struct {
		in   string
		want TLSMod
		bad  bool
	}{
		{in: "", want: TLSMod{}},
		{in: "none", want: TLSMod{None: true}},
		{in: "rnd", want: TLSMod{Rnd: true}},
		{in: "rnd,rndsni", want: TLSMod{Rnd: true, RndSNI: true}},
		{in: "dupsid,padencap", want: TLSMod{DupSID: true, PadEncap: true}},
		{in: "rnd,dupsid,sni=www.google.com", want: TLSMod{Rnd: true, DupSID: true, SNI: "www.google.com"}},
		{in: " RND , DupSID ", want: TLSMod{Rnd: true, DupSID: true}},
		{in: "SNI = Www.Example.COM ", want: TLSMod{SNI: "Www.Example.COM"}},
		{in: "rnd,,padencap", want: TLSMod{Rnd: true, PadEncap: true}},
		{in: "bogus", bad: true},
		{in: "rnd,bogus", bad: true},
		{in: "sni=", bad: true},
		{in: "sni=has space", bad: true},
		{in: "sni=.leading.dot", bad: true},
		{in: "host=www.google.com", bad: true},
		{in: "sni=" + strings.Repeat("a", 254), bad: true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseTLSMod(tc.in)
			if tc.bad {
				if err == nil {
					t.Fatalf("expected an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseHTTPRequest(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		ok     bool
		host   string
		sld    string
		noHost bool
	}{
		{name: "simple get", in: "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n", ok: true, host: "www.google.com", sld: "google"},
		{name: "no space after colon", in: "GET / HTTP/1.1\r\nHost:4pda.to\r\n\r\n", ok: true, host: "4pda.to", sld: "4pda"},
		{name: "tab and mixed case", in: "POST /x HTTP/1.1\r\nhOsT:\t Rutracker.ORG \r\nA: b\r\n\r\n", ok: true, host: "rutracker.org", sld: "Rutracker"},
		{name: "with port", in: "GET /x HTTP/1.1\r\nHost: example.com:8080\r\n\r\n", ok: true, host: "example.com", sld: "example"},
		{name: "connect", in: "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", ok: true, host: "example.com", sld: "example"},
		{name: "host after other headers", in: "HEAD / HTTP/1.1\r\nUser-Agent: x\r\nHost: a.b.co.uk\r\n\r\n", ok: true, host: "a.b.co.uk", sld: "co"},
		{name: "unix eol", in: "GET / HTTP/1.1\nHost: single.label\n\n", ok: true, host: "single.label", sld: "single"},
		{name: "ipv6 literal", in: "GET / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n", ok: true, host: "[2001:db8::1]"},
		{name: "no host header", in: "GET / HTTP/1.0\r\nAccept: */*\r\n\r\n", ok: true, noHost: true},
		{name: "host in body only", in: "GET / HTTP/1.1\r\n\r\nHost: evil.com\r\n", ok: true, noHost: true},
		{name: "headers not received yet", in: "GET /longer/path HTT", ok: true, noHost: true},
		{name: "options", in: "OPTIONS * HTTP/1.1\r\nHost: opt.example\r\n\r\n", ok: true, host: "opt.example", sld: "opt"},
		{name: "empty", in: "", ok: false},
		{name: "not http", in: "\x16\x03\x01\x00\x05hello", ok: false},
		{name: "lowercase method", in: "get / HTTP/1.1\r\nHost: a.com\r\n\r\n", ok: false},
		{name: "unknown method", in: "FOO / HTTP/1.1\r\nHost: a.com\r\n\r\n", ok: false},
		{name: "no target", in: "GET  HTTP/1.1\r\n\r\n", ok: false},
		{name: "method only", in: "GET ", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := []byte(tc.in)
			info, ok := ParseHTTPRequest(p)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			if info.Proto != L7HTTP {
				t.Errorf("Proto = %d, want L7HTTP", info.Proto)
			}
			if info.MethodOff != 0 {
				t.Errorf("MethodOff = %d, want 0", info.MethodOff)
			}
			if tc.noHost {
				if info.Host != "" || info.HostOff != 0 || info.HostLen != 0 {
					t.Fatalf("expected no host, got %+v", info)
				}
				return
			}
			if info.Host != tc.host {
				t.Fatalf("Host = %q, want %q", info.Host, tc.host)
			}
			if got := strings.ToLower(string(p[info.HostOff : info.HostOff+info.HostLen])); got != tc.host {
				t.Fatalf("payload[HostOff:+HostLen] = %q, want %q", got, tc.host)
			}
			if tc.sld != "" {
				if got := string(p[info.SLDOff : info.SLDOff+info.SLDLen]); got != tc.sld {
					t.Fatalf("payload[SLDOff:+SLDLen] = %q, want %q", got, tc.sld)
				}
			}
			for _, m := range []HostlistMarker{MarkerMethod, MarkerHost, MarkerEndHost, MarkerSLD, MarkerEndSLD, MarkerMidSLD} {
				if pos := FindSplitPos(p, info, m, 0); pos < 0 || pos > len(p) {
					t.Fatalf("marker %d resolved outside the payload: %d", m, pos)
				}
			}
		})
	}
}

func TestParseHTTPRequestTruncated(t *testing.T) {
	full := []byte("POST /submit?a=b HTTP/1.1\r\nUser-Agent: t\r\nHost: www.example.com:8080\r\nX: y\r\n\r\nbody")
	for n := 0; n <= len(full); n++ {
		in := full[:n]
		info, ok := ParseHTTPRequest(in)
		if !ok {
			continue
		}
		if info.HostOff < 0 || info.HostOff+info.HostLen > n || info.SLDOff+info.SLDLen > n {
			t.Fatalf("[:%d]: offsets out of range: %+v", n, info)
		}
		if info.Host != "" && !strings.HasPrefix("www.example.com", info.Host) {
			t.Fatalf("[:%d]: Host = %q", n, info.Host)
		}
		_ = TamperHost(in, info, TamperOpts{
			HostCase: true, HostNoSpace: true, HostDot: true, HostTab: true,
			HostPad: 40, DomCase: true, MethodSpace: true, MethodEOL: true, UnixEOL: true,
		})
	}
}

func TestTamperHostHTTP(t *testing.T) {
	const req = "GET /a HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
	tests := []struct {
		name string
		o    TamperOpts
		want string
	}{
		{name: "nothing", o: TamperOpts{}, want: req},
		{name: "hostcase", o: TamperOpts{HostCase: true},
			want: "GET /a HTTP/1.1\r\nhost: example.com\r\nAccept: */*\r\n\r\n"},
		{name: "hostspell", o: TamperOpts{HostSpell: "hoSt"},
			want: "GET /a HTTP/1.1\r\nhoSt: example.com\r\nAccept: */*\r\n\r\n"},
		{name: "hostspell wins over hostcase", o: TamperOpts{HostCase: true, HostSpell: "HOST"},
			want: "GET /a HTTP/1.1\r\nHOST: example.com\r\nAccept: */*\r\n\r\n"},
		{name: "hostnospace", o: TamperOpts{HostNoSpace: true},
			want: "GET /a HTTP/1.1\r\nHost:example.com\r\nAccept: */*\r\n\r\n"},
		{name: "hostdot", o: TamperOpts{HostDot: true},
			want: "GET /a HTTP/1.1\r\nHost: example.com.\r\nAccept: */*\r\n\r\n"},
		{name: "hosttab", o: TamperOpts{HostTab: true},
			want: "GET /a HTTP/1.1\r\nHost: example.com\t\r\nAccept: */*\r\n\r\n"},
		{name: "dot and tab", o: TamperOpts{HostDot: true, HostTab: true},
			want: "GET /a HTTP/1.1\r\nHost: example.com.\t\r\nAccept: */*\r\n\r\n"},
		{name: "methodspace", o: TamperOpts{MethodSpace: true},
			want: "GET  /a HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"},
		{name: "methodeol", o: TamperOpts{MethodEOL: true},
			want: "\nGET /a HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"},
		{name: "unixeol", o: TamperOpts{UnixEOL: true},
			want: "GET /a HTTP/1.1\nHost: example.com\nAccept: */*\n\n"},
		{name: "hostcase nospace dot unixeol", o: TamperOpts{HostCase: true, HostNoSpace: true, HostDot: true, UnixEOL: true},
			want: "GET /a HTTP/1.1\nhost:example.com.\nAccept: */*\n\n"},
		{name: "methodspace and methodeol", o: TamperOpts{MethodSpace: true, MethodEOL: true},
			want: "\nGET  /a HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"},
		{name: "pad too small to be a header", o: TamperOpts{HostPad: 4}, want: req},
	}
	info, ok := ParseHTTPRequest([]byte(req))
	if !ok {
		t.Fatal("fixture did not parse")
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TamperHost([]byte(req), info, tc.o)
			if string(got) != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestTamperHostDomCaseHTTP(t *testing.T) {
	const req = "GET / HTTP/1.1\r\nHost: www.example.com:8080\r\n\r\n"
	info, ok := ParseHTTPRequest([]byte(req))
	if !ok {
		t.Fatal("fixture did not parse")
	}
	sawMixed := false
	for i := 0; i < 20; i++ {
		out := TamperHost([]byte(req), info, TamperOpts{DomCase: true})
		if len(out) != len(req) {
			t.Fatalf("domcase changed the length: %d -> %d", len(req), len(out))
		}
		if !strings.EqualFold(string(out), req) {
			t.Fatalf("domcase changed more than letter case: %q", out)
		}
		got, ok2 := ParseHTTPRequest(out)
		if !ok2 || got.Host != "www.example.com" {
			t.Fatalf("reparse: ok=%v Host=%q", ok2, got.Host)
		}
		if string(out) != req {
			sawMixed = true
		}
		// Only the hostname may change: the port and the rest stay put.
		if !bytes.Equal(out[info.HostOff+info.HostLen:], []byte(req)[info.HostOff+info.HostLen:]) {
			t.Fatalf("domcase touched bytes past the hostname: %q", out)
		}
	}
	if !sawMixed {
		t.Error("domcase never changed any case in 20 tries")
	}
}

func TestTamperHostPad(t *testing.T) {
	const req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	info, ok := ParseHTTPRequest([]byte(req))
	if !ok {
		t.Fatal("fixture did not parse")
	}
	for _, n := range []int{10, 11, 40, 209, 210, 512, 4000} {
		out := TamperHost([]byte(req), info, TamperOpts{HostPad: n})
		if len(out) != len(req)+n {
			t.Fatalf("pad %d: output is %d bytes, want %d", n, len(out), len(req)+n)
		}
		hostIdx := bytes.Index(out, []byte("Host: example.com"))
		padIdx := bytes.Index(out, []byte("X-Pad: "))
		if padIdx < 0 || hostIdx < 0 || padIdx > hostIdx {
			t.Fatalf("pad %d: padding must precede the Host header (%d vs %d)", n, padIdx, hostIdx)
		}
		if !bytes.HasPrefix(out, []byte("GET / HTTP/1.1\r\n")) {
			t.Fatalf("pad %d: request line damaged: %q", n, out[:20])
		}
		got, ok2 := ParseHTTPRequest(out)
		if !ok2 || got.Host != "example.com" {
			t.Fatalf("pad %d: reparse ok=%v Host=%q", n, ok2, got.Host)
		}
		// Every padding line must be CRLF terminated and hold a header name.
		lines := bytes.Split(out[16:padIdx+n], []byte("\r\n"))
		for _, ln := range lines {
			if len(ln) == 0 {
				continue
			}
			if !bytes.HasPrefix(ln, []byte("X-Pad: ")) {
				t.Fatalf("pad %d: bad padding line %q", n, ln)
			}
		}
	}
}

func TestTamperHostTLSDomCase(t *testing.T) {
	p := tlsLoadFake(t, "tls_clienthello_www_google_com.bin")
	info, ok := ParseTLSClientHello(p)
	if !ok {
		t.Fatal("vector did not parse")
	}
	sawMixed := false
	for i := 0; i < 20; i++ {
		out := TamperHost(p, info, TamperOpts{
			// The HTTP knobs must be ignored for a ClientHello.
			DomCase: true, HostCase: true, HostDot: true, HostPad: 64,
			MethodSpace: true, MethodEOL: true, UnixEOL: true, HostNoSpace: true,
		})
		if len(out) != len(p) {
			t.Fatalf("TLS tampering changed the length: %d -> %d", len(p), len(out))
		}
		if got := tlsCheckHello(t, out); !strings.EqualFold(got, "www.google.com") {
			t.Fatalf("SNI became %q", got)
		}
		got, ok2 := ParseTLSClientHello(out)
		if !ok2 || got.Host != "www.google.com" {
			t.Fatalf("reparse: ok=%v Host=%q", ok2, got.Host)
		}
		if !bytes.Equal(out[:info.HostOff], p[:info.HostOff]) ||
			!bytes.Equal(out[info.HostOff+info.HostLen:], p[info.HostOff+info.HostLen:]) {
			t.Fatal("TLS domcase touched bytes outside the SNI")
		}
		if !bytes.Equal(out, p) {
			sawMixed = true
		}
	}
	if !sawMixed {
		t.Error("domcase never changed the SNI case in 20 tries")
	}
}

func TestTamperHostUnknownProto(t *testing.T) {
	in := []byte{0x00, 0x01, 0x02, 0xff}
	out := TamperHost(in, L7Info{Proto: L7Unknown}, TamperOpts{
		HostCase: true, HostDot: true, DomCase: true, HostPad: 32, UnixEOL: true,
	})
	if !bytes.Equal(out, in) {
		t.Fatalf("unknown payload was modified: % x", out)
	}
	out[0] = 0x55
	if in[0] == 0x55 {
		t.Fatal("TamperHost returned a slice aliasing its input")
	}
}

// TestParsersSurviveMutations hammers every entry point with deterministically
// corrupted vectors: length fields set to extremes, bytes flipped, prefixes cut.
// Nothing may panic and no reported offset may leave the payload.
func TestParsersSurviveMutations(t *testing.T) {
	seeds := [][]byte{
		tlsLoadFake(t, "tls_clienthello_www_google_com.bin"),
		tlsLoadFake(t, "tls_clienthello_4pda_to.bin"),
		[]byte("GET /path HTTP/1.1\r\nHost: www.example.com:443\r\nA: b\r\n\r\n"),
		[]byte("CONNECT a.b.c:443 HTTP/1.1\r\nhost:\ta.b.c\r\n\r\n"),
	}
	rng := rand.New(rand.NewSource(20260727))
	for si, seed := range seeds {
		for iter := 0; iter < 2000; iter++ {
			in := append([]byte(nil), seed...)
			switch iter % 4 {
			case 0: // flip a byte
				in[rng.Intn(len(in))] = byte(rng.Intn(256))
			case 1: // flip a byte and cut the tail
				in[rng.Intn(len(in))] = byte(rng.Intn(256))
				in = in[:rng.Intn(len(in)+1)]
			case 2: // extreme 16-bit field somewhere
				if len(in) >= 2 {
					o := rng.Intn(len(in) - 1)
					in[o], in[o+1] = 0xff, 0xff
				}
			case 3: // splice random junk in
				o := rng.Intn(len(in) + 1)
				junk := make([]byte, rng.Intn(8))
				for i := range junk {
					junk[i] = byte(rng.Intn(256))
				}
				in = protoSplice(in, o, 0, junk)
			}

			var info L7Info
			if l7, ok := ParseTLSClientHello(in); ok {
				info = l7
			} else if l7, ok := ParseHTTPRequest(in); ok {
				info = l7
			} else {
				info = L7Info{Proto: L7Unknown}
			}
			for _, x := range [][2]int{
				{info.HostOff, info.HostLen}, {info.SLDOff, info.SLDLen},
				{info.SNIExtOff, 0}, {info.MethodOff, 0},
			} {
				if x[0] < 0 || x[0]+x[1] > len(in) {
					t.Fatalf("seed %d iter %d: offset %d len %d outside %d bytes",
						si, iter, x[0], x[1], len(in))
				}
			}
			for _, m := range []HostlistMarker{
				MarkerAbs, MarkerMethod, MarkerHost, MarkerEndHost,
				MarkerSLD, MarkerEndSLD, MarkerMidSLD, MarkerSNIExt,
			} {
				for _, off := range []int{-3, 0, 1, 1 << 20} {
					if pos := FindSplitPos(in, info, m, off); pos < 0 || pos > len(in) {
						t.Fatalf("seed %d iter %d: marker %d%+d -> %d (payload %d)",
							si, iter, m, off, pos, len(in))
					}
				}
			}
			if out, err := TLSRecordSplit(in, len(in)/2); err == nil {
				if len(out) != len(in)+tlsRecHdrLen {
					t.Fatalf("seed %d iter %d: split output %d bytes, want %d",
						si, iter, len(out), len(in)+tlsRecHdrLen)
				}
			}
			lin, helloIn := tlsParseHello(in)
			for _, mod := range []TLSMod{
				{Rnd: true}, {RndSNI: true}, {DupSID: true}, {PadEncap: true},
				{SNI: "x.example.org"}, {Rnd: true, RndSNI: true, DupSID: true, PadEncap: true, SNI: "a.b"},
			} {
				out := ModifyTLSFake(in, mod)
				if !helloIn {
					// Not a ClientHello: the only allowed answer is a plain copy.
					if !bytes.Equal(out, in) {
						t.Fatalf("seed %d iter %d: mod %+v changed a non-hello payload", si, iter, mod)
					}
					continue
				}
				lout, ok := tlsParseHello(out)
				if !ok {
					t.Fatalf("seed %d iter %d: mod %+v destroyed the hello", si, iter, mod)
				}
				// The length arithmetic must never break the record/handshake
				// framing of a hello that had consistent framing to begin with.
				if lin.complete && !lout.complete {
					t.Fatalf("seed %d iter %d: mod %+v broke the record/handshake lengths (%d bytes, recLen %d, hsLen %d)",
						si, iter, mod, len(out), lout.recLen, lout.hsLen)
				}
			}
			_ = TamperHost(in, info, TamperOpts{
				HostCase: true, HostSpell: "hoSt", HostNoSpace: true, HostDot: true,
				HostTab: true, HostPad: 33, DomCase: true, MethodSpace: true,
				MethodEOL: true, UnixEOL: true,
			})
		}
	}
}

// itoa avoids pulling strconv into the test just for subtest names.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
