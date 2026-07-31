package proto

// httpRequestMethods is the set of request methods nfqws recognises. Methods are
// matched case-sensitively: HTTP defines them as upper case tokens, and a DPI
// box looking for "GET " sees exactly these bytes.
var httpRequestMethods = [...]string{
	"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT",
}

// httpMethodLen returns the length of the request method at the start of p, or 0
// when p does not begin with "<METHOD> <target>".
func httpMethodLen(p []byte) int {
	for _, m := range httpRequestMethods {
		n := len(m)
		// Need the method, its space, and at least one target byte.
		if len(p) < n+2 || p[n] != ' ' {
			continue
		}
		if string(p[:n]) != m {
			continue
		}
		// The target must start with a visible character (rules out "GET  " and
		// "GET \r\n", which no client sends and which would confuse the offsets).
		if c := p[n+1]; c <= ' ' || c == 0x7f {
			continue
		}
		return n
	}
	return 0
}

// httpHostLoc is where the Host header and its parts live inside a request.
type httpHostLoc struct {
	lineOff  int // start of the header line, i.e. of the header name
	nameLen  int // length of the header name token ("Host")
	colonOff int // the ':' after the name
	valOff   int // first value byte (leading spaces/tabs skipped)
	valEnd   int // end of the value, trailing spaces/tabs and CR removed
	hostEnd  int // end of the hostname inside the value (excludes ":port")
}

// httpFindHost locates the Host header case-insensitively, scanning header lines
// only (never the request line, never the body).
func httpFindHost(p []byte) (httpHostLoc, bool) {
	var loc httpHostLoc
	s := -1
	for i := 0; i < len(p); i++ {
		if p[i] == '\n' {
			s = i + 1
			break
		}
	}
	if s < 0 {
		return loc, false // no complete request line yet
	}
	for s < len(p) {
		e := -1
		for i := s; i < len(p); i++ {
			if p[i] == '\n' {
				e = i
				break
			}
		}
		if e < 0 {
			// The last line has not arrived in full. Reporting a half-received
			// hostname would let the engine cache a profile decision on a prefix
			// of the real name, so wait for the terminator instead.
			return loc, false
		}
		lineEnd := e
		if lineEnd > s && p[lineEnd-1] == '\r' {
			lineEnd--
		}
		if lineEnd == s {
			return loc, false // empty line: end of the header block
		}
		if l, ok := httpMatchHostLine(p, s, lineEnd); ok {
			return l, true
		}
		s = e + 1
	}
	return loc, false
}

// httpMatchHostLine tests one header line [s,end) for being the Host header and
// splits it into name/colon/value/hostname spans.
func httpMatchHostLine(p []byte, s, end int) (httpHostLoc, bool) {
	var loc httpHostLoc
	const name = "host"
	if end-s < len(name)+1 {
		return loc, false
	}
	for i := 0; i < len(name); i++ {
		c := p[s+i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != name[i] {
			return loc, false
		}
	}
	q := s + len(name)
	// Tolerate whitespace between the name and the colon: it is illegal HTTP but
	// a DPI evader may emit it, and we still want to find the hostname.
	for q < end && (p[q] == ' ' || p[q] == '\t') {
		q++
	}
	if q >= end || p[q] != ':' {
		return loc, false
	}
	loc.lineOff = s
	loc.nameLen = len(name)
	loc.colonOff = q
	v := q + 1
	for v < end && (p[v] == ' ' || p[v] == '\t') {
		v++
	}
	ve := end
	for ve > v && (p[ve-1] == ' ' || p[ve-1] == '\t') {
		ve--
	}
	loc.valOff, loc.valEnd = v, ve
	loc.hostEnd = httpHostNameEnd(p, v, ve)
	return loc, true
}

// httpHostNameEnd returns the end of the hostname inside the value [v,ve),
// dropping a trailing ":port". An IPv6 literal keeps its brackets.
func httpHostNameEnd(p []byte, v, ve int) int {
	if v >= ve {
		return ve
	}
	if p[v] == '[' {
		for i := v + 1; i < ve; i++ {
			if p[i] == ']' {
				return i + 1
			}
		}
		return ve
	}
	colon := -1
	for i := ve - 1; i >= v; i-- {
		if p[i] == ':' {
			colon = i
			break
		}
	}
	if colon < 0 {
		return ve
	}
	// An empty run after the colon ("host:") counts as a port separator too.
	for i := colon + 1; i < ve; i++ {
		if p[i] < '0' || p[i] > '9' {
			return ve
		}
	}
	return colon
}

// ParseHTTPRequest recognises an HTTP request and locates its Host header.
//
// HostOff/HostLen cover the hostname bytes of the header value with any
// trailing ":port" excluded, so payload[HostOff:HostOff+HostLen] is exactly the
// name reported in Host (Host is additionally lowercased). MethodOff is 0 and
// SLDOff/SLDLen mark the second-level label.
//
// ok is false when the payload does not start with a known method; a request
// with no (or a not yet received) Host header returns ok=true and Host "".
func ParseHTTPRequest(payload []byte) (L7Info, bool) {
	var info L7Info
	if httpMethodLen(payload) == 0 {
		return info, false
	}
	info.Proto = L7HTTP
	info.MethodOff = 0
	loc, ok := httpFindHost(payload)
	if !ok || loc.hostEnd <= loc.valOff {
		return info, true
	}
	name := payload[loc.valOff:loc.hostEnd]
	info.Host = tlsLowerASCII(name)
	info.HostOff, info.HostLen = loc.valOff, loc.hostEnd-loc.valOff
	if off, n := hostSLDSpan(name); n > 0 {
		info.SLDOff, info.SLDLen = loc.valOff+off, n
	}
	return info, true
}
