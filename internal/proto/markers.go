package proto

// FindSplitPos resolves one --dpi-desync-split-pos entry (a marker plus a signed
// offset) to a byte offset inside payload.
//
// The anchors are taken from info:
//
//	MarkerAbs      off, negative counting back from the end of the payload
//	MarkerMethod   info.MethodOff + off
//	MarkerHost     info.HostOff + off
//	MarkerEndHost  info.HostOff + info.HostLen + off
//	MarkerSLD      info.SLDOff + off
//	MarkerEndSLD   info.SLDOff + info.SLDLen + off
//	MarkerMidSLD   info.SLDOff + info.SLDLen/2 + off
//	MarkerSNIExt   info.SNIExtOff + off
//
// The result is clamped to [0, len(payload)]. When the anchor is unknown — the
// corresponding L7Info offset is 0, which no real host/SLD/extension can have —
// the answer is 0, so a caller that splits unconditionally still produces a
// well-formed (if useless) split instead of an out-of-range one.
func FindSplitPos(payload []byte, info L7Info, m HostlistMarker, off int) int {
	n := len(payload)
	var pos int
	switch m {
	case MarkerAbs:
		// zapret style: a negative absolute position counts from the end.
		if off < 0 {
			pos = n + off
		} else {
			pos = off
		}
	case MarkerMethod:
		// MethodOff is legitimately 0 for HTTP (the method starts the request),
		// so the anchor is keyed off the protocol instead of the offset.
		if info.Proto != L7HTTP {
			return 0
		}
		pos = info.MethodOff + off
	case MarkerHost:
		if info.HostOff <= 0 {
			return 0
		}
		pos = info.HostOff + off
	case MarkerEndHost:
		if info.HostOff <= 0 {
			return 0
		}
		pos = info.HostOff + info.HostLen + off
	case MarkerSLD:
		if info.SLDOff <= 0 {
			return 0
		}
		pos = info.SLDOff + off
	case MarkerEndSLD:
		if info.SLDOff <= 0 {
			return 0
		}
		pos = info.SLDOff + info.SLDLen + off
	case MarkerMidSLD:
		if info.SLDOff <= 0 {
			return 0
		}
		pos = info.SLDOff + info.SLDLen/2 + off
	case MarkerSNIExt:
		if info.SNIExtOff <= 0 {
			return 0
		}
		pos = info.SNIExtOff + off
	default:
		return 0
	}
	return clampSplitOffset(pos, n)
}

// clampSplitOffset confines pos to [0, n].
func clampSplitOffset(pos, n int) int {
	if pos < 0 {
		return 0
	}
	if pos > n {
		return n
	}
	return pos
}

// hostSLDSpan returns the offset and length of the second-level label inside a
// hostname: "google" in "www.google.com", "4pda" in "4pda.to". A single-label
// name is its own SLD. Trailing dots are ignored. (0,0) means "no label found",
// which only happens for an empty or all-dots name.
//
// Shared by the TLS SNI and HTTP Host parsers; the caller adds the offset of the
// hostname bytes inside the payload.
func hostSLDSpan(h []byte) (int, int) {
	end := len(h)
	for end > 0 && h[end-1] == '.' {
		end--
	}
	if end == 0 {
		return 0, 0
	}
	last := -1
	for i := end - 1; i >= 0; i-- {
		if h[i] == '.' {
			last = i
			break
		}
	}
	if last < 0 {
		return 0, end // single label, e.g. "localhost"
	}
	prev := -1
	for i := last - 1; i >= 0; i-- {
		if h[i] == '.' {
			prev = i
			break
		}
	}
	return prev + 1, last - (prev + 1)
}
