package desync

// UDP-side second-stage op: --dpi-desync=udplen.

// injUDPLenDefaultIncrement is nfqws' UDPLEN_INCREMENT_DEFAULT.
const injUDPLenDefaultIncrement = 2

// injUDPMaxPayload is the largest UDP payload an IP total-length field can
// describe; nfqws clamps to the same u16 range in prepare_udp_segment.
const injUDPMaxPayload = 0xFFFF

func init() {
	Register("udplen", func() Op { return &udpLenOp{} })
}

// udpLenOp implements --dpi-desync=udplen: the real datagram is re-sent with its
// payload grown (or shrunk, for a negative increment) by N bytes.
//
// It works on protocols whose length is carried inside the payload — a QUIC
// Initial, a WireGuard handshake, a STUN binding request — where the DPI
// signature includes "datagram length equals the length the protocol claims".
// The peer's parser reads its own length field and ignores the tail, the DPI's
// fingerprint no longer matches.
//
// This is a modification of the real datagram, not an injected decoy: the plan
// carries one data Dgram and no fake.
type udpLenOp struct{}

// Name reports the --dpi-desync spelling.
func (*udpLenOp) Name() string { return "udplen" }

// Phase reports that udplen mutates what is already planned.
func (*udpLenOp) Phase() Phase { return PhaseModify }

// Requires reports UDP visibility plus the ability to suppress the application's
// own datagram, since the modified copy replaces it.
func (*udpLenOp) Requires() Caps { return Caps{UDP: true, DropOriginal: true} }

// Apply replaces the plan's data datagram with the padded payload.
func (o *udpLenOp) Apply(c *Ctx, p *Plan) error {
	if c == nil || p == nil || c.Flow == nil {
		return nil
	}
	if !injIsUDP(c) || len(c.Payload) == 0 {
		// nfqws only reaches DESYNC_UDPLEN from the UDP datapath.
		return nil
	}
	inc := c.Params.UDPLenIncrement
	if inc == 0 {
		// nfqws' dp_init default. An explicit 0 would be a no-op anyway, so
		// treating "unset" and "zero" alike loses nothing.
		inc = injUDPLenDefaultIncrement
	}
	data := injUDPLenResize(c.Payload, inc, c.Params.UDPLenPattern)

	// Reuse an existing data datagram so a Fool bit another PhaseModify op
	// (hopbyhop/destopt) already set survives.
	for i := range p.Dgrams {
		if p.Dgrams[i].Kind == SegData {
			p.Dgrams[i].Data = data
			if p.Dgrams[i].Frag > 0 {
				// ipfrag2 ran first and sized its split against the unpadded
				// datagram. A truncating increment can leave that position past
				// the end, which proto.IPFragment rejects, so re-derive it for the
				// bytes actually going out.
				p.Dgrams[i].Frag = injFragPosLen(c, true, len(data))
			}
			return nil
		}
	}
	p.Dgrams = append(p.Dgrams, Dgram{Kind: SegData, Data: data})
	return nil
}

// injUDPLenResize applies --dpi-desync-udplen-increment to a payload, padding
// with --dpi-desync-udplen-pattern.
//
// The clamping is nfqws' prepare_udp_segment, in the same order:
//
//	if (len+padlen)<=0   padlen = -len+1   // never shrink below one byte
//	if (len+padlen)>FFFF padlen = FFFF-len // stay inside the u16 length field
//	if (padlen<0)        len += padlen     // a negative increment truncates
//
// The pattern is repeated cyclically from its first byte (fill_pattern with
// offset 0); with no pattern the tail is zero-filled.
func injUDPLenResize(payload []byte, inc int, pattern []byte) []byte {
	n := len(payload)
	pad := inc
	if n+pad <= 0 {
		pad = -n + 1
	}
	if n+pad > injUDPMaxPayload {
		pad = injUDPMaxPayload - n
	}
	if pad < 0 {
		n += pad
		pad = 0
	}
	if n < 0 {
		n = 0
	}
	out := make([]byte, n+pad)
	copy(out, payload[:n])
	if pad > 0 && len(pattern) > 0 {
		injFillPattern(out[n:], pattern)
	}
	return out
}

// injFillPattern tiles pattern over dst, starting from the pattern's first byte.
func injFillPattern(dst, pattern []byte) {
	for off := 0; off < len(dst); off += len(pattern) {
		copy(dst[off:], pattern)
	}
}
