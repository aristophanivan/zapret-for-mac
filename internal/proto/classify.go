package proto

// Classify recognises the application protocol carried by one client->server
// payload. It is the single entry point the engine calls, and the macOS
// equivalent of the L7 detection in zapret's nfq/protocol.c.
//
// TCP is tried as TLS then HTTP; UDP as QUIC Initial, STUN, Discord voice IP
// discovery, WireGuard and finally BitTorrent DHT. Recognition is purely
// payload-driven — dstPort is accepted because the engine always has it and
// zapret's own filters are port-scoped, but a service moved to a non-standard
// port is still identified by content, exactly as nfqws does it.
//
// Offsets in the result are relative to the start of payload. For QUIC they stay
// zero: the ClientHello lives inside an AEAD-protected packet, so there is no
// plaintext position in the payload a split marker could point at.
//
// An empty payload, or anything unrecognised, yields L7Info{Proto: L7Unknown} —
// which is a real filter class ("--filter-l7=unknown"), not a zero value.
func Classify(payload []byte, dstPort uint16, ipproto uint8) (info L7Info) {
	info = L7Info{Proto: L7Unknown}
	if len(payload) == 0 {
		return info
	}

	// The datapath must survive any packet an attacker can put on the wire: a
	// panic in a recogniser would take the whole daemon down, so absorb it and
	// treat the payload as unclassified.
	defer func() {
		if recover() != nil {
			info = L7Info{Proto: L7Unknown}
		}
	}()

	switch ipproto {
	case IPProtoTCP:
		if tls, ok := ParseTLSClientHello(payload); ok {
			return tls
		}
		if http, ok := ParseHTTPRequest(payload); ok {
			return http
		}
	case IPProtoUDP:
		if IsQUICInitial(payload) {
			q := L7Info{Proto: L7QUIC}
			// An Initial we cannot decrypt (unsupported cipher, CRYPTO frames
			// spread over several datagrams) is still QUIC for filtering; only
			// the hostname-gated profiles need the SNI.
			if host, ok := QUICSNI(payload); ok {
				q.Host = host
			}
			return q
		}
		if IsSTUN(payload) {
			return L7Info{Proto: L7STUN}
		}
		if IsDiscordIPDiscovery(payload) {
			return L7Info{Proto: L7Discord}
		}
		if IsWireGuard(payload) {
			return L7Info{Proto: L7WireGuard}
		}
		if IsDHT(payload) {
			return L7Info{Proto: L7DHT}
		}
	}
	return L7Info{Proto: L7Unknown}
}
