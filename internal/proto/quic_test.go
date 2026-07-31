package proto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Real winws fake blobs. Several of the files on disk are byte-identical
// (ACTIVE_DISCORD_UDP.bin == quic_initial_steamcommunity_com.bin,
// ACTIVE_GAME_UDP.bin == quic_initial_dbankcloud_ru.bin ==
// quic_initial_4pda.to.bin), so the expectations below describe what the bytes
// really are, not what the file names suggest.
const (
	l7fakeGoogleQUIC  = "quic_initial_www_google_com.bin"
	l7fakeSteamQUIC   = "quic_initial_steamcommunity_com.bin"
	l7fake4pdaQUIC    = "quic_initial_4pda.to.bin"
	l7fakeDbankQUIC   = "quic_initial_dbankcloud_ru.bin"
	l7fakeTencentQUIC = "quic_initial_tencent_com.bin"
	l7fakeDiscordUDP  = "ACTIVE_DISCORD_UDP.bin"
	l7fakeGameUDP     = "ACTIVE_GAME_UDP.bin"
	l7fakeSTUN        = "stun.bin"
	l7fakeSTUN2       = "stun2.bin"
	l7fakeTLSGoogle   = "tls_clienthello_www_google_com.bin"
	l7fakeTLS4pda     = "tls_clienthello_4pda_to.bin"
	l7fakeTLSMax      = "tls_clienthello_max_ru.bin"
)

func l7readFake(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "fakes", name))
	if err != nil {
		t.Fatalf("read fake %s: %v", name, err)
	}
	return b
}

func TestQUICVarint(t *testing.T) {
	// Appendix A.1 of RFC 9000 plus the degenerate/short cases.
	tests := []struct {
		name string
		in   []byte
		want uint64
		n    int
		ok   bool
	}{
		{"8byte", []byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652, 8, true},
		{"4byte", []byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333, 4, true},
		{"2byte", []byte{0x7b, 0xbd}, 15293, 2, true},
		{"1byte", []byte{0x25}, 37, 1, true},
		{"2byte_redundant", []byte{0x40, 0x25}, 37, 2, true},
		{"zero", []byte{0x00}, 0, 1, true},
		{"max_1byte", []byte{0x3f}, 63, 1, true},
		{"trailing_ignored", []byte{0x25, 0xff, 0xff}, 37, 1, true},
		{"empty", nil, 0, 0, false},
		{"short_2byte", []byte{0x7b}, 0, 0, false},
		{"short_4byte", []byte{0x9d, 0x7f, 0x3e}, 0, 0, false},
		{"short_8byte", []byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8}, 0, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, n, ok := quicVarint(tc.in)
			if ok != tc.ok || n != tc.n || got != tc.want {
				t.Fatalf("quicVarint(%x) = (%d,%d,%v), want (%d,%d,%v)", tc.in, got, n, ok, tc.want, tc.n, tc.ok)
			}
		})
	}
}

func TestIsQUICInitial(t *testing.T) {
	tests := []struct {
		file string
		want bool
	}{
		{l7fakeGoogleQUIC, true},
		{l7fakeSteamQUIC, true},
		{l7fake4pdaQUIC, true},
		{l7fakeDbankQUIC, true},
		// This blob is NOT a QUIC Initial: its version field reads 0xdfd221e2,
		// its type bits say 2 (Handshake in v1) and its DCID length byte says
		// 214. The whole file is high entropy with no known QUIC version
		// anywhere in it — a random fake payload, not a capture.
		{l7fakeTencentQUIC, false},
		{l7fakeDiscordUDP, true}, // identical bytes to quic_initial_steamcommunity_com.bin
		{l7fakeGameUDP, true},    // identical bytes to quic_initial_4pda.to.bin
		{l7fakeSTUN, false},
		{l7fakeSTUN2, false},
		{l7fakeTLSGoogle, false},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			if got := IsQUICInitial(l7readFake(t, tc.file)); got != tc.want {
				t.Fatalf("IsQUICInitial(%s) = %v, want %v", tc.file, got, tc.want)
			}
		})
	}
}

func TestIsQUICInitialSynthetic(t *testing.T) {
	// A minimal well-formed v1 Initial skeleton: flags, version, 0-length CIDs,
	// empty token, Length = 0x40,0x20 (32) covering pn+payload+tag.
	base := func() []byte {
		p := make([]byte, 0, 64)
		p = append(p, 0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x20)
		return append(p, make([]byte, 32)...)
	}
	tests := []struct {
		name string
		mut  func([]byte) []byte
		want bool
	}{
		{"pristine", func(p []byte) []byte { return p }, true},
		{"short_header", func(p []byte) []byte { return p[:6] }, false},
		{"empty", func([]byte) []byte { return nil }, false},
		{"no_long_bit", func(p []byte) []byte { p[0] &= 0x7f; return p }, false},
		{"no_fixed_bit", func(p []byte) []byte { p[0] &= 0xbf; return p }, false},
		{"handshake_type", func(p []byte) []byte { p[0] = 0xe0; return p }, false},
		{"v2_type_bits_wrong", func(p []byte) []byte {
			binary.BigEndian.PutUint32(p[1:5], quicVer2)
			return p // type bits still 0, but v2 numbers Initial as 1
		}, false},
		{"v2_ok", func(p []byte) []byte {
			binary.BigEndian.PutUint32(p[1:5], quicVer2)
			p[0] = 0xd0 // type bits = 1
			return p
		}, true},
		{"draft29_ok", func(p []byte) []byte {
			binary.BigEndian.PutUint32(p[1:5], quicVerDraft29)
			return p
		}, true},
		{"unknown_version", func(p []byte) []byte {
			binary.BigEndian.PutUint32(p[1:5], 0x0a0a0a0a)
			return p
		}, false},
		{"dcid_too_long", func(p []byte) []byte { p[5] = 21; return p }, false},
		{"dcid_past_end", func(p []byte) []byte { p[5] = 20; return p[:12] }, false},
		{"scid_too_long", func(p []byte) []byte { p[6] = 21; return p }, false},
		{"token_past_end", func(p []byte) []byte { p[7] = 0x3f; return p }, false},
		{"length_past_end", func(p []byte) []byte { p[8], p[9] = 0x7f, 0xff; return p }, false},
		{"length_too_small", func(p []byte) []byte { p[8], p[9] = 0x40, 0x10; return p }, false},
		{"truncated_payload", func(p []byte) []byte { return p[:len(p)-1] }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsQUICInitial(tc.mut(base())); got != tc.want {
				t.Fatalf("IsQUICInitial = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestQUICSNI(t *testing.T) {
	tests := []struct {
		file string
		host string
		ok   bool
	}{
		{l7fakeGoogleQUIC, "www.google.com", true},
		{l7fakeSteamQUIC, "steamcommunity.com", true},
		{l7fake4pdaQUIC, "4pda.to", true},
		// Same bytes as quic_initial_4pda.to.bin, hence the same SNI.
		{l7fakeDbankQUIC, "4pda.to", true},
		{l7fakeDiscordUDP, "steamcommunity.com", true},
		{l7fakeGameUDP, "4pda.to", true},
		{l7fakeTencentQUIC, "", false},
		{l7fakeSTUN, "", false},
		{l7fakeTLSGoogle, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			host, ok := QUICSNI(l7readFake(t, tc.file))
			if host != tc.host || ok != tc.ok {
				t.Fatalf("QUICSNI(%s) = (%q,%v), want (%q,%v)", tc.file, host, ok, tc.host, tc.ok)
			}
		})
	}
}

func TestQUICSNIDoesNotModifyPayload(t *testing.T) {
	// The engine hands us a slice aliasing the live packet buffer.
	for _, f := range []string{l7fakeGoogleQUIC, l7fake4pdaQUIC, l7fakeTencentQUIC} {
		p := l7readFake(t, f)
		orig := bytes.Clone(p)
		QUICSNI(p)
		Classify(p, 443, IPProtoUDP)
		if !bytes.Equal(p, orig) {
			t.Fatalf("%s: payload was modified", f)
		}
	}
}

// buildQUICInitial re-encrypts a handshake stream as a client Initial of the
// given version, so the v2 and draft-29 key schedules get exercised without a
// real capture of them.
func buildQUICInitial(t *testing.T, ver uint32, dcid, hs []byte, total int) []byte {
	t.Helper()

	// One CRYPTO frame at stream offset 0; 4-byte varint for the length keeps the
	// header size arithmetic below independent of the handshake size.
	frame := make([]byte, 0, 6+len(hs))
	frame = append(frame, 0x06, 0x00)
	frame = append(frame, byte(0x80|len(hs)>>24), byte(len(hs)>>16), byte(len(hs)>>8), byte(len(hs)))
	frame = append(frame, hs...)

	hdrLen := 1 + 4 + 1 + len(dcid) + 1 + 1 + 2 // flags, ver, dcid, scid, token, length
	const pnLen = 1
	plainLen := total - hdrLen - pnLen - quicTagLen
	if plainLen < len(frame) {
		t.Fatalf("total %d too small for %d handshake bytes", total, len(hs))
	}
	plain := make([]byte, plainLen)
	copy(plain, frame) // the remainder stays zero: PADDING frames

	typeBits, ok := quicInitialTypeBits(ver)
	if !ok {
		t.Fatalf("unknown version %#08x", ver)
	}
	hdr := make([]byte, 0, hdrLen)
	hdr = append(hdr, 0xc0|typeBits<<4|(pnLen-1))
	hdr = binary.BigEndian.AppendUint32(hdr, ver)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00) // zero-length SCID
	hdr = append(hdr, 0x00) // zero-length token
	length := pnLen + plainLen + quicTagLen
	hdr = append(hdr, 0x40|byte(length>>8), byte(length))
	if len(hdr) != hdrLen {
		t.Fatalf("header length %d != computed %d", len(hdr), hdrLen)
	}

	hp, key, iv, ok := quicInitialKeys(ver, dcid)
	if !ok {
		t.Fatal("key derivation failed")
	}
	aad := append(bytes.Clone(hdr), 0x00) // packet number 0
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatal(err)
	}
	pkt := append(bytes.Clone(aad), aead.Seal(nil, iv, plain, aad)...)
	if len(pkt) != total {
		t.Fatalf("built %d bytes, want %d", len(pkt), total)
	}

	// Apply header protection the same way a client would.
	pnOff := hdrLen
	hpBlk, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	var mask [aes.BlockSize]byte
	hpBlk.Encrypt(mask[:], pkt[pnOff+4:pnOff+4+quicSampleLen])
	pkt[0] ^= mask[0] & 0x0f
	pkt[pnOff] ^= mask[1]
	return pkt
}

func TestQUICSNIVersions(t *testing.T) {
	// Take a real handshake out of the google capture and re-wrap it.
	plain, ok := quicDecryptInitial(l7readFake(t, l7fakeGoogleQUIC))
	if !ok {
		t.Fatal("cannot decrypt the reference capture")
	}
	hs, ok := quicCryptoStream(plain)
	if !ok {
		t.Fatal("no CRYPTO frames in the reference capture")
	}

	for _, tc := range []struct {
		name string
		ver  uint32
	}{
		{"v1", quicVer1},
		{"v2", quicVer2},
		{"draft29", quicVerDraft29},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := buildQUICInitial(t, tc.ver, []byte{1, 2, 3, 4, 5, 6, 7, 8}, hs, 1200)
			if !IsQUICInitial(pkt) {
				t.Fatal("rebuilt packet not recognised as Initial")
			}
			host, ok := QUICSNI(pkt)
			if !ok || host != "www.google.com" {
				t.Fatalf("QUICSNI = (%q,%v), want (\"www.google.com\",true)", host, ok)
			}
			if info := Classify(pkt, 443, IPProtoUDP); info.Proto != L7QUIC || info.Host != "www.google.com" {
				t.Fatalf("Classify = %+v, want QUIC/www.google.com", info)
			}
		})
	}

	t.Run("tampered_ciphertext", func(t *testing.T) {
		// The AEAD tag no longer matches; the lenient CTR path still recovers the
		// plaintext, exactly like zapret's quic.c, so the SNI survives.
		pkt := buildQUICInitial(t, quicVer1, []byte{9, 9, 9, 9}, hs, 1200)
		pkt[len(pkt)-1] ^= 0xff
		if host, ok := QUICSNI(pkt); !ok || host != "www.google.com" {
			t.Fatalf("QUICSNI = (%q,%v), want the hostname despite a bad tag", host, ok)
		}
	})

	t.Run("garbled_payload", func(t *testing.T) {
		// Random ciphertext must not yield a hostname.
		pkt := buildQUICInitial(t, quicVer1, []byte{8, 7, 6, 5}, hs, 1200)
		for i := 20; i < len(pkt); i++ {
			pkt[i] = byte(i * 7)
		}
		if host, ok := QUICSNI(pkt); ok {
			t.Fatalf("QUICSNI = (%q,true), want failure", host)
		}
	})
}

func TestQUICCryptoStream(t *testing.T) {
	// Frame-level reassembly: offsets are honoured, PADDING/PING/ACK are skipped
	// and only the contiguous prefix from offset 0 is returned.
	crypto := func(off int, data string) []byte {
		f := []byte{0x06}
		f = append(f, 0x40|byte(off>>8), byte(off)) // 2-byte varint offset
		f = append(f, 0x40|byte(len(data)>>8), byte(len(data)))
		return append(f, data...)
	}
	tests := []struct {
		name string
		in   []byte
		want string
		ok   bool
	}{
		{"single", crypto(0, "hello"), "hello", true},
		{"padding_then_crypto", append([]byte{0x00, 0x00, 0x01}, crypto(0, "abc")...), "abc", true},
		{"two_in_order", append(crypto(0, "abc"), crypto(3, "def")...), "abcdef", true},
		{"out_of_order", append(crypto(3, "def"), crypto(0, "abc")...), "abcdef", true},
		{"gap_dropped", append(crypto(0, "abc"), crypto(9, "xyz")...), "abc", true},
		{"missing_head", crypto(4, "abc"), "", false},
		{"unknown_frame_stops", append(crypto(0, "abc"), 0x1c, 0x00), "abc", true},
		{"unknown_frame_first", append([]byte{0x1c}, crypto(0, "abc")...), "", false},
		{"ack_then_crypto", append([]byte{0x02, 0x00, 0x00, 0x00, 0x00}, crypto(0, "abc")...), "abc", true},
		{"ack_ecn_then_crypto", append([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, crypto(0, "abc")...), "abc", true},
		{"ack_with_ranges", append([]byte{0x02, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00}, crypto(0, "abc")...), "abc", true},
		{"truncated_crypto_len", []byte{0x06, 0x00, 0x40}, "", false},
		{"crypto_len_past_end", []byte{0x06, 0x00, 0x41, 0x00, 'a'}, "", false},
		{"empty", nil, "", false},
		{"all_padding", make([]byte, 32), "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := quicCryptoStream(tc.in)
			if ok != tc.ok || string(got) != tc.want {
				t.Fatalf("quicCryptoStream = (%q,%v), want (%q,%v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestIsSTUN(t *testing.T) {
	stun := l7readFake(t, l7fakeSTUN)
	stun2 := l7readFake(t, l7fakeSTUN2)
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"stun.bin", stun, true},
		{"stun2.bin", stun2, true},
		{"quic", l7readFake(t, l7fakeGoogleQUIC), false},
		{"short", stun[:19], false},
		{"truncated_body", stun[:60], false},
		{"header_only_zero_len", []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42,
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, true},
		{"trailing_bytes_ok", append(bytes.Clone(stun), 0, 0, 0, 0), true},
		{"high_bits_set", func() []byte { b := bytes.Clone(stun); b[0] = 0x40; return b }(), false},
		{"bad_cookie", func() []byte { b := bytes.Clone(stun); b[5] ^= 0xff; return b }(), false},
		{"length_not_multiple_of_4", func() []byte { b := bytes.Clone(stun); b[3]++; return b }(), false},
		{"length_beyond_datagram", func() []byte { b := bytes.Clone(stun); b[2] = 0xff; return b }(), false},
		{"empty", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsSTUN(tc.in); got != tc.want {
				t.Fatalf("IsSTUN = %v, want %v", got, tc.want)
			}
		})
	}
}

// l7discordIPDiscovery builds a well-formed Discord voice IP-discovery datagram.
func l7discordIPDiscovery(msgType, bodyLen uint16) []byte {
	p := make([]byte, discordIPDiscoveryLen)
	binary.BigEndian.PutUint16(p[0:2], msgType)
	binary.BigEndian.PutUint16(p[2:4], bodyLen)
	binary.BigEndian.PutUint32(p[4:8], 0x12345678) // SSRC
	copy(p[8:], "192.168.1.10")                    // address field, NUL padded
	binary.BigEndian.PutUint16(p[72:74], 50001)    // port
	return p
}

func TestIsDiscordIPDiscovery(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"request", l7discordIPDiscovery(1, 70), true},
		{"response", l7discordIPDiscovery(2, 70), true},
		{"wrong_type", l7discordIPDiscovery(3, 70), false},
		{"zero_type", l7discordIPDiscovery(0, 70), false},
		{"wrong_body_len", l7discordIPDiscovery(1, 64), false},
		{"too_short", l7discordIPDiscovery(1, 70)[:73], false},
		{"too_long", append(l7discordIPDiscovery(1, 70), 0), false},
		{"empty", nil, false},
		{"quic", l7readFake(t, l7fakeDiscordUDP), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsDiscordIPDiscovery(tc.in); got != tc.want {
				t.Fatalf("IsDiscordIPDiscovery = %v, want %v", got, tc.want)
			}
		})
	}
}

// l7wgMsg builds a WireGuard message of the given type and total size.
func l7wgMsg(msgType byte, n int) []byte {
	p := make([]byte, n)
	if n > 0 {
		p[0] = msgType
	}
	for i := 4; i < n; i++ {
		p[i] = byte(i)
	}
	return p
}

func TestIsWireGuard(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"initiation", l7wgMsg(1, 148), true},
		{"response", l7wgMsg(2, 92), true},
		{"data_keepalive", l7wgMsg(4, 32), true},
		{"data_payload", l7wgMsg(4, 32+16*5), true},
		{"initiation_wrong_len", l7wgMsg(1, 147), false},
		{"response_wrong_len", l7wgMsg(2, 148), false},
		{"data_unaligned", l7wgMsg(4, 33), false},
		{"data_too_short", l7wgMsg(4, 16), false},
		{"cookie_reply_not_matched", l7wgMsg(3, 64), false},
		{"reserved_nonzero", func() []byte { p := l7wgMsg(1, 148); p[2] = 1; return p }(), false},
		{"unknown_type", l7wgMsg(5, 148), false},
		{"short", l7wgMsg(1, 3), false},
		{"empty", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsWireGuard(tc.in); got != tc.want {
				t.Fatalf("IsWireGuard = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsDHT(t *testing.T) {
	id := bytes.Repeat([]byte{0xab}, 20)
	query := append([]byte("d1:ad2:id20:"), id...)
	resp := append([]byte("d1:rd2:id20:"), id...)
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"query", append(bytes.Clone(query), []byte("e1:q9:find_node1:y1:qe")...), true},
		{"response", append(bytes.Clone(resp), []byte("e1:t2:aa1:y1:re")...), true},
		{"exact_prefix_and_id", query, true},
		{"id_truncated", query[:len(query)-1], false},
		{"prefix_only", []byte("d1:ad2:id20:"), false},
		{"wrong_prefix", append([]byte("d1:xd2:id20:"), id...), false},
		{"empty", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsDHT(tc.in); got != tc.want {
				t.Fatalf("IsDHT = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClassifyUDP(t *testing.T) {
	id := bytes.Repeat([]byte{0x11}, 20)
	tests := []struct {
		name  string
		in    []byte
		proto L7
		host  string
	}{
		{l7fakeGoogleQUIC, l7readFake(t, l7fakeGoogleQUIC), L7QUIC, "www.google.com"},
		{l7fakeSteamQUIC, l7readFake(t, l7fakeSteamQUIC), L7QUIC, "steamcommunity.com"},
		{l7fake4pdaQUIC, l7readFake(t, l7fake4pdaQUIC), L7QUIC, "4pda.to"},
		{l7fakeDbankQUIC, l7readFake(t, l7fakeDbankQUIC), L7QUIC, "4pda.to"},
		{l7fakeDiscordUDP, l7readFake(t, l7fakeDiscordUDP), L7QUIC, "steamcommunity.com"},
		{l7fakeGameUDP, l7readFake(t, l7fakeGameUDP), L7QUIC, "4pda.to"},
		// Random 1231-byte blob: no known QUIC version, nothing else matches.
		{l7fakeTencentQUIC, l7readFake(t, l7fakeTencentQUIC), L7Unknown, ""},
		{l7fakeSTUN, l7readFake(t, l7fakeSTUN), L7STUN, ""},
		{l7fakeSTUN2, l7readFake(t, l7fakeSTUN2), L7STUN, ""},
		{"discord_ip_discovery", l7discordIPDiscovery(1, 70), L7Discord, ""},
		{"wireguard_initiation", l7wgMsg(1, 148), L7WireGuard, ""},
		{"dht_query", append([]byte("d1:ad2:id20:"), id...), L7DHT, ""},
		{"empty", nil, L7Unknown, ""},
		{"garbage", []byte{0xde, 0xad, 0xbe, 0xef}, L7Unknown, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.in, 443, IPProtoUDP)
			if got.Proto != tc.proto || got.Host != tc.host {
				t.Fatalf("Classify = {%v %q}, want {%v %q}", got.Proto, got.Host, tc.proto, tc.host)
			}
		})
	}
}

func TestClassifyTCP(t *testing.T) {
	// The TCP recognisers live in tls.go / http.go; this only checks that
	// Classify routes to them and hands their result back untouched.
	tests := []struct {
		name  string
		in    []byte
		proto L7
		host  string
	}{
		{l7fakeTLSGoogle, l7readFake(t, l7fakeTLSGoogle), L7TLS, "www.google.com"},
		{l7fakeTLS4pda, l7readFake(t, l7fakeTLS4pda), L7TLS, "4pda.to"},
		// The blob's SNI extension really says www.onetrust.com, whatever its
		// file name claims (same kind of mislabelling as the QUIC fakes).
		{l7fakeTLSMax, l7readFake(t, l7fakeTLSMax), L7TLS, "www.onetrust.com"},
		{"http_get", []byte("GET / HTTP/1.1\r\nHost: example.org\r\nAccept: */*\r\n\r\n"), L7HTTP, "example.org"},
		{"empty", nil, L7Unknown, ""},
		{"garbage", []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, L7Unknown, ""},
		// A QUIC Initial arriving on TCP must not be taken for QUIC.
		{"quic_over_tcp", l7readFake(t, l7fakeGoogleQUIC), L7Unknown, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.in, 443, IPProtoTCP)
			if got.Proto != tc.proto || got.Host != tc.host {
				t.Fatalf("Classify = {%v %q}, want {%v %q}", got.Proto, got.Host, tc.proto, tc.host)
			}
		})
	}
}

func TestClassifyOtherProto(t *testing.T) {
	// Only TCP and UDP payloads are classified.
	for _, ipproto := range []uint8{IPProtoICMP, IPProtoICMPv6, IPProtoHopOpt, 0xff} {
		if got := Classify(l7readFake(t, l7fakeGoogleQUIC), 443, ipproto); got.Proto != L7Unknown {
			t.Fatalf("Classify(ipproto=%d) = %v, want L7Unknown", ipproto, got.Proto)
		}
	}
}

// l7prefixLengths returns the prefix sizes worth probing for a blob: every byte
// near the start (where the headers are) and a coarse sweep after that.
func l7prefixLengths(n int) []int {
	var out []int
	for i := 0; i <= n && i < 80; i++ {
		out = append(out, i)
	}
	for i := 80; i < n; i += 13 {
		out = append(out, i)
	}
	return out
}

func TestTruncatedPrefixes(t *testing.T) {
	// Every truncated prefix of every real blob must be parsed without panicking
	// and must never be claimed as a protocol it is not: a QUIC Initial whose
	// declared Length does not fit in the datagram is not a QUIC Initial.
	tests := []struct {
		file string
		full L7
	}{
		{l7fakeGoogleQUIC, L7QUIC},
		{l7fakeSteamQUIC, L7QUIC},
		{l7fake4pdaQUIC, L7QUIC},
		{l7fakeDbankQUIC, L7QUIC},
		{l7fakeDiscordUDP, L7QUIC},
		{l7fakeGameUDP, L7QUIC},
		{l7fakeTencentQUIC, L7Unknown},
		{l7fakeSTUN, L7STUN},
		{l7fakeSTUN2, L7STUN},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			blob := l7readFake(t, tc.file)
			for _, n := range l7prefixLengths(len(blob)) {
				p := blob[:n:n] // cap the slice: a bug reading past n must not hide
				// None of the recognisers may panic on a partial datagram.
				if IsQUICInitial(p) {
					t.Fatalf("prefix %d: IsQUICInitial true, want false", n)
				}
				if host, ok := QUICSNI(p); ok {
					t.Fatalf("prefix %d: QUICSNI returned %q", n, host)
				}
				got := Classify(p, 443, IPProtoUDP)
				if got.Proto != L7Unknown {
					t.Fatalf("prefix %d: Classify = %v, want L7Unknown", n, got.Proto)
				}
				// The TCP path must survive the same input.
				Classify(p, 443, IPProtoTCP)
			}
			if got := Classify(blob, 443, IPProtoUDP); got.Proto != tc.full {
				t.Fatalf("full blob: Classify = %v, want %v", got.Proto, tc.full)
			}
		})
	}
}

func TestTruncatedTLSPrefixesDoNotPanic(t *testing.T) {
	for _, f := range []string{l7fakeTLSGoogle, l7fakeTLS4pda, l7fakeTLSMax} {
		blob := l7readFake(t, f)
		for _, n := range l7prefixLengths(len(blob)) {
			p := blob[:n:n]
			Classify(p, 443, IPProtoTCP)
			Classify(p, 443, IPProtoUDP)
		}
	}
}

func TestQUICKeyDerivationVector(t *testing.T) {
	// RFC 9001 Appendix A.1: DCID 0x8394c8f03e515708 yields these client Initial
	// keys. This pins HKDF-Expand-Label, the label spellings and the v1 salt.
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	hp, key, iv, ok := quicInitialKeys(quicVer1, dcid)
	if !ok {
		t.Fatal("quicInitialKeys failed")
	}
	want := map[string]string{
		"key": "1f369613dd76d5467730efcbe3b1a22d",
		"iv":  "fa044b2f42a3fd3b46fb255c",
		"hp":  "9f50449e04a0e810283a1e9933adedd2",
	}
	for name, got := range map[string][]byte{"key": key, "iv": iv, "hp": hp} {
		if h := l7hex(got); h != want[name] {
			t.Fatalf("%s = %s, want %s", name, h, want[name])
		}
	}
}

func l7hex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
