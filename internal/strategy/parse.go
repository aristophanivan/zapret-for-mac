package strategy

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// Defaults and bounds ported verbatim from zapret's nfq/params.h + nfq/desync.h.
// They are the numbers winws itself uses, so a converted flowseal strategy that
// omits an option behaves exactly as it did on Windows.
const (
	// autoTTLDefault* are AUTOTTL_DEFAULT_DESYNC_DELTA/MIN/MAX.
	autoTTLDefaultDelta = -1
	autoTTLDefaultMin   = 3
	autoTTLDefaultMax   = 20

	// maxSplits is MAX_SPLITS: nfqws stores at most this many split positions.
	maxSplits = 64

	// maxFakeLen is max(FAKE_MAX_TCP=1460, FAKE_MAX_UDP=1472): the largest fake
	// blob nfqws will keep. It truncates silently; we refuse instead (see
	// LoadFake) because a silently halved ClientHello is not a fake at all.
	maxFakeLen = 1472

	// maxSeqovl is DPI_DESYNC_MAX_FAKE_LEN + 100, the size of nfqws' overlap
	// scratch buffer (desync.c: uint8_t ovlseg[DPI_DESYNC_MAX_FAKE_LEN + 100]).
	maxSeqovl = 9216 + 100

	// maxRepeats is nfqws' bound on --dpi-desync-repeats (1..1024).
	maxRepeats = 1024

	// udpLenIncrementDefault is UDPLEN_INCREMENT_DEFAULT.
	udpLenIncrementDefault = 2

	// ipFragPos*Default are IPFRAG_TCP_DEFAULT / IPFRAG_UDP_DEFAULT.
	ipFragPosTCPDefault = 32
	ipFragPosUDPDefault = 8

	// maxIPFragPos is DPI_DESYNC_MAX_FAKE_LEN, the bound nfqws puts on
	// --dpi-desync-ipfrag-pos-tcp/-udp.
	maxIPFragPos = 9216

	// posMin/posMax are the int16 range nfqws' parse_int16 accepts for a split
	// position or offset.
	posMin = -32768
	posMax = 32767
)

// ParsePortSet compiles port entries — winws' --wf-tcp / --wf-udp / --filter-tcp
// / --filter-udp values — into a PortSet.
//
// Grammar is nfqws' pf_parse (nfq/helpers.c): "443", "19294-19344", or "*" for
// every port (1-65535, port 0 excluded exactly as pf_in_range excludes it). Each
// entry may itself be a comma-separated list, so a converted .bat line can be
// dropped in as one string; blank entries are ignored so a trailing comma from a
// batch variable that expanded to nothing is harmless.
//
// Ranges are sorted and merged, which changes nothing about membership but lets a
// transport emit one pf rule per range.
//
// Two nfqws spellings are deliberately refused instead of being approximated,
// because PortSet has no way to say them: the "~" negation prefix and the
// deny-all "0". Both return an error telling the caller what to write instead.
func ParsePortSet(entries []string) (PortSet, error) {
	var out PortSet
	for _, entry := range entries {
		for _, tok := range strings.Split(entry, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if tok == "*" || strings.EqualFold(tok, "any") {
				out = append(out, PortRange{Lo: 1, Hi: 65535})
				continue
			}
			if strings.HasPrefix(tok, "~") {
				return nil, fmt.Errorf("port filter %q: a negated (~) port filter cannot be compiled; list the ports you do want instead", tok)
			}
			if lo, hi, isRange := strings.Cut(tok, "-"); isRange {
				l, err := parsePort(lo, tok)
				if err != nil {
					return nil, err
				}
				h, err := parsePort(hi, tok)
				if err != nil {
					return nil, err
				}
				if l > h {
					return nil, fmt.Errorf("port range %q: low port %d is above high port %d; write it as %d-%d", tok, l, h, h, l)
				}
				out = append(out, PortRange{Lo: l, Hi: h})
				continue
			}
			p, err := parsePort(tok, tok)
			if err != nil {
				return nil, err
			}
			out = append(out, PortRange{Lo: p, Hi: p})
		}
	}
	return mergePorts(out), nil
}

// parsePort parses one port number. ctx is the whole entry, quoted in the error.
func parsePort(s, ctx string) (uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("port filter %q: missing port number; write it as \"443\" or \"19294-19344\"", ctx)
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("port filter %q: %q is not a port number; write a decimal 1..65535", ctx, s)
	}
	if v == 0 {
		return 0, fmt.Errorf("port filter %q: port 0 is not usable (nfqws reads it as deny-all); drop the entry or use \"*\"", ctx)
	}
	if v > 65535 {
		return 0, fmt.Errorf("port filter %q: port %d is above 65535; use a port in 1..65535", ctx, v)
	}
	return uint16(v), nil
}

// mergePorts sorts ranges and coalesces overlapping or adjacent ones.
func mergePorts(in PortSet) PortSet {
	if len(in) < 2 {
		return in
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].Lo != in[j].Lo {
			return in[i].Lo < in[j].Lo
		}
		return in[i].Hi < in[j].Hi
	})
	out := in[:1]
	for _, r := range in[1:] {
		last := &out[len(out)-1]
		// int arithmetic: Hi+1 would wrap for the 65535 range.
		if int(r.Lo) <= int(last.Hi)+1 {
			if r.Hi > last.Hi {
				last.Hi = r.Hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// ParseCounter compiles a --dpi-desync-start / --dpi-desync-cutoff value.
//
// Port of nfqws' parse_cutoff: an optional leading kind letter — 'n' packet
// number, 'd' data-packet number, 's' relative sequence number — followed by an
// unsigned decimal; a bare number means 'n'. An empty string means "no bound"
// and yields the zero Counter, which the engine reads as "always in window".
//
// Unlike nfqws (which uses sscanf and so accepts "3junk") trailing garbage is
// rejected, so a typo fails at load instead of silently changing the bound.
func ParseCounter(s string) (Counter, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Counter{}, nil
	}
	kind := byte('n')
	switch s[0] {
	case 'n', 'd', 's':
		kind, s = s[0], s[1:]
	case 'N', 'D', 'S':
		kind, s = s[0]+('a'-'A'), s[1:]
	}
	if s == "" {
		return Counter{}, fmt.Errorf("counter %q: missing number after the kind letter; write \"n3\" (3rd packet), \"d2\" (2nd data packet) or \"s5000\" (5000 bytes into the stream)", s)
	}
	v, err := strconv.ParseUint(s, 10, 31)
	if err != nil {
		return Counter{}, fmt.Errorf("counter %q: not a number; write \"n3\", \"d2\" or \"s5000\"", s)
	}
	return Counter{Kind: kind, N: int(v)}, nil
}

// ParseTTLSpec compiles the TOML `ttl` field of an op into either a fixed TTL or
// an autottl rule.
//
// Grammar:
//
//	""             no TTL override (everything zero)
//	"5"            fixed TTL 5
//	"auto"         autottl with zapret's --dpi-desync-autottl defaults: delta -1, min 3, max 20
//	"auto:-1:3-20" explicit delta, min and max
//	"hops:-2"      "hops" is a synonym of "auto": delta -2, default clamps
//	"auto:-"       autottl explicitly disabled (nfqws spells this "-")
//
// The part after the colon is nfqws' parse_autottl grammar
// ([+|-]delta[:min[-max]]) and is ported exactly, including the surprise that
// the sign defaults to *negative*: "auto:2" is delta -2, "auto:+2" is delta +2.
// The clamp checks are nfqws': a non-zero delta with a zero min or max is an
// error, min must not exceed max, and delta must be within 0..127.
func ParseTTLSpec(s string) (ttl uint8, auto bool, delta int8, min, max uint8, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false, 0, 0, 0, nil
	}
	head, rest, hasRest := strings.Cut(s, ":")
	switch strings.ToLower(strings.TrimSpace(head)) {
	case "auto", "hops":
		if !hasRest {
			rest = ""
		}
		return parseAutoTTL(s, strings.TrimSpace(rest))
	}
	if hasRest {
		return 0, false, 0, 0, 0, fmt.Errorf("ttl %q: only \"auto\"/\"hops\" take a \":\" suffix; write \"5\", \"auto\" or \"auto:-1:3-20\"", s)
	}
	v, e := strconv.ParseUint(s, 10, 32)
	if e != nil {
		return 0, false, 0, 0, 0, fmt.Errorf("ttl %q: not a TTL; write a number 0..255, \"auto\", or \"auto:-1:3-20\"", s)
	}
	if v > 255 {
		return 0, false, 0, 0, 0, fmt.Errorf("ttl %q: %d is above 255; a TTL is one byte", s, v)
	}
	return uint8(v), false, 0, 0, 0, nil
}

// parseAutoTTL ports nfqws' parse_autottl. spec is the text after "auto:"/"hops:";
// whole is the original string, quoted in errors.
func parseAutoTTL(whole, spec string) (ttl uint8, auto bool, delta int8, min, max uint8, err error) {
	d, mn, mx := int8(autoTTLDefaultDelta), uint8(autoTTLDefaultMin), uint8(autoTTLDefaultMax)
	if spec == "" {
		return 0, true, d, mn, mx, nil
	}
	// nfqws: "-" alone disables autottl entirely.
	if spec == "-" {
		return 0, false, 0, 0, 0, nil
	}
	neg := true
	switch spec[0] {
	case '+':
		neg, spec = false, spec[1:]
	case '-':
		spec = spec[1:]
	}
	deltaStr, clamp, hasClamp := strings.Cut(spec, ":")
	dv, e := strconv.ParseUint(strings.TrimSpace(deltaStr), 10, 32)
	if e != nil {
		return 0, false, 0, 0, 0, fmt.Errorf("ttl %q: %q is not a hop delta; write \"auto:-1\" or \"auto:-1:3-20\"", whole, deltaStr)
	}
	if dv > 127 {
		return 0, false, 0, 0, 0, fmt.Errorf("ttl %q: hop delta %d is above 127; nfqws stores it in a signed byte", whole, dv)
	}
	if neg {
		d = -int8(dv)
	} else {
		d = int8(dv)
	}
	if hasClamp {
		minStr, maxStr, hasMax := strings.Cut(clamp, "-")
		if hasMax {
			v, e := strconv.ParseUint(strings.TrimSpace(maxStr), 10, 32)
			if e != nil || v > 255 {
				return 0, false, 0, 0, 0, fmt.Errorf("ttl %q: %q is not a max TTL; write \"auto:-1:3-20\"", whole, maxStr)
			}
			if d != 0 && v == 0 {
				return 0, false, 0, 0, 0, fmt.Errorf("ttl %q: max TTL 0 with a non-zero delta clamps every fake to nothing; use \"auto:%d:%d-20\"", whole, d, autoTTLDefaultMin)
			}
			mx = uint8(v)
		}
		v, e := strconv.ParseUint(strings.TrimSpace(minStr), 10, 32)
		if e != nil || v > 255 {
			return 0, false, 0, 0, 0, fmt.Errorf("ttl %q: %q is not a min TTL; write \"auto:-1:3-20\"", whole, minStr)
		}
		if d != 0 && v == 0 {
			return 0, false, 0, 0, 0, fmt.Errorf("ttl %q: min TTL 0 with a non-zero delta is rejected by nfqws; use at least 1 (default %d)", whole, autoTTLDefaultMin)
		}
		if uint8(v) > mx {
			return 0, false, 0, 0, 0, fmt.Errorf("ttl %q: min TTL %d is above max TTL %d; write them as min-max", whole, v, mx)
		}
		mn = uint8(v)
	}
	return 0, true, d, mn, mx, nil
}

// ParseSplitPos compiles --dpi-desync-split-pos entries into PosSpecs.
//
// Grammar is nfqws' parse_split_pos_list / parse_split_pos / parse_posmarker:
// either a signed absolute byte position, or one of the markers method, host,
// endhost, sld, endsld, midsld, sniext with an optional signed offset. Every
// entry may carry a comma-separated list, so "2,sniext+1" is two positions.
//
// Ported exactly:
//   - an absolute 0 is rejected (nfqws' parse_split_pos returns !!pos), while a
//     marker with offset 0 ("midsld") is fine;
//   - a negative absolute position counts back from the end of the payload —
//     proto.FindSplitPos does that resolution;
//   - positions and offsets must fit in int16, nfqws' storage;
//   - at most MAX_SPLITS (64) positions.
//
// Deliberately stricter than nfqws: it parses with atoi, so "2x" silently means
// 2; here trailing garbage is an error.
func ParseSplitPos(entries []string) ([]desync.PosSpec, error) {
	var out []desync.PosSpec
	for _, entry := range entries {
		for _, tok := range strings.Split(entry, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if len(out) == maxSplits {
				return nil, fmt.Errorf("split position %q: more than %d positions; nfqws keeps at most MAX_SPLITS=%d, drop the extras", tok, maxSplits, maxSplits)
			}
			ps, err := parseOnePos(tok)
			if err != nil {
				return nil, err
			}
			out = append(out, ps)
		}
	}
	return out, nil
}

// parseOnePos parses a single split-position token.
func parseOnePos(tok string) (desync.PosSpec, error) {
	if c := tok[0]; c == '+' || c == '-' || (c >= '0' && c <= '9') {
		n, err := parsePosInt(tok, tok)
		if err != nil {
			return desync.PosSpec{}, err
		}
		if n == 0 {
			return desync.PosSpec{}, fmt.Errorf("split position %q: 0 is not a split position (nfqws rejects it); use 1 to split after the first byte", tok)
		}
		return desync.PosSpec{Marker: proto.MarkerAbs, Offset: n}, nil
	}
	// A marker name runs up to the first sign, which starts its offset.
	cut := len(tok)
	for i := 0; i < len(tok); i++ {
		if tok[i] == '+' || tok[i] == '-' {
			cut = i
			break
		}
	}
	name, offStr := tok[:cut], tok[cut:]
	m, ok := proto.MarkerNames[strings.ToLower(name)]
	if !ok {
		return desync.PosSpec{}, fmt.Errorf("split position %q: unknown marker %q; use one of %s, or a plain number", tok, name, markerList())
	}
	if offStr == "" {
		return desync.PosSpec{Marker: m, Offset: 0}, nil
	}
	n, err := parsePosInt(offStr, tok)
	if err != nil {
		return desync.PosSpec{}, err
	}
	return desync.PosSpec{Marker: m, Offset: n}, nil
}

// parsePosInt parses a signed int16 position or offset. ctx is quoted in errors.
func parsePosInt(s, ctx string) (int, error) {
	v, err := strconv.ParseInt(strings.TrimPrefix(s, "+"), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("split position %q: %q is not a signed number; write e.g. \"2\", \"-1\", \"sniext+1\"", ctx, s)
	}
	if v < posMin || v > posMax {
		return 0, fmt.Errorf("split position %q: %d is outside nfqws' int16 range %d..%d", ctx, v, posMin, posMax)
	}
	return int(v), nil
}

// markerList is the sorted marker vocabulary, for error messages.
func markerList() string {
	names := make([]string, 0, len(proto.MarkerNames))
	for n := range proto.MarkerNames {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// defaultFakeTLSHelloHex is zapret's built-in fake ClientHello — the 680-byte
// fake_tls_clienthello_default array from nfq/desync.c, SNI www.microsoft.com.
// It is what --dpi-desync-fake-tls=! selects, and flowseal's .bat files write
// that as "^!" because cmd.exe eats a bare '!' under delayed expansion.
const defaultFakeTLSHelloHex = "16030102a30100029f03034188822d4ffd81489ee790651fba057bffa75af95b" +
	"8a8f458b41f03d1bdde3f8209b23a5d2211e9fe7856cfc61803a3fbab960bab3" +
	"0e98276cf7382865805d40380022130113031302c02bc02fcca9cca8c02cc030" +
	"c00ac009c013c014009c009d002f003501000234000000160014000011777777" +
	"2e6d6963726f736f66742e636f6d00170000ff01000100000a000e000c001d00" +
	"170018001901000101000b00020100002300000010000e000c02683208687474" +
	"702f312e310005000501000000000022000a0008040305030603020300120000" +
	"0033006b0069001d0020691516296dadd56888272fdeafac3c4ca4e4d8c8fb41" +
	"87f4764e0efa64c4e9290017004104fe62b908c8c32ab9873784426b5ccdc9ca" +
	"6238d3d9998ac42dc6d0a360b21254418e525ee3abf9c20781dcf8f26a91402f" +
	"cba4ff6f24c74d77772d6fe077aa92002b00050403040303000d001800160403" +
	"0503060308040805080604010501060102030201002d00020101001c00024001" +
	"001b000706000100020003fe0d0119000001000321002062e883d897058abea1" +
	"f2634ece93848ecfe7ddb2e48706ac1119be0e7187f1a600efd86b275ec0a75d" +
	"424e8cdcf39f1c5162efff5bedc8fdee6fbb889bb1309c6642ab0f6689188b11" +
	"c16de72aeb963b7f5278dbf86d04f7951aa8f064520739f0a81d0d1636b7180e" +
	"c84427fef331f0de8c74f5a1d88f6f459769795e2ed4b02c0c1a6fccce90c7dd" +
	"c66095f3c219de5080bfdef22563152663091fc5df32f5ea9cd2ff994e67a2e5" +
	"1a9485e3df36a5834b0a1cafd748c94b8a27dd587f95f26bde2b12d3ec4d6937" +
	"9c139b16b04552387769efaa6519bcc2934db01b7f5b41ffafba5051c3f12709" +
	"25f5609009b1e5c0c74278543b23197d8e7213b4d3cd63b6c44a283d453e8bdb" +
	"844f78643069e21b"

// defaultFakeTLSHello is defaultFakeTLSHelloHex decoded once. The literal is a
// compile-time constant, so the error is structurally impossible; a test asserts
// the length and the leading record header rather than trusting that.
var defaultFakeTLSHello, _ = hex.DecodeString(defaultFakeTLSHelloHex)

// LoadFake resolves a fake-payload spec — the value of any of winws'
// --dpi-desync-fake-* / --dpi-desync-*-pattern options — into bytes.
//
// Accepted forms, all from nfqws' load_file_or_exit:
//
//	""              no payload (nil, nil)
//	"0xDEADBEEF"    inline hex bytes (an even number of hex digits)
//	"name.bin"      file resolved against dir (an absolute path is used as is)
//	"@name.bin"     same, nfqws' explicit file spelling
//	"+16@name.bin"  the file from byte 16 on
//	"!" / "^!"      zapret's built-in fake ClientHello (680 bytes, SNI
//	                www.microsoft.com), which is what --dpi-desync-fake-tls=!
//	                means: it is *not* "no fake". flowseal writes it "^!"
//	                because cmd.exe would otherwise eat the '!'.
//	"!+16"          the built-in hello from byte 16 on
//
// An offset is applied by dropping the leading bytes, which is exactly what
// nfqws does when it sends the blob (desync.c: fake_data = data + offset).
//
// A blob larger than max(FAKE_MAX_TCP, FAKE_MAX_UDP) is refused. nfqws truncates
// there instead; a half ClientHello would be a silently useless fake, so this
// asks the caller to trim the file on purpose.
func LoadFake(dir, spec string) ([]byte, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	// "^!" is the batch-escaped spelling of "!".
	if strings.HasPrefix(spec, "^!") {
		spec = spec[1:]
	}
	if spec[0] == '!' && (len(spec) == 1 || spec[1] == '+') {
		ofs := 0
		if len(spec) > 1 {
			v, err := strconv.Atoi(spec[2:])
			if err != nil || v < 0 {
				return nil, fmt.Errorf("fake %q: %q is not an offset; write \"!\" or \"!+16\"", spec, spec[2:])
			}
			ofs = v
		}
		if ofs >= len(defaultFakeTLSHello) {
			return nil, fmt.Errorf("fake %q: offset %d is past the end of the %d-byte built-in ClientHello; use a smaller offset", spec, ofs, len(defaultFakeTLSHello))
		}
		out := make([]byte, len(defaultFakeTLSHello)-ofs)
		copy(out, defaultFakeTLSHello[ofs:])
		return out, nil
	}
	if strings.HasPrefix(spec, "0x") || strings.HasPrefix(spec, "0X") {
		return parseHexBlob(spec)
	}

	name, ofs := spec, 0
	if name[0] == '+' {
		num, rest, ok := strings.Cut(name[1:], "@")
		if !ok {
			return nil, fmt.Errorf("fake %q: an offset needs a file after it; write \"+16@tls_clienthello_www_google_com.bin\"", spec)
		}
		v, err := strconv.Atoi(strings.TrimSpace(num))
		if err != nil || v < 0 {
			return nil, fmt.Errorf("fake %q: %q is not an offset; write \"+16@file.bin\"", spec, num)
		}
		name, ofs = rest, v
	} else if name[0] == '@' {
		name = name[1:]
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("fake %q: missing file name; name a .bin in the fakes directory or use an inline \"0x...\" literal", spec)
	}
	path := name
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("fake %q: %s does not exist; put the blob in %s or use an inline \"0x...\" literal", spec, path, fakesDirLabel(dir))
		}
		return nil, fmt.Errorf("fake %q: cannot read %s: %w; check the file's permissions", spec, path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("fake %q: %s is empty; nfqws refuses empty fakes, put real bytes in it or drop the option", spec, path)
	}
	if ofs >= len(data) {
		return nil, fmt.Errorf("fake %q: offset %d is past the end of the %d-byte %s; use an offset below %d", spec, ofs, len(data), path, len(data))
	}
	data = data[ofs:]
	if len(data) > maxFakeLen {
		return nil, fmt.Errorf("fake %q: %s is %d bytes, above nfqws' %d-byte fake limit (winws would truncate it); trim the file or use \"+N@%s\"", spec, path, len(data), maxFakeLen, name)
	}
	return data, nil
}

// parseHexBlob ports nfqws' parse_hex_str: whole bytes only, no separators.
func parseHexBlob(spec string) ([]byte, error) {
	digits := spec[2:]
	if digits == "" {
		return nil, fmt.Errorf("fake %q: no bytes after \"0x\"; write e.g. \"0x00000000\"", spec)
	}
	if len(digits)%2 != 0 {
		return nil, fmt.Errorf("fake %q: %d hex digits is not a whole number of bytes; pad it to an even length", spec, len(digits))
	}
	b, err := hex.DecodeString(digits)
	if err != nil {
		return nil, fmt.Errorf("fake %q: not hex; write only 0-9a-f after \"0x\"", spec)
	}
	if len(b) > maxFakeLen {
		return nil, fmt.Errorf("fake %q: %d bytes is above nfqws' %d-byte fake limit; shorten the literal", spec, len(b), maxFakeLen)
	}
	return b, nil
}

// fakesDirLabel names the fakes directory in an error, even when it is empty.
func fakesDirLabel(dir string) string {
	if dir == "" {
		return "the working directory"
	}
	return dir
}

// parseWSSize compiles a --wssize value, "N" or "N:scale" (nfqws'
// parse_ws_scale_factor). An empty string yields 0,0 = leave the window alone.
//
// size is the receive window to advertise and scale the window-scale shift the
// peer applies to it; --wssize-cutoff, which says how long the rewrite lasts, is
// a separate knob and arrives through the op's mod map (see compiler.opMod).
func parseWSSize(s string) (size, scale int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, nil
	}
	sizeStr, scaleStr, hasScale := strings.Cut(s, ":")
	v, e := strconv.ParseUint(strings.TrimSpace(sizeStr), 10, 32)
	if e != nil || v > 65535 {
		return 0, 0, fmt.Errorf("wssize %q: %q is not a window size; write \"128\" or \"128:6\"", s, sizeStr)
	}
	size = int(v)
	if hasScale {
		v, e := strconv.ParseUint(strings.TrimSpace(scaleStr), 10, 32)
		if e != nil || v > 255 {
			return 0, 0, fmt.Errorf("wssize %q: %q is not a window scale; write a number 0..255, e.g. \"128:6\"", s, scaleStr)
		}
		scale = int(v)
	}
	return size, scale, nil
}

// parseIPIDMode compiles the `mode` field of the ip_id pseudo-op, nfqws' --ip-id.
//
// Every spelling upstream has now maps onto a desync.IPIDMode of its own:
// "seqgroup" gives one identification per sequence group, so a decoy reuses the
// ip.id of the real part it stands in for (desync.SeqGroups documents the exact
// grouping), and "same" copies the intercepted packet's ip.id onto everything the
// plan emits. An empty value is "leave it to the transport" (IPIDDefault), which
// is what an op without an --ip-id gets.
func parseIPIDMode(s string) (desync.IPIDMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "default":
		return desync.IPIDDefault, nil
	case "zero":
		return desync.IPIDZero, nil
	case "seq":
		return desync.IPIDSeq, nil
	case "seqgroup":
		return desync.IPIDSeqGroup, nil
	case "same":
		return desync.IPIDSame, nil
	case "rnd", "random":
		return desync.IPIDRandom, nil
	}
	return 0, fmt.Errorf("ip_id mode %q: unknown; use zero, seq, seqgroup, same or random", s)
}

// parseMidHost compiles --dpi-desync-hostfakesplit-midhost, the extra cut inside
// the real hostname hostfakesplit can make.
//
// Upstream takes a position spec there, not a flag, but the spelling flowseal's
// .bat files use is the bare "1". Both are accepted:
//
//	"" "0" "false" "no" "off"      not set
//	"1" "true" "yes" "on"          the middle of the second-level domain (midsld)
//	"midsld+1" "sld+3" "endsld-2"  an explicit marker with an offset
//	"+120"                         an absolute position
//
// A bare "1" is therefore the flag, never absolute position 1; write "+1" for
// that. set is false only for the explicitly-off spellings, so a caller can tell
// "cut at absolute 0" (impossible, and rejected) from "no cut asked for".
func parseMidHost(s string) (spec desync.PosSpec, set bool, err error) {
	s = strings.TrimSpace(s)
	if b, e := parseBool(s); e == nil {
		if !b {
			return desync.PosSpec{}, false, nil
		}
		// nfqws' own midhost anchor: halfway through the second-level domain.
		return desync.PosSpec{Marker: proto.MarkerMidSLD}, true, nil
	}
	spec, err = parseOnePos(s)
	if err != nil {
		return desync.PosSpec{}, false, fmt.Errorf("is not a boolean and not a split position (%v); "+
			"use \"1\" to cut at the middle of the second-level domain, a spec such as \"midsld+1\", or drop the key", err)
	}
	return spec, true, nil
}

// digitRun matches one run of decimal digits inside a file name.
var digitRun = regexp.MustCompile(`[0-9]+`)

// nameSortKey is flowseal's strategy-list ordering, ported from service.bat:
//
//	Sort-Object { [Regex]::Replace($_.Name, '(\d+)', { $args[0].Value.PadLeft(8, '0') }) }
//
// Every digit run is left-padded with zeros to width 8 and the result is compared
// case-insensitively (PowerShell's default string sort), so "ALT2" sorts before
// "ALT10" instead of after it. Runs already 8 digits or longer are left alone,
// exactly as PadLeft does.
func nameSortKey(name string) string {
	return strings.ToLower(digitRun.ReplaceAllStringFunc(name, func(d string) string {
		if len(d) >= 8 {
			return d
		}
		return strings.Repeat("0", 8-len(d)) + d
	}))
}
