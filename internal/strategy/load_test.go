package strategy

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// The real repository directories: the tests compile against the lists and fake
// blobs the product actually ships, so a change to either shows up here.
const (
	repoLists = "../../lists"
	repoFakes = "../../fakes"
)

// fullOpts is the divert transport's view: every capability, real lists, real fakes.
func fullOpts() LoadOpts {
	return LoadOpts{ListsDir: repoLists, FakesDir: repoFakes, Caps: desync.FullCaps()}
}

// write drops content into dir/name and returns the path.
func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// loadTOML compiles a strategy from an inline fixture.
func loadTOML(t *testing.T, content string, o LoadOpts) *Strategy {
	t.Helper()
	p := write(t, t.TempDir(), "fixture.toml", content)
	s, err := Load(p, o)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return s
}

// wantErr compiles a fixture that must fail and checks the message is actionable.
func wantErr(t *testing.T, content string, o LoadOpts, subs ...string) error {
	t.Helper()
	p := write(t, t.TempDir(), "fixture.toml", content)
	s, err := Load(p, o)
	if err == nil {
		t.Fatalf("Load succeeded, want error (compiled %q)", s.Summary())
	}
	for _, sub := range subs {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("error %q does not mention %q", err, sub)
		}
	}
	return err
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr %q: %v", s, err)
	}
	return a
}

// ---------- ParsePortSet ----------

func TestParsePortSet(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want PortSet
	}{
		{"empty", nil, nil},
		{"blank entries", []string{"", "  ", ","}, nil},
		{"single", []string{"443"}, PortSet{{443, 443}}},
		// Every port window flowseal's .bat files use.
		{"flowseal wf-tcp", []string{"80,443,2053,2083,2087,2096,8443"},
			PortSet{{80, 80}, {443, 443}, {2053, 2053}, {2083, 2083}, {2087, 2087}, {2096, 2096}, {8443, 8443}}},
		{"flowseal wf-udp", []string{"443", "19294-19344", "50000-50100"},
			PortSet{{443, 443}, {19294, 19344}, {50000, 50100}}},
		{"discord range", []string{"19294-19344"}, PortSet{{19294, 19344}}},
		{"star", []string{"*"}, PortSet{{1, 65535}}},
		{"any", []string{"any"}, PortSet{{1, 65535}}},
		{"sorted and merged", []string{"443", "80", "81", "82"}, PortSet{{80, 82}, {443, 443}}},
		{"overlap merged", []string{"100-200", "150-300"}, PortSet{{100, 300}}},
		{"adjacent merged", []string{"100-200", "201-300"}, PortSet{{100, 300}}},
		{"top of range", []string{"65535"}, PortSet{{65535, 65535}}},
		{"whole range plus one", []string{"1-65535", "443"}, PortSet{{1, 65535}}},
		{"spaces", []string{" 80 , 443 "}, PortSet{{80, 80}, {443, 443}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePortSet(tc.in)
			if err != nil {
				t.Fatalf("ParsePortSet(%q): %v", tc.in, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ParsePortSet(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ParsePortSet(%q) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

func TestParsePortSetErrors(t *testing.T) {
	tests := []struct {
		in   []string
		want string
	}{
		{[]string{"~443"}, "negated"},
		{[]string{"0"}, "deny-all"},
		{[]string{"70000"}, "above 65535"},
		{[]string{"443-80"}, "above high port"},
		{[]string{"abc"}, "not a port number"},
		{[]string{"443-"}, "missing port number"},
		{[]string{"-443"}, "missing port number"},
		{[]string{"1-2-3"}, "not a port number"},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.in, "_"), func(t *testing.T) {
			_, err := ParsePortSet(tc.in)
			if err == nil {
				t.Fatalf("ParsePortSet(%q) succeeded, want error", tc.in)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestPortSetHas(t *testing.T) {
	ps, err := ParsePortSet([]string{"443", "19294-19344"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []uint16{443, 19294, 19300, 19344} {
		if !ps.Has(p) {
			t.Errorf("Has(%d) = false, want true", p)
		}
	}
	for _, p := range []uint16{0, 442, 444, 19293, 19345} {
		if ps.Has(p) {
			t.Errorf("Has(%d) = true, want false", p)
		}
	}
	var empty PortSet
	if !empty.Has(1) {
		t.Error("an empty PortSet must match every port")
	}
}

// ---------- ParseCounter ----------

func TestParseCounter(t *testing.T) {
	tests := []struct {
		in   string
		want Counter
	}{
		{"", Counter{}},
		// Every --dpi-desync-cutoff value in flowseal's strategies.
		{"n2", Counter{'n', 2}},
		{"n3", Counter{'n', 3}},
		{"n4", Counter{'n', 4}},
		{"n5", Counter{'n', 5}},
		{"d2", Counter{'d', 2}},
		{"s5000", Counter{'s', 5000}},
		{"3", Counter{'n', 3}}, // nfqws: no letter means packet number
		{"0", Counter{'n', 0}},
		{" n3 ", Counter{'n', 3}},
		{"N3", Counter{'n', 3}},
		{"S5000", Counter{'s', 5000}},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseCounter(tc.in)
			if err != nil {
				t.Fatalf("ParseCounter(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseCounter(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseCounterErrors(t *testing.T) {
	for _, in := range []string{"n", "d", "s", "x3", "-1", "3junk", "n-1", "n3.5", "999999999999"} {
		t.Run(in, func(t *testing.T) {
			if _, err := ParseCounter(in); err == nil {
				t.Fatalf("ParseCounter(%q) succeeded, want error", in)
			}
		})
	}
}

// ---------- ParseTTLSpec ----------

func TestParseTTLSpec(t *testing.T) {
	type want struct {
		ttl      uint8
		auto     bool
		delta    int8
		min, max uint8
	}
	tests := []struct {
		in string
		w  want
	}{
		{"", want{}},
		{"5", want{ttl: 5}},
		{"1", want{ttl: 1}},
		{"255", want{ttl: 255}},
		{"0", want{}},
		{" 5 ", want{ttl: 5}},
		// zapret's --dpi-desync-autottl defaults.
		{"auto", want{auto: true, delta: -1, min: 3, max: 20}},
		{"hops", want{auto: true, delta: -1, min: 3, max: 20}},
		{"AUTO", want{auto: true, delta: -1, min: 3, max: 20}},
		{"auto:-1:3-20", want{auto: true, delta: -1, min: 3, max: 20}},
		{"hops:-2", want{auto: true, delta: -2, min: 3, max: 20}},
		{"auto:-2:4-30", want{auto: true, delta: -2, min: 4, max: 30}},
		{"auto:+5:3-64", want{auto: true, delta: 5, min: 3, max: 64}},
		// nfqws' parse_autottl defaults the sign to negative.
		{"auto:2", want{auto: true, delta: -2, min: 3, max: 20}},
		{"auto:1:5", want{auto: true, delta: -1, min: 5, max: 20}},
		// nfqws spells "disabled" as a bare "-".
		{"auto:-", want{}},
		{"auto:0", want{auto: true, delta: 0, min: 3, max: 20}},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			ttl, auto, delta, min, max, err := ParseTTLSpec(tc.in)
			if err != nil {
				t.Fatalf("ParseTTLSpec(%q): %v", tc.in, err)
			}
			got := want{ttl, auto, delta, min, max}
			if got != tc.w {
				t.Fatalf("ParseTTLSpec(%q) = %+v, want %+v", tc.in, got, tc.w)
			}
		})
	}
}

func TestParseTTLSpecErrors(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"256", "above 255"},
		{"junk", "not a TTL"},
		{"5:6", "only \"auto\""},
		{"auto:200", "above 127"},
		{"auto:-1:0-20", "min TTL 0"},
		{"auto:-1:3-0", "max TTL 0"},
		{"auto:-1:30-20", "above max TTL"},
		{"auto:x", "not a hop delta"},
		{"auto:1:x-20", "not a min TTL"},
		{"auto:1:3-x", "not a max TTL"},
		{"auto:1:3-300", "not a max TTL"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			_, _, _, _, _, err := ParseTTLSpec(tc.in)
			if err == nil {
				t.Fatalf("ParseTTLSpec(%q) succeeded, want error", tc.in)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// ---------- ParseSplitPos ----------

func TestParseSplitPos(t *testing.T) {
	tests := []struct {
		in   []string
		want []desync.PosSpec
	}{
		{nil, nil},
		{[]string{""}, nil},
		// Every --dpi-desync-split-pos value in flowseal's strategies.
		{[]string{"1"}, []desync.PosSpec{{Marker: proto.MarkerAbs, Offset: 1}}},
		{[]string{"2"}, []desync.PosSpec{{Marker: proto.MarkerAbs, Offset: 2}}},
		{[]string{"1,midsld"}, []desync.PosSpec{
			{Marker: proto.MarkerAbs, Offset: 1},
			{Marker: proto.MarkerMidSLD, Offset: 0},
		}},
		{[]string{"2,sniext+1"}, []desync.PosSpec{
			{Marker: proto.MarkerAbs, Offset: 2},
			{Marker: proto.MarkerSNIExt, Offset: 1},
		}},
		// The rest of the documented grammar.
		{[]string{"-1"}, []desync.PosSpec{{Marker: proto.MarkerAbs, Offset: -1}}},
		{[]string{"+3"}, []desync.PosSpec{{Marker: proto.MarkerAbs, Offset: 3}}},
		{[]string{"midsld"}, []desync.PosSpec{{Marker: proto.MarkerMidSLD, Offset: 0}}},
		{[]string{"sld"}, []desync.PosSpec{{Marker: proto.MarkerSLD, Offset: 0}}},
		{[]string{"sniext+1"}, []desync.PosSpec{{Marker: proto.MarkerSNIExt, Offset: 1}}},
		{[]string{"host-2"}, []desync.PosSpec{{Marker: proto.MarkerHost, Offset: -2}}},
		{[]string{"endsld+1"}, []desync.PosSpec{{Marker: proto.MarkerEndSLD, Offset: 1}}},
		{[]string{"endhost"}, []desync.PosSpec{{Marker: proto.MarkerEndHost, Offset: 0}}},
		{[]string{"method+2"}, []desync.PosSpec{{Marker: proto.MarkerMethod, Offset: 2}}},
		{[]string{"MidSLD+1"}, []desync.PosSpec{{Marker: proto.MarkerMidSLD, Offset: 1}}},
		// readme.en.md's own example: method+2 for http, midsld for TLS, 5 otherwise.
		{[]string{"method+2", "midsld", "5"}, []desync.PosSpec{
			{Marker: proto.MarkerMethod, Offset: 2},
			{Marker: proto.MarkerMidSLD, Offset: 0},
			{Marker: proto.MarkerAbs, Offset: 5},
		}},
		{[]string{"32767", "-32768"}, []desync.PosSpec{
			{Marker: proto.MarkerAbs, Offset: 32767},
			{Marker: proto.MarkerAbs, Offset: -32768},
		}},
		{[]string{" 2 , sniext+1 "}, []desync.PosSpec{
			{Marker: proto.MarkerAbs, Offset: 2},
			{Marker: proto.MarkerSNIExt, Offset: 1},
		}},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.in, "_"), func(t *testing.T) {
			got, err := ParseSplitPos(tc.in)
			if err != nil {
				t.Fatalf("ParseSplitPos(%q): %v", tc.in, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ParseSplitPos(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ParseSplitPos(%q) = %+v, want %+v", tc.in, got, tc.want)
				}
			}
		})
	}
}

func TestParseSplitPosErrors(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"0", "0 is not a split position"},
		{"midsldx", "unknown marker"},
		{"sni", "unknown marker"},
		{"midsld+", "not a signed number"},
		{"midsld+x", "not a signed number"},
		{"2x", "not a signed number"},
		{"40000", "int16 range"},
		{"midsld+40000", "int16 range"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			_, err := ParseSplitPos([]string{tc.in})
			if err == nil {
				t.Fatalf("ParseSplitPos(%q) succeeded, want error", tc.in)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestParseSplitPosTooMany(t *testing.T) {
	many := make([]string, 0, maxSplits+1)
	for i := 0; i <= maxSplits; i++ {
		many = append(many, "1")
	}
	if _, err := ParseSplitPos(many); err == nil || !strings.Contains(err.Error(), "MAX_SPLITS") {
		t.Fatalf("want a MAX_SPLITS error, got %v", err)
	}
	ok := many[:maxSplits]
	if got, err := ParseSplitPos(ok); err != nil || len(got) != maxSplits {
		t.Fatalf("ParseSplitPos of exactly %d positions: %d, %v", maxSplits, len(got), err)
	}
}

// ---------- LoadFake ----------

func TestBuiltinFakeTLSHello(t *testing.T) {
	// zapret's fake_tls_clienthello_default: 680 bytes, TLS 1.0 record header,
	// handshake type 1 (ClientHello), SNI www.microsoft.com.
	if n := len(defaultFakeTLSHello); n != 680 {
		t.Fatalf("built-in fake hello is %d bytes, want 680", n)
	}
	if !bytes.HasPrefix(defaultFakeTLSHello, []byte{0x16, 0x03, 0x01, 0x02, 0xa3, 0x01}) {
		t.Fatalf("built-in fake hello does not start with a ClientHello record: % x", defaultFakeTLSHello[:6])
	}
	if !bytes.Contains(defaultFakeTLSHello, []byte("www.microsoft.com")) {
		t.Fatal("built-in fake hello does not carry the www.microsoft.com SNI")
	}
	if _, ok := proto.ParseTLSClientHello(defaultFakeTLSHello); !ok {
		t.Fatal("built-in fake hello does not parse as a ClientHello")
	}
}

func TestLoadFakeInline(t *testing.T) {
	tests := []struct {
		in   string
		want []byte
	}{
		{"", nil},
		{"  ", nil},
		// Both inline literals flowseal passes to winws.
		{"0x00000000", []byte{0, 0, 0, 0}},
		{"0x00", []byte{0}},
		{"0xDEADBEEF", []byte{0xde, 0xad, 0xbe, 0xef}},
		{"0xdeadbeef", []byte{0xde, 0xad, 0xbe, 0xef}},
		{"0X00FF", []byte{0x00, 0xff}},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := LoadFake(repoFakes, tc.in)
			if err != nil {
				t.Fatalf("LoadFake(%q): %v", tc.in, err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("LoadFake(%q) = % x, want % x", tc.in, got, tc.want)
			}
		})
	}
}

func TestLoadFakeBuiltinSpelling(t *testing.T) {
	// "^!" is what flowseal writes in a .bat; winws sees "!", which selects
	// zapret's built-in ClientHello — not an empty fake.
	for _, spec := range []string{"!", "^!"} {
		got, err := LoadFake(repoFakes, spec)
		if err != nil {
			t.Fatalf("LoadFake(%q): %v", spec, err)
		}
		if !bytes.Equal(got, defaultFakeTLSHello) {
			t.Fatalf("LoadFake(%q) is not the built-in hello (%d bytes)", spec, len(got))
		}
	}
	got, err := LoadFake(repoFakes, "!+4")
	if err != nil {
		t.Fatalf("LoadFake(\"!+4\"): %v", err)
	}
	if !bytes.Equal(got, defaultFakeTLSHello[4:]) {
		t.Fatal("LoadFake(\"!+4\") did not skip 4 bytes")
	}
	if _, err := LoadFake(repoFakes, "!+9999"); err == nil {
		t.Fatal("LoadFake(\"!+9999\") succeeded, want an out-of-range error")
	}
}

func TestLoadFakeFiles(t *testing.T) {
	tests := []struct {
		spec string
		size int
	}{
		{"tls_clienthello_www_google_com.bin", 681},
		{"@tls_clienthello_www_google_com.bin", 681},
		{"tls_clienthello_max_ru.bin", 664},
		{"tls_clienthello_4pda_to.bin", 284},
		{"stun.bin", 100},
		{"stun2.bin", 120},
		{"quic_initial_www_google_com.bin", 1200},
		{"ACTIVE_DISCORD_UDP.bin", 1200},
		{"ACTIVE_GAME_UDP.bin", 1250},
		{"+4@stun.bin", 96},
		{"+1199@quic_initial_www_google_com.bin", 1},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			got, err := LoadFake(repoFakes, tc.spec)
			if err != nil {
				t.Fatalf("LoadFake(%q): %v", tc.spec, err)
			}
			if len(got) != tc.size {
				t.Fatalf("LoadFake(%q) is %d bytes, want %d", tc.spec, len(got), tc.size)
			}
		})
	}

	// An absolute path bypasses the fakes directory.
	abs, err := filepath.Abs(filepath.Join(repoFakes, "stun.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := LoadFake("/nonexistent", abs); err != nil || len(got) != 100 {
		t.Fatalf("LoadFake(absolute) = %d bytes, %v", len(got), err)
	}
}

func TestLoadFakeErrors(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "empty.bin", "")
	write(t, dir, "big.bin", strings.Repeat("A", maxFakeLen+1))

	tests := []struct {
		dir  string
		spec string
		want string
	}{
		{repoFakes, "nope.bin", "does not exist"},
		{repoFakes, "0x", "no bytes"},
		{repoFakes, "0xABC", "not a whole number of bytes"},
		{repoFakes, "0xZZ", "not hex"},
		{repoFakes, "+4@", "missing file name"},
		{repoFakes, "+x@stun.bin", "not an offset"},
		{repoFakes, "+100@stun.bin", "past the end"},
		{repoFakes, "@", "missing file name"},
		{dir, "empty.bin", "is empty"},
		{dir, "big.bin", "fake limit"},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			_, err := LoadFake(tc.dir, tc.spec)
			if err == nil {
				t.Fatalf("LoadFake(%q) succeeded, want error", tc.spec)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// ---------- small parsers ----------

func TestParseWSSize(t *testing.T) {
	tests := []struct {
		in          string
		size, scale int
	}{
		{"", 0, 0},
		{"128", 128, 0},
		{"128:6", 128, 6},
		{"1:0", 1, 0},
		{"65535:255", 65535, 255},
		{" 128 : 6 ", 128, 6},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			size, scale, err := parseWSSize(tc.in)
			if err != nil {
				t.Fatalf("parseWSSize(%q): %v", tc.in, err)
			}
			if size != tc.size || scale != tc.scale {
				t.Fatalf("parseWSSize(%q) = %d,%d want %d,%d", tc.in, size, scale, tc.size, tc.scale)
			}
		})
	}
	for _, in := range []string{"x", "65536", "128:256", "128:x", "-1"} {
		if _, _, err := parseWSSize(in); err == nil {
			t.Errorf("parseWSSize(%q) succeeded, want error", in)
		}
	}
}

func TestParseIPIDMode(t *testing.T) {
	tests := []struct {
		in   string
		want desync.IPIDMode
	}{
		{"", desync.IPIDDefault},
		{"default", desync.IPIDDefault},
		{"zero", desync.IPIDZero},
		{"ZERO", desync.IPIDZero},
		{"seq", desync.IPIDSeq},
		{"rnd", desync.IPIDRandom},
		{"random", desync.IPIDRandom},
		// Both used to be refused / folded onto IPIDDefault; IPIDMode has values
		// of its own for them now.
		{"seqgroup", desync.IPIDSeqGroup},
		{"same", desync.IPIDSame},
	}
	for _, tc := range tests {
		got, err := parseIPIDMode(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("parseIPIDMode(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
		}
	}
	if _, err := parseIPIDMode("junk"); err == nil {
		t.Error("junk ip_id mode should be refused")
	}
}

func TestNameSortKey(t *testing.T) {
	// flowseal's service.bat: digit runs zero-padded to width 8, so ALT2 < ALT10.
	names := []string{
		"general (ALT10).toml",
		"general.toml",
		"general (ALT2).toml",
		"general (ALT).toml",
		"general (ALT9).toml",
		"general (FAKE TLS AUTO ALT3).toml",
	}
	got := append([]string(nil), names...)
	sortNames(got)
	want := []string{
		"general (ALT).toml",
		"general (ALT2).toml",
		"general (ALT9).toml",
		"general (ALT10).toml",
		"general (FAKE TLS AUTO ALT3).toml",
		"general.toml",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sorted = %q, want %q", got, want)
		}
	}
	// A digit run of 8 or more is left alone, exactly as PadLeft(8,'0') does.
	if k := nameSortKey("a123456789b"); k != "a123456789b" {
		t.Fatalf("nameSortKey kept %q", k)
	}
}

// sortNames applies the same ordering LoadDir uses.
func sortNames(names []string) {
	for i := 1; i < len(names); i++ {
		for j := i; j > 0; j-- {
			ka, kb := nameSortKey(names[j-1]), nameSortKey(names[j])
			if ka < kb || (ka == kb && names[j-1] <= names[j]) {
				break
			}
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
}

// ---------- whole-file compilation ----------

// seqovlMultisplitTOML is flowseal's most common shape: multisplit with a large
// seqovl whose overlap bytes come from a real ClientHello, gated on a hostlist
// plus the shipped exclusion lists.
const seqovlMultisplitTOML = `
name = "ALT2-like"
description = "seqovl multisplit over the shipped lists"
source = "general (ALT2).bat"

[window]
tcp = ["80,443,2053,2083,2087,2096,8443"]
udp = ["443", "19294-19344", "50000-50100"]

[[profile]]
name = "google-tcp"

[profile.filter]
proto = "tcp"
l3 = "ipv4"
ports = ["443"]
hostlist = ["list-google.txt"]
hostlist_exclude = ["list-exclude.txt", "list-exclude-user.txt"]
ipset_exclude = ["ipset-exclude.txt", "ipset-exclude-user.txt"]

# Written before the split on purpose: ip_id is a PhaseModify op and must end up
# after it in the compiled profile.
[[profile.ops]]
op = "ip_id"
mode = "zero"

[[profile.ops]]
op = "multisplit"
pos = ["1"]
seqovl = 681
seqovl_pattern = "tls_clienthello_www_google_com.bin"
`

func TestLoadSeqovlMultisplit(t *testing.T) {
	s := loadTOML(t, seqovlMultisplitTOML, fullOpts())

	if s.Name != "ALT2-like" || s.Source != "general (ALT2).bat" {
		t.Fatalf("name/source = %q/%q", s.Name, s.Source)
	}
	wantTCP := PortSet{{80, 80}, {443, 443}, {2053, 2053}, {2083, 2083}, {2087, 2087}, {2096, 2096}, {8443, 8443}}
	if len(s.WindowTCP) != len(wantTCP) {
		t.Fatalf("window.tcp = %v, want %v", s.WindowTCP, wantTCP)
	}
	if len(s.WindowUDP) != 3 || s.WindowUDP[1] != (PortRange{19294, 19344}) {
		t.Fatalf("window.udp = %v", s.WindowUDP)
	}
	if len(s.Profiles) != 1 {
		t.Fatalf("got %d profiles, want 1", len(s.Profiles))
	}
	p := s.Profiles[0]
	if p.Name != "google-tcp" || p.OnUnsupported != desync.UnsupDegrade {
		t.Fatalf("profile = %q, on_unsupported = %v", p.Name, p.OnUnsupported)
	}
	if p.Filter.Proto != proto.IPProtoTCP || p.Filter.L3 != 4 {
		t.Fatalf("filter proto/l3 = %d/%d", p.Filter.Proto, p.Filter.L3)
	}
	if !p.Filter.Ports.Has(443) || p.Filter.Ports.Has(80) {
		t.Fatalf("filter ports = %v", p.Filter.Ports)
	}
	if p.Filter.L7 != 0 {
		t.Fatalf("filter l7 = %d, want unconstrained", p.Filter.L7)
	}

	// Hostlist and exclusions must be real, matching sets.
	if p.Filter.Hostlist == nil || !p.Filter.Hostlist.Match("yt3.ggpht.com") {
		t.Fatal("hostlist does not match a domain from list-google.txt")
	}
	if p.Filter.Hostlist.Match("example.invalid") {
		t.Fatal("hostlist matches a domain it does not contain")
	}
	if p.Filter.HostlistExclude == nil || !p.Filter.HostlistExclude.Match("mail.ru") {
		t.Fatal("exclude list does not match a domain from list-exclude.txt")
	}
	// The regression this guards: list-exclude-user.txt ships with nothing but a
	// comment. Merged naively it raises the set's match-everything flag and every
	// profile stops matching. An empty list must contribute nothing.
	if p.Filter.HostlistExclude.Match("yt3.ggpht.com") {
		t.Fatal("comment-only list-exclude-user.txt turned the exclude list into match-everything")
	}
	if p.Filter.IPSetExclude == nil || !p.Filter.IPSetExclude.Match(mustAddr(t, "10.0.0.1")) {
		t.Fatal("ipset_exclude does not match a prefix from ipset-exclude.txt")
	}
	if p.Filter.IPSetExclude.Match(mustAddr(t, "142.250.185.78")) {
		t.Fatal("ipset_exclude matches a public address")
	}
	if p.Filter.IPSet != nil {
		t.Fatal("ipset must stay nil when the profile names none")
	}

	// Ops are ordered by phase, not by file order.
	if len(p.Ops) != 2 {
		t.Fatalf("got %d ops, want 2", len(p.Ops))
	}
	if p.Ops[0].Op.Name() != "multisplit" || p.Ops[1].Op.Name() != "ip_id" {
		t.Fatalf("op order = %q, %q; want multisplit before ip_id", p.Ops[0].Op.Name(), p.Ops[1].Op.Name())
	}
	ms := p.Ops[0].Params
	if ms.Seqovl != 681 {
		t.Fatalf("seqovl = %d, want 681", ms.Seqovl)
	}
	if len(ms.SeqovlPattern) != 681 {
		t.Fatalf("seqovl pattern is %d bytes, want the 681-byte ClientHello", len(ms.SeqovlPattern))
	}
	if len(ms.SplitPos) != 1 || ms.SplitPos[0] != (desync.PosSpec{Marker: proto.MarkerAbs, Offset: 1}) {
		t.Fatalf("split pos = %+v", ms.SplitPos)
	}
	if ms.Repeats != 1 {
		t.Fatalf("repeats = %d, want nfqws' default of 1", ms.Repeats)
	}
	if ms.FoolP != desync.DefaultFoolParams() {
		t.Fatalf("fool params = %+v, want zapret defaults", ms.FoolP)
	}
	if ms.FragPosTCP != 32 || ms.FragPosUDP != 8 {
		t.Fatalf("frag pos = %d/%d, want nfqws' 32/8", ms.FragPosTCP, ms.FragPosUDP)
	}
	if ms.UDPLenIncrement != 2 {
		t.Fatalf("udplen increment = %d, want nfqws' default of 2", ms.UDPLenIncrement)
	}
	if p.Ops[1].Params.IPID != desync.IPIDZero {
		t.Fatalf("ip_id mode = %v, want zero", p.Ops[1].Params.IPID)
	}
	// The spec is kept verbatim for `zaprctl show`.
	if p.Ops[0].Spec.Op != "multisplit" || p.Ops[0].Spec.Seqovl != 681 {
		t.Fatalf("spec not preserved: %+v", p.Ops[0].Spec)
	}

	if got := s.Summary(); got != "ALT2-like: 1 profile, ops: ip_id, multisplit" {
		t.Fatalf("Summary() = %q", got)
	}
	if u := s.Unsupported(desync.FullCaps()); len(u) != 0 {
		t.Fatalf("divert transport should run everything, got %q", u)
	}
	// ip_id needs the IPv4 id field, which a socket-level relay cannot touch.
	u := s.Unsupported(desync.ProxyCaps())
	if len(u) != 1 || !strings.Contains(u[0], "ip_id") || !strings.Contains(u[0], "ip-id") {
		t.Fatalf("Unsupported(proxy) = %q, want the ip_id op", u)
	}
}

// fakeFakedsplitTOML is the fake+fakedsplit shape with ts fooling, an autottl, a
// built-in fake hello, inline hostlist domains and a tls-mod.
const fakeFakedsplitTOML = `
name = "fake-fakedsplit"

[[profile]]
name = "tls-fake"
cutoff = "n4"
start = "d2"
on_unsupported = "error"

[profile.filter]
proto = "tcp"
ports = ["80", "443"]
l7 = ["tls", "http"]
hostlist_domains = ["discord.media", "discord.gg"]
hostlist_exclude_domains = ["fonts.googleapis.com"]
hostlist_auto = "autolist.txt"

[[profile.ops]]
op = "fakedsplit"
pos = ["1", "midsld"]
pattern = "0x00"
mod = { altorder = "1" }

[[profile.ops]]
op = "fake"
repeats = 11
fooling = ["ts", "md5sig"]
ts_increment = -600000
badseq_increment = 1000
ttl = "auto:-1:3-20"
tls_mod = "rnd,dupsid,sni=www.google.com"
fake = { tls = "^!", http = "0xDEADBEEF" }
`

func TestLoadFakeFakedsplit(t *testing.T) {
	s := loadTOML(t, fakeFakedsplitTOML, fullOpts())
	if len(s.Profiles) != 1 {
		t.Fatalf("got %d profiles", len(s.Profiles))
	}
	p := s.Profiles[0]
	if p.Cutoff != (Counter{'n', 4}) || p.Start != (Counter{'d', 2}) {
		t.Fatalf("cutoff/start = %+v/%+v", p.Cutoff, p.Start)
	}
	if p.OnUnsupported != desync.UnsupError {
		t.Fatalf("on_unsupported = %v, want error", p.OnUnsupported)
	}
	if p.Filter.L7 != proto.L7TLS|proto.L7HTTP {
		t.Fatalf("filter l7 = %d", p.Filter.L7)
	}
	// Inline domains are suffix-matched like a file entry, and must not leak into
	// the shared set of any other profile.
	if p.Filter.Hostlist == nil || !p.Filter.Hostlist.Match("discord.media") ||
		!p.Filter.Hostlist.Match("cdn.discord.media") || p.Filter.Hostlist.Match("discord.com") {
		t.Fatal("inline hostlist_domains do not match as expected")
	}
	if p.Filter.HostlistExclude == nil || !p.Filter.HostlistExclude.Match("fonts.googleapis.com") {
		t.Fatal("inline hostlist_exclude_domains do not match")
	}
	if !strings.HasSuffix(p.Filter.AutoHostlist, filepath.Join("lists", "autolist.txt")) {
		t.Fatalf("hostlist_auto = %q, want it resolved under the lists dir", p.Filter.AutoHostlist)
	}

	// fake is PhaseFake, fakedsplit is PhaseSplit: the decoy goes first.
	if p.Ops[0].Op.Name() != "fake" || p.Ops[1].Op.Name() != "fakedsplit" {
		t.Fatalf("op order = %q, %q", p.Ops[0].Op.Name(), p.Ops[1].Op.Name())
	}
	f := p.Ops[0].Params
	if f.Repeats != 11 {
		t.Fatalf("repeats = %d, want 11", f.Repeats)
	}
	if f.Fool != desync.FoolTS|desync.FoolMD5Sig {
		t.Fatalf("fooling = %b, want ts|md5sig", f.Fool)
	}
	if f.FoolP.TSIncrement != -600000 || f.FoolP.BadSeqIncrement != 1000 || f.FoolP.BadAckIncrement != -66000 {
		t.Fatalf("fool params = %+v", f.FoolP)
	}
	if !f.TTLAuto || f.TTLDelta != -1 || f.TTLMin != 3 || f.TTLMax != 20 {
		t.Fatalf("autottl = %+v", f)
	}
	if len(f.FakeTLS) != 680 || !bytes.Equal(f.FakeTLS, defaultFakeTLSHello) {
		t.Fatalf("fake.tls is %d bytes, want the built-in hello", len(f.FakeTLS))
	}
	if !bytes.Equal(f.FakeHTTP, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("fake.http = % x", f.FakeHTTP)
	}
	if f.TLSMod != (desync.TLSMod{Rnd: true, DupSID: true, SNI: "www.google.com"}) {
		t.Fatalf("tls_mod = %+v", f.TLSMod)
	}
	fs := p.Ops[1].Params
	if !bytes.Equal(fs.Pattern, []byte{0x00}) {
		t.Fatalf("fakedsplit pattern = % x", fs.Pattern)
	}
	if fs.AltOrder != 1 {
		t.Fatalf("altorder = %d", fs.AltOrder)
	}
	if len(fs.SplitPos) != 2 || fs.SplitPos[1].Marker != proto.MarkerMidSLD {
		t.Fatalf("split pos = %+v", fs.SplitPos)
	}

	// Under the proxy transport neither op can run.
	u := s.Unsupported(desync.ProxyCaps())
	if len(u) != 2 {
		t.Fatalf("Unsupported(proxy) = %q, want both ops", u)
	}
}

// udpQUICTOML is the UDP half of a flowseal strategy: a QUIC fake, a
// Discord/STUN fake with several blobs, and a udplen tail pad.
const udpQUICTOML = `
name = "quic-udp"

[window]
udp = ["443", "19294-19344", "50000-50100"]

[[profile]]
name = "quic-443"
cutoff = "n2"

[profile.filter]
proto = "udp"
ports = ["443"]
l7 = ["quic"]
ipset = ["ipset-all.txt"]
ipset_exclude = ["ipset-exclude.txt", "ipset-exclude-user.txt"]

[[profile.ops]]
op = "fake"
repeats = 6
any_protocol = true
fake = { quic = "quic_initial_www_google_com.bin" }

[[profile]]
name = "discord-voice"

[profile.filter]
proto = "udp"
ports = ["19294-19344", "50000-50100"]
l7 = ["discord", "stun", "unknown"]

[[profile.ops]]
op = "fake"
repeats = 12
fake = { discord = ["ACTIVE_DISCORD_UDP.bin"], stun = ["stun.bin", "stun2.bin"], unknown_udp = ["ACTIVE_GAME_UDP.bin"] }

[[profile.ops]]
op = "udplen"
udplen_increment = 5
udplen_pattern = "0xAA"
`

func TestLoadUDPQUIC(t *testing.T) {
	s := loadTOML(t, udpQUICTOML, fullOpts())
	if len(s.Profiles) != 2 {
		t.Fatalf("got %d profiles, want 2", len(s.Profiles))
	}

	q := s.Profiles[0]
	if q.Filter.Proto != proto.IPProtoUDP || q.Filter.L7 != proto.L7QUIC {
		t.Fatalf("quic filter = %d/%d", q.Filter.Proto, q.Filter.L7)
	}
	if q.Cutoff != (Counter{'n', 2}) {
		t.Fatalf("cutoff = %+v", q.Cutoff)
	}
	if q.Filter.IPSet == nil || !q.Filter.IPSet.Match(mustAddr(t, "1.1.1.1")) {
		t.Fatal("ipset does not match a prefix from ipset-all.txt")
	}
	qp := q.Ops[0].Params
	if len(qp.FakeQUIC) != 1200 {
		t.Fatalf("fake.quic is %d bytes, want 1200", len(qp.FakeQUIC))
	}
	if !qp.AnyProtocol || qp.Repeats != 6 {
		t.Fatalf("any_protocol/repeats = %v/%d", qp.AnyProtocol, qp.Repeats)
	}

	d := s.Profiles[1]
	if d.Filter.L7 != proto.L7Discord|proto.L7STUN|proto.L7Unknown {
		t.Fatalf("discord filter l7 = %d", d.Filter.L7)
	}
	// fake is PhaseFake, udplen is PhaseModify.
	if d.Ops[0].Op.Name() != "fake" || d.Ops[1].Op.Name() != "udplen" {
		t.Fatalf("op order = %q, %q", d.Ops[0].Op.Name(), d.Ops[1].Op.Name())
	}
	dp := d.Ops[0].Params
	if len(dp.FakeDiscord) != 1 || len(dp.FakeDiscord[0]) != 1200 {
		t.Fatalf("fake.discord = %d blobs", len(dp.FakeDiscord))
	}
	if len(dp.FakeSTUN) != 2 || len(dp.FakeSTUN[0]) != 100 || len(dp.FakeSTUN[1]) != 120 {
		t.Fatalf("fake.stun = %d blobs", len(dp.FakeSTUN))
	}
	if len(dp.FakeUnknownUDP) != 1 || len(dp.FakeUnknownUDP[0]) != 1250 {
		t.Fatalf("fake.unknown_udp = %d blobs", len(dp.FakeUnknownUDP))
	}
	up := d.Ops[1].Params
	if up.UDPLenIncrement != 5 || !bytes.Equal(up.UDPLenPattern, []byte{0xaa}) {
		t.Fatalf("udplen = %d, % x", up.UDPLenIncrement, up.UDPLenPattern)
	}

	// udplen needs UDP visibility, which the socket relay does not have.
	u := s.Unsupported(desync.ProxyCaps())
	found := false
	for _, line := range u {
		if strings.HasPrefix(line, "udplen ") && strings.Contains(line, "udp") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Unsupported(proxy) = %q, want udplen listed", u)
	}
}

// ---------- validation ----------

func TestLoadValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		toml string
		caps desync.Caps
		subs []string
	}{
		{
			name: "unknown op",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "multispilt"
`,
			subs: []string{"the-profile", "unknown desync op", "multispilt", "fix the op name"},
		},
		{
			name: "unknown fooling",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "fake"
fooling = ["ts", "badsun"]
`,
			subs: []string{"the-profile", `"fake"`, `fooling "badsun" is unknown`, "use one of"},
		},
		{
			name: "unknown marker",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "multisplit"
pos = ["midsldx"]
`,
			subs: []string{"the-profile", "unknown marker", "midsld"},
		},
		{
			name: "seqovl past first split",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "fakedsplit"
pos = ["2"]
seqovl = 681
`,
			subs: []string{"the-profile", "fakedsplit", "reaches or passes", "multisplit"},
		},
		{
			name: "negative repeats",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "fake"
repeats = -1
`,
			subs: []string{"the-profile", "repeats = -1 is negative", "1 or more"},
		},
		{
			name: "udp op in tcp profile",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[profile.filter]
proto = "tcp"
[[profile.ops]]
op = "udplen"
udplen_increment = 2
`,
			subs: []string{"the-profile", "udplen", "only works on UDP", "widen the filter"},
		},
		{
			name: "inject op with on_unsupported=error under proxy caps",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
on_unsupported = "error"
[[profile.ops]]
op = "fake"
`,
			caps: desync.ProxyCaps(),
			subs: []string{"the-profile", `"fake"`, "inject", "on_unsupported", "divert"},
		},
		{
			name: "missing fake file",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "fake"
fake = { tls = "no_such_fake.bin" }
`,
			subs: []string{"the-profile", "fake.tls", "no_such_fake.bin", "does not exist"},
		},
		{
			name: "missing hostlist",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[profile.filter]
hostlist = ["list-typo.txt"]
[[profile.ops]]
op = "multisplit"
pos = ["1"]
`,
			subs: []string{"the-profile", "filter.hostlist", "list-typo.txt", "does not exist", "-user.txt"},
		},
		{
			name: "unknown key",
			toml: `
name = "bad"
whatever = 1
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "multisplit"
pos = ["1"]
`,
			subs: []string{"unknown key(s)", "whatever"},
		},
		{
			name: "unknown op knob",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "multisplit"
poss = ["1"]
`,
			subs: []string{"unknown key(s)", "profile.ops.poss"},
		},
		{
			name: "no profiles",
			toml: `name = "bad"`,
			subs: []string{"no [[profile]] sections", "at least one profile"},
		},
		{
			name: "no ops",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
`,
			subs: []string{"the-profile", "no [[profile.ops]]"},
		},
		{
			name: "unknown on_unsupported",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
on_unsupported = "explode"
[[profile.ops]]
op = "multisplit"
pos = ["1"]
`,
			subs: []string{"the-profile", "on_unsupported", "degrade"},
		},
		{
			name: "unknown l7",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[profile.filter]
l7 = ["kwik"]
[[profile.ops]]
op = "multisplit"
pos = ["1"]
`,
			subs: []string{"the-profile", "filter.l7", "kwik", "quic"},
		},
		{
			name: "unknown proto",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[profile.filter]
proto = "sctp"
[[profile.ops]]
op = "multisplit"
pos = ["1"]
`,
			subs: []string{"the-profile", "filter.proto", "sctp"},
		},
		{
			name: "bad cutoff",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
cutoff = "n"
[[profile.ops]]
op = "multisplit"
pos = ["1"]
`,
			subs: []string{"the-profile", "cutoff", "n3"},
		},
		{
			name: "ip_id without mode",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "ip_id"
`,
			subs: []string{"the-profile", "ip_id needs mode"},
		},
		{
			name: "wssize without value",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "wssize"
`,
			subs: []string{"the-profile", "wssize needs wssize"},
		},
		{
			name: "bad altorder for hostfakesplit",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "hostfakesplit"
mod = { altorder = "2" }
`,
			subs: []string{"the-profile", "hostfakesplit only has orderings 0 and 1"},
		},
		{
			name: "unknown mod key",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "hostfakesplit"
mod = { hots = "ya.ru" }
`,
			subs: []string{"the-profile", "mod key", "hots", "host="},
		},
		{
			name: "frag_pos not a multiple of 8",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "ipfrag2"
frag_pos = 12
`,
			subs: []string{"the-profile", "multiple of 8", "8-byte units"},
		},
		{
			name: "negative seqovl",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "multisplit"
pos = ["1"]
seqovl = -5
`,
			subs: []string{"the-profile", "seqovl = -5 is negative"},
		},
		{
			name: "bad tls_mod",
			toml: `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "fake"
tls_mod = "rnd,dupsidd"
`,
			subs: []string{"the-profile", "tls_mod", "dupsid"},
		},
		{
			name: "bad window port",
			toml: `
name = "bad"
[window]
tcp = ["443", "0"]
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "multisplit"
pos = ["1"]
`,
			subs: []string{"window.tcp", "deny-all"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := fullOpts()
			if tc.caps != (desync.Caps{}) {
				o.Caps = tc.caps
			}
			wantErr(t, tc.toml, o, tc.subs...)
		})
	}
}

// TestLoadSeqovlAllowedForMultisplit pins the exemption: 21 flowseal strategies
// pair a 681-byte seqovl with split pos 1 under multisplit, where nfqws puts the
// overlap below the first segment and applies it whatever the position is.
func TestLoadSeqovlAllowedForMultisplit(t *testing.T) {
	s := loadTOML(t, `
name = "ok"
[[profile]]
name = "p"
[[profile.ops]]
op = "multisplit"
pos = ["1"]
seqovl = 681
`, fullOpts())
	if got := s.Profiles[0].Ops[0].Params.Seqovl; got != 681 {
		t.Fatalf("seqovl = %d, want 681", got)
	}
	// A marker-based first position is unknowable at load time, so a disorder with
	// a big seqovl must still compile.
	s = loadTOML(t, `
name = "ok"
[[profile]]
name = "p"
[[profile.ops]]
op = "multidisorder"
pos = ["midsld"]
seqovl = 652
`, fullOpts())
	if got := s.Profiles[0].Ops[0].Params.Seqovl; got != 652 {
		t.Fatalf("seqovl = %d, want 652", got)
	}
}

// TestLoadSeqovlValues walks every seqovl flowseal actually ships.
func TestLoadSeqovlValues(t *testing.T) {
	for _, v := range []int{480, 568, 652, 664, 679, 681} {
		s := loadTOML(t, `
name = "ok"
[[profile]]
name = "p"
[[profile.ops]]
op = "multisplit"
pos = ["1"]
seqovl = `+itoa(v)+`
seqovl_pattern = "tls_clienthello_www_google_com.bin"
`, fullOpts())
		if got := s.Profiles[0].Ops[0].Params.Seqovl; got != v {
			t.Fatalf("seqovl = %d, want %d", got, v)
		}
	}
}

// TestLoadRepeatsValues walks every --dpi-desync-repeats flowseal ships.
func TestLoadRepeatsValues(t *testing.T) {
	for _, v := range []int{3, 4, 5, 6, 8, 10, 11, 12, 14} {
		s := loadTOML(t, `
name = "ok"
[[profile]]
name = "p"
[[profile.ops]]
op = "fake"
repeats = `+itoa(v)+`
`, fullOpts())
		if got := s.Profiles[0].Ops[0].Params.Repeats; got != v {
			t.Fatalf("repeats = %d, want %d", got, v)
		}
	}
	if _, err := Load(write(t, t.TempDir(), "x.toml", `
name = "ok"
[[profile]]
[[profile.ops]]
op = "fake"
repeats = 2000
`), fullOpts()); err == nil {
		t.Fatal("repeats = 2000 should be refused")
	}
}

// TestLoadFoolingIncrements covers every increment flowseal passes.
func TestLoadFoolingIncrements(t *testing.T) {
	tests := []struct {
		fooling string
		badseq  int32
		ts      int32
	}{
		{`["badseq"]`, 1000, -600000},
		{`["badseq"]`, 2, -600000},
		{`["badseq"]`, 10000000, -600000},
		{`["ts"]`, -10000, -600000},
	}
	for _, tc := range tests {
		s := loadTOML(t, `
name = "ok"
[[profile]]
name = "p"
[[profile.ops]]
op = "fake"
fooling = `+tc.fooling+`
badseq_increment = `+itoa(int(tc.badseq))+`
ts_increment = `+itoa(int(tc.ts))+`
`, fullOpts())
		got := s.Profiles[0].Ops[0].Params.FoolP
		if got.BadSeqIncrement != tc.badseq || got.TSIncrement != tc.ts {
			t.Fatalf("fool params = %+v, want badseq %d ts %d", got, tc.badseq, tc.ts)
		}
		if got.BadAckIncrement != -66000 {
			t.Fatalf("badack = %d, want zapret's default -66000", got.BadAckIncrement)
		}
	}
}

// TestLoadOptionalUserList checks flowseal's rule that only *-user.txt lists may
// be missing — and that a comment-only user list changes nothing.
func TestLoadOptionalUserList(t *testing.T) {
	s := loadTOML(t, `
name = "ok"
[[profile]]
name = "p"
[profile.filter]
hostlist = ["list-google.txt", "list-nonexistent-user.txt"]
[[profile.ops]]
op = "multisplit"
pos = ["1"]
`, fullOpts())
	hl := s.Profiles[0].Filter.Hostlist
	if hl == nil || !hl.Match("yt3.ggpht.com") {
		t.Fatal("hostlist lost its entries")
	}
	if hl.Match("example.invalid") {
		t.Fatal("a missing user list must not turn the hostlist into match-everything")
	}
}

// TestLoadAllEmptyListsCompileToNil pins nfqws' rule that a list naming only
// empty files constrains nothing.
func TestLoadAllEmptyListsCompileToNil(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "blank.txt", "# nothing but a comment\n\n")
	s := loadTOML(t, `
name = "ok"
[[profile]]
name = "p"
[profile.filter]
hostlist = ["blank.txt"]
hostlist_exclude = ["blank.txt"]
[[profile.ops]]
op = "multisplit"
pos = ["1"]
`, LoadOpts{ListsDir: dir, FakesDir: repoFakes, Caps: desync.FullCaps()})
	f := s.Profiles[0].Filter
	if f.Hostlist != nil {
		t.Error("an all-empty hostlist must compile to nil (unrestricted)")
	}
	if f.HostlistExclude != nil {
		t.Error("an all-empty exclude list must compile to nil (excludes nothing)")
	}
}

// TestLoadHostfakesplitMod covers --dpi-desync-hostfakesplit-mod, including the
// four real host templates flowseal ships.
func TestLoadHostfakesplitMod(t *testing.T) {
	for _, host := range []string{"www.google.com", "ya.ru", "ozon.ru", "x.com"} {
		s := loadTOML(t, `
name = "ok"
[[profile]]
name = "p"
[[profile.ops]]
op = "hostfakesplit"
mod = { host = "`+host+`", altorder = "1", midhost = "1" }
`, fullOpts())
		got := s.Profiles[0].Ops[0].Params
		// midhost = "1" is the flag spelling: it compiles to the midsld anchor.
		if got.HostFakeHost != host || got.AltOrder != 1 || !got.MidHostSet ||
			got.MidHost != (desync.PosSpec{Marker: proto.MarkerMidSLD}) {
			t.Fatalf("mod = %q/%d/%v/%+v", got.HostFakeHost, got.AltOrder, got.MidHostSet, got.MidHost)
		}
	}
	// "none" is nfqws' explicit no-op mod, and midhost defaults to off.
	s := loadTOML(t, `
name = "ok"
[[profile]]
name = "p"
[[profile.ops]]
op = "hostfakesplit"
mod = { none = "", altorder = "0" }
`, fullOpts())
	if got := s.Profiles[0].Ops[0].Params; got.HostFakeHost != "" || got.AltOrder != 0 || got.MidHostSet {
		t.Fatalf("mod = %+v", got)
	}
	// fakedsplit's ordering selector is a bitmask: 0..3, optionally +8 or +16.
	for _, v := range []string{"0", "3", "8", "11", "16", "19"} {
		loadTOML(t, `
name = "ok"
[[profile]]
name = "p"
[[profile.ops]]
op = "fakedsplit"
pos = ["1"]
mod = { altorder = "`+v+`" }
`, fullOpts())
	}
	// host= and midhost= are hostfakesplit's alone now, so each row names the op
	// that reads its key; the assertions themselves are unchanged.
	for _, tc := range []struct{ op, mod, want string }{
		{"fakedsplit", `altorder = "x"`, "not a number; use 0..3"},
		{"fakedsplit", `altorder = "4"`, "0..3, optionally +8 or +16"},
		{"fakedsplit", `altorder = "24"`, "0..3, optionally +8 or +16"},
		{"fakedsplit", `altorder = "-1"`, "0..3, optionally +8 or +16"},
		{"hostfakesplit", `host = ""`, "mod.host is empty"},
		{"hostfakesplit", `host = "not a host"`, "is not a hostname"},
		{"hostfakesplit", `midhost = "maybe"`, "not a boolean"},
	} {
		wantErr(t, `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "`+tc.op+`"
pos = ["1"]
mod = { `+tc.mod+` }
`, fullOpts(), "the-profile", tc.want)
	}
	// A key on an op that does not read it is a silently ignored knob.
	wantErr(t, `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "fakedsplit"
pos = ["1"]
mod = { host = "ya.ru" }
`, fullOpts(), "the-profile", "only read by hostfakesplit")
	wantErr(t, `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "hostfakesplit"
mod = { altorder = "x" }
`, fullOpts(), "the-profile", "not a number; use 0 or 1")
}

// TestLoadFragPos covers the ipfrag position knob and its nfqws bounds.
func TestLoadFragPos(t *testing.T) {
	for _, v := range []int{8, 24, 32, 9216} {
		s := loadTOML(t, `
name = "ok"
[[profile]]
name = "p"
[[profile.ops]]
op = "ipfrag2"
frag_pos = `+itoa(v)+`
`, fullOpts())
		got := s.Profiles[0].Ops[0].Params
		if got.FragPosTCP != v || got.FragPosUDP != v {
			t.Fatalf("frag pos = %d/%d, want %d", got.FragPosTCP, got.FragPosUDP, v)
		}
	}
	for _, tc := range []struct{ v, want string }{
		{"4", "outside nfqws' range"},
		{"9224", "outside nfqws' range"},
		{"-8", "outside nfqws' range"},
		{"12", "multiple of 8"},
	} {
		wantErr(t, `
name = "bad"
[[profile]]
name = "the-profile"
[[profile.ops]]
op = "ipfrag2"
frag_pos = `+tc.v+`
`, fullOpts(), "the-profile", tc.want)
	}
}

// TestLoadInlineDomainValidation rejects an inline domain the list parser would
// silently discard.
func TestLoadInlineDomainValidation(t *testing.T) {
	wantErr(t, `
name = "bad"
[[profile]]
name = "the-profile"
[profile.filter]
hostlist_domains = ["discord.media", "not a domain"]
[[profile.ops]]
op = "multisplit"
pos = ["1"]
`, fullOpts(), "the-profile", "filter.hostlist domain", "not a domain", "bare domain")

	// A wildcard prefix is accepted: the list layer strips it.
	s := loadTOML(t, `
name = "ok"
[[profile]]
name = "p"
[profile.filter]
hostlist_domains = ["*.discord.media"]
[[profile.ops]]
op = "multisplit"
pos = ["1"]
`, fullOpts())
	if !s.Profiles[0].Filter.Hostlist.Match("cdn.discord.media") {
		t.Fatal("*.discord.media should match cdn.discord.media")
	}
}

// TestLoadWSSizeOp compiles the wssize pseudo-op.
func TestLoadWSSizeOp(t *testing.T) {
	s := loadTOML(t, `
name = "ok"
[[profile]]
name = "p"
[[profile.ops]]
op = "wssize"
wssize = "128:6"
`, fullOpts())
	got := s.Profiles[0].Ops[0].Params
	if got.WSSize != 128 || got.WSSizeScale != 6 {
		t.Fatalf("wssize = %d:%d", got.WSSize, got.WSSizeScale)
	}
}

// ---------- LoadDir ----------

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	body := func(name string) string {
		return `
name = "` + name + `"
[[profile]]
[profile.filter]
proto = "tcp"
[[profile.ops]]
op = "multisplit"
pos = ["1"]
`
	}
	for _, n := range []string{
		"general (ALT10).toml",
		"general (ALT2).toml",
		"general (ALT).toml",
		"general.toml",
	} {
		write(t, dir, n, body(strings.TrimSuffix(n, ".toml")))
	}
	// Ignored: not a strategy file.
	write(t, dir, "notes.md", "hello")
	write(t, dir, ".hidden.toml", body("hidden"))

	got, err := LoadDir(dir, fullOpts())
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	want := []string{"general (ALT)", "general (ALT2)", "general (ALT10)", "general"}
	if len(got) != len(want) {
		t.Fatalf("LoadDir returned %d strategies, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Name != want[i] {
			t.Fatalf("order = %v, want %v", names(got), want)
		}
	}
	// An unnamed profile is numbered.
	if got[0].Profiles[0].Name != "#1" {
		t.Fatalf("default profile name = %q, want \"#1\"", got[0].Profiles[0].Name)
	}
	// The name falls back to the file name when the file omits it.
	write(t, dir, "unnamed.toml", `
[[profile]]
[[profile.ops]]
op = "multisplit"
pos = ["1"]
`)
	got, err = LoadDir(dir, fullOpts())
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	found := false
	for _, s := range got {
		if s.Name == "unnamed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a file without a name should be called after itself, got %v", names(got))
	}
}

func TestLoadDirErrors(t *testing.T) {
	if _, err := LoadDir(filepath.Join(t.TempDir(), "nope"), fullOpts()); err == nil {
		t.Fatal("LoadDir on a missing directory should fail")
	}
	if _, err := LoadDir(t.TempDir(), fullOpts()); err == nil || !strings.Contains(err.Error(), "no *.toml") {
		t.Fatalf("LoadDir on an empty directory: %v", err)
	}
	// One broken file fails the whole directory, naming itself.
	dir := t.TempDir()
	write(t, dir, "good.toml", `
name = "good"
[[profile]]
[[profile.ops]]
op = "multisplit"
pos = ["1"]
`)
	write(t, dir, "broken.toml", "name = \"broken\"\n[[profile]]\n[[profile.ops]]\nop = \"nope\"\n")
	_, err := LoadDir(dir, fullOpts())
	if err == nil || !strings.Contains(err.Error(), "broken.toml") {
		t.Fatalf("LoadDir should fail naming broken.toml, got %v", err)
	}
}

func TestLoadFileErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.toml"), fullOpts()); err == nil {
		t.Fatal("Load on a missing file should fail")
	}
	p := write(t, t.TempDir(), "broken.toml", "name = \n")
	if _, err := Load(p, fullOpts()); err == nil || !strings.Contains(err.Error(), "TOML") {
		t.Fatalf("Load on malformed TOML: %v", err)
	}
}

// ---------- Summary / Unsupported ----------

func TestSummary(t *testing.T) {
	s := loadTOML(t, udpQUICTOML, fullOpts())
	if got := s.Summary(); got != "quic-udp: 2 profiles, ops: fake, udplen" {
		t.Fatalf("Summary() = %q", got)
	}
	// Aliases collapse onto the canonical op name.
	s = loadTOML(t, `
name = "aliases"
[[profile]]
name = "p"
[[profile.ops]]
op = "split2"
pos = ["1"]
[[profile.ops]]
op = "multisplit"
pos = ["2"]
`, fullOpts())
	if got := s.Summary(); got != "aliases: 1 profile, ops: multisplit" {
		t.Fatalf("Summary() = %q", got)
	}
}

func TestUnsupportedIsEmptyForFullCaps(t *testing.T) {
	for _, fixture := range []string{seqovlMultisplitTOML, fakeFakedsplitTOML, udpQUICTOML} {
		s := loadTOML(t, fixture, fullOpts())
		if u := s.Unsupported(desync.FullCaps()); len(u) != 0 {
			t.Fatalf("%s: Unsupported(full) = %q", s.Name, u)
		}
		if u := s.Unsupported(desync.ProxyCaps()); len(u) == 0 {
			t.Fatalf("%s: the proxy transport cannot run this, but Unsupported is empty", s.Name)
		}
	}
}

// itoa keeps the fixture builders readable.
func itoa(v int) string { return strconv.Itoa(v) }

func names(ss []*Strategy) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.Name
	}
	return out
}
