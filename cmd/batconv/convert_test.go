package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// batDir is where the upstream .bat files were downloaded to.
const batDir = "../../.upstream/bat"

// tomlDir is the generated strategy directory this converter owns.
const tomlDir = "../../strategies"

func TestSlugName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"general.bat", "general"},
		{"general (ALT).bat", "general-alt"},
		{"general (ALT12).bat", "general-alt12"},
		{"general (EXP).bat", "general-exp"},
		{"general (FAKE TLS AUTO).bat", "general-fake-tls-auto"},
		{"general (FAKE TLS AUTO ALT2).bat", "general-fake-tls-auto-alt2"},
		{"general (SIMPLE FAKE ALT2).bat", "general-simple-fake-alt2"},
	} {
		if got := SlugName(tc.in); got != tc.want {
			t.Errorf("SlugName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestGameFilterFor(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		tcp, udp string
	}{
		{"off", "12", "12"},
		{"", "12", "12"},
		{"tcp", "1024-65535", "12"},
		{"udp", "12", "1024-65535"},
		{"all", "1024-65535", "1024-65535"},
	} {
		gf, err := GameFilterFor(tc.mode)
		if err != nil {
			t.Fatalf("GameFilterFor(%q): %v", tc.mode, err)
		}
		if gf.TCP != tc.tcp || gf.UDP != tc.udp {
			t.Errorf("GameFilterFor(%q) = %+v, want %s/%s", tc.mode, gf, tc.tcp, tc.udp)
		}
	}
	if _, err := GameFilterFor("nope"); err == nil {
		t.Error("GameFilterFor(nope) should fail")
	}
}

func TestTokenize(t *testing.T) {
	// "^!" is how a .bat escapes the literal '!' that selects winws' built-in
	// fake; quotes group a value that contains no spaces here but may.
	toks, err := Tokenize(`--a="x y" --dpi-desync-fake-tls=^! --b=1`, 7)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`--a=x y`, `--dpi-desync-fake-tls=!`, `--b=1`}
	if len(toks) != len(want) {
		t.Fatalf("got %d tokens %v, want %d", len(toks), toks, len(want))
	}
	for i := range want {
		if toks[i].Text != want[i] {
			t.Errorf("token %d = %q, want %q", i, toks[i].Text, want[i])
		}
		if toks[i].Line != 7 {
			t.Errorf("token %d line = %d, want 7", i, toks[i].Line)
		}
	}
	if _, err := Tokenize(`--a="unterminated`, 1); err == nil {
		t.Error("unterminated quote should fail")
	}
}

func TestSplitStatementJoinsContinuations(t *testing.T) {
	src := "@echo off\r\nset \"BIN=x\"\r\nstart \"z\" \"%BIN%winws.exe\" --wf-tcp=443 ^\r\n--filter-tcp=443 --dpi-desync=fake ^\r\n--new --filter-udp=443 --dpi-desync=fake\r\necho done\r\n"
	lines, nums, err := SplitStatement(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 {
		t.Fatalf("got %d lines %q, want 3", len(lines), lines)
	}
	if nums[0] != 3 || nums[2] != 5 {
		t.Errorf("line numbers = %v, want [3 4 5]", nums)
	}
	if strings.HasSuffix(lines[0], "^") {
		t.Errorf("continuation marker not stripped: %q", lines[0])
	}
	if _, _, err := SplitStatement("@echo off\n"); err == nil {
		t.Error("a .bat without winws.exe should fail")
	}
}

func TestConvertRejectsUnknownFlag(t *testing.T) {
	src := "start \"%BIN%winws.exe\" --wf-tcp=443 ^\n--filter-tcp=443 --dpi-desync=fake --totally-bogus=1\n"
	_, err := Convert("x.bat", []byte(src), GameFilter{TCP: "12", UDP: "12"})
	if err == nil {
		t.Fatal("unknown flag must fail the conversion")
	}
	for _, want := range []string{"x.bat", ":2", "--totally-bogus=1", "unknown winws flag"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

func TestConvertRejectsUnconsumedKnob(t *testing.T) {
	// multisplit never reads --dpi-desync-repeats (it calls no rawsend_rep in
	// zapret), so silently keeping the flag would be a lie.
	src := "start \"%BIN%winws.exe\" --wf-tcp=443 ^\n--filter-tcp=443 --dpi-desync=multisplit --dpi-desync-repeats=6\n"
	_, err := Convert("x.bat", []byte(src), GameFilter{TCP: "12", UDP: "12"})
	if err == nil || !strings.Contains(err.Error(), "--dpi-desync-repeats") {
		t.Fatalf("want unconsumed-knob error, got %v", err)
	}
}

func TestConvertGameFilterExpansion(t *testing.T) {
	src := "start \"%BIN%winws.exe\" --wf-tcp=443,%GameFilterTCP% --wf-udp=443,%GameFilterUDP% ^\n" +
		"--filter-tcp=%GameFilterTCP% --dpi-desync=multisplit\n"
	for _, tc := range []struct {
		mode      string
		wantTCP   []string
		wantPorts []string
	}{
		{"off", []string{"443", "12"}, []string{"12"}},
		{"all", []string{"443", "1024-65535"}, []string{"1024-65535"}},
	} {
		gf, err := GameFilterFor(tc.mode)
		if err != nil {
			t.Fatal(err)
		}
		res, err := Convert("x.bat", []byte(src), gf)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(res.File.Window.TCP, tc.wantTCP) {
			t.Errorf("%s: window.tcp = %v, want %v", tc.mode, res.File.Window.TCP, tc.wantTCP)
		}
		if !reflect.DeepEqual(res.File.Profiles[0].Filter.Ports, tc.wantPorts) {
			t.Errorf("%s: ports = %v, want %v", tc.mode, res.File.Profiles[0].Filter.Ports, tc.wantPorts)
		}
	}
}

// TestUpstreamConvertsAndRoundTrips converts every downloaded .bat, renders it
// and decodes the result back into strategy.File. The decoded value must equal
// the value the converter built: that is the guarantee that what we write is
// exactly what the loader will read.
func TestUpstreamConvertsAndRoundTrips(t *testing.T) {
	bats := upstreamBats(t)
	gf, err := GameFilterFor("off")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range bats {
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join(batDir, name))
			if err != nil {
				t.Fatal(err)
			}
			res, err := Convert(name, src, gf)
			if err != nil {
				t.Fatal(err)
			}
			var got strategy.File
			if _, err := toml.Decode(res.Marshal(), &got); err != nil {
				t.Fatalf("decoding generated TOML: %v\n%s", err, res.Marshal())
			}
			if !reflect.DeepEqual(got, res.File) {
				t.Errorf("round trip differs\n got: %#v\nwant: %#v", got, res.File)
			}
			// Every strategy must keep the shape flowseal gives it.
			if len(res.File.Profiles) < 6 {
				t.Errorf("only %d profiles", len(res.File.Profiles))
			}
			if len(res.File.Window.TCP) == 0 || len(res.File.Window.UDP) == 0 {
				t.Errorf("empty port window: %+v", res.File.Window)
			}
		})
	}
}

// TestGeneratedFilesAreUpToDate re-runs the conversion and compares it with the
// committed strategies/ directory, so a stale generated file fails CI.
func TestGeneratedFilesAreUpToDate(t *testing.T) {
	bats := upstreamBats(t)
	gf, err := GameFilterFor("off")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tomlDir); err != nil {
		t.Skipf("no %s: %v", tomlDir, err)
	}
	generated := map[string]bool{}
	for _, name := range bats {
		src, err := os.ReadFile(filepath.Join(batDir, name))
		if err != nil {
			t.Fatal(err)
		}
		res, err := Convert(name, src, gf)
		if err != nil {
			t.Fatal(err)
		}
		generated[res.OutName] = true
		onDisk, err := os.ReadFile(filepath.Join(tomlDir, res.OutName))
		if err != nil {
			t.Errorf("%s: %v (run `go run ./cmd/batconv`)", res.OutName, err)
			continue
		}
		if string(onDisk) != res.Marshal() {
			t.Errorf("%s is stale; run `go run ./cmd/batconv`", res.OutName)
		}
	}
	files, err := filepath.Glob(filepath.Join(tomlDir, "*.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(generated) {
		t.Errorf("strategies/ has %d .toml files, converter produces %d", len(files), len(generated))
	}
	for _, f := range files {
		if !generated[filepath.Base(f)] {
			t.Errorf("%s has no upstream .bat", filepath.Base(f))
		}
	}
}

// ---------- hand-checked expectations ----------
//
// The specs below were read off the .bat files by hand. They pin the exact
// meaning of the interesting slots of five representative strategies so a
// regression in the flag -> op mapping cannot slip through.

// opSpec is a compact, comparable projection of strategy.OpSpec.
type opSpec struct {
	op          string
	repeats     int
	fooling     string // comma joined
	badseq      string // "" when unset
	pos         string // comma joined
	seqovl      int
	seqovlPat   string
	pattern     string
	tlsMod      string
	mod         string // "k=v" pairs, sorted, comma joined
	fakeTLS     string
	fakeHTTP    string
	fakeQUIC    string
	fakeDiscord string
	fakeSTUN    string
	fakeUnknown string
	mode        string
	anyProto    bool
}

func project(o *strategy.OpSpec) opSpec {
	s := opSpec{
		op: o.Op, repeats: o.Repeats, fooling: strings.Join(o.Fooling, ","),
		pos: strings.Join(o.Pos, ","), seqovl: o.Seqovl, seqovlPat: o.SeqovlPattern,
		pattern: o.Pattern, tlsMod: o.TLSMod, fakeTLS: o.Fake.TLS,
		fakeHTTP: o.Fake.HTTP, fakeQUIC: o.Fake.QUIC,
		fakeDiscord: strings.Join(o.Fake.Discord, ","),
		fakeSTUN:    strings.Join(o.Fake.STUN, ","),
		fakeUnknown: strings.Join(o.Fake.UnknownUDP, ","),
		mode:        o.Mode, anyProto: o.AnyProtocol,
	}
	if o.BadSeqIncrement != nil {
		s.badseq = fmt.Sprint(*o.BadSeqIncrement)
	}
	if len(o.Mod) > 0 {
		keys := make([]string, 0, len(o.Mod))
		for k := range o.Mod {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = k + "=" + o.Mod[k]
		}
		s.mod = strings.Join(parts, ",")
	}
	return s
}

// profExp is a hand-written expectation for one profile.
type profExp struct {
	name     string
	proto    string
	ports    string // comma joined
	l3       string
	l7       string
	domains  string
	exclDoms string
	hostlist string
	ipset    string
	cutoff   string
	ops      []opSpec
}

func checkStrategy(t *testing.T, batName string, wantWindowTCP, wantWindowUDP string, want []profExp) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(batDir, batName))
	if err != nil {
		t.Skipf("no %s: %v", batName, err)
	}
	gf, err := GameFilterFor("off")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Convert(batName, src, gf)
	if err != nil {
		t.Fatal(err)
	}
	// Assert on the decoded form, not the in-memory one, so the TOML text is
	// what is being validated.
	var f strategy.File
	if _, err := toml.Decode(res.Marshal(), &f); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.Window.TCP, ","); got != wantWindowTCP {
		t.Errorf("window.tcp = %q, want %q", got, wantWindowTCP)
	}
	if got := strings.Join(f.Window.UDP, ","); got != wantWindowUDP {
		t.Errorf("window.udp = %q, want %q", got, wantWindowUDP)
	}
	if len(f.Profiles) != len(want) {
		t.Fatalf("got %d profiles, want %d", len(f.Profiles), len(want))
	}
	for i, w := range want {
		p := &f.Profiles[i]
		fl := &p.Filter
		check := func(what, got, exp string) {
			if got != exp {
				t.Errorf("profile %d (%s): %s = %q, want %q", i+1, p.Name, what, got, exp)
			}
		}
		check("name", p.Name, w.name)
		check("proto", fl.Proto, w.proto)
		check("ports", strings.Join(fl.Ports, ","), w.ports)
		check("l3", fl.L3, w.l3)
		check("l7", strings.Join(fl.L7, ","), w.l7)
		check("hostlist_domains", strings.Join(fl.HostlistDomains, ","), w.domains)
		check("hostlist_exclude_domains", strings.Join(fl.HostlistExcludeDomains, ","), w.exclDoms)
		check("hostlist", strings.Join(fl.Hostlist, ","), w.hostlist)
		check("ipset", strings.Join(fl.IPSet, ","), w.ipset)
		check("cutoff", p.Cutoff, w.cutoff)
		if len(p.Ops) != len(w.ops) {
			t.Errorf("profile %d (%s): got %d ops %v, want %d", i+1, p.Name, len(p.Ops), p.Ops, len(w.ops))
			continue
		}
		for j := range w.ops {
			if got := project(&p.Ops[j]); got != w.ops[j] {
				t.Errorf("profile %d (%s) op %d:\n got %+v\nwant %+v", i+1, p.Name, j+1, got, w.ops[j])
			}
		}
	}
}

// Shared constants of every flowseal strategy.
const (
	winTCP  = "80,443,2053,2083,2087,2096,8443,12"
	winUDP  = "443,19294-19344,50000-50100,12"
	genList = "list-general.txt,list-general-user.txt"
	googLst = "list-google.txt"
	allSet  = "ipset-all.txt"
	gQUIC   = "quic_initial_www_google_com.bin"
	gTLS    = "tls_clienthello_www_google_com.bin"
	maxTLS  = "tls_clienthello_max_ru.bin"
	dUDP    = "ACTIVE_DISCORD_UDP.bin"
	gameUDP = "ACTIVE_GAME_UDP.bin"
)

// voiceProfile is the UDP voice slot every strategy shares:
// --filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun
// --dpi-desync=fake --dpi-desync-fake-discord=... --dpi-desync-fake-stun=...
// --dpi-desync-repeats=N
func voiceProfile(idx, repeats int) profExp {
	return profExp{
		name:  fmt.Sprintf("p%d-udp-19294-19344_50000-50100", idx),
		proto: "udp", ports: "19294-19344,50000-50100", l7: "discord,stun",
		ops: []opSpec{{op: "fake", repeats: repeats, fakeDiscord: dUDP, fakeSTUN: dUDP}},
	}
}

func TestGeneralToml(t *testing.T) {
	ms := func(seqovl int, pat string, any bool) opSpec {
		return opSpec{op: "multisplit", pos: "1", seqovl: seqovl, seqovlPat: pat, anyProto: any}
	}
	checkStrategy(t, "general.bat", winTCP, winUDP, []profExp{
		{name: "p1-udp-443", proto: "udp", ports: "443", hostlist: genList,
			ops: []opSpec{{op: "fake", repeats: 6, fakeQUIC: gQUIC}}},
		voiceProfile(2, 6),
		{name: "p3-tcp-2053_2083_2087_2096_8443", proto: "tcp", ports: "2053,2083,2087,2096,8443",
			domains: "discord.media", ops: []opSpec{ms(681, gTLS, false)}},
		{name: "p4-tcp-443", proto: "tcp", ports: "443", hostlist: googLst,
			ops: []opSpec{ms(681, gTLS, false), {op: "ip_id", mode: "zero"}}},
		{name: "p5-tcp-80_443", proto: "tcp", ports: "80,443", hostlist: genList,
			ops: []opSpec{ms(568, "tls_clienthello_4pda_to.bin", false)}},
		{name: "p6-udp-443", proto: "udp", ports: "443", ipset: allSet,
			ops: []opSpec{{op: "fake", repeats: 6, fakeQUIC: gQUIC}}},
		{name: "p7-tcp-80_443_8443", proto: "tcp", ports: "80,443,8443", ipset: allSet,
			ops: []opSpec{ms(568, "tls_clienthello_4pda_to.bin", false)}},
		{name: "p8-tcp-12", proto: "tcp", ports: "12", ipset: allSet, cutoff: "n3",
			ops: []opSpec{ms(568, "tls_clienthello_4pda_to.bin", true)}},
		{name: "p9-udp-12", proto: "udp", ports: "12", ipset: allSet, cutoff: "n2",
			ops: []opSpec{{op: "fake", repeats: 12, fakeUnknown: gameUDP, anyProto: true}}},
	})
}

func TestGeneralAltToml(t *testing.T) {
	// fake,fakedsplit with repeats/fooling/badseq shared and the fakedsplit
	// filler pattern attached only to fakedsplit.
	fk := func(tls, http string, any bool) opSpec {
		return opSpec{op: "fake", repeats: 6, fooling: "ts", fakeTLS: tls, fakeHTTP: http, anyProto: any}
	}
	fs := func(any bool) opSpec {
		return opSpec{op: "fakedsplit", repeats: 6, fooling: "ts", pattern: "0x00", anyProto: any}
	}
	checkStrategy(t, "general (ALT).bat", winTCP, winUDP, []profExp{
		{name: "p1-udp-443", proto: "udp", ports: "443", hostlist: genList,
			ops: []opSpec{{op: "fake", repeats: 6, fakeQUIC: gQUIC}}},
		voiceProfile(2, 6),
		{name: "p3-tcp-2053_2083_2087_2096_8443", proto: "tcp", ports: "2053,2083,2087,2096,8443",
			domains: "discord.media", ops: []opSpec{fk(gTLS, "", false), fs(false)}},
		{name: "p4-tcp-443", proto: "tcp", ports: "443", hostlist: googLst,
			ops: []opSpec{fk(gTLS, "", false), fs(false), {op: "ip_id", mode: "zero"}}},
		// stun.bin + tls_clienthello_www_google_com.bin: FakeSpec.TLS keeps the last.
		{name: "p5-tcp-80_443", proto: "tcp", ports: "80,443", hostlist: genList,
			ops: []opSpec{fk(gTLS, maxTLS, false), fs(false)}},
		{name: "p6-udp-443", proto: "udp", ports: "443", ipset: allSet,
			ops: []opSpec{{op: "fake", repeats: 6, fakeQUIC: gQUIC}}},
		{name: "p7-tcp-80_443_8443", proto: "tcp", ports: "80,443,8443", ipset: allSet,
			ops: []opSpec{fk(gTLS, maxTLS, false), fs(false)}},
		{name: "p8-tcp-12", proto: "tcp", ports: "12", ipset: allSet, cutoff: "n4",
			ops: []opSpec{fk(gTLS, maxTLS, true), fs(true)}},
		{name: "p9-udp-12", proto: "udp", ports: "12", ipset: allSet, cutoff: "n3",
			ops: []opSpec{{op: "fake", repeats: 12, fakeUnknown: gameUDP, anyProto: true}}},
	})
}

func TestGeneralAlt3Toml(t *testing.T) {
	// fake,hostfakesplit: fake-tls-mod goes on fake, hostfakesplit-mod on
	// hostfakesplit, fooling on both (both inject).
	fk := func(sni, http string, any bool) opSpec {
		return opSpec{op: "fake", fooling: "ts", tlsMod: "rnd,dupsid,sni=" + sni, fakeHTTP: http, anyProto: any}
	}
	hfs := func(host string, any bool) opSpec {
		return opSpec{op: "hostfakesplit", fooling: "ts", mod: "altorder=1,host=" + host, anyProto: any}
	}
	checkStrategy(t, "general (ALT3).bat", winTCP, winUDP, []profExp{
		{name: "p1-udp-443", proto: "udp", ports: "443", hostlist: genList,
			ops: []opSpec{{op: "fake", repeats: 6, fakeQUIC: gQUIC}}},
		voiceProfile(2, 6),
		{name: "p3-tcp-2053_2083_2087_2096_8443", proto: "tcp", ports: "2053,2083,2087,2096,8443",
			domains: "discord.media",
			ops:     []opSpec{fk("www.google.com", "", false), hfs("www.google.com", false)}},
		{name: "p4-tcp-443", proto: "tcp", ports: "443", hostlist: googLst,
			ops: []opSpec{fk("www.google.com", "", false), hfs("www.google.com", false), {op: "ip_id", mode: "zero"}}},
		{name: "p5-tcp-80_443", proto: "tcp", ports: "80,443", hostlist: genList,
			ops: []opSpec{fk("ya.ru", maxTLS, false), hfs("ya.ru", false)}},
		{name: "p6-udp-443", proto: "udp", ports: "443", ipset: allSet,
			ops: []opSpec{{op: "fake", repeats: 6, fakeQUIC: gQUIC}}},
		{name: "p7-tcp-80_443_8443", proto: "tcp", ports: "80,443,8443", ipset: allSet,
			ops: []opSpec{fk("ya.ru", maxTLS, false), hfs("ya.ru", false)}},
		{name: "p8-tcp-12", proto: "tcp", ports: "12", ipset: allSet, cutoff: "n4",
			ops: []opSpec{fk("ya.ru", maxTLS, true), hfs("ya.ru", true)}},
		{name: "p9-udp-12", proto: "udp", ports: "12", ipset: allSet, cutoff: "n4",
			ops: []opSpec{{op: "fake", repeats: 10, fakeUnknown: gameUDP, anyProto: true}}},
	})
}

func TestGeneralFakeTLSAutoToml(t *testing.T) {
	// --dpi-desync-fake-tls=0x00000000 --dpi-desync-fake-tls=^! : the last wins
	// and '!' is winws' built-in fake, i.e. FakeSpec.TLS stays empty while
	// tls_mod carries the sni rewrite. split-pos belongs to multidisorder only.
	fk := func(http string, any bool) opSpec {
		return opSpec{op: "fake", repeats: 11, fooling: "badseq",
			tlsMod: "rnd,dupsid,sni=www.google.com", fakeHTTP: http, anyProto: any}
	}
	md := func(any bool) opSpec {
		return opSpec{op: "multidisorder", pos: "1,midsld", anyProto: any}
	}
	checkStrategy(t, "general (FAKE TLS AUTO).bat", winTCP, winUDP, []profExp{
		{name: "p1-udp-443", proto: "udp", ports: "443", hostlist: genList,
			ops: []opSpec{{op: "fake", repeats: 11, fakeQUIC: gQUIC}}},
		voiceProfile(2, 6),
		{name: "p3-tcp-2053_2083_2087_2096_8443", proto: "tcp", ports: "2053,2083,2087,2096,8443",
			domains: "discord.media", ops: []opSpec{fk("", false), md(false)}},
		{name: "p4-tcp-443", proto: "tcp", ports: "443", hostlist: googLst,
			ops: []opSpec{fk("", false), md(false), {op: "ip_id", mode: "zero"}}},
		{name: "p5-tcp-80_443", proto: "tcp", ports: "80,443", hostlist: genList,
			ops: []opSpec{fk(maxTLS, false), md(false)}},
		{name: "p6-udp-443", proto: "udp", ports: "443", ipset: allSet,
			ops: []opSpec{{op: "fake", repeats: 11, fakeQUIC: gQUIC}}},
		{name: "p7-tcp-80_443_8443", proto: "tcp", ports: "80,443,8443", ipset: allSet,
			ops: []opSpec{fk(maxTLS, false), md(false)}},
		{name: "p8-tcp-12", proto: "tcp", ports: "12", ipset: allSet, cutoff: "n4",
			ops: []opSpec{fk(maxTLS, true), md(true)}},
		{name: "p9-udp-12", proto: "udp", ports: "12", ipset: allSet, cutoff: "n2",
			ops: []opSpec{{op: "fake", repeats: 10, fakeUnknown: gameUDP, anyProto: true}}},
	})
}

func TestGeneralExpToml(t *testing.T) {
	// EXP is the only strategy with a port-less --filter-l7=quic profile, an
	// "unknown" L7 in the voice slot, --hostlist-exclude-domains, and multiple
	// fake-discord / fake-unknown-udp blobs (both of which FakeSpec keeps as
	// lists, so nothing is lost there).
	fkms := func(seqovl int, pat, tls, http string, repeats int, any bool) []opSpec {
		return []opSpec{
			{op: "fake", repeats: repeats, fooling: "ts", fakeTLS: tls, fakeHTTP: http, anyProto: any},
			{op: "multisplit", pos: "1", seqovl: seqovl, seqovlPat: pat, anyProto: any},
		}
	}
	checkStrategy(t, "general (EXP).bat", winTCP, winUDP, []profExp{
		{name: "p1-any-quic", proto: "any", l7: "quic", hostlist: genList,
			ops: []opSpec{{op: "fake", repeats: 11, fakeQUIC: gQUIC}}},
		{name: "p2-udp-19294-19344_50000-50100", proto: "udp",
			ports: "19294-19344,50000-50100", l7: "discord,stun,unknown",
			ops: []opSpec{{op: "fake", repeats: 4,
				fakeDiscord: gQUIC + "," + dUDP, fakeSTUN: dUDP,
				fakeUnknown: gQUIC + "," + dUDP}}},
		{name: "p3-tcp-2053_2083_2087_2096_8443", proto: "tcp", ports: "2053,2083,2087,2096,8443",
			domains: "discord.media", ops: fkms(681, gTLS, gTLS, "", 8, false)},
		{name: "p4-tcp-443", proto: "tcp", ports: "443", hostlist: googLst,
			ops: []opSpec{
				{op: "hostfakesplit", fooling: "ts", mod: "host=www.google.com"},
				{op: "ip_id", mode: "zero"},
			}},
		{name: "p5-tcp-80_443", proto: "tcp", ports: "80,443", hostlist: genList,
			ops: fkms(480, "stun2.bin", maxTLS, maxTLS, 4, false)},
		{name: "p6-udp-443", proto: "udp", ports: "443", ipset: allSet,
			ops: []opSpec{{op: "fake", repeats: 11, fakeQUIC: gQUIC}}},
		{name: "p7-tcp-80_443_8443", proto: "tcp", ports: "80,443,8443", ipset: allSet,
			exclDoms: "fonts.googleapis.com",
			ops:      fkms(480, "stun2.bin", maxTLS, maxTLS, 4, false)},
		{name: "p8-tcp-12", proto: "tcp", ports: "12", ipset: allSet, cutoff: "n4",
			ops: fkms(664, maxTLS, maxTLS, maxTLS, 8, true)},
		{name: "p9-udp-12", proto: "udp", ports: "12", ipset: allSet, cutoff: "n4",
			ops: []opSpec{{op: "fake", repeats: 5,
				fakeUnknown: "quic_initial_4pda.to.bin," + gameUDP, anyProto: true}}},
	})
}

// TestGeneratedFilesCompile puts every committed strategy through the real
// loader and records what desync.ProxyCaps() cannot honour. This is the check
// behind the converter's summary table, so it also guards the claim that the
// generated TOML is loadable at all.
func TestGeneratedFilesCompile(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(tomlDir, "*.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Skipf("no strategies in %s", tomlDir)
	}
	opts := strategy.LoadOpts{ListsDir: "../../lists", FakesDir: "../../fakes", Caps: desync.FullCaps()}
	if _, err := os.Stat(opts.ListsDir); err != nil {
		t.Skipf("no lists dir: %v", err)
	}
	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			s, err := strategy.Load(f, opts)
			if err != nil {
				t.Fatalf("does not compile: %v", err)
			}
			if len(s.Profiles) < 6 {
				t.Errorf("only %d compiled profiles", len(s.Profiles))
			}
			if s.Source == "" || !strings.HasSuffix(s.Source, ".bat") {
				t.Errorf("source = %q, want the upstream .bat name", s.Source)
			}
			// Every flowseal strategy leans on packet injection, so none of
			// them is fully runnable under the socket-level transport.
			if u := s.Unsupported(desync.ProxyCaps()); len(u) == 0 {
				t.Errorf("expected some ops to be unsupported under ProxyCaps")
			}
		})
	}
	// general.toml is the reference: fake needs injection, ip_id the IPv4 id.
	s, err := strategy.Load(filepath.Join(tomlDir, "general.toml"), opts)
	if err != nil {
		t.Fatal(err)
	}
	got := s.Unsupported(desync.ProxyCaps())
	for _, want := range []string{"fake", "ip_id"} {
		found := false
		for _, line := range got {
			if strings.HasPrefix(line, want+" (needs ") {
				found = true
			}
		}
		if !found {
			t.Errorf("general.toml: %s should be ProxyCaps-unsupported; got %v", want, got)
		}
	}
}

func upstreamBats(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(batDir)
	if err != nil {
		t.Skipf("no %s: %v", batDir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bat") || strings.EqualFold(e.Name(), "service.bat") {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Skip("no .bat files downloaded")
	}
	return out
}
