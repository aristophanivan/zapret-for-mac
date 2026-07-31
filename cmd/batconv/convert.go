// Command batconv converts Flowseal's winws *.bat strategies into our TOML
// strategy schema (internal/strategy.File).
//
// # Batch tokenisation
//
// A .bat statement is one logical line: physical lines are joined while the
// previous one ends with a bare "^" (cmd.exe's line continuation). Inside the
// joined line, `"` toggles quoting and, outside quotes, `^` escapes the next
// character (this is how Flowseal writes `--dpi-desync-fake-tls=^!`: the token
// value is a single `!`). Only the statement containing winws.exe is parsed;
// everything before the first `--` token in it is the `start ... winws.exe`
// prefix and is discarded.
//
// The batch variables are expanded to nothing but the bare file name, because
// our loader resolves hostlist/ipset names against the lists dir and fake blob
// names against the fakes dir:
//
//	%BIN%\x    -> x
//	%LISTS%\x  -> x
//
// %GameFilterTCP% / %GameFilterUDP% expand exactly like service.bat does:
// "12" (a dummy, unused port = feature disabled) by default, "1024-65535" for
// the side(s) enabled by -game-filter.
//
// # Knob -> op attachment rules
//
// winws keeps every --dpi-desync-* knob on the profile; our schema keeps them
// on the individual ops entry that consumes them. The attachment table below is
// derived from zapret's nfq/desync.c (which desync mode actually reads which
// field) rather than guessed:
//
//	repeats, fooling, badseq/badack/ts increment, ttl/autottl
//	    -> every op that injects a synthetic packet, i.e. the modes that call
//	       rawsend_rep() in desync.c: fake, fakeknown, rst, rstack, synack,
//	       syndata, fakedsplit, fakeddisorder, hostfakesplit, hopbyhop,
//	       destopt, ipfrag1.
//	       NOT multisplit/multidisorder/ipfrag2/udplen/tamper: those only
//	       reshape real data and never call rawsend_rep().
//	split_pos, seqovl, seqovl_pattern
//	    -> multisplit, multidisorder, fakedsplit, fakeddisorder
//	       (desync.c reads seqovl_pos only in those four cases).
//	fakedsplit_pattern            -> fakedsplit, fakeddisorder
//	hostfakesplit_mod (host=, altorder=, midhost) -> hostfakesplit
//	fake blobs (tls/http/quic/discord/stun/unknown_udp) and fake_tls_mod
//	    -> fake, fakeknown (the only modes that emit a protocol fake;
//	       fakedsplit uses fakedsplit-pattern and hostfakesplit generates its
//	       fake host names itself)
//	fake_syndata                  -> syndata
//	udplen_increment, udplen_pattern -> udplen
//	ipfrag_pos_tcp / ipfrag_pos_udp  -> ipfrag1, ipfrag2 (whichever matches
//	                                    the profile's filter proto)
//	any_protocol                  -> every op of the profile (winws gates the
//	                                  whole profile; our schema is per-op)
//	cutoff, start                 -> the profile, not an op
//	--ip-id / --wssize            -> their own pseudo-ops, appended after the
//	                                  --dpi-desync modes because both only
//	                                  mutate an already planned packet
//	                                  (desync.Phase == PhaseModify)
//
// A knob with no consuming op in its profile is a hard error: silently dropping
// it would produce a quietly weaker strategy. So is an unknown flag.
//
// # Known schema limitation
//
// strategy.FakeSpec.TLS/HTTP/QUIC are single strings while winws accepts
// --dpi-desync-fake-tls/-http/-quic repeatedly and sends every blob in order.
// When a profile lists several, the LAST one wins (it is also the one zapret
// pairs with a trailing --dpi-desync-fake-tls-mod) and the dropped values are
// reported as warnings and written into the generated file as comments.
package main

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// GameFilter holds the %GameFilterTCP% / %GameFilterUDP% expansions.
type GameFilter struct {
	TCP string
	UDP string
}

// gameFilterDisabled is flowseal's "feature off" placeholder: a port nobody
// uses, so the window and the game profiles match nothing.
const gameFilterDisabled = "12"

// gameFilterPorts is the range service.bat substitutes when the game filter is on.
const gameFilterPorts = "1024-65535"

// GameFilterFor maps the -game-filter mode onto the two placeholders exactly
// like service.bat's load_game_filter does.
func GameFilterFor(mode string) (GameFilter, error) {
	switch strings.ToLower(mode) {
	case "", "off":
		return GameFilter{TCP: gameFilterDisabled, UDP: gameFilterDisabled}, nil
	case "tcp":
		return GameFilter{TCP: gameFilterPorts, UDP: gameFilterDisabled}, nil
	case "udp":
		return GameFilter{TCP: gameFilterDisabled, UDP: gameFilterPorts}, nil
	case "all":
		return GameFilter{TCP: gameFilterPorts, UDP: gameFilterPorts}, nil
	}
	return GameFilter{}, fmt.Errorf("bad -game-filter %q (want off|tcp|udp|all)", mode)
}

// Token is one tokenised batch word plus the physical line it came from, so
// diagnostics can point at the original .bat.
type Token struct {
	Text string
	Line int
}

// Result is one converted strategy.
type Result struct {
	Source   string        // original .bat file name
	OutName  string        // generated file name, e.g. "general-alt2.toml"
	File     strategy.File // the schema value that gets marshalled
	Ops      []string      // distinct op names, in order of first appearance
	Warnings []string      // non-fatal fidelity losses, printed by main

	// Unsupported is strategy.Strategy.Unsupported(desync.ProxyCaps()) for the
	// file we wrote: "op (needs inject, seq)" lines, straight from the loader
	// so the summary can never disagree with what the daemon will decide.
	Unsupported []string

	// opNotes[profileIdx][opIdx] are comment lines emitted above that ops table.
	opNotes map[[2]int][]string
	// skipped counts profiles dropped because of winws' --skip.
	skipped int
}

// SlugName turns a .bat file name into a stable, shell-friendly base name:
// "general (FAKE TLS AUTO ALT2).bat" -> "general-fake-tls-auto-alt2".
func SlugName(bat string) string {
	s := strings.TrimSuffix(bat, ".bat")
	s = strings.TrimSuffix(s, ".BAT")
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		default:
			// Collapse every run of separators/punctuation into one dash.
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// SplitStatement finds the winws command line in a .bat and returns its
// physical lines with the trailing "^" continuations removed, together with the
// 1-based line number of each.
func SplitStatement(src string) ([]string, []int, error) {
	raw := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	start := -1
	for i, ln := range raw {
		if strings.Contains(ln, "winws.exe") {
			start = i
			break
		}
	}
	if start < 0 {
		return nil, nil, fmt.Errorf("no winws.exe command line found")
	}
	var lines []string
	var nums []int
	for i := start; i < len(raw); i++ {
		ln := strings.TrimRight(raw[i], " \t\r")
		cont := strings.HasSuffix(ln, "^")
		if cont {
			ln = ln[:len(ln)-1]
		}
		lines = append(lines, ln)
		nums = append(nums, i+1)
		if !cont {
			break
		}
	}
	return lines, nums, nil
}

// Tokenize splits one physical batch line into words. Quotes group, and outside
// quotes "^" escapes the next character (cmd.exe's escape); inside quotes "^"
// is literal.
func Tokenize(line string, lineNo int) ([]Token, error) {
	var out []Token
	var cur strings.Builder
	has := false
	inQ := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inQ:
			if c == '"' {
				inQ = false
			} else {
				cur.WriteByte(c)
			}
			has = true
		case c == '"':
			inQ = true
			has = true
		case c == '^':
			// Trailing "^" was already stripped by SplitStatement, so any "^"
			// still here escapes the next byte (e.g. "^!" -> "!").
			if i+1 < len(line) {
				i++
				cur.WriteByte(line[i])
				has = true
			}
		case c == ' ' || c == '\t':
			if has {
				out = append(out, Token{Text: cur.String(), Line: lineNo})
				cur.Reset()
				has = false
			}
		default:
			cur.WriteByte(c)
			has = true
		}
	}
	if inQ {
		return nil, fmt.Errorf("line %d: unterminated quote", lineNo)
	}
	if has {
		out = append(out, Token{Text: cur.String(), Line: lineNo})
	}
	return out, nil
}

// expandVars replaces the batch variables a strategy line can contain.
func expandVars(s string, gf GameFilter) string {
	s = strings.ReplaceAll(s, "%GameFilterTCP%", gf.TCP)
	s = strings.ReplaceAll(s, "%GameFilterUDP%", gf.UDP)
	s = strings.ReplaceAll(s, "%GameFilter%", gf.TCP)
	s = strings.ReplaceAll(s, "%BIN%", "")
	s = strings.ReplaceAll(s, "%LISTS%", "")
	return s
}

// baseName reduces a possibly path-qualified value to its file name: our loader
// resolves list and fake names against its own directories.
func baseName(s string) string {
	s = strings.ReplaceAll(s, "\\", "/")
	s = strings.TrimLeft(s, "/")
	return path.Base(s)
}

// blobRef normalises a --dpi-desync-fake-*/pattern value into what FakeSpec
// stores: a "0x..." literal verbatim, "!" (winws' built-in fake) as the empty
// string, anything else as a bare file name.
func blobRef(v string) (string, error) {
	switch {
	case v == "!":
		// '!' selects nfqws' built-in fake; our FakeSpec spells that "unset".
		return "", nil
	case strings.HasPrefix(v, "0x"), strings.HasPrefix(v, "0X"):
		return v, nil
	case strings.HasPrefix(v, "+"):
		// [+ofs]@file: our schema has nowhere to keep the offset.
		return "", fmt.Errorf("blob offset prefix %q is not representable", v)
	}
	return baseName(strings.TrimPrefix(v, "@")), nil
}

// parseInt32 accepts zapret's <int|0xHEX> increments. Hex values above
// MaxInt32 keep their two's-complement meaning, which is how nfqws reads them.
func parseInt32(v string) (int32, error) {
	neg := false
	s := v
	if strings.HasPrefix(s, "-") {
		neg, s = true, s[1:]
	} else {
		s = strings.TrimPrefix(s, "+")
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		u, err := strconv.ParseUint(s[2:], 16, 32)
		if err != nil {
			return 0, fmt.Errorf("bad hex value %q", v)
		}
		n := int32(uint32(u))
		if neg {
			n = -n
		}
		return n, nil
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("bad integer %q", v)
	}
	return int32(n), nil
}

// csv splits a comma separated flag value, dropping empties.
func csv(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------- op classification ----------

// injectOps are the --dpi-desync modes that put a synthetic packet on the wire
// (the rawsend_rep() call sites in nfq/desync.c). They are the modes that read
// repeats/fooling/ttl.
var injectOps = map[string]bool{
	"fake": true, "fakeknown": true, "rst": true, "rstack": true,
	"synack": true, "syndata": true, "fakedsplit": true, "fakeddisorder": true,
	"hostfakesplit": true, "hopbyhop": true, "destopt": true, "ipfrag1": true,
}

// splitPosOps read --dpi-desync-split-pos / -split-seqovl[-pattern].
var splitPosOps = map[string]bool{
	"multisplit": true, "multidisorder": true,
	"fakedsplit": true, "fakeddisorder": true,
}

// fakedPatternOps read --dpi-desync-fakedsplit-pattern.
var fakedPatternOps = map[string]bool{"fakedsplit": true, "fakeddisorder": true}

// fakeBlobOps emit a protocol fake, so they read --dpi-desync-fake-* and
// --dpi-desync-fake-tls-mod.
var fakeBlobOps = map[string]bool{"fake": true, "fakeknown": true}

// fragOps read --dpi-desync-ipfrag-pos-tcp/-udp.
var fragOps = map[string]bool{"ipfrag1": true, "ipfrag2": true}

// modeAliases maps winws' legacy --dpi-desync spellings onto the canonical op
// names, mirroring desync_mode_from_string() in nfq/desync.c.
var modeAliases = map[string]string{
	"split": "fakedsplit", "disorder": "fakeddisorder",
	"split2": "multisplit", "disorder2": "multidisorder",
}

// knownModes is every --dpi-desync mode nfqws accepts.
var knownModes = map[string]bool{
	"fake": true, "fakeknown": true, "rst": true, "rstack": true,
	"synack": true, "syndata": true, "fakedsplit": true, "fakeddisorder": true,
	"multisplit": true, "multidisorder": true, "hostfakesplit": true,
	"ipfrag1": true, "ipfrag2": true, "hopbyhop": true, "destopt": true,
	"udplen": true, "tamper": true, "none": true,
}

// ---------- per-profile accumulator ----------

// profileFlags is every winws flag of one --new section, before it is projected
// onto ops.
type profileFlags struct {
	line int // first line of the section, for diagnostics

	filterTCP, filterUDP string
	haveTCP, haveUDP     bool
	l3                   string
	l7                   []string

	hostlist, hostlistDomains       []string
	hostlistExclude, excludeDomains []string
	hostlistAuto                    string
	ipset, ipsetExclude             []string

	modes []string
	skip  bool

	repeats    int
	haveRep    bool
	ttl        string
	fooling    []string
	badseq     *int32
	badack     *int32
	tsInc      *int32
	anyProto   bool
	cutoff     string
	start      string
	splitPos   []string
	seqovl     int
	haveSeqovl bool
	seqovlPat  string
	fakedPat   string
	hfsMod     map[string]string
	hfsMidHost string

	fakeTLS, fakeHTTP, fakeQUIC          []string
	fakeDiscord, fakeSTUN, fakeUnknownUD []string
	fakeSynData                          string
	tlsMod                               string

	udplenInc  int
	udplenPat  string
	haveUDPLen bool

	ipID         string
	wssize       string
	wssizeCutoff string
	fragTCP      int
	fragUDP      int
	haveFragT    bool
	haveFragU    bool
	rawFlagSet   map[string]bool
}

func newProfileFlags(line int) *profileFlags {
	return &profileFlags{line: line, hfsMod: map[string]string{}, rawFlagSet: map[string]bool{}}
}

// ---------- conversion ----------

// Convert turns one .bat into a strategy.File. It fails on any flag it cannot
// map, naming the file, line and flag, so a dropped flag can never silently
// weaken a strategy.
func Convert(batName string, src []byte, gf GameFilter) (*Result, error) {
	lines, nums, err := SplitStatement(string(src))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", batName, err)
	}
	var toks []Token
	for i, ln := range lines {
		t, err := Tokenize(expandVars(ln, gf), nums[i])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", batName, err)
		}
		toks = append(toks, t...)
	}
	// Drop the `start "zapret: ..." /min "...winws.exe"` prefix.
	for len(toks) > 0 && !strings.HasPrefix(toks[0].Text, "--") {
		toks = toks[1:]
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("%s: winws command line has no -- flags", batName)
	}

	res := &Result{Source: batName, OutName: SlugName(batName) + ".toml", opNotes: map[[2]int][]string{}}
	slug := SlugName(batName)
	res.File.Name = slug
	res.File.Source = batName
	res.File.Description = "Converted from flowseal's winws strategy " + strconv.Quote(batName) + "."

	fail := func(t Token, format string, a ...any) error {
		return fmt.Errorf("%s:%d: %s: %s", batName, t.Line, t.Text, fmt.Sprintf(format, a...))
	}

	var sections []*profileFlags
	cur := newProfileFlags(toks[0].Line)
	for _, t := range toks {
		name, val, hasVal := strings.Cut(t.Text, "=")
		if !strings.HasPrefix(name, "--") {
			return nil, fail(t, "not a flag")
		}
		switch name {
		case "--new":
			sections = append(sections, cur)
			cur = newProfileFlags(t.Line)
			continue
		case "--skip":
			cur.skip = true
			continue
		}
		cur.rawFlagSet[name] = true

		// --wf-tcp/--wf-udp are global, not per-profile.
		switch name {
		case "--wf-tcp":
			res.File.Window.TCP = append(res.File.Window.TCP, csv(val)...)
			continue
		case "--wf-udp":
			res.File.Window.UDP = append(res.File.Window.UDP, csv(val)...)
			continue
		}

		if !hasVal {
			// Only valueless flags nfqws accepts get here.
			switch name {
			case "--dpi-desync-autottl":
				cur.ttl = "auto"
				continue
			}
			return nil, fail(t, "flag needs a value")
		}

		switch name {
		case "--filter-tcp":
			if err := checkPorts(val); err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.filterTCP, cur.haveTCP = val, true
		case "--filter-udp":
			if err := checkPorts(val); err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.filterUDP, cur.haveUDP = val, true
		case "--filter-l3":
			cur.l3 = val
		case "--filter-l7":
			cur.l7 = append(cur.l7, csv(val)...)
		case "--hostlist":
			cur.hostlist = append(cur.hostlist, baseName(val))
		case "--hostlist-domains":
			cur.hostlistDomains = append(cur.hostlistDomains, csv(val)...)
		case "--hostlist-exclude":
			cur.hostlistExclude = append(cur.hostlistExclude, baseName(val))
		case "--hostlist-exclude-domains":
			cur.excludeDomains = append(cur.excludeDomains, csv(val)...)
		case "--hostlist-auto":
			cur.hostlistAuto = baseName(val)
		case "--ipset":
			cur.ipset = append(cur.ipset, baseName(val))
		case "--ipset-exclude":
			cur.ipsetExclude = append(cur.ipsetExclude, baseName(val))

		case "--dpi-desync":
			for _, m := range csv(val) {
				if a, ok := modeAliases[m]; ok {
					m = a
				}
				if !knownModes[m] {
					return nil, fail(t, "unknown --dpi-desync mode %q", m)
				}
				if m != "none" {
					cur.modes = append(cur.modes, m)
				}
			}
		case "--dpi-desync-repeats":
			n, err := strconv.Atoi(val)
			if err != nil || n < 1 {
				return nil, fail(t, "bad repeats count")
			}
			cur.repeats, cur.haveRep = n, true
		case "--dpi-desync-ttl":
			if _, err := strconv.Atoi(val); err != nil {
				return nil, fail(t, "bad ttl")
			}
			if !strings.HasPrefix(cur.ttl, "auto") {
				cur.ttl = val
			}
		case "--dpi-desync-autottl":
			switch val {
			case "-", "0:0-0":
				// autottl explicitly disabled; leave any plain --dpi-desync-ttl.
			case "":
				cur.ttl = "auto"
			default:
				cur.ttl = "auto:" + val
			}
		case "--dpi-desync-fooling":
			for _, f := range csv(val) {
				if _, ok := desync.FoolNames[f]; !ok {
					return nil, fail(t, "unknown fooling mode %q", f)
				}
				if f != "none" {
					cur.fooling = append(cur.fooling, f)
				}
			}
		case "--dpi-desync-badseq-increment":
			n, err := parseInt32(val)
			if err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.badseq = &n
		case "--dpi-desync-badack-increment":
			n, err := parseInt32(val)
			if err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.badack = &n
		case "--dpi-desync-ts-increment":
			n, err := parseInt32(val)
			if err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.tsInc = &n
		case "--dpi-desync-any-protocol":
			switch val {
			case "0":
				cur.anyProto = false
			case "1":
				cur.anyProto = true
			default:
				return nil, fail(t, "want 0 or 1")
			}
		case "--dpi-desync-cutoff":
			if err := checkCounter(val); err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.cutoff = val
		case "--dpi-desync-start":
			if err := checkCounter(val); err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.start = val
		case "--dpi-desync-split-pos":
			cur.splitPos = append(cur.splitPos, csv(val)...)
		case "--dpi-desync-split-seqovl":
			n, err := strconv.Atoi(val)
			if err != nil {
				// A marker-relative seqovl has no field in OpSpec (int).
				return nil, fail(t, "only an absolute seqovl is representable")
			}
			cur.seqovl, cur.haveSeqovl = n, true
		case "--dpi-desync-split-seqovl-pattern":
			b, err := blobRef(val)
			if err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.seqovlPat = b
		case "--dpi-desync-fakedsplit-pattern":
			b, err := blobRef(val)
			if err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.fakedPat = b
		case "--dpi-desync-fakedsplit-mod":
			// Same mod vocabulary as hostfakesplit's; OpSpec.Mod carries both.
			for _, m := range csv(val) {
				k, v, _ := strings.Cut(m, "=")
				if k == "none" {
					continue
				}
				cur.hfsMod[k] = v
			}
		case "--dpi-desync-hostfakesplit-mod":
			for _, m := range csv(val) {
				k, v, _ := strings.Cut(m, "=")
				if k == "none" {
					continue
				}
				switch k {
				case "host", "altorder", "midhost":
					cur.hfsMod[k] = v
				default:
					return nil, fail(t, "unknown hostfakesplit mod %q", k)
				}
			}
		case "--dpi-desync-hostfakesplit-midhost":
			cur.hfsMidHost = val
		case "--dpi-desync-fake-tls":
			b, err := blobRef(val)
			if err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.fakeTLS = append(cur.fakeTLS, b)
		case "--dpi-desync-fake-tls-mod":
			cur.tlsMod = val
		case "--dpi-desync-fake-http":
			b, err := blobRef(val)
			if err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.fakeHTTP = append(cur.fakeHTTP, b)
		case "--dpi-desync-fake-quic":
			b, err := blobRef(val)
			if err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.fakeQUIC = append(cur.fakeQUIC, b)
		case "--dpi-desync-fake-discord":
			b, err := blobRef(val)
			if err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.fakeDiscord = append(cur.fakeDiscord, b)
		case "--dpi-desync-fake-stun":
			b, err := blobRef(val)
			if err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.fakeSTUN = append(cur.fakeSTUN, b)
		case "--dpi-desync-fake-unknown-udp":
			b, err := blobRef(val)
			if err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.fakeUnknownUD = append(cur.fakeUnknownUD, b)
		case "--dpi-desync-fake-syndata":
			b, err := blobRef(val)
			if err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.fakeSynData = b
		case "--dpi-desync-udplen-increment":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fail(t, "bad udplen increment")
			}
			cur.udplenInc, cur.haveUDPLen = n, true
		case "--dpi-desync-udplen-pattern":
			b, err := blobRef(val)
			if err != nil {
				return nil, fail(t, "%v", err)
			}
			cur.udplenPat = b
		case "--dpi-desync-ipfrag-pos-tcp":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fail(t, "bad ipfrag pos")
			}
			cur.fragTCP, cur.haveFragT = n, true
		case "--dpi-desync-ipfrag-pos-udp":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fail(t, "bad ipfrag pos")
			}
			cur.fragUDP, cur.haveFragU = n, true
		case "--ip-id":
			switch val {
			case "zero", "seq", "seqgroup", "same":
				cur.ipID = val
			case "rnd", "random":
				cur.ipID = "random"
			default:
				return nil, fail(t, "unsupported --ip-id mode %q", val)
			}
		case "--wssize":
			cur.wssize = val
		case "--wssize-cutoff":
			// wssize's cutoff has no TOML field of its own (types.go is a
			// contract file), so the loader reads it from OpSpec.Mod, where
			// "cutoff" is wssize's key. Validated here so a bad counter fails
			// during conversion rather than at strategy load.
			if _, err := strategy.ParseCounter(val); err != nil {
				return nil, fail(t, "bad --wssize-cutoff %q: %v", val, err)
			}
			cur.wssizeCutoff = val
		default:
			return nil, fail(t, "unknown winws flag")
		}
	}
	sections = append(sections, cur)

	for _, sec := range sections {
		if sec.skip {
			res.skipped++
			continue
		}
		prof, warns, err := buildProfile(batName, len(res.File.Profiles)+1, sec)
		if err != nil {
			return nil, err
		}
		res.File.Profiles = append(res.File.Profiles, *prof)
		pi := len(res.File.Profiles) - 1
		for _, w := range warns {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: profile %s: %s", batName, prof.Name, w.text))
			if w.op >= 0 {
				k := [2]int{pi, w.op}
				res.opNotes[k] = append(res.opNotes[k], "batconv: "+w.text)
			}
		}
	}
	if len(res.File.Profiles) == 0 {
		return nil, fmt.Errorf("%s: no profiles", batName)
	}

	seen := map[string]bool{}
	for i := range res.File.Profiles {
		for _, op := range res.File.Profiles[i].Ops {
			if !seen[op.Op] {
				seen[op.Op] = true
				res.Ops = append(res.Ops, op.Op)
			}
		}
	}
	return res, nil
}

// warning is a fidelity note; op is the ops index it belongs to, or -1.
type warning struct {
	text string
	op   int
}

// buildProfile projects one --new section's flags onto a ProfileSpec, applying
// the knob -> op attachment table documented at the top of this file.
func buildProfile(batName string, idx int, sec *profileFlags) (*strategy.ProfileSpec, []warning, error) {
	var prof strategy.ProfileSpec
	var warns []warning

	f := &prof.Filter
	switch {
	case sec.haveTCP && sec.haveUDP:
		return nil, nil, fmt.Errorf("%s:%d: profile sets both --filter-tcp and --filter-udp; FilterSpec.Proto holds one", batName, sec.line)
	case sec.haveTCP:
		f.Proto = "tcp"
		f.Ports = portList(sec.filterTCP)
	case sec.haveUDP:
		f.Proto = "udp"
		f.Ports = portList(sec.filterUDP)
	default:
		f.Proto = "any"
	}
	if sec.l3 != "" {
		if l3 := csv(sec.l3); len(l3) == 1 {
			f.L3 = l3[0]
		} else {
			// "ipv4,ipv6" is the same as no restriction.
			f.L3 = "any"
		}
	}
	f.L7 = sec.l7
	f.Hostlist = sec.hostlist
	f.HostlistDomains = sec.hostlistDomains
	f.HostlistExclude = sec.hostlistExclude
	f.HostlistExcludeDomains = sec.excludeDomains
	f.HostlistAuto = sec.hostlistAuto
	f.IPSet = sec.ipset
	f.IPSetExclude = sec.ipsetExclude

	prof.Cutoff = sec.cutoff
	prof.Start = sec.start
	prof.Name = profileName(idx, f)

	// Build the ops list: the --dpi-desync modes in order, then the pseudo-ops
	// that only mutate an already planned packet.
	modes := sec.modes
	if len(modes) == 0 && sec.ipID == "" && sec.wssize == "" {
		return nil, nil, fmt.Errorf("%s:%d: profile has no --dpi-desync and no --ip-id/--wssize", batName, sec.line)
	}

	// consumed tracks whether each shared knob found at least one taker.
	consumed := map[string]bool{}
	for _, m := range modes {
		op := strategy.OpSpec{Op: m, AnyProtocol: sec.anyProto}

		if injectOps[m] {
			if sec.haveRep {
				op.Repeats = sec.repeats
				consumed["repeats"] = true
			}
			if sec.ttl != "" {
				op.TTL = sec.ttl
				consumed["ttl"] = true
			}
			if len(sec.fooling) > 0 {
				op.Fooling = sec.fooling
				consumed["fooling"] = true
			}
			if sec.badseq != nil {
				v := *sec.badseq
				op.BadSeqIncrement = &v
				consumed["badseq"] = true
			}
			if sec.badack != nil {
				v := *sec.badack
				op.BadAckIncrement = &v
				consumed["badack"] = true
			}
			if sec.tsInc != nil {
				v := *sec.tsInc
				op.TSIncrement = &v
				consumed["ts"] = true
			}
		}
		if splitPosOps[m] {
			op.Pos = sec.splitPos
			if len(sec.splitPos) > 0 {
				consumed["split-pos"] = true
			}
			if sec.haveSeqovl {
				op.Seqovl = sec.seqovl
				consumed["seqovl"] = true
			}
			if sec.seqovlPat != "" {
				op.SeqovlPattern = sec.seqovlPat
				consumed["seqovl-pattern"] = true
			}
		}
		if fakedPatternOps[m] && sec.fakedPat != "" {
			op.Pattern = sec.fakedPat
			consumed["fakedsplit-pattern"] = true
		}
		if m == "hostfakesplit" || m == "fakedsplit" || m == "fakeddisorder" {
			if len(sec.hfsMod) > 0 {
				op.Mod = map[string]string{}
				for k, v := range sec.hfsMod {
					op.Mod[k] = v
				}
				consumed["mod"] = true
			}
			if m == "hostfakesplit" && sec.hfsMidHost != "" {
				if op.Mod == nil {
					op.Mod = map[string]string{}
				}
				op.Mod["midhost"] = sec.hfsMidHost
				consumed["midhost"] = true
			}
		}
		if fakeBlobOps[m] {
			last := func(kind string, vals []string) string {
				if len(vals) == 0 {
					return ""
				}
				consumed["fake-"+kind] = true
				if len(vals) > 1 {
					// FakeSpec keeps one blob per TCP/QUIC kind; winws would
					// send them all, in order. Keep the last (the one a
					// trailing -fake-tls-mod pairs with) and say what was lost.
					warns = append(warns, warning{
						text: fmt.Sprintf("--dpi-desync-fake-%s given %d times (%s); schema keeps one, using %s",
							kind, len(vals), strings.Join(quoteAll(vals), ", "), describeBlob(vals[len(vals)-1])),
						op: len(prof.Ops),
					})
				}
				return vals[len(vals)-1]
			}
			op.Fake.TLS = last("tls", sec.fakeTLS)
			op.Fake.HTTP = last("http", sec.fakeHTTP)
			op.Fake.QUIC = last("quic", sec.fakeQUIC)
			if len(sec.fakeDiscord) > 0 {
				op.Fake.Discord = sec.fakeDiscord
				consumed["fake-discord"] = true
			}
			if len(sec.fakeSTUN) > 0 {
				op.Fake.STUN = sec.fakeSTUN
				consumed["fake-stun"] = true
			}
			if len(sec.fakeUnknownUD) > 0 {
				op.Fake.UnknownUDP = sec.fakeUnknownUD
				consumed["fake-unknown-udp"] = true
			}
			if sec.tlsMod != "" {
				op.TLSMod = sec.tlsMod
				consumed["fake-tls-mod"] = true
			}
		}
		if m == "syndata" && sec.fakeSynData != "" {
			op.Fake.SynData = sec.fakeSynData
			consumed["fake-syndata"] = true
		}
		if m == "udplen" {
			if sec.haveUDPLen {
				op.UDPLenIncrement = sec.udplenInc
				consumed["udplen-increment"] = true
			}
			if sec.udplenPat != "" {
				op.UDPLenPattern = sec.udplenPat
				consumed["udplen-pattern"] = true
			}
		}
		if fragOps[m] {
			// One FragPos field, so pick the one matching the filter proto.
			switch {
			case sec.haveFragT && sec.haveFragU && f.Proto == "any":
				return nil, nil, fmt.Errorf("%s:%d: both --dpi-desync-ipfrag-pos-tcp and -udp on a proto-agnostic profile; OpSpec.FragPos holds one", batName, sec.line)
			case sec.haveFragU && (f.Proto == "udp" || !sec.haveFragT):
				op.FragPos = sec.fragUDP
				consumed["ipfrag-pos-udp"] = true
			case sec.haveFragT:
				op.FragPos = sec.fragTCP
				consumed["ipfrag-pos-tcp"] = true
			}
		}
		prof.Ops = append(prof.Ops, op)
	}

	if sec.wssize != "" {
		op := strategy.OpSpec{Op: "wssize", WSSize: sec.wssize, AnyProtocol: sec.anyProto}
		if sec.wssizeCutoff != "" {
			op.Mod = map[string]string{"cutoff": sec.wssizeCutoff}
			consumed["wssize-cutoff"] = true
		}
		prof.Ops = append(prof.Ops, op)
	}
	if sec.ipID != "" {
		prof.Ops = append(prof.Ops, strategy.OpSpec{Op: "ip_id", Mode: sec.ipID, AnyProtocol: sec.anyProto})
	}

	// Refuse to drop a knob nobody took: that is a quietly weaker strategy.
	type req struct {
		set  bool
		name string
		key  string
	}
	for _, r := range []req{
		{sec.haveRep, "--dpi-desync-repeats", "repeats"},
		{sec.ttl != "", "--dpi-desync-ttl/-autottl", "ttl"},
		{len(sec.fooling) > 0, "--dpi-desync-fooling", "fooling"},
		{sec.badseq != nil, "--dpi-desync-badseq-increment", "badseq"},
		{sec.badack != nil, "--dpi-desync-badack-increment", "badack"},
		{sec.tsInc != nil, "--dpi-desync-ts-increment", "ts"},
		{len(sec.splitPos) > 0, "--dpi-desync-split-pos", "split-pos"},
		{sec.haveSeqovl, "--dpi-desync-split-seqovl", "seqovl"},
		{sec.seqovlPat != "", "--dpi-desync-split-seqovl-pattern", "seqovl-pattern"},
		{sec.fakedPat != "", "--dpi-desync-fakedsplit-pattern", "fakedsplit-pattern"},
		{len(sec.hfsMod) > 0, "--dpi-desync-hostfakesplit-mod/-fakedsplit-mod", "mod"},
		{sec.hfsMidHost != "", "--dpi-desync-hostfakesplit-midhost", "midhost"},
		{len(sec.fakeTLS) > 0, "--dpi-desync-fake-tls", "fake-tls"},
		{sec.tlsMod != "", "--dpi-desync-fake-tls-mod", "fake-tls-mod"},
		{len(sec.fakeHTTP) > 0, "--dpi-desync-fake-http", "fake-http"},
		{len(sec.fakeQUIC) > 0, "--dpi-desync-fake-quic", "fake-quic"},
		{len(sec.fakeDiscord) > 0, "--dpi-desync-fake-discord", "fake-discord"},
		{len(sec.fakeSTUN) > 0, "--dpi-desync-fake-stun", "fake-stun"},
		{len(sec.fakeUnknownUD) > 0, "--dpi-desync-fake-unknown-udp", "fake-unknown-udp"},
		{sec.fakeSynData != "", "--dpi-desync-fake-syndata", "fake-syndata"},
		{sec.haveUDPLen, "--dpi-desync-udplen-increment", "udplen-increment"},
		{sec.udplenPat != "", "--dpi-desync-udplen-pattern", "udplen-pattern"},
		{sec.haveFragT, "--dpi-desync-ipfrag-pos-tcp", "ipfrag-pos-tcp"},
		{sec.haveFragU, "--dpi-desync-ipfrag-pos-udp", "ipfrag-pos-udp"},
		// --wssize-cutoff rides the wssize op's Mod, so it is dropped whenever
		// --wssize itself is absent.
		{sec.wssizeCutoff != "", "--wssize-cutoff", "wssize-cutoff"},
	} {
		if r.set && !consumed[r.key] {
			return nil, nil, fmt.Errorf("%s:%d: %s has no consuming op in --dpi-desync=%s",
				batName, sec.line, r.name, strings.Join(modes, ","))
		}
	}
	return &prof, warns, nil
}

func quoteAll(v []string) []string {
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = describeBlob(s)
	}
	return out
}

// describeBlob names a FakeSpec value for diagnostics; the empty string is how
// we spell winws' built-in fake ("!").
func describeBlob(s string) string {
	if s == "" {
		return `built-in fake ("!")`
	}
	return strconv.Quote(s)
}

// portList turns a --filter-tcp/-udp value into PortSpec entries; "*" means any.
func portList(v string) []string {
	if v == "*" {
		return nil
	}
	return csv(v)
}

// checkPorts rejects the port syntaxes FilterSpec.Ports cannot hold.
func checkPorts(v string) error {
	if v == "*" {
		return nil
	}
	for _, p := range csv(v) {
		if strings.HasPrefix(p, "~") {
			return fmt.Errorf("negated port filter %q is not representable", p)
		}
		lo, hi, isRange := strings.Cut(p, "-")
		if _, err := strconv.ParseUint(lo, 10, 16); err != nil {
			return fmt.Errorf("bad port %q", p)
		}
		if isRange {
			if _, err := strconv.ParseUint(hi, 10, 16); err != nil {
				return fmt.Errorf("bad port range %q", p)
			}
		}
	}
	return nil
}

// checkCounter validates a --dpi-desync-start/-cutoff value ([n|d|s]N).
func checkCounter(v string) error {
	s := v
	if s == "" {
		return fmt.Errorf("empty counter")
	}
	switch s[0] {
	case 'n', 'd', 's':
		s = s[1:]
	}
	if _, err := strconv.Atoi(s); err != nil {
		return fmt.Errorf("bad counter %q (want [n|d|s]N)", v)
	}
	return nil
}

// profileName builds a stable, human-readable profile name from its position
// and filter, so `zaprctl show` and engine logs can name a slot.
func profileName(idx int, f *strategy.FilterSpec) string {
	tag := f.Proto
	if tag == "" {
		tag = "any"
	}
	var detail string
	switch {
	case len(f.Ports) > 0:
		detail = strings.Join(f.Ports, "_")
	case len(f.L7) > 0:
		detail = strings.Join(f.L7, "_")
	default:
		detail = "all"
	}
	return fmt.Sprintf("p%d-%s-%s", idx, tag, detail)
}

// ---------- TOML output ----------

// Marshal renders a converted strategy as TOML. It writes the fields our schema
// declares, skipping zero values, and prefixes the file with a generated-by
// header so nobody hand-edits it by accident.
func (r *Result) Marshal() string {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	p("# Generated by batconv from %q (Flowseal/zapret-discord-youtube).\n", r.Source)
	p("# DO NOT EDIT: hand edits are overwritten the next time batconv runs.\n")
	p("# Knob -> op attachment rules are documented in cmd/batconv/convert.go.\n")
	if r.skipped > 0 {
		p("# %d upstream profile(s) carried --skip and were dropped.\n", r.skipped)
	}
	p("\n")
	p("name = %s\n", tomlStr(r.File.Name))
	p("description = %s\n", tomlStr(r.File.Description))
	p("source = %s\n", tomlStr(r.File.Source))
	p("\n[window]\n")
	if len(r.File.Window.TCP) > 0 {
		p("tcp = %s\n", tomlArr(r.File.Window.TCP))
	}
	if len(r.File.Window.UDP) > 0 {
		p("udp = %s\n", tomlArr(r.File.Window.UDP))
	}

	for pi := range r.File.Profiles {
		prof := &r.File.Profiles[pi]
		p("\n[[profile]]\n")
		p("name = %s\n", tomlStr(prof.Name))
		if prof.Cutoff != "" {
			p("cutoff = %s\n", tomlStr(prof.Cutoff))
		}
		if prof.Start != "" {
			p("start = %s\n", tomlStr(prof.Start))
		}
		if prof.OnUnsupported != "" {
			p("on_unsupported = %s\n", tomlStr(prof.OnUnsupported))
		}

		f := &prof.Filter
		p("\n[profile.filter]\n")
		if f.Proto != "" {
			p("proto = %s\n", tomlStr(f.Proto))
		}
		for _, kv := range []struct {
			k string
			v []string
		}{
			{"ports", f.Ports},
			{"l7", f.L7},
			{"hostlist", f.Hostlist},
			{"hostlist_domains", f.HostlistDomains},
			{"hostlist_exclude", f.HostlistExclude},
			{"hostlist_exclude_domains", f.HostlistExcludeDomains},
			{"ipset", f.IPSet},
			{"ipset_exclude", f.IPSetExclude},
		} {
			if len(kv.v) > 0 {
				p("%s = %s\n", kv.k, tomlArr(kv.v))
			}
		}
		if f.L3 != "" {
			p("l3 = %s\n", tomlStr(f.L3))
		}
		if f.HostlistAuto != "" {
			p("hostlist_auto = %s\n", tomlStr(f.HostlistAuto))
		}

		for oi := range prof.Ops {
			op := &prof.Ops[oi]
			p("\n")
			for _, note := range r.opNotes[[2]int{pi, oi}] {
				p("# %s\n", note)
			}
			p("[[profile.ops]]\n")
			p("op = %s\n", tomlStr(op.Op))
			if op.Repeats != 0 {
				p("repeats = %d\n", op.Repeats)
			}
			if op.TTL != "" {
				p("ttl = %s\n", tomlStr(op.TTL))
			}
			if len(op.Fooling) > 0 {
				p("fooling = %s\n", tomlArr(op.Fooling))
			}
			if op.BadSeqIncrement != nil {
				p("badseq_increment = %d\n", *op.BadSeqIncrement)
			}
			if op.BadAckIncrement != nil {
				p("badack_increment = %d\n", *op.BadAckIncrement)
			}
			if op.TSIncrement != nil {
				p("ts_increment = %d\n", *op.TSIncrement)
			}
			if len(op.Pos) > 0 {
				p("pos = %s\n", tomlArr(op.Pos))
			}
			if op.Seqovl != 0 {
				p("seqovl = %d\n", op.Seqovl)
			}
			if op.SeqovlPattern != "" {
				p("seqovl_pattern = %s\n", tomlStr(op.SeqovlPattern))
			}
			if op.Pattern != "" {
				p("pattern = %s\n", tomlStr(op.Pattern))
			}
			if op.TLSMod != "" {
				p("tls_mod = %s\n", tomlStr(op.TLSMod))
			}
			if op.UDPLenIncrement != 0 {
				p("udplen_increment = %d\n", op.UDPLenIncrement)
			}
			if op.UDPLenPattern != "" {
				p("udplen_pattern = %s\n", tomlStr(op.UDPLenPattern))
			}
			if op.WSSize != "" {
				p("wssize = %s\n", tomlStr(op.WSSize))
			}
			if op.Mode != "" {
				p("mode = %s\n", tomlStr(op.Mode))
			}
			if op.FragPos != 0 {
				p("frag_pos = %d\n", op.FragPos)
			}
			if op.AnyProtocol {
				p("any_protocol = true\n")
			}
			if fk := op.Fake; fk.TLS != "" || fk.HTTP != "" || fk.QUIC != "" ||
				len(fk.Discord) > 0 || len(fk.STUN) > 0 || len(fk.UnknownUDP) > 0 || fk.SynData != "" {
				p("\n[profile.ops.fake]\n")
				if fk.TLS != "" {
					p("tls = %s\n", tomlStr(fk.TLS))
				}
				if fk.HTTP != "" {
					p("http = %s\n", tomlStr(fk.HTTP))
				}
				if fk.QUIC != "" {
					p("quic = %s\n", tomlStr(fk.QUIC))
				}
				if len(fk.Discord) > 0 {
					p("discord = %s\n", tomlArr(fk.Discord))
				}
				if len(fk.STUN) > 0 {
					p("stun = %s\n", tomlArr(fk.STUN))
				}
				if len(fk.UnknownUDP) > 0 {
					p("unknown_udp = %s\n", tomlArr(fk.UnknownUDP))
				}
				if fk.SynData != "" {
					p("syndata = %s\n", tomlStr(fk.SynData))
				}
			}
			if len(op.Mod) > 0 {
				p("\n[profile.ops.mod]\n")
				keys := make([]string, 0, len(op.Mod))
				for k := range op.Mod {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					p("%s = %s\n", k, tomlStr(op.Mod[k]))
				}
			}
		}
	}
	return b.String()
}

// tomlStr renders a TOML basic string.
func tomlStr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if c < 0x20 {
				fmt.Fprintf(&b, `\u%04X`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// tomlArr renders a TOML inline array of strings.
func tomlArr(v []string) string {
	parts := make([]string, len(v))
	for i, s := range v {
		parts[i] = tomlStr(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
