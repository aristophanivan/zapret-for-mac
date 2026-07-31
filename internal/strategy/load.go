package strategy

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/lists"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// Load reads one TOML strategy file and compiles it into a *Strategy the engine
// can run: every op is resolved through desync.Lookup, every knob is validated
// against nfqws' own bounds, and every hostlist/ipset named by a filter is
// parsed from o.ListsDir.
//
// Compilation is strict on purpose. A strategy is loaded once, at activation, and
// then drives every packet — a typo that silently disables a desync would look
// like "the DPI got smarter", so anything unrecognised is an error naming the
// file, the profile, the op and what to write instead.
func Load(path string, o LoadOpts) (*Strategy, error) {
	return compileFile(path, o, lists.NewSet(o.ListsDir))
}

// LoadDir compiles every *.toml file in dir.
//
// Files come back in flowseal's strategy-menu order (service.bat sorts with
// PowerShell's Sort-Object over the name with each digit run zero-padded to
// width 8), so "general (ALT2)" precedes "general (ALT10)" the way it does in the
// Windows launcher. Every strategy shares one lists.Set, so two files naming the
// same hostlist parse it once.
//
// The first file that fails to compile fails the whole call: a half-loaded
// strategy menu would silently renumber the user's choices.
func LoadDir(dir string, o LoadOpts) ([]*Strategy, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("strategy directory %s: %w; create it or point the loader at the directory holding your *.toml strategies", dir, err)
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasPrefix(n, ".") || !strings.EqualFold(filepath.Ext(n), ".toml") {
			continue
		}
		names = append(names, n)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("strategy directory %s: no *.toml files; add a strategy file there", dir)
	}
	sort.SliceStable(names, func(i, j int) bool {
		ki, kj := nameSortKey(names[i]), nameSortKey(names[j])
		if ki != kj {
			return ki < kj
		}
		return names[i] < names[j]
	})

	set := lists.NewSet(o.ListsDir)
	out := make([]*Strategy, 0, len(names))
	for _, n := range names {
		s, err := compileFile(filepath.Join(dir, n), o, set)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Summary is the one-line description `zaprctl list` prints per strategy: its
// name, how many profiles it chains and which distinct ops it uses (canonical op
// names, sorted, so two spellings of the same technique appear once).
func (s *Strategy) Summary() string {
	var b strings.Builder
	b.WriteString(s.Name)
	b.WriteString(": ")
	b.WriteString(strconv.Itoa(len(s.Profiles)))
	b.WriteString(" profile")
	if len(s.Profiles) != 1 {
		b.WriteByte('s')
	}
	ops := s.opNames()
	b.WriteString(", ops: ")
	if len(ops) == 0 {
		b.WriteString("none")
	} else {
		b.WriteString(strings.Join(ops, ", "))
	}
	return b.String()
}

// opNames lists the distinct canonical op names used by the strategy, sorted.
func (s *Strategy) opNames() []string {
	seen := make(map[string]struct{})
	var out []string
	for _, p := range s.Profiles {
		for _, co := range p.Ops {
			n := co.Op.Name()
			if _, dup := seen[n]; dup {
				continue
			}
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Unsupported reports which of the strategy's ops the given transport cannot
// honour, as printable lines of the form
//
//	fake (needs inject, per-packet-ttl)
//
// one per distinct op, sorted. An empty result means the transport can run the
// whole strategy. This is the warning the CLI prints before activating a
// strategy under desync.ProxyCaps; whether such an op is degraded, skipped or
// fatal is each profile's on_unsupported setting.
func (s *Strategy) Unsupported(caps desync.Caps) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, p := range s.Profiles {
		for _, co := range p.Ops {
			n := co.Op.Name()
			if _, dup := seen[n]; dup {
				continue
			}
			seen[n] = struct{}{}
			if missing, ok := capsMissing(caps, co.Op.Requires()); !ok {
				out = append(out, fmt.Sprintf("%s (needs %s)", n, strings.Join(missing, ", ")))
			}
		}
	}
	sort.Strings(out)
	return out
}

// ParamDegradations reports tricks this strategy configures that the transport
// will silently drop at runtime — the honesty Unsupported cannot give.
//
// WHY a second list is needed: desync.Op.Requires() cannot see OpParams, so an op
// whose BASE behaviour a transport supports passes the static gate even when one
// of its parameters does not. --dpi-desync-split-seqovl is the case that matters:
// multisplit needs only {Segment, DropOriginal}, which the socket-level transport
// has, but the overlap prepends bytes BELOW the window and so needs Caps.Seq. The
// op drops it and says so on the Plan (desync.Plan.Degraded), which only reaches a
// debug log; this makes the same fact available before a single packet moves.
//
// Ops already named by Unsupported are skipped: they will not run at all, so
// reporting their parameters twice would only be noise. Lines are deduplicated
// and sorted.
func (s *Strategy) ParamDegradations(caps desync.Caps) []string {
	gated := make(map[string]struct{})
	for _, p := range s.Profiles {
		for _, co := range p.Ops {
			if _, ok := capsMissing(caps, co.Op.Requires()); !ok {
				gated[co.Op.Name()] = struct{}{}
			}
		}
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		if _, dup := seen[line]; dup {
			return
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	for _, p := range s.Profiles {
		for _, co := range p.Ops {
			name := co.Op.Name()
			if _, skip := gated[name]; skip {
				continue
			}
			if co.Params.Seqovl > 0 && !caps.Seq {
				add("%s: seqovl %d will be dropped (needs seq); the split still happens, "+
					"but without the sub-window overlap", name, co.Params.Seqovl)
			}
		}
	}
	sort.Strings(out)
	return out
}

// capsMissing lists the capability names need has and have lacks. It is the same
// comparison the engine makes before calling an op, kept here so the loader and
// the CLI can answer "will this strategy work" without importing the engine.
func capsMissing(have, need desync.Caps) ([]string, bool) {
	var missing []string
	check := func(n, h bool, name string) {
		if n && !h {
			missing = append(missing, name)
		}
	}
	check(need.Inject, have.Inject, "inject")
	check(need.Seq, have.Seq, "seq")
	check(need.DropOriginal, have.DropOriginal, "drop")
	check(need.PerPacketTTL, have.PerPacketTTL, "per-packet-ttl")
	check(need.Fooling, have.Fooling, "fooling")
	check(need.IPID, have.IPID, "ip-id")
	check(need.UDP, have.UDP, "udp")
	check(need.IPv6ExtHdr, have.IPv6ExtHdr, "ipv6-exthdr")
	check(need.Frag, have.Frag, "frag")
	check(need.Segment, have.Segment, "segment")
	check(need.TLSRec, have.TLSRec, "tlsrec")
	return missing, len(missing) == 0
}

// ---------- compilation ----------

// compiler carries the location context every error message needs.
type compiler struct {
	file   string // strategy file path
	o      LoadOpts
	set    *lists.Set
	prof   string // current profile name, "" outside a profile
	opName string // current op name, "" outside an op
	opIdx  int    // index of the current op within the profile
}

// errf formats an error prefixed with as much location as is known.
func (c *compiler) errf(format string, a ...any) error {
	var b strings.Builder
	b.WriteString(c.file)
	if c.prof != "" {
		fmt.Fprintf(&b, ": profile %q", c.prof)
	}
	if c.opName != "" {
		fmt.Fprintf(&b, ": ops[%d] %q", c.opIdx, c.opName)
	}
	b.WriteString(": ")
	fmt.Fprintf(&b, format, a...)
	return errors.New(b.String())
}

// compileFile decodes and compiles one strategy file against a shared list set.
func compileFile(path string, o LoadOpts, set *lists.Set) (*Strategy, error) {
	var f File
	md, err := toml.DecodeFile(path, &f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w; fix the TOML syntax", path, err)
	}
	if un := md.Undecoded(); len(un) > 0 {
		keys := make([]string, 0, len(un))
		for _, k := range un {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("%s: unknown key(s): %s; remove them or fix the spelling (profiles are [[profile]], their filter is [profile.filter], their techniques are [[profile.ops]])",
			path, strings.Join(keys, ", "))
	}
	c := &compiler{file: path, o: o, set: set}
	return c.strategy(&f)
}

// strategy compiles the decoded file.
func (c *compiler) strategy(f *File) (*Strategy, error) {
	s := &Strategy{
		Name:        strings.TrimSpace(f.Name),
		Description: strings.TrimSpace(f.Description),
		Source:      strings.TrimSpace(f.Source),
	}
	if s.Name == "" {
		base := filepath.Base(c.file)
		s.Name = strings.TrimSuffix(base, filepath.Ext(base))
	}

	var err error
	if s.WindowTCP, err = ParsePortSet(f.Window.TCP); err != nil {
		return nil, c.errf("window.tcp: %v", err)
	}
	if s.WindowUDP, err = ParsePortSet(f.Window.UDP); err != nil {
		return nil, c.errf("window.udp: %v", err)
	}
	if len(f.Profiles) == 0 {
		return nil, c.errf("no [[profile]] sections; a strategy needs at least one profile, even if its filter matches everything")
	}
	s.Profiles = make([]*Profile, 0, len(f.Profiles))
	for i := range f.Profiles {
		p, err := c.profile(i, &f.Profiles[i])
		if err != nil {
			return nil, err
		}
		s.Profiles = append(s.Profiles, p)
	}
	return s, nil
}

// profile compiles one --new chain element.
func (c *compiler) profile(idx int, ps *ProfileSpec) (*Profile, error) {
	p := &Profile{Name: strings.TrimSpace(ps.Name)}
	if p.Name == "" {
		p.Name = fmt.Sprintf("#%d", idx+1)
	}
	c.prof, c.opName = p.Name, ""

	switch strings.ToLower(strings.TrimSpace(ps.OnUnsupported)) {
	case "", "degrade":
		p.OnUnsupported = desync.UnsupDegrade
	case "skip":
		p.OnUnsupported = desync.UnsupSkip
	case "error":
		p.OnUnsupported = desync.UnsupError
	default:
		return nil, c.errf("on_unsupported = %q is unknown; use \"degrade\" (default), \"skip\" or \"error\"", ps.OnUnsupported)
	}

	var err error
	if p.Cutoff, err = ParseCounter(ps.Cutoff); err != nil {
		return nil, c.errf("cutoff: %v", err)
	}
	if p.Start, err = ParseCounter(ps.Start); err != nil {
		return nil, c.errf("start: %v", err)
	}
	if p.Filter, err = c.filter(&ps.Filter); err != nil {
		return nil, err
	}
	if len(ps.Ops) == 0 {
		return nil, c.errf("no [[profile.ops]]; a profile without a technique matches traffic and then does nothing — add one or delete the profile")
	}
	p.Ops = make([]CompiledOp, 0, len(ps.Ops))
	for i := range ps.Ops {
		co, err := c.compileOp(i, &ps.Ops[i], p)
		if err != nil {
			return nil, err
		}
		p.Ops = append(p.Ops, co)
	}
	c.opName = ""

	// The engine applies ops in slice order, so the loader owns phase ordering:
	// syndata rides the SYN, fakes go before the payload, splits carve it up and
	// modifiers rewrite what is already planned. Stable, so the file order still
	// decides within a phase (that is nfqws' --dpi-desync=fake,multisplit order).
	sort.SliceStable(p.Ops, func(i, j int) bool {
		return p.Ops[i].Op.Phase() < p.Ops[j].Op.Phase()
	})
	return p, nil
}

// filter compiles the --filter-*/--hostlist*/--ipset* set of one profile.
func (c *compiler) filter(fspec *FilterSpec) (Filter, error) {
	var f Filter
	var err error

	switch strings.ToLower(strings.TrimSpace(fspec.Proto)) {
	case "", "any", "all":
		f.Proto = 0
	case "tcp":
		f.Proto = proto.IPProtoTCP
	case "udp":
		f.Proto = proto.IPProtoUDP
	default:
		return f, c.errf("filter.proto = %q is unknown; use \"tcp\", \"udp\" or leave it out for any", fspec.Proto)
	}

	switch strings.ToLower(strings.TrimSpace(fspec.L3)) {
	case "", "any", "all":
		f.L3 = 0
	case "ipv4", "ip4", "4":
		f.L3 = 4
	case "ipv6", "ip6", "6":
		f.L3 = 6
	default:
		return f, c.errf("filter.l3 = %q is unknown; use \"ipv4\", \"ipv6\" or leave it out for both", fspec.L3)
	}

	if f.Ports, err = ParsePortSet(fspec.Ports); err != nil {
		return f, c.errf("filter.ports: %v", err)
	}
	if f.L7, err = c.l7(fspec.L7); err != nil {
		return f, err
	}

	if f.Hostlist, err = c.hosts(fspec.Hostlist, fspec.HostlistDomains, "filter.hostlist"); err != nil {
		return f, err
	}
	if f.HostlistExclude, err = c.hosts(fspec.HostlistExclude, fspec.HostlistExcludeDomains, "filter.hostlist_exclude"); err != nil {
		return f, err
	}
	if f.IPSet, err = c.cidrs(fspec.IPSet, "filter.ipset"); err != nil {
		return f, err
	}
	if f.IPSetExclude, err = c.cidrs(fspec.IPSetExclude, "filter.ipset_exclude"); err != nil {
		return f, err
	}
	if a := strings.TrimSpace(fspec.HostlistAuto); a != "" {
		// The file is written, not read, so it does not have to exist yet.
		f.AutoHostlist = c.resolveList(a)
	}
	return f, nil
}

// l7 compiles --filter-l7 into a bitmask. Entries may be comma-separated.
func (c *compiler) l7(entries []string) (proto.L7, error) {
	var m proto.L7
	for _, entry := range entries {
		for _, tok := range strings.Split(entry, ",") {
			tok = strings.ToLower(strings.TrimSpace(tok))
			if tok == "" {
				continue
			}
			bit, ok := proto.L7Names[tok]
			if !ok {
				return 0, c.errf("filter.l7 %q is unknown; use one of %s", tok, sortedKeys(proto.L7Names))
			}
			m |= bit
		}
	}
	return m, nil
}

// hosts builds the hostlist for one filter field: the named files merged into one
// set, plus any inline domains.
//
// With no inline domains the set comes from the shared lists.Set, so two profiles
// naming the same files share one parsed copy and one reload. Inline domains force
// a private set: adding them to the shared one would leak them into every other
// profile that names the same files.
func (c *compiler) hosts(names, inline []string, field string) (*lists.HostSet, error) {
	names, inline = cleanList(names), cleanList(inline)
	if len(names) == 0 && len(inline) == 0 {
		return nil, nil
	}
	if err := c.checkListFiles(names, field); err != nil {
		return nil, err
	}
	names, err := c.dropEmptyLists(names, field)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 && len(inline) == 0 {
		return nil, nil
	}
	if len(inline) == 0 {
		hs, err := c.set.Hosts(names...)
		if err != nil {
			return nil, c.errf("%s: %v; fix the file or drop the entry", field, err)
		}
		return hs, nil
	}
	hs := lists.NewHostSet()
	for _, n := range names {
		path := c.resolveList(n)
		if err := hs.LoadFile(path); err != nil {
			if optionalMissing(path, err) {
				continue
			}
			return nil, c.errf("%s %s: %v; fix the file or drop the entry", field, path, err)
		}
	}
	for _, d := range inline {
		if !validInlineDomain(d) {
			return nil, c.errf("%s domain %q is not a hostname; write a bare domain such as \"discord.media\"", field, d)
		}
		hs.Add(d)
	}
	return hs, nil
}

// cidrs builds the ipset for one filter field, merging several files into one set.
func (c *compiler) cidrs(names []string, field string) (*lists.CIDRSet, error) {
	names = cleanList(names)
	if len(names) == 0 {
		return nil, nil
	}
	if err := c.checkListFiles(names, field); err != nil {
		return nil, err
	}
	names, err := c.dropEmptyLists(names, field)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, nil
	}
	cs, err := c.set.CIDRs(names...)
	if err != nil {
		return nil, c.errf("%s: %v; fix the file or drop the entry", field, err)
	}
	return cs, nil
}

// dropEmptyLists removes named list files that hold no entries.
//
// This is nfqws' rule, not a shortcut: HostlistCheck_ searches each file's own
// pool, so a file with no entries contributes nothing, and only when *every*
// include list is empty does the check pass unconditionally ("old behavior
// compat: all include lists are empty means check passes"). An empty exclude list
// excludes nothing at all.
//
// It also has to be done here because lists.HostSet/CIDRSet raise their
// match-everything Any flag as soon as *one* of the merged files parses to zero
// entries — and flowseal ships list-exclude-user.txt containing nothing but a
// comment. Left alone, that one comment would make every exclude list match every
// host and silently disable the whole strategy. With the empty files dropped, a
// field that names only empty files compiles to a nil set, which is exactly
// nfqws' behaviour in both roles: unrestricted for an include list, excluding
// nothing for an exclude list.
func (c *compiler) dropEmptyLists(names []string, field string) ([]string, error) {
	var out []string
	for _, n := range names {
		path := c.resolveList(n)
		has, err := listFileHasEntries(path)
		if err != nil {
			if optionalMissing(path, err) {
				continue
			}
			return nil, c.errf("%s: cannot read %s: %v; fix the file or drop the entry", field, path, err)
		}
		if has {
			out = append(out, n)
		}
	}
	return out, nil
}

// listFileHasEntries reports whether path holds at least one line that is not
// blank and not a comment. It stops at the first one, so a 32k-line ipset costs
// one read.
func listFileHasEntries(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 8<<10), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if strings.TrimSpace(line) != "" {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		// An over-long or unreadable line is not proof of emptiness: keep the
		// file and let the list parser decide.
		return true, nil
	}
	return false, nil
}

// checkListFiles enforces flowseal's rule: a *-user.txt override may be absent
// (the launcher creates it on demand), any other named list must exist.
func (c *compiler) checkListFiles(names []string, field string) error {
	for _, n := range names {
		path := c.resolveList(n)
		if _, err := os.Stat(path); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				if isUserList(path) {
					continue // optional override
				}
				return c.errf("%s: %s does not exist; create the list or remove %q from this profile (only *-user.txt files may be missing)", field, path, n)
			}
			return c.errf("%s: cannot stat %s: %v; check the file's permissions", field, path, err)
		}
	}
	return nil
}

// resolveList turns a list name into a path under LoadOpts.ListsDir. An absolute
// name is used as given, mirroring lists.Set.
func (c *compiler) resolveList(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(c.o.ListsDir, name)
}

// ---------- ops ----------

// compileOp resolves one op and fills its OpParams.
func (c *compiler) compileOp(idx int, spec *OpSpec, p *Profile) (CompiledOp, error) {
	c.opIdx = idx
	name := strings.ToLower(strings.TrimSpace(spec.Op))
	c.opName = name
	if name == "" {
		c.opName = ""
		return CompiledOp{}, c.errf("ops[%d] has no op name; set op = \"multisplit\" (or another technique)", idx)
	}
	op, err := desync.Lookup(name)
	if err != nil {
		return CompiledOp{}, c.errf("%v; fix the op name", err)
	}

	var pp desync.OpParams

	// --dpi-desync-repeats. nfqws' dp_init defaults it to 1 and bounds it to 1024.
	if spec.Repeats < 0 {
		return CompiledOp{}, c.errf("repeats = %d is negative; use 1 or more (1 is the default: send each desync packet once)", spec.Repeats)
	}
	if spec.Repeats > maxRepeats {
		return CompiledOp{}, c.errf("repeats = %d is above nfqws' limit of %d; lower it", spec.Repeats, maxRepeats)
	}
	pp.Repeats = spec.Repeats
	if pp.Repeats == 0 {
		pp.Repeats = 1
	}

	if pp.TTL, pp.TTLAuto, pp.TTLDelta, pp.TTLMin, pp.TTLMax, err = ParseTTLSpec(spec.TTL); err != nil {
		return CompiledOp{}, c.errf("%v", err)
	}

	if pp.Fool, err = c.fooling(spec.Fooling); err != nil {
		return CompiledOp{}, err
	}
	pp.FoolP = desync.DefaultFoolParams()
	if spec.BadSeqIncrement != nil {
		pp.FoolP.BadSeqIncrement = *spec.BadSeqIncrement
	}
	if spec.BadAckIncrement != nil {
		pp.FoolP.BadAckIncrement = *spec.BadAckIncrement
	}
	if spec.TSIncrement != nil {
		pp.FoolP.TSIncrement = *spec.TSIncrement
	}

	if pp.SplitPos, err = ParseSplitPos(spec.Pos); err != nil {
		return CompiledOp{}, c.errf("%v", err)
	}

	if pp.Seqovl, err = c.seqovl(spec, name, pp.SplitPos); err != nil {
		return CompiledOp{}, err
	}
	if pp.SeqovlPattern, err = LoadFake(c.o.FakesDir, spec.SeqovlPattern); err != nil {
		return CompiledOp{}, c.errf("seqovl_pattern: %v", err)
	}
	if pp.Pattern, err = LoadFake(c.o.FakesDir, spec.Pattern); err != nil {
		return CompiledOp{}, c.errf("pattern: %v", err)
	}

	if pp.FakeTLS, err = LoadFake(c.o.FakesDir, spec.Fake.TLS); err != nil {
		return CompiledOp{}, c.errf("fake.tls: %v", err)
	}
	if pp.FakeHTTP, err = LoadFake(c.o.FakesDir, spec.Fake.HTTP); err != nil {
		return CompiledOp{}, c.errf("fake.http: %v", err)
	}
	if pp.FakeQUIC, err = LoadFake(c.o.FakesDir, spec.Fake.QUIC); err != nil {
		return CompiledOp{}, c.errf("fake.quic: %v", err)
	}
	if pp.FakeSynData, err = LoadFake(c.o.FakesDir, spec.Fake.SynData); err != nil {
		return CompiledOp{}, c.errf("fake.syndata: %v", err)
	}
	if pp.FakeDiscord, err = c.fakeList(spec.Fake.Discord, "fake.discord"); err != nil {
		return CompiledOp{}, err
	}
	if pp.FakeSTUN, err = c.fakeList(spec.Fake.STUN, "fake.stun"); err != nil {
		return CompiledOp{}, err
	}
	if pp.FakeUnknownUDP, err = c.fakeList(spec.Fake.UnknownUDP, "fake.unknown_udp"); err != nil {
		return CompiledOp{}, err
	}

	mod, err := proto.ParseTLSMod(spec.TLSMod)
	if err != nil {
		return CompiledOp{}, c.errf("tls_mod %q: %v; mods are none,rnd,rndsni,dupsid,padencap,sni=<host>", spec.TLSMod, err)
	}
	// proto.TLSMod and desync.TLSMod are field-for-field identical by contract.
	pp.TLSMod = desync.TLSMod(mod)

	if err := c.opMod(spec, name, &pp); err != nil {
		return CompiledOp{}, err
	}

	// --dpi-desync-udplen-increment. 0 is nfqws' "unset", not "add nothing".
	if spec.UDPLenIncrement < posMin || spec.UDPLenIncrement > posMax {
		return CompiledOp{}, c.errf("udplen_increment = %d is outside nfqws' range %d..%d", spec.UDPLenIncrement, posMin, posMax)
	}
	pp.UDPLenIncrement = spec.UDPLenIncrement
	if pp.UDPLenIncrement == 0 {
		pp.UDPLenIncrement = udpLenIncrementDefault
	}
	if pp.UDPLenPattern, err = LoadFake(c.o.FakesDir, spec.UDPLenPattern); err != nil {
		return CompiledOp{}, c.errf("udplen_pattern: %v", err)
	}

	if pp.WSSize, pp.WSSizeScale, err = parseWSSize(spec.WSSize); err != nil {
		return CompiledOp{}, c.errf("%v", err)
	}
	if pp.IPID, err = parseIPIDMode(spec.Mode); err != nil {
		return CompiledOp{}, c.errf("%v", err)
	}
	if pp.FragPosTCP, pp.FragPosUDP, err = c.fragPos(spec.FragPos); err != nil {
		return CompiledOp{}, err
	}
	pp.AnyProtocol = spec.AnyProtocol

	if err := c.checkOpNeeds(name, &pp); err != nil {
		return CompiledOp{}, err
	}
	if err := c.checkOpCaps(op, p); err != nil {
		return CompiledOp{}, err
	}
	return CompiledOp{Op: op, Params: pp, Spec: *spec}, nil
}

// fooling compiles --dpi-desync-fooling into a bitmask. Entries may be
// comma-separated, so "ts,md5sig" works as one string.
func (c *compiler) fooling(entries []string) (desync.Fooling, error) {
	var m desync.Fooling
	for _, entry := range entries {
		for _, tok := range strings.Split(entry, ",") {
			tok = strings.ToLower(strings.TrimSpace(tok))
			if tok == "" {
				continue
			}
			bit, ok := desync.FoolNames[tok]
			if !ok {
				return 0, c.errf("fooling %q is unknown; use one of %s", tok, sortedKeys(desync.FoolNames))
			}
			m |= bit
		}
	}
	return m, nil
}

// fakeList resolves a multi-valued fake set (nfqws lets --dpi-desync-fake-discord
// and friends repeat; repeats rotate through the blobs).
func (c *compiler) fakeList(specs []string, field string) ([][]byte, error) {
	var out [][]byte
	for _, s := range specs {
		if strings.TrimSpace(s) == "" {
			continue
		}
		b, err := LoadFake(c.o.FakesDir, s)
		if err != nil {
			return nil, c.errf("%s: %v", field, err)
		}
		out = append(out, b)
	}
	return out, nil
}

// seqovl validates --dpi-desync-split-seqovl against the first split position.
//
// nfqws only accepts an absolute positive seqovl for the split modes
// (nfqws.c: "split seqovl supports only absolute positive positions"), and for
// the disorder/fakedsplit family it *cancels* the overlap at runtime when it
// reaches or passes the split position, because the overlap is prepended to a
// segment that starts there. We refuse at load instead: a strategy whose central
// trick is silently dropped on every packet is a broken strategy, and the log
// line that says so scrolls past once.
//
// multisplit is deliberately exempt. There the overlap goes in front of the very
// first segment, below sequence zero, so nfqws applies it whatever the split
// position is — which is exactly what flowseal's "seqovl=681 pos=1" strategies
// rely on.
func (c *compiler) seqovl(spec *OpSpec, name string, pos []desync.PosSpec) (int, error) {
	if spec.Seqovl < 0 {
		return 0, c.errf("seqovl = %d is negative; nfqws only takes an absolute positive overlap for split modes", spec.Seqovl)
	}
	if spec.Seqovl > maxSeqovl {
		return 0, c.errf("seqovl = %d is above nfqws' overlap buffer of %d bytes; lower it", spec.Seqovl, maxSeqovl)
	}
	if spec.Seqovl == 0 || len(pos) == 0 || !seqovlLimitedBySplit(name) {
		return spec.Seqovl, nil
	}
	first := pos[0]
	if first.Marker != proto.MarkerAbs || first.Offset <= 0 || spec.Seqovl < first.Offset {
		return spec.Seqovl, nil
	}
	return 0, c.errf("seqovl = %d reaches or passes the first split position %d, so %s would drop the overlap on every packet; use a seqovl below %d, a later split position, or switch to multisplit (where the overlap sits below the first segment)",
		spec.Seqovl, first.Offset, name, first.Offset)
}

// seqovlLimitedBySplit reports whether the op attaches the overlap to a segment
// that begins at the split position — the modes whose desync.c branch contains
// the "seqovl>=split_pos. cancelling seqovl" check.
func seqovlLimitedBySplit(name string) bool {
	switch name {
	case "fakedsplit", "split", "fakeddisorder", "disorder", "multidisorder", "disorder2":
		return true
	}
	return false
}

// opMod compiles the `mod` map.
//
// One generic string map per op has to carry three unrelated families of knobs,
// because the TOML schema has no dedicated field for any of them. Which keys an
// op reads is fixed by modKeyOps, so a knob nobody would read is refused instead
// of silently weakening the strategy:
//
//	hostfakesplit                     --dpi-desync-hostfakesplit-mod / -midhost
//	  host=<hostname>                 ...,host=          (fake-host template)
//	  altorder=<n>                    ...,altorder=      (also fakedsplit family)
//	  midhost=1 | midhost=<position>  --dpi-desync-hostfakesplit-midhost
//	tamper — one key per zapret option, "1" for the flags:
//	  hostcase=1      --hostcase        hostspell=hoSt   --hostspell
//	  hostnospace=1   --hostnospace     hostdot=1        --hostdot
//	  hosttab=1       --hosttab         hostpad=<bytes>  --hostpad
//	  domcase=1       --domcase         methodspace=1    --methodspace
//	  methodeol=1     --methodeol       unixeol=1        --unixeol
//	wssize
//	  cutoff=<n|d|s><number>          --wssize-cutoff
//
// The keys above are spelled the way zapret's command line spells them; in the
// TOML every value is a string, so the tamper block of a strategy file reads
//
//	mod = { hostcase = "1", hostspell = "hoSt", hostpad = "64", domcase = "1" }
//
// nfqws' lone "none" — "this option is present but selects no mod" — is accepted
// for every op.
func (c *compiler) opMod(spec *OpSpec, name string, pp *desync.OpParams) error {
	// Sorted, because a map iterates in random order and two bad keys would
	// otherwise report a different one on every run.
	keys := make([]string, 0, len(spec.Mod))
	for k := range spec.Mod {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, rawKey := range keys {
		key := strings.ToLower(strings.TrimSpace(rawKey))
		val := strings.TrimSpace(spec.Mod[rawKey])
		if err := c.checkModKey(name, key, rawKey); err != nil {
			return err
		}
		switch key {
		case "none":
			// nfqws accepts a lone "none" meaning "no mods".
		case "host":
			if val == "" {
				return c.errf("mod.host is empty; give a short template hostname such as \"ya.ru\", or drop the key")
			}
			if !validInlineDomain(val) {
				return c.errf("mod.host = %q is not a hostname; use a short template such as \"ya.ru\"", val)
			}
			pp.HostFakeHost = val
		case "altorder":
			v, err := strconv.Atoi(val)
			if err != nil {
				return c.errf("mod.altorder = %q is not a number; %s", val, altOrderHint(name))
			}
			if err := checkAltOrder(name, v); err != nil {
				return c.errf("mod.altorder = %d: %v", v, err)
			}
			pp.AltOrder = v
		case "midhost":
			midHost, set, err := parseMidHost(val)
			if err != nil {
				return c.errf("mod.midhost = %q %v", val, err)
			}
			pp.MidHost, pp.MidHostSet = midHost, set
		case "cutoff":
			ctr, err := ParseCounter(val)
			if err != nil {
				return c.errf("mod.cutoff = %q: %v", val, err)
			}
			pp.WSSizeCutoffKind, pp.WSSizeCutoffN = ctr.Kind, ctr.N
		default:
			if err := c.tamperMod(key, val, pp); err != nil {
				return err
			}
		}
	}
	return nil
}

// modKeyOps lists, per `mod` key, the ops that read it. A key handed to any
// other op would be a knob the datapath never looks at.
//
// The faked-split family shares altorder with hostfakesplit because nfqws'
// --dpi-desync-fakedsplit-mod and --dpi-desync-hostfakesplit-mod overlap there;
// the fake-host template and the midhost cut exist only in hostfakesplit.
var modKeyOps = map[string][]string{
	"host":        {"hostfakesplit"},
	"midhost":     {"hostfakesplit"},
	"altorder":    {"hostfakesplit", "fakedsplit", "split", "fakeddisorder", "disorder"},
	"cutoff":      {"wssize"},
	"hostcase":    {"tamper"},
	"hostspell":   {"tamper"},
	"hostnospace": {"tamper"},
	"hostdot":     {"tamper"},
	"hosttab":     {"tamper"},
	"hostpad":     {"tamper"},
	"domcase":     {"tamper"},
	"methodspace": {"tamper"},
	"methodeol":   {"tamper"},
	"unixeol":     {"tamper"},
}

// checkModKey rejects an unknown mod key, and a known one on an op that does not
// read it.
func (c *compiler) checkModKey(name, key, rawKey string) error {
	if key == "none" {
		return nil
	}
	owners, known := modKeyOps[key]
	if !known {
		return c.errf("mod key %q is unknown; %s", rawKey, modKeyHint(name))
	}
	for _, o := range owners {
		if o == name {
			return nil
		}
	}
	return c.errf("mod key %q is only read by %s, not by %q; %s",
		rawKey, strings.Join(owners, "/"), name, modKeyHint(name))
}

// modHint is the vocabulary each op's `mod` map accepts, for error messages.
// Every value is a string, because the TOML map is map[string]string: write
// hostpad = "64", not hostpad = 64.
var modHint = map[string]string{
	"hostfakesplit": `hostfakesplit takes host="<hostname>", altorder="<n>" and midhost="1" (or midhost="<position>")`,
	"fakedsplit":    `the fakedsplit family takes altorder="<n>"`,
	"fakeddisorder": `the fakedsplit family takes altorder="<n>"`,
	"split":         `the fakedsplit family takes altorder="<n>"`,
	"disorder":      `the fakedsplit family takes altorder="<n>"`,
	"tamper":        `tamper takes hostcase="1", hostspell="<spelling of Host>", hostnospace="1", hostdot="1", hosttab="1", hostpad="<bytes>", domcase="1", methodspace="1", methodeol="1" and unixeol="1"`,
	"wssize":        `wssize takes cutoff="<n|d|s><number>"`,
}

// modKeyHint names the keys the current op accepts.
func modKeyHint(name string) string {
	if h, ok := modHint[name]; ok {
		return h
	}
	return `only hostfakesplit (host="<hostname>", altorder="<n>", midhost="<position>"), the fakedsplit ` +
		`family (altorder="<n>"), tamper (hostcase="1" and the other --hostcase-family knobs) and wssize ` +
		`(cutoff="<n|d|s><number>") read a mod map`
}

// tamperMod compiles one tamper knob into OpParams.Tamper.
//
// Only the flags and the two valued knobs zapret has; the mapping from key to
// option is one-to-one with the tpws/nfqws command line (see opMod). The knobs
// that change the payload's length (hostdot, hosttab, hostpad, methodspace,
// methodeol) are accepted here and reported by the op at runtime, because whether
// they are safe depends on the transport, not on the strategy.
func (c *compiler) tamperMod(key, val string, pp *desync.OpParams) error {
	flag := func(dst *bool) error {
		b, err := parseBool(val)
		if err != nil {
			return c.errf("mod.%s = %q is not a boolean; use \"1\" to switch it on, or drop the key", key, val)
		}
		*dst = b
		return nil
	}
	switch key {
	case "hostcase":
		return flag(&pp.Tamper.HostCase)
	case "hostnospace":
		return flag(&pp.Tamper.HostNoSpace)
	case "hostdot":
		return flag(&pp.Tamper.HostDot)
	case "hosttab":
		return flag(&pp.Tamper.HostTab)
	case "domcase":
		return flag(&pp.Tamper.DomCase)
	case "methodspace":
		return flag(&pp.Tamper.MethodSpace)
	case "methodeol":
		return flag(&pp.Tamper.MethodEOL)
	case "unixeol":
		return flag(&pp.Tamper.UnixEOL)
	case "hostspell":
		// nfqws/tpws: --hostspell is a respelling of the four bytes "Host", so a
		// spelling of another length or another word would change the request's
		// length (and stop being a Host header at all).
		if len(val) != len("host") || !strings.EqualFold(val, "host") {
			return c.errf("mod.hostspell = %q is not a spelling of \"Host\"; use a mixed-case variant such as \"hoSt\"", val)
		}
		pp.Tamper.HostSpell = val
		// --hostspell implies --hostcase upstream: the header name is rewritten
		// either way, the spelling just says how.
		pp.Tamper.HostCase = true
		return nil
	case "hostpad":
		v, err := strconv.Atoi(val)
		if err != nil {
			return c.errf("mod.hostpad = %q is not a number of bytes; write e.g. hostpad = \"64\"", val)
		}
		if v < 1 || v > posMax {
			return c.errf("mod.hostpad = %d is outside 1..%d; that many bytes of junk headers is what --hostpad inserts before the Host line", v, posMax)
		}
		pp.Tamper.HostPad = v
		return nil
	}
	// checkModKey has already rejected every key that is not in modKeyOps, so
	// this is unreachable unless a key is added there and not here.
	return c.errf("mod key %q is not implemented; %s", key, modKeyHint("tamper"))
}

// checkAltOrder applies nfqws' per-mode bounds on the segment-ordering selector.
func checkAltOrder(name string, v int) error {
	if name == "hostfakesplit" {
		if v < 0 || v > 1 {
			return errors.New("hostfakesplit only has orderings 0 and 1")
		}
		return nil
	}
	// nfqws' parse_fakedsplit_mod: ordering & 0xFFFFFFE4 must be clear (bits
	// 0,1 select the unsplit ordering, bits 3,4 the split one) and the split
	// selector must be 0..2.
	if v < 0 || v&^0x1B != 0 || (v>>3)&3 > 2 {
		return errors.New("valid fakedsplit/fakeddisorder orderings are 0..3, optionally +8 or +16")
	}
	return nil
}

// altOrderHint is the per-mode advice for a malformed altorder.
func altOrderHint(name string) string {
	if name == "hostfakesplit" {
		return "use 0 or 1"
	}
	return "use 0..3, optionally +8 or +16"
}

// fragPos compiles --dpi-desync-ipfrag-pos-tcp/-udp from the single `frag_pos`
// knob, falling back to nfqws' per-protocol defaults (32 for TCP, 8 for UDP).
func (c *compiler) fragPos(v int) (tcp, udp int, err error) {
	if v == 0 {
		return ipFragPosTCPDefault, ipFragPosUDPDefault, nil
	}
	if v < 8 || v > maxIPFragPos {
		return 0, 0, c.errf("frag_pos = %d is outside nfqws' range 8..%d; use a value in that range", v, maxIPFragPos)
	}
	if v%8 != 0 {
		return 0, 0, c.errf("frag_pos = %d is not a multiple of 8; an IPv4 fragment offset counts in 8-byte units, use %d or %d", v, v-v%8, v+8-v%8)
	}
	return v, v, nil
}

// checkOpNeeds catches the pseudo-ops that would compile into a no-op when their
// one mandatory knob is missing. (udplen needs no such check: nfqws' own default
// increment is +2, which the loader supplies.)
func (c *compiler) checkOpNeeds(name string, pp *desync.OpParams) error {
	switch name {
	case "ip_id":
		if pp.IPID == desync.IPIDDefault {
			return c.errf("ip_id needs mode = \"zero\", \"seq\", \"seqgroup\", \"same\" or \"random\"; without it the op would leave every ip.id alone")
		}
	case "wssize":
		if pp.WSSize == 0 {
			return c.errf("wssize needs wssize = \"<size>[:<scale>]\", e.g. wssize = \"128:6\"; without it the op would leave the window alone")
		}
	case "tamper":
		if pp.Tamper == (proto.TamperOpts{}) {
			return c.errf("tamper needs at least one knob in its mod map, e.g. mod = { hostcase = \"1\" }; without one the op would forward the request unchanged")
		}
	}
	return nil
}

// checkOpCaps rejects, at load time, ops the configured transport cannot run when
// the profile has asked to fail instead of degrade — and ops that can never fire
// because the profile filters out the address family they need.
//
// The Caps check is skipped when LoadOpts.Caps is the zero value: a caller that
// only wants to inspect a strategy (zaprctl list) has no transport in mind, and
// every real transport sets at least Segment.
func (c *compiler) checkOpCaps(op desync.Op, p *Profile) error {
	req := op.Requires()
	if req.UDP && p.Filter.Proto == proto.IPProtoTCP {
		return c.errf("this op only works on UDP but the profile filters proto = \"tcp\"; move it to a UDP profile or widen the filter")
	}
	if (c.o.Caps == desync.Caps{}) || p.OnUnsupported != desync.UnsupError {
		return nil
	}
	if missing, ok := capsMissing(c.o.Caps, req); !ok {
		return c.errf("this op needs capabilities the selected transport lacks (%s) and the profile has on_unsupported = \"error\"; run it on the divert transport, or set on_unsupported = \"degrade\"",
			strings.Join(missing, ", "))
	}
	return nil
}

// ---------- helpers ----------

// cleanList trims entries and drops empty ones, so a trailing comma or a blank
// TOML array element is not mistaken for a file named "".
func cleanList(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// isUserList reports whether path is one of flowseal's optional *-user.txt
// overrides, which may legitimately be missing.
func isUserList(path string) bool {
	return strings.HasSuffix(strings.ToLower(filepath.Base(path)), "-user.txt")
}

// optionalMissing reports whether err is "missing" for a file allowed to be absent.
func optionalMissing(path string, err error) bool {
	return errors.Is(err, fs.ErrNotExist) && isUserList(path)
}

// validInlineDomain mirrors the acceptance rule of lists' entry normaliser, so an
// inline --hostlist-domains value that would be silently discarded is reported
// instead.
func validInlineDomain(s string) bool {
	s = strings.TrimPrefix(strings.TrimSpace(s), "*")
	s = strings.Trim(s, ".")
	if s == "" || strings.ContainsAny(s, " \t\v\f\r/\\#") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// parseBool accepts the spellings a hand-written TOML string is likely to use.
func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "", "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("not a boolean")
}

// sortedKeys renders a vocabulary map for an error message.
func sortedKeys[V any](m map[string]V) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
