package netcfg

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// reTableName bounds pf table names to what the grammar accepts unquoted, so a
// name can never break out of the `-t <name>` argument or the `table <name>`
// statement we generate.
var reTableName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

// Table is one pf table inside our anchor: the address set a rule refers to as
// `<name>`. Tables are declared `persist` by the rule generators so they keep
// existing across ruleset reloads and can be repopulated independently of rule
// loading.
type Table struct {
	pf *PF
	// Name is the table's pf name, without the angle brackets.
	Name string
}

// Table returns a handle for the named table in this PF's anchor. The name is
// not validated here; each operation validates before it runs.
func (p *PF) Table(name string) *Table { return &Table{pf: p, Name: name} }

// Anchor returns the anchor the table lives in.
func (t *Table) Anchor() string { return t.pf.Anchor() }

// Replace sets the table's contents to exactly prefixes. See PF.TableReplace.
func (t *Table) Replace(prefixes []netip.Prefix) error {
	return t.pf.TableReplace(t.Name, prefixes)
}

// Count returns the number of addresses in the table.
func (t *Table) Count() (int, error) { return t.pf.TableCount(t.Name) }

// Entries returns the prefixes currently in the table.
func (t *Table) Entries() ([]netip.Prefix, error) { return t.pf.TableEntries(t.Name) }

// Flush empties the table.
func (t *Table) Flush() error { return t.pf.TableFlush(t.Name) }

// validateTable checks the anchor and table names.
func (p *PF) validateTable(name string) error {
	if err := p.validateAnchor(); err != nil {
		return err
	}
	if !reTableName.MatchString(name) {
		return fmt.Errorf("netcfg: invalid pf table name %q: want [A-Za-z0-9][A-Za-z0-9._-]{0,31}", name)
	}
	return nil
}

// TableReplace sets the named table's contents to exactly prefixes, using
//
//	pfctl -a <anchor> -t <name> -T replace -f -
//
// with one prefix per line on stdin. The addresses go through stdin, never
// argv: flowseal's ipsets run to tens of thousands of entries and would blow
// past ARG_MAX (and pfctl's own argument handling) long before that.
//
// An empty prefix list flushes the table instead: `-T replace` with no
// addresses is an error in pfctl, and "replace with nothing" is exactly a
// flush.
func (p *PF) TableReplace(name string, prefixes []netip.Prefix) error {
	if err := p.validateTable(name); err != nil {
		return err
	}
	if len(prefixes) == 0 {
		return p.TableFlush(name)
	}

	var sb strings.Builder
	sb.Grow(len(prefixes) * 20)
	n := 0
	for _, pfx := range prefixes {
		if !pfx.IsValid() {
			continue // never hand pfctl a zero Prefix; it would render as "invalid Prefix"
		}
		sb.WriteString(pfx.Masked().String())
		sb.WriteByte('\n')
		n++
	}
	if n == 0 {
		return p.TableFlush(name)
	}
	body := sb.String()

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dryRun {
		p.logf("netcfg: dry run: would replace table <%s> in anchor %q with %d prefix(es)", name, p.anchor, n)
		return nil
	}
	if _, _, err := p.run(body, "-a", p.effAnchorLocked(), "-t", name, "-T", "replace", "-f", "-"); err != nil {
		return fmt.Errorf("netcfg: replacing table <%s> in anchor %q with %d prefix(es) failed: %w",
			name, p.anchor, n, err)
	}
	p.recordLocked(StepPfTable, map[string]string{
		"anchor": p.anchor,
		"table":  name,
		"count":  strconv.Itoa(n),
	})
	p.logf("netcfg: table <%s> in anchor %q now holds %d prefix(es)", name, p.anchor, n)
	return nil
}

// TableFlush empties the named table without removing it.
func (p *PF) TableFlush(name string) error {
	if err := p.validateTable(name); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dryRun {
		p.logf("netcfg: dry run: would flush table <%s> in anchor %q", name, p.anchor)
		return nil
	}
	if _, _, err := p.run("", "-a", p.effAnchorLocked(), "-t", name, "-T", "flush"); err != nil {
		return fmt.Errorf("netcfg: flushing table <%s> in anchor %q failed: %w", name, p.anchor, err)
	}
	return nil
}

// reTableShowEntry matches one line of `pfctl -T show` output: pfctl indents
// each address and prints a prefix length only when it is not host-wide.
var reTableShowEntry = regexp.MustCompile(`^\s*!?\s*([0-9a-fA-F:.]+(?:/\d{1,3})?)\s*$`)

// TableEntries returns the prefixes currently in the named table
// (`pfctl -a <anchor> -t <name> -T show`). Lines pfctl renders that are not
// plain addresses (a negated entry, a hostname it could not collapse) are
// skipped rather than treated as fatal: the caller wants the address set, and a
// count mismatch is reported by TableCount.
func (p *PF) TableEntries(name string) ([]netip.Prefix, error) {
	if err := p.validateTable(name); err != nil {
		return nil, err
	}
	p.mu.Lock()
	out, _, err := p.run("", "-a", p.effAnchorLocked(), "-t", name, "-T", "show")
	p.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("netcfg: reading table <%s> in anchor %q failed: %w", name, p.anchor, err)
	}
	var prefixes []netip.Prefix
	for _, line := range strings.Split(out, "\n") {
		m := reTableShowEntry.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if pfx, err := parsePrefixLoose(m[1]); err == nil {
			prefixes = append(prefixes, pfx)
		}
	}
	return prefixes, nil
}

// TableCount returns the number of addresses in the named table.
func (p *PF) TableCount(name string) (int, error) {
	if err := p.validateTable(name); err != nil {
		return 0, err
	}
	p.mu.Lock()
	out, _, err := p.run("", "-a", p.effAnchorLocked(), "-t", name, "-T", "show")
	p.mu.Unlock()
	if err != nil {
		return 0, fmt.Errorf("netcfg: reading table <%s> in anchor %q failed: %w", name, p.anchor, err)
	}
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		n++
	}
	return n, nil
}

// parsePrefixLoose parses either "1.2.3.0/24" or a bare address, in which case
// the host prefix length is implied (/32 or /128) — the form pfctl prints.
func parsePrefixLoose(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return pfx.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// ParsePrefixList parses one prefix or address per line, ignoring blank lines
// and '#' comments — the format flowseal's ipset-*.txt files use. Malformed
// lines are collected into the returned error; the prefixes parsed before and
// after them are still returned, so a single bad line in a 32k-entry list does
// not cost the whole list.
func ParsePrefixList(b []byte) ([]netip.Prefix, error) {
	var (
		out  []netip.Prefix
		bad  []string
		seen = make(map[netip.Prefix]bool)
	)
	for i, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if idx := strings.IndexByte(t, '#'); idx >= 0 {
			t = strings.TrimSpace(t[:idx])
			if t == "" {
				continue
			}
		}
		pfx, err := parsePrefixLoose(t)
		if err != nil {
			if len(bad) < 16 {
				bad = append(bad, fmt.Sprintf("line %d: %q", i+1, t))
			}
			continue
		}
		if seen[pfx] {
			continue
		}
		seen[pfx] = true
		out = append(out, pfx)
	}
	if len(bad) > 0 {
		return out, fmt.Errorf("netcfg: skipped %d malformed prefix line(s): %s",
			len(bad), strings.Join(bad, "; "))
	}
	return out, nil
}
