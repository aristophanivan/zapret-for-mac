package netcfg

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// DefaultHostsPath is the system hosts file.
const DefaultHostsPath = "/etc/hosts"

// HostEntry is one hosts-file line: an address and the names it resolves.
type HostEntry struct {
	// IP is the address the names map to.
	IP netip.Addr
	// Names are the hostnames on that line, in file order. At least one is
	// required for the entry to be valid.
	Names []string
	// Comment is the trailing '#' comment, without the '#' and surrounding
	// space. Empty when there is none.
	Comment string
}

// String renders the entry as a hosts-file line (no trailing newline).
func (e HostEntry) String() string {
	var sb strings.Builder
	sb.WriteString(e.IP.String())
	for _, n := range e.Names {
		sb.WriteByte(' ')
		sb.WriteString(n)
	}
	if e.Comment != "" {
		sb.WriteString(" # ")
		sb.WriteString(e.Comment)
	}
	return sb.String()
}

// Validate reports why the entry cannot be written to a hosts file.
func (e HostEntry) Validate() error {
	if !e.IP.IsValid() {
		return errors.New("address is invalid")
	}
	if len(e.Names) == 0 {
		return errors.New("no hostnames")
	}
	for _, n := range e.Names {
		if err := validHostname(n); err != nil {
			return fmt.Errorf("hostname %q: %w", n, err)
		}
	}
	if strings.ContainsAny(e.Comment, "\r\n") {
		return errors.New("comment contains a newline")
	}
	return nil
}

// validHostname rejects anything that must never end up in /etc/hosts: an
// over-long name, an empty label, or a byte outside the LDH set plus '_' and
// '*' (both occur in real hosts files). This is the guard that keeps hostile
// list content from injecting extra lines into a system file.
func validHostname(n string) error {
	if n == "" {
		return errors.New("empty")
	}
	if len(n) > 253 {
		return fmt.Errorf("longer than 253 bytes (%d)", len(n))
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_' || c == '*':
		default:
			return fmt.Errorf("illegal byte %q at offset %d", c, i)
		}
	}
	if strings.HasPrefix(n, ".") || strings.Contains(n, "..") {
		return errors.New("empty label")
	}
	for _, label := range strings.Split(strings.TrimSuffix(n, "."), ".") {
		if len(label) > 63 {
			return fmt.Errorf("label %q longer than 63 bytes", label)
		}
	}
	return nil
}

// HostsParseError reports lines ParseHostsFile skipped. The entries returned
// alongside it are complete and usable; this is a report, not a failure.
type HostsParseError struct {
	// Lines are the 1-based line numbers that were skipped, capped at 32.
	Lines []int
	// Reasons parallels Lines.
	Reasons []string
	// Total is the number of skipped lines, including any beyond the cap.
	Total int
}

// Error summarises the skipped lines.
func (e *HostsParseError) Error() string {
	var parts []string
	for i := range e.Lines {
		parts = append(parts, fmt.Sprintf("line %d: %s", e.Lines[i], e.Reasons[i]))
	}
	s := fmt.Sprintf("netcfg: skipped %d unparseable hosts line(s)", e.Total)
	if len(parts) > 0 {
		s += ": " + strings.Join(parts, "; ")
	}
	return s
}

// ParseHostsFile parses hosts-file bytes into entries.
//
// The format is the traditional one: `<address> <name> [name ...]` with '#'
// starting a comment, blank and comment-only lines ignored. It handles
// flowseal's .upstream/service/hosts verbatim (243 lines, 241 entries, two
// blank separators).
//
// Parsing is deliberately lenient: a line that is not a valid entry is skipped
// and reported through a *HostsParseError, while every well-formed line before
// and after it is still returned. Callers that only want the data can ignore the
// error; Hosts.Apply does not, because it must never write a line it could not
// parse back.
func ParseHostsFile(b []byte) ([]HostEntry, error) {
	var (
		out []HostEntry
		pe  HostsParseError
	)
	note := func(lineNo int, reason string) {
		pe.Total++
		if len(pe.Lines) < 32 {
			pe.Lines = append(pe.Lines, lineNo)
			pe.Reasons = append(pe.Reasons, reason)
		}
	}
	for i, raw := range strings.Split(string(b), "\n") {
		lineNo := i + 1
		line := strings.TrimRight(raw, "\r")
		comment := ""
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			comment = strings.TrimSpace(line[idx+1:])
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue // blank or comment-only: not an error
		}
		if len(fields) < 2 {
			note(lineNo, "address with no hostname")
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			note(lineNo, fmt.Sprintf("%q is not an IP address", fields[0]))
			continue
		}
		names := make([]string, 0, len(fields)-1)
		bad := ""
		for _, n := range fields[1:] {
			if err := validHostname(n); err != nil {
				bad = fmt.Sprintf("hostname %q: %v", n, err)
				break
			}
			names = append(names, n)
		}
		if bad != "" {
			note(lineNo, bad)
			continue
		}
		out = append(out, HostEntry{IP: ip, Names: names, Comment: comment})
	}
	if pe.Total > 0 {
		return out, &pe
	}
	return out, nil
}

// Hosts manages a marker-delimited block inside a hosts file. This is
// flowseal's "Update Hosts File" feature: its service/hosts pins Discord voice
// and githubusercontent addresses so DNS poisoning cannot redirect them.
//
// The block is delimited by the same markers pf.conf patching uses, and Apply
// follows the same discipline: byte-exact backup with its SHA-256 journalled
// first, atomic replace preserving mode and owner, re-read and verify, restore
// on any mismatch. Lines outside the block are never touched.
//
// Hosts is safe for concurrent use.
type Hosts struct {
	mu       sync.Mutex
	path     string
	stateDir string
	marker   string
	dryRun   bool
	logf     Logf
	journal  *Journal
}

// NewHosts returns a Hosts for path (usually /etc/hosts), keeping backups and
// the rollback journal in stateDir. An empty path defaults to /etc/hosts.
func NewHosts(path string, stateDir string) *Hosts {
	if path == "" {
		path = DefaultHostsPath
	}
	return &Hosts{
		path:     path,
		stateDir: stateDir,
		marker:   "zapret-mac",
		logf:     func(string, ...any) {},
	}
}

// SetLogf installs a logging hook.
func (h *Hosts) SetLogf(l Logf) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if l == nil {
		l = func(string, ...any) {}
	}
	h.logf = l
}

// SetDryRun makes Apply and Remove validate and log without writing.
func (h *Hosts) SetDryRun(v bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dryRun = v
}

// SetMarker overrides the marker name embedded in the block delimiters.
// Two installations with different markers can coexist in one hosts file.
func (h *Hosts) SetMarker(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if name != "" {
		h.marker = name
	}
}

// Path returns the hosts file being managed.
func (h *Hosts) Path() string { return h.path }

// journalLocked opens the rollback journal on demand.
func (h *Hosts) journalLocked() *Journal {
	if h.journal != nil {
		return h.journal
	}
	if h.stateDir == "" || h.dryRun {
		return nil
	}
	j, err := OpenJournal(h.stateDir)
	if err != nil {
		h.logf("netcfg: cannot open rollback journal: %v", err)
		return nil
	}
	h.journal = j
	return j
}

// Apply makes the marker block contain exactly entries. Passing an empty slice
// removes the block, which is what Remove does.
//
// Every entry is validated before anything is written: a single malformed
// hostname aborts the whole operation rather than putting a broken line into a
// file the resolver reads on every lookup.
//
// Note that the resolver caches negative and positive answers, so callers
// should follow a successful Apply with FlushDNSCache.
func (h *Hosts) Apply(entries []HostEntry) error {
	for i, e := range entries {
		if err := e.Validate(); err != nil {
			return fmt.Errorf("netcfg: hosts entry %d (%s): %w", i, e.IP, err)
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	orig, ok, err := readFileIfExists(h.path)
	if err != nil {
		return fmt.Errorf("netcfg: read %s: %w", h.path, err)
	}
	if !ok {
		return fmt.Errorf("netcfg: %s does not exist; refusing to create a hosts file", h.path)
	}
	st, err := os.Stat(h.path)
	if err != nil {
		return fmt.Errorf("netcfg: stat %s: %w", h.path, err)
	}

	want := h.planLocked(orig, entries)
	if bytesEqual(want, orig) {
		h.logf("netcfg: %s already holds the requested %d entry/entries", h.path, len(entries))
		return nil
	}
	// Round-trip check: whatever we are about to write must parse back to
	// exactly the entries requested.
	if err := h.verifyBlockLocked(want, entries); err != nil {
		return fmt.Errorf("netcfg: refusing to write %s: %w", h.path, err)
	}

	if h.dryRun {
		h.logf("netcfg: dry run: would write %d entry/entries into %s", len(entries), h.path)
		return nil
	}

	backup, sumBefore, err := h.backupLocked(orig, st)
	if err != nil {
		return err
	}
	if j := h.journalLocked(); j != nil {
		if err := j.Record(StepHosts, map[string]string{
			"path":          h.path,
			"backup":        backup,
			"sha256_before": sumBefore,
			"sha256_after":  sha256Hex(want),
			"entries":       strconv.Itoa(len(entries)),
			"marker":        h.marker,
		}); err != nil {
			h.logf("netcfg: journal record %s failed: %v", StepHosts, err)
		}
	}

	if err := writeFileAtomic(h.path, want, st.Mode().Perm(), st); err != nil {
		return err
	}
	got, rerr := os.ReadFile(h.path)
	if rerr != nil || !bytesEqual(got, want) {
		if werr := writeFileAtomic(h.path, orig, st.Mode().Perm(), st); werr != nil {
			return fmt.Errorf("netcfg: %s verification failed AND restoring backup %s failed: %w; "+
				"restore it by hand", h.path, backup, werr)
		}
		if rerr != nil {
			return fmt.Errorf("netcfg: re-reading %s failed, backup restored from %s: %w", h.path, backup, rerr)
		}
		return fmt.Errorf("netcfg: %s differs from what was written, backup restored from %s", h.path, backup)
	}
	h.logf("netcfg: wrote %d entry/entries into %s, backup %s", len(entries), h.path, backup)
	return nil
}

// Remove deletes our marker block from the hosts file, leaving every other line
// byte-identical. It is safe to call when no block is present.
func (h *Hosts) Remove() error { return h.Apply(nil) }

// Applied returns the entries currently inside our marker block, or nil when
// there is no block. A non-nil error reports lines inside the block that could
// not be parsed; the entries returned are still usable.
func (h *Hosts) Applied() ([]HostEntry, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, ok, err := readFileIfExists(h.path)
	if err != nil {
		return nil, fmt.Errorf("netcfg: read %s: %w", h.path, err)
	}
	if !ok {
		return nil, nil
	}
	block, found := extractBlock(b, h.marker)
	if !found {
		return nil, nil
	}
	return ParseHostsFile(block)
}

// planLocked computes the desired file content: the original with our block
// stripped, plus a fresh block appended when there is anything to write.
//
// No blank separator line is inserted around the block. That is deliberate:
// anything we add must be removable byte-for-byte, and a blank line we could
// not distinguish from one the operator wrote would either survive Remove (file
// grows on every cycle) or be deleted from a file we do not own.
//
// An Apply followed by Remove therefore restores the file byte for byte, with
// one unavoidable exception: if the original's last line was unterminated,
// appending a block has to supply the missing newline, and that byte stays.
func (h *Hosts) planLocked(orig []byte, entries []HostEntry) []byte {
	lines, trailing := splitLines(orig)
	base, _ := stripMarkerBlocks(lines, h.marker)
	if len(entries) == 0 {
		return joinLines(base, trailing)
	}
	out := append(make([]string, 0, len(base)+len(entries)+2), base...)
	out = append(out, markerBegin(h.marker))
	for _, e := range entries {
		out = append(out, e.String())
	}
	out = append(out, markerEnd(h.marker))
	return joinLines(out, true)
}

// verifyBlockLocked parses the block back out of candidate content and checks
// it matches entries exactly.
func (h *Hosts) verifyBlockLocked(content []byte, entries []HostEntry) error {
	if len(entries) == 0 {
		if _, found := extractBlock(content, h.marker); found {
			return errors.New("the marker block was supposed to be gone but is still present")
		}
		return nil
	}
	block, found := extractBlock(content, h.marker)
	if !found {
		return errors.New("the marker block is missing from the content that was about to be written")
	}
	got, err := ParseHostsFile(block)
	if err != nil {
		return fmt.Errorf("the block does not parse back: %w", err)
	}
	if len(got) != len(entries) {
		return fmt.Errorf("the block parses back to %d entry/entries, want %d", len(got), len(entries))
	}
	for i := range got {
		if got[i].IP != entries[i].IP || len(got[i].Names) != len(entries[i].Names) {
			return fmt.Errorf("entry %d does not round-trip: %q vs %q", i, got[i].String(), entries[i].String())
		}
		for j := range got[i].Names {
			if got[i].Names[j] != entries[i].Names[j] {
				return fmt.Errorf("entry %d does not round-trip: %q vs %q", i, got[i].String(), entries[i].String())
			}
		}
	}
	return nil
}

// backupLocked writes a byte-exact copy of the hosts file into the state dir.
func (h *Hosts) backupLocked(orig []byte, st os.FileInfo) (path, sum string, err error) {
	if h.stateDir == "" {
		return "", "", errors.New("netcfg: no state directory configured; refusing to patch a system file without a backup")
	}
	dir := filepath.Join(h.stateDir, BackupDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("netcfg: create backup dir %s: %w", dir, err)
	}
	name := filepath.Base(h.path)
	path, sum, err = backupFile(h.path, dir, name)
	if err != nil {
		return "", "", err
	}
	// backupFile re-read the file; confirm it matched what we planned from.
	if sum != sha256Hex(orig) {
		return "", "", fmt.Errorf("netcfg: %s changed while it was being backed up", h.path)
	}
	_ = st
	return path, sum, nil
}

// Close releases the journal handle.
func (h *Hosts) Close() error {
	h.mu.Lock()
	j := h.journal
	h.journal = nil
	h.mu.Unlock()
	if j != nil {
		return j.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// marker block helpers, shared with the pf.conf patcher
// ---------------------------------------------------------------------------

// stripMarkerBlocks removes every complete marker block, returning the
// surviving lines and how many were dropped. Unlike the pf.conf stripper it
// does not cap the block length, because a hosts block legitimately runs to
// hundreds of lines; an unterminated opening marker therefore drops only the
// marker line itself.
func stripMarkerBlocks(lines []string, name string) ([]string, int) {
	begin := markerBegin(name)
	end := markerEnd(name)
	out := make([]string, 0, len(lines))
	removed := 0
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != begin {
			if strings.TrimSpace(lines[i]) == end {
				removed++ // orphaned closing marker
				continue
			}
			out = append(out, lines[i])
			continue
		}
		closeAt := -1
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == end {
				closeAt = j
				break
			}
		}
		if closeAt < 0 {
			// No terminator: drop only this line so an interrupted write can
			// never delete unrelated host entries.
			removed++
			continue
		}
		removed += closeAt - i + 1
		i = closeAt
	}
	return out, removed
}

// extractBlock returns the lines between (exclusive) the markers, as bytes.
// found is false when there is no complete block.
func extractBlock(b []byte, name string) ([]byte, bool) {
	lines, _ := splitLines(b)
	begin := markerBegin(name)
	end := markerEnd(name)
	start := -1
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if start < 0 && t == begin {
			start = i
			continue
		}
		if start >= 0 && t == end {
			return joinLines(lines[start+1:i], true), true
		}
	}
	return nil, false
}
