// Package netcfg owns every system-level side effect zapret-mac performs:
// patching /etc/pf.conf, loading pf rules into a private anchor, maintaining
// pf tables, pinning /etc/hosts entries, flushing the DNS cache and reading the
// routing table.
//
// Everything in this package runs as root, so rollback is a first-class
// concern rather than an afterthought. The discipline every mutating operation
// follows is the same:
//
//  1. Take a byte-exact backup of the file (or record the kernel handle) and
//     append a Journal entry naming it, fsynced, BEFORE anything changes.
//  2. Validate the candidate state out-of-band (a temp copy parsed by
//     `pfctl -n -f`) so a syntactically broken ruleset never reaches the real
//     path.
//  3. Write atomically (temp file in the same directory + rename), preserving
//     mode and ownership.
//  4. Re-read and verify. On any mismatch, restore the backup immediately.
//
// Because the journal is append-only and fsynced, a daemon that is SIGKILLed
// mid-change leaves behind enough information for `zaprctl doctor --repair` to
// undo the change on the next run. Nothing in this package ever blanket-
// restores a backup over a file a third party has since edited: only our own
// marker-delimited blocks are ever removed.
package netcfg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// JournalName is the file name, inside the state directory, of the append-only
// rollback log.
const JournalName = "journal.jsonl"

// Journal step names recorded by this package. `zaprctl doctor --repair`
// switches on these when it rolls back a crashed daemon's changes.
const (
	// StepPfToken records a `pfctl -E` reference that must be released with
	// `pfctl -X <token>`. Data: "token".
	StepPfToken = "pf.token"
	// StepPfConf records a patch to the main pf configuration file.
	// Data: "path", "backup", "sha256_before", "sha256_after", "anchor".
	StepPfConf = "pf.conf"
	// StepPfRules records that a ruleset was loaded into our anchor.
	// Data: "anchor", "sha256".
	StepPfRules = "pf.rules"
	// StepPfTable records that a pf table was populated. Data: "anchor",
	// "table", "count".
	StepPfTable = "pf.table"
	// StepHosts records a patch to the hosts file. Data: "path", "backup",
	// "sha256_before", "sha256_after", "entries".
	StepHosts = "hosts"
	// StepUtun records a tunnel interface the daemon created. Data: "iface".
	StepUtun = "utun"
	// StepRoute records a route the daemon installed. Data: "dst", "iface",
	// "gateway".
	StepRoute = "route"
)

// Entry is one append-only journal record.
type Entry struct {
	// Time is the RFC3339 (nanosecond) timestamp the record was written.
	Time string `json:"time"`
	// Seq is a monotonically increasing per-file sequence number, so entries
	// stay ordered even when two records share a timestamp.
	Seq int `json:"seq"`
	// Step is one of the Step* constants.
	Step string `json:"step"`
	// Data carries the step's reversal parameters. String-valued so the file
	// stays trivially greppable and forward-compatible.
	Data map[string]string `json:"data,omitempty"`
}

// Journal is an append-only, fsynced JSON-lines record of every reversible
// change the daemon has made. It is safe for concurrent use.
type Journal struct {
	mu   sync.Mutex
	dir  string
	path string
	f    *os.File
	seq  int
}

// OpenJournal opens (creating if needed) the rollback journal in dir. The
// directory is created with mode 0700 and the journal with mode 0600 because
// it names backup files that may contain host configuration.
func OpenJournal(dir string) (*Journal, error) {
	if dir == "" {
		return nil, errors.New("netcfg: journal directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("netcfg: create state dir %s: %w", dir, err)
	}
	path := filepath.Join(dir, JournalName)
	// A crash can leave a partially written final line. Truncate it before
	// opening for append, or the next record would be concatenated onto the
	// torn one and lost as well.
	if err := truncateTornTail(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("netcfg: open journal %s: %w", path, err)
	}
	j := &Journal{dir: dir, path: path, f: f}
	// Continue the sequence where a previous process left off so ordering
	// survives a restart.
	if existing, err := readJournal(path); err == nil {
		for _, e := range existing {
			if e.Seq > j.seq {
				j.seq = e.Seq
			}
		}
	}
	return j, nil
}

// truncateTornTail drops an unterminated final line from a JSON-lines file, so
// the file always ends on a record boundary. A missing file is not an error.
func truncateTornTail(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("netcfg: read journal %s: %w", path, err)
	}
	if len(b) == 0 || b[len(b)-1] == '\n' {
		return nil
	}
	keep := 0
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == '\n' {
			keep = i + 1
			break
		}
	}
	if err := os.Truncate(path, int64(keep)); err != nil {
		return fmt.Errorf("netcfg: truncate torn journal tail in %s: %w", path, err)
	}
	return nil
}

// Path returns the journal file's absolute path.
func (j *Journal) Path() string { return j.path }

// Dir returns the state directory the journal lives in.
func (j *Journal) Dir() string { return j.dir }

// Record appends one entry and fsyncs it. A change must be journalled before
// it is made, never after: a record for a change that did not happen is
// harmless (rollback is idempotent), a change with no record is not.
func (j *Journal) Record(step string, data map[string]string) error {
	if j == nil {
		return errors.New("netcfg: nil journal")
	}
	if step == "" {
		return errors.New("netcfg: journal step must not be empty")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return errors.New("netcfg: journal is closed")
	}
	j.seq++
	e := Entry{
		Time: time.Now().UTC().Format(time.RFC3339Nano),
		Seq:  j.seq,
		Step: step,
	}
	if len(data) > 0 {
		e.Data = make(map[string]string, len(data))
		for k, v := range data {
			e.Data[k] = v
		}
	}
	line, err := json.Marshal(e)
	if err != nil {
		j.seq--
		return fmt.Errorf("netcfg: marshal journal entry: %w", err)
	}
	line = append(line, '\n')
	if _, err := j.f.Write(line); err != nil {
		return fmt.Errorf("netcfg: append to %s: %w", j.path, err)
	}
	if err := j.f.Sync(); err != nil {
		return fmt.Errorf("netcfg: fsync %s: %w", j.path, err)
	}
	return nil
}

// Entries returns every record currently in the journal, in write order.
// Malformed lines (a record torn by a power loss, for instance) are skipped
// rather than reported, because a partially written trailing line must not
// prevent rollback of the complete records before it.
func (j *Journal) Entries() ([]Entry, error) {
	if j == nil {
		return nil, errors.New("netcfg: nil journal")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return readJournal(j.path)
}

// entriesUnlocked reads the journal file WITHOUT taking j.mu.
//
// It exists for exactly one caller: code running inside a Rollback handler, which
// is already under j.mu. Taking the mutex again from the same goroutine is a
// self-deadlock — the daemon's StepPfConf handler used to hit it through
// PF.RemoveAnchorStatements -> detectPfConfDriftLocked -> Entries, wedging the
// process for ever on its first start after an unclean exit, with the pf rules
// already flushed and the control socket never created.
//
// j.path is immutable after construction, so reading it needs no lock. The worst
// a concurrent rewriteLocked can do is make this read see the pre- or post-
// rewrite file, both of which are complete JSON-lines documents.
func (j *Journal) entriesUnlocked() ([]Entry, error) {
	if j == nil {
		return nil, errors.New("netcfg: nil journal")
	}
	return readJournal(j.path)
}

// readJournal parses a JSON-lines journal, tolerating a torn final line.
func readJournal(path string) ([]Entry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("netcfg: read journal %s: %w", path, err)
	}
	var out []Entry
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue // torn or foreign line: skip, never abort
		}
		if e.Step == "" {
			continue
		}
		out = append(out, e)
	}
	// Stable order by sequence number; ties keep file order.
	sort.SliceStable(out, func(a, b int) bool { return out[a].Seq < out[b].Seq })
	return out, nil
}

// Rollback replays the journal in reverse (last change undone first) calling fn
// for each entry. Entries fn handles without error are dropped; entries fn
// fails on are kept so a later repair run can retry them. The journal file is
// rewritten atomically at the end, so an interrupted Rollback never loses
// records it has not yet undone.
//
// A nil fn is treated as "cannot undo anything" and leaves the journal intact.
func (j *Journal) Rollback(fn func(step string, data map[string]string) error) error {
	if j == nil {
		return errors.New("netcfg: nil journal")
	}
	if fn == nil {
		return errors.New("netcfg: Rollback needs a handler")
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	entries, err := readJournal(j.path)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	var (
		errs      []error
		remaining []Entry
	)
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if err := fn(e.Step, e.Data); err != nil {
			errs = append(errs, fmt.Errorf("rollback %s (seq %d): %w", e.Step, e.Seq, err))
			remaining = append(remaining, e)
		}
	}
	// remaining was built newest-first; restore write order before rewriting.
	sort.SliceStable(remaining, func(a, b int) bool { return remaining[a].Seq < remaining[b].Seq })
	if err := j.rewriteLocked(remaining); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Clear empties the journal. Call it only once every recorded change has been
// reverted (or deliberately adopted), because the records are the sole memory
// of what must be undone.
func (j *Journal) Clear() error {
	if j == nil {
		return errors.New("netcfg: nil journal")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.rewriteLocked(nil)
}

// ClearExcept empties the journal but keeps every record whose Step is listed.
//
// It exists because not everything in the journal describes a change the process
// owns for its lifetime: an /etc/hosts pinning block is an explicit user action
// ("zaprctl hosts apply") that must survive a clean shutdown, and clearing its
// record would leave `zaprctl doctor --repair` with nothing to revert.
func (j *Journal) ClearExcept(steps ...string) error {
	if j == nil {
		return errors.New("netcfg: nil journal")
	}
	if len(steps) == 0 {
		return j.Clear()
	}
	keep := make(map[string]bool, len(steps))
	for _, s := range steps {
		keep[s] = true
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := readJournal(j.path)
	if err != nil {
		return err
	}
	var out []Entry
	for _, e := range entries {
		if keep[e.Step] {
			out = append(out, e)
		}
	}
	return j.rewriteLocked(out)
}

// rewriteLocked replaces the journal's contents with entries. The caller holds
// j.mu. The append handle is reopened afterwards so subsequent Records land in
// the new file.
func (j *Journal) rewriteLocked(entries []Entry) error {
	var buf []byte
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("netcfg: marshal journal entry: %w", err)
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	if j.f != nil {
		_ = j.f.Close()
		j.f = nil
	}
	if err := writeFileAtomic(j.path, buf, 0o600, nil); err != nil {
		// Reopen so the journal stays usable even though the rewrite failed.
		if f, oerr := os.OpenFile(j.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); oerr == nil {
			j.f = f
		}
		return err
	}
	f, err := os.OpenFile(j.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("netcfg: reopen journal %s: %w", j.path, err)
	}
	j.f = f
	return nil
}

// Close releases the journal's file handle. The file itself is left in place.
func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return nil
	}
	err := j.f.Close()
	j.f = nil
	return err
}

// ---------------------------------------------------------------------------
// shared file plumbing
//
// Both the pf.conf and the hosts patcher need the same three primitives:
// hash a file, copy it byte-for-byte to the state directory, and replace it
// atomically without changing its mode or owner. They live here because the
// journal is what makes the resulting changes reversible.
// ---------------------------------------------------------------------------

// writeFileAtomic replaces path with data via a temp file in the same
// directory plus rename(2), which is atomic within a filesystem. When ref is
// non-nil the temp file inherits its mode, uid and gid, so replacing a
// root:wheel 0644 system file does not silently change its metadata.
//
// The containing directory is fsynced after the rename so the new name is
// durable, not just its contents.
func writeFileAtomic(path string, data []byte, mode os.FileMode, ref os.FileInfo) error {
	// rename(2) replaces the SYMLINK, not its target. A user who has symlinked
	// /etc/pf.conf (or /etc/hosts) into a dotfiles repository would silently lose
	// the link, keep an untouched repository copy, and have every later edit to it
	// ignored by the system. Operate on the real file instead.
	path, err := resolveForWrite(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, "."+base+".zapret-*")
	if err != nil {
		return fmt.Errorf("netcfg: create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("netcfg: write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("netcfg: fsync %s: %w", tmpName, err)
	}
	wantMode := mode
	if ref != nil {
		wantMode = ref.Mode().Perm()
	}
	if err := tmp.Chmod(wantMode); err != nil {
		cleanup()
		return fmt.Errorf("netcfg: chmod %s: %w", tmpName, err)
	}
	if uid, gid, ok := ownerOf(ref); ok {
		// Best effort: a non-root process cannot chown, and in that case the
		// temp file already belongs to the right (unprivileged) user.
		if err := tmp.Chown(uid, gid); err != nil && os.Geteuid() == 0 {
			cleanup()
			return fmt.Errorf("netcfg: chown %s: %w", tmpName, err)
		}
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("netcfg: close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("netcfg: rename %s -> %s: %w", tmpName, path, err)
	}
	syncDir(dir)
	return nil
}

// resolveForWrite returns the path an atomic replace should actually target:
// path itself for a regular (or absent) file, and the fully resolved target for a
// symlink. A symlink that cannot be resolved is an error rather than something to
// overwrite blindly.
//
// SymlinkTarget reports the same thing to callers that want to tell the operator.
func resolveForWrite(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return path, nil
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("netcfg: %s is a symlink whose target cannot be resolved: %w", path, err)
	}
	return real, nil
}

// SymlinkTarget reports the file a path really refers to when it is a symlink,
// and "" when it is a regular file, is absent, or cannot be resolved. Callers use
// it to tell the operator which file was actually edited.
func SymlinkTarget(path string) string {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return ""
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real == path {
		return ""
	}
	return real
}

// syncDir fsyncs a directory so a rename into it survives a crash. Failures
// are ignored: some filesystems reject O_RDONLY fsync on directories, and a
// missing directory fsync only weakens durability, it does not corrupt.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// ownerOf extracts the uid/gid of a stat result. ok is false when fi is nil or
// carries no Darwin stat structure.
func ownerOf(fi os.FileInfo) (uid, gid int, ok bool) {
	if fi == nil {
		return 0, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

// sha256Hex is the lowercase hex SHA-256 of b, the form recorded in the
// journal and compared against when detecting third-party edits.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// backupFile copies src byte-for-byte into dir and returns the new path plus
// the source's SHA-256. The copy keeps the original's permission bits so a
// restore reproduces them.
func backupFile(src, dir, prefix string) (path, sum string, err error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return "", "", fmt.Errorf("netcfg: read %s: %w", src, err)
	}
	st, err := os.Stat(src)
	if err != nil {
		return "", "", fmt.Errorf("netcfg: stat %s: %w", src, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("netcfg: create backup dir %s: %w", dir, err)
	}
	name := fmt.Sprintf("%s.%d.bak", prefix, time.Now().UTC().UnixNano())
	path = filepath.Join(dir, name)
	if err := writeFileAtomic(path, data, st.Mode().Perm(), nil); err != nil {
		return "", "", err
	}
	return path, sha256Hex(data), nil
}
