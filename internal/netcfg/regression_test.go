package netcfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This file holds regression tests for the review findings the integration pass
// fixed in this package. Each one FAILED before the fix; several failed by
// hanging, which is why they run inside a goroutine with a timeout.

// TestRollbackHandlerMayCallRemoveAnchorStatements is the journal lock inversion.
//
// BEFORE: Journal.Rollback held j.mu across the whole replay, and the daemon's
// StepPfConf handler called PF.RemoveAnchorStatements -> detectPfConfDriftLocked
// -> Journal.Entries -> j.mu.Lock() on the SAME goroutine. sync.Mutex is not
// reentrant, so the daemon wedged for ever on its first start after an unclean
// exit: pf rules already flushed, control socket never created, launchd never
// restarting it because the process never exited.
func TestRollbackHandlerMayCallRemoveAnchorStatements(t *testing.T) {
	p, conf, state := newTestPF(t, stockPfConf)

	// Journal one pf.conf record, exactly as EnsureAnchorStatements would, and
	// put our marker block into the file so the removal has something to do.
	j := p.Journal()
	if j == nil {
		t.Fatal("no journal")
	}
	patched := planPfConf([]byte(stockPfConf), p.Anchor())
	if !patched.Changed {
		t.Fatal("planPfConf did not change the stock file")
	}
	if err := os.WriteFile(conf, patched.Content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := j.Record(StepPfConf, map[string]string{
		"path":          conf,
		"sha256_before": sha256Hex([]byte(stockPfConf)),
		"sha256_after":  sha256Hex(patched.Content),
		"anchor":        p.Anchor(),
	}); err != nil {
		t.Fatal(err)
	}
	_ = state

	done := make(chan error, 1)
	go func() {
		done <- j.Rollback(func(step string, _ map[string]string) error {
			if step != StepPfConf {
				return nil
			}
			// THE call that used to deadlock.
			return p.RemoveAnchorStatements()
		})
	}()
	select {
	case err := <-done:
		// pfctl may be unavailable in the sandbox; the point of the test is that
		// the call RETURNS. A parse-check failure is an acceptable outcome.
		if err != nil {
			t.Logf("Rollback returned %v (fine: it returned at all)", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Journal.Rollback deadlocked calling RemoveAnchorStatements from its handler")
	}
}

// TestPlanPfConfAlwaysTerminatesTheFile: pfctl cannot parse a pf.conf whose last
// line has no newline, so faithfully preserving a missing final byte made our own
// candidate fail the parse check, turned EnsureAnchorStatements into a hard error
// and left launchd crash-looping the daemon every 10 seconds.
func TestPlanPfConfAlwaysTerminatesTheFile(t *testing.T) {
	for _, in := range []string{
		`anchor "com.apple/*"`,                                 // no trailing newline at all
		"scrub-anchor \"com.apple/*\"\nanchor \"com.apple/*\"", // ditto, two lines
	} {
		plan := planPfConf([]byte(in), "zapret-mac")
		if len(plan.Content) == 0 || plan.Content[len(plan.Content)-1] != '\n' {
			t.Fatalf("planPfConf(%q) does not end with a newline:\n%q", in, plan.Content)
		}
		rem := planPfConfRemoval(plan.Content, "zapret-mac")
		if len(rem.Content) == 0 || rem.Content[len(rem.Content)-1] != '\n' {
			t.Fatalf("planPfConfRemoval does not end with a newline:\n%q", rem.Content)
		}
	}
}

// TestSectionInsertPointsIgnoresMacros: reFilterLine used `\b`, which also matches
// before '-', so the ordinary macro `pass-through = "{ 80 }"` was taken for the
// start of the filter section and both statements were inserted above it — and
// above any options statement, which a stricter ruleset rejects outright.
func TestSectionInsertPointsIgnoresMacros(t *testing.T) {
	conf := `pass-through = "{ 80 443 }"
set skip on lo0
scrub-anchor "com.apple/*"
anchor "com.apple/*"
`
	plan := planPfConf([]byte(conf), "zapret-mac")
	lines := strings.Split(string(plan.Content), "\n")
	if lines[0] != `pass-through = "{ 80 443 }"` {
		t.Fatalf("the macro is no longer the first line:\n%s", plan.Content)
	}
	if lines[1] != "set skip on lo0" {
		t.Fatalf("a statement was inserted above the options section:\n%s", plan.Content)
	}
	// Our block must land at the com.apple filter anchor, not at line 1.
	idx := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == markerBegin("zapret-mac") {
			idx = i
			break
		}
	}
	if idx < 2 {
		t.Fatalf("our first marker is at line %d, want it after the macro and the options statement:\n%s",
			idx, plan.Content)
	}
}

// TestWriteFileAtomicPreservesASymlink: rename(2) replaces the SYMLINK, not its
// target, so a user who had symlinked /etc/pf.conf into a dotfiles repository lost
// the link, kept an untouched repository copy, and had every later edit to it
// ignored by the system.
func TestWriteFileAtomicPreservesASymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.conf")
	link := filepath.Join(dir, "link.conf")
	if err := os.WriteFile(real, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	if err := writeFileAtomic(link, []byte("patched\n"), 0o644, nil); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was replaced by a regular file (mode %s)", fi.Mode())
	}
	got, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "patched\n" {
		t.Fatalf("the real target holds %q, want the patched content", got)
	}
	// EvalSymlinks also resolves /var -> /private/var on macOS, so compare against
	// the resolved form.
	wantTarget, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if target := SymlinkTarget(link); target != wantTarget {
		t.Fatalf("SymlinkTarget = %q, want %q", target, wantTarget)
	}
	if target := SymlinkTarget(real); target != "" {
		t.Fatalf("SymlinkTarget of a regular file = %q, want \"\"", target)
	}
}

// TestBackupPfConfRefusesAConcurrentWriter: between the read in
// EnsureAnchorStatements and the backup we fork `pfctl -n -f` on a scratch copy,
// which takes tens of milliseconds. A third party rewriting the file in that
// window used to be silently overwritten, AND the "byte-exact backup" held OUR
// stale read, making their edit unrecoverable.
func TestBackupPfConfRefusesAConcurrentWriter(t *testing.T) {
	p, conf, _ := newTestPF(t, stockPfConf)
	st, err := os.Stat(conf)
	if err != nil {
		t.Fatal(err)
	}
	// Somebody else rewrote the file after we read `orig`.
	if err := os.WriteFile(conf, []byte("# a VPN's postinstall got here first\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	p.mu.Lock()
	_, _, berr := p.backupPfConf([]byte(stockPfConf), st)
	p.mu.Unlock()
	if berr == nil {
		t.Fatal("backupPfConf accepted a file that had changed under it")
	}
	if !strings.Contains(berr.Error(), "changed while it was being backed up") {
		t.Fatalf("error = %v, want it to name the concurrent change", berr)
	}
	// And their content is still there.
	got, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "postinstall") {
		t.Fatalf("the third party's content was destroyed: %q", got)
	}
}

// TestPruneBackupsKeepsTheNewest: every patch wrote a timestamped backup and
// nothing ever removed one.
func TestPruneBackupsKeepsTheNewest(t *testing.T) {
	p, _, state := newTestPF(t, stockPfConf)
	dir := filepath.Join(state, BackupDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxKeptBackups+4; i++ {
		// Fixed-width timestamps so the lexical sort is chronological.
		name := filepath.Join(dir, "pf.conf.17000000000000000"+string(rune('0'+i))+".bak")
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A foreign file must survive untouched.
	foreign := filepath.Join(dir, "hosts.1700000000000000000.bak")
	if err := os.WriteFile(foreign, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}

	p.mu.Lock()
	p.pruneBackupsLocked(dir, "pf.conf")
	p.mu.Unlock()

	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	ours, others := 0, 0
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "pf.conf.") {
			ours++
		} else {
			others++
		}
	}
	if ours != maxKeptBackups {
		t.Fatalf("%d pf.conf backups left, want %d", ours, maxKeptBackups)
	}
	if others != 1 {
		t.Fatalf("%d foreign files left, want the hosts backup untouched", others)
	}
}

// TestClearExceptKeepsTheHostsRecord: cleanup() used to clear the WHOLE journal on
// a clean shutdown, including the /etc/hosts record rollbackPrevious deliberately
// keeps — leaving `zaprctl doctor --repair` with nothing to revert.
func TestClearExceptKeepsTheHostsRecord(t *testing.T) {
	j, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	for _, step := range []string{StepPfToken, StepHosts, StepPfRules, StepPfTable} {
		if err := j.Record(step, map[string]string{"k": "v"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.ClearExcept(StepHosts); err != nil {
		t.Fatalf("ClearExcept: %v", err)
	}
	got, err := j.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Step != StepHosts {
		t.Fatalf("entries = %+v, want only the hosts record", got)
	}
	// The append handle must still work afterwards.
	if err := j.Record(StepUtun, nil); err != nil {
		t.Fatalf("Record after ClearExcept: %v", err)
	}
	if got, _ = j.Entries(); len(got) != 2 {
		t.Fatalf("entries = %+v, want the hosts record plus the new one", got)
	}
}

// TestPfConfSumSurvivesAJournalClear: detectPfConfDrift read the hash from the
// journal, which a clean shutdown empties, so after the first clean stop
// ErrPfConfDrift — the documented "somebody else edited this file" signal — could
// never fire again.
func TestPfConfSumSurvivesAJournalClear(t *testing.T) {
	p, conf, _ := newTestPF(t, stockPfConf)
	patched := planPfConf([]byte(stockPfConf), p.Anchor())

	p.mu.Lock()
	p.writePfConfSumLocked(sha256Hex(patched.Content))
	p.mu.Unlock()

	if j := p.Journal(); j != nil {
		if err := j.Clear(); err != nil {
			t.Fatal(err)
		}
	}

	// Same content as recorded: no drift.
	p.mu.Lock()
	err := p.detectPfConfDriftLocked(patched.Content)
	p.mu.Unlock()
	if err != nil {
		t.Fatalf("detectPfConfDrift reported drift for the recorded content: %v", err)
	}

	// Somebody else edited it: drift, even though the journal is empty.
	p.mu.Lock()
	err = p.detectPfConfDriftLocked([]byte(string(patched.Content) + "# a VPN was here\n"))
	p.mu.Unlock()
	if err == nil {
		t.Fatal("detectPfConfDrift reported no drift after the file changed and the journal was cleared")
	}
	_ = conf
}
