package lists

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Defaults for AutoList, matching nfqws' --hostlist-auto-fail-threshold,
// --hostlist-auto-fail-time and --hostlist-auto-retrans-threshold.
const (
	defaultFailThreshold    = 3
	defaultFailTimeSeconds  = 60
	defaultRetransThreshold = 3

	// maxAutoTracked bounds the pending-host table so a flood of distinct
	// hostnames cannot grow it without limit.
	maxAutoTracked = 4096

	autoHeader = "# zapret-mac --hostlist-auto: hosts learned automatically. Remove a line to unlearn it."
)

// autoClock returns the current time in nanoseconds. It is a package variable so
// tests can inject a deterministic clock: AutoList's fields are fixed by the
// contract file, so there is nowhere to keep a per-instance clock.
var autoClock = monotonicNowNs

// monotonicNowNs is the production clock.
func monotonicNowNs() int64 { return time.Now().UnixNano() }

// NewAutoList opens (or prepares to create) the self-learning hostlist at path.
// An existing file is loaded so hosts learned in an earlier run keep matching. A
// missing file is not an error; it is created by the first Flush.
func NewAutoList(path string) (*AutoList, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("lists: hostlist-auto path is empty")
	}
	a := &AutoList{
		path:             path,
		FailThreshold:    defaultFailThreshold,
		FailTimeSeconds:  defaultFailTimeSeconds,
		RetransThreshold: defaultRetransThreshold,
		hosts:            make(map[string]*autoEntry),
		set:              NewHostSet(),
	}
	if err := a.set.LoadFile(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	// An empty or header-only auto-list must match nothing. The zapret rule that
	// an empty hostlist means "match everything" applies to configured lists, not
	// to a list we are still learning.
	a.set.clearAny()
	return a, nil
}

// Set returns the HostSet holding the learned hosts. It is safe to use as a
// filter's hostlist: it grows as hosts are learned.
func (a *AutoList) Set() *HostSet { return a.set }

// Fail records one connection failure for host and reports whether that pushed
// the host onto the list. A host is added once FailThreshold failures land inside
// a FailTimeSeconds window; the window restarts when it expires, so slow
// trickles of unrelated failures never accumulate.
func (a *AutoList) Fail(host string) bool {
	h, ok := normalizeHostEntry(host)
	if !ok {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.set.Match(h) {
		return false // already covered by a learned entry
	}
	now := autoClock()
	e := a.entryLocked(h, now)
	window := int64(a.failTime()) * int64(time.Second)
	if e.firstNs == 0 || now-e.firstNs > window {
		e.firstNs = now
		e.fails = 0
	}
	e.fails++
	if e.fails >= a.failThreshold() {
		return a.addLocked(h)
	}
	return false
}

// Retrans records one client retransmission for host and reports whether that
// pushed the host onto the list. Retransmissions are not time-windowed: nfqws
// treats RetransThreshold of them as proof the handshake is being dropped.
func (a *AutoList) Retrans(host string) bool {
	h, ok := normalizeHostEntry(host)
	if !ok {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.set.Match(h) {
		return false
	}
	e := a.entryLocked(h, autoClock())
	e.retrans++
	if e.retrans >= a.retransThreshold() {
		return a.addLocked(h)
	}
	return false
}

// Flush persists the learned hosts. It is idempotent — a Flush with nothing new
// to write does no I/O — and atomic: the full list is written to a temporary file
// in the same directory and renamed over the target, so a reader never sees a
// half-written list. The file is a plain one-host-per-line hostlist with a header
// comment, so it can be fed back to --hostlist unchanged.
func (a *AutoList) Flush() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.dirty {
		return nil
	}
	domains := a.set.domains()

	var b strings.Builder
	b.Grow(len(autoHeader) + 1 + len(domains)*24)
	b.WriteString(autoHeader)
	b.WriteByte('\n')
	for _, d := range domains {
		b.WriteString(d)
		b.WriteByte('\n')
	}

	dir := filepath.Dir(a.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".hostlist-auto-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpName, a.path); err != nil {
		return err
	}
	tmpName = "" // renamed away; nothing to clean up
	a.dirty = false
	return nil
}

// entryLocked returns the pending counter for h, creating it if needed. The
// caller holds a.mu.
func (a *AutoList) entryLocked(h string, now int64) *autoEntry {
	if a.hosts == nil {
		a.hosts = make(map[string]*autoEntry)
	}
	if e := a.hosts[h]; e != nil {
		return e
	}
	if len(a.hosts) >= maxAutoTracked {
		a.gcLocked(now)
	}
	e := &autoEntry{firstNs: now}
	a.hosts[h] = e
	return e
}

// gcLocked drops pending counters whose fail window has expired; if that frees
// nothing the table is cleared outright. The caller holds a.mu.
func (a *AutoList) gcLocked(now int64) {
	window := int64(a.failTime()) * int64(time.Second)
	for h, e := range a.hosts {
		if now-e.firstNs > window {
			delete(a.hosts, h)
		}
	}
	if len(a.hosts) >= maxAutoTracked {
		a.hosts = make(map[string]*autoEntry, maxAutoTracked/2)
	}
}

// addLocked promotes h onto the list. Returns false when it was already covered.
// The caller holds a.mu.
func (a *AutoList) addLocked(h string) bool {
	if a.set.Match(h) {
		return false
	}
	a.set.Add(h)
	delete(a.hosts, h)
	a.dirty = true
	return true
}

// The threshold accessors treat a non-positive field as "use the default", so a
// zero-valued AutoList field still behaves like nfqws.

func (a *AutoList) failThreshold() int {
	if a.FailThreshold > 0 {
		return a.FailThreshold
	}
	return defaultFailThreshold
}

func (a *AutoList) failTime() int {
	if a.FailTimeSeconds > 0 {
		return a.FailTimeSeconds
	}
	return defaultFailTimeSeconds
}

func (a *AutoList) retransThreshold() int {
	if a.RetransThreshold > 0 {
		return a.RetransThreshold
	}
	return defaultRetransThreshold
}
