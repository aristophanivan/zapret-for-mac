package lists

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// readBufSize bounds how much of a single line the loaders will buffer. Longer
// lines are skipped instead of being accumulated, so a hostile or binary file
// cannot make a load allocate without limit.
const readBufSize = 64 << 10

// NewSet returns a list collection resolving relative names against dir.
func NewSet(dir string) *Set {
	return &Set{
		dir:   dir,
		hosts: make(map[string]*HostSet),
		cidrs: make(map[string]*CIDRSet),
	}
}

// Hosts returns the merged hostlist for names, parsing each file at most once
// per name tuple: two profiles naming the same list get the exact same *HostSet,
// so a reload updates both. Passing several names merges them into one set,
// which is how flowseal passes --hostlist twice.
//
// Calling it with no names returns (nil, nil): a nil *HostSet is how a compiled
// filter spells "unrestricted".
//
// A missing file whose name ends in "-user.txt" is skipped — those are optional
// user overrides. Any other missing or unreadable file is an error.
func (s *Set) Hosts(names ...string) (*HostSet, error) {
	if len(names) == 0 {
		return nil, nil
	}
	key := cacheKey(names)
	s.mu.Lock()
	defer s.mu.Unlock()
	if hs, ok := s.hosts[key]; ok {
		return hs, nil
	}
	hs := NewHostSet()
	for _, name := range names {
		path := s.resolve(name)
		if err := hs.LoadFile(path); err != nil {
			if isOptionalMissing(path, err) {
				continue
			}
			return nil, fmt.Errorf("hostlist %s: %w", path, err)
		}
	}
	s.hosts[key] = hs
	return hs, nil
}

// CIDRs returns the merged ipset for names, with the same caching, merging and
// optional-user-file rules as Hosts. No names returns (nil, nil).
func (s *Set) CIDRs(names ...string) (*CIDRSet, error) {
	if len(names) == 0 {
		return nil, nil
	}
	key := cacheKey(names)
	s.mu.Lock()
	defer s.mu.Unlock()
	if cs, ok := s.cidrs[key]; ok {
		return cs, nil
	}
	cs := NewCIDRSet()
	for _, name := range names {
		path := s.resolve(name)
		if err := cs.LoadFile(path); err != nil {
			if isOptionalMissing(path, err) {
				continue
			}
			return nil, fmt.Errorf("ipset %s: %w", path, err)
		}
	}
	s.cidrs[key] = cs
	return cs, nil
}

// ReloadAll re-reads every cached list in place, so filters already compiled
// against them see the new contents. Every list is attempted even if one fails;
// the failures are returned joined.
func (s *Set) ReloadAll() error {
	s.mu.Lock()
	hosts := make([]*HostSet, 0, len(s.hosts))
	for _, h := range s.hosts {
		hosts = append(hosts, h)
	}
	cidrs := make([]*CIDRSet, 0, len(s.cidrs))
	for _, c := range s.cidrs {
		cidrs = append(cidrs, c)
	}
	s.mu.Unlock()

	var errs []error
	for _, h := range hosts {
		if err := h.Reload(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, c := range cidrs {
		if err := c.Reload(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Stats reports the entry count of every cached list, keyed by the name tuple it
// was requested with (comma-separated when merged). A list in the Any state
// reports 0 because it holds no entries. An ipset that happens to share a name
// with a hostlist is reported under name+"#ipset".
func (s *Set) Stats() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.hosts)+len(s.cidrs))
	for k, h := range s.hosts {
		out[k] = h.Len()
	}
	for k, c := range s.cidrs {
		if _, dup := out[k]; dup {
			k += "#ipset"
		}
		out[k] = c.Len()
	}
	return out
}

// resolve turns a list name into a path. Absolute paths pass through.
func (s *Set) resolve(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(s.dir, name)
}

// cacheKey is the cache/Stats key for a name tuple, in the order given.
func cacheKey(names []string) string {
	if len(names) == 1 {
		return names[0]
	}
	return strings.Join(names, ",")
}

// isOptionalMissing reports whether err is "file does not exist" for a file that
// is allowed to be absent: flowseal's *-user.txt overrides.
func isOptionalMissing(path string, err error) bool {
	if !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return strings.HasSuffix(strings.ToLower(filepath.Base(path)), "-user.txt")
}

// forEachLine calls fn once per line of path, without the line terminator. The
// slice passed to fn is only valid for the duration of the call. Lines longer
// than readBufSize are skipped whole rather than buffered.
func forEachLine(path string, fn func(line []byte)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, readBufSize)
	for {
		line, isPrefix, err := br.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if isPrefix {
			// Oversized line: drain its remaining fragments and ignore it.
			for isPrefix {
				_, isPrefix, err = br.ReadLine()
				if err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					}
					return err
				}
			}
			continue
		}
		fn(line)
	}
}
