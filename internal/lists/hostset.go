package lists

import (
	"bytes"
	"slices"
	"strings"
)

// maxInlineHost is the size of the stack buffer Match uses to case-fold a
// hostname. Anything above the DNS limit (253 bytes) is pathological, so the
// buffer never needs to grow and lookups stay allocation-free.
const maxInlineHost = 256

// NewHostSet returns an empty HostSet. It matches nothing until entries are
// added or a file is loaded.
func NewHostSet() *HostSet {
	return &HostSet{root: &node{}}
}

// Add inserts one domain entry. The entry is normalised the same way file lines
// are: whitespace and an inline '#' comment are stripped, a leading "*." or "."
// wildcard marker and trailing dots are removed, and the result is lowercased.
// Junk (empty, embedded whitespace, a path) is ignored. Adding an entry that is
// already present is a no-op.
func (s *HostSet) Add(domain string) {
	e, ok := normalizeHostEntry(domain)
	if !ok {
		return
	}
	s.mu.Lock()
	s.addLocked(e)
	s.mu.Unlock()
}

// LoadFile parses path and adds its entries to the set; it is additive, so
// several files can be merged into one set (that is how flowseal passes
// --hostlist twice). The path is recorded in Files for Reload.
//
// A file with no usable entries sets Any: zapret treats an empty hostlist as
// "match everything", and Match honours that.
func (s *HostSet) LoadFile(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	parsed := 0
	err := forEachLine(path, func(line []byte) {
		e, ok := normalizeHostEntry(string(line))
		if !ok {
			return
		}
		parsed++
		s.addLocked(e)
	})
	if err != nil {
		return err
	}
	s.Files = append(s.Files, path)
	if parsed == 0 {
		s.Any = true
	}
	return nil
}

// Match reports whether host is covered by the set, using zapret's suffix rule:
// the entry "discord.com" matches "discord.com" and "cdn.discord.com" but not
// "notdiscord.com". Comparison is case-insensitive and a trailing dot on host is
// ignored. A set with Any matches every host, including the empty one.
//
// The lookup walks the reversed-label tree and allocates nothing: labels are
// sub-slices of host, and for hosts that contain ASCII upper case the folded
// copy lives in a stack buffer (m[string(b)] map lookups do not copy the key).
func (s *HostSet) Match(host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.Any {
		return true
	}
	if s.count == 0 || s.root == nil {
		return false
	}
	h := trimHostname(host)
	if h == "" {
		return false
	}
	if !hasASCIIUpper(h) {
		return matchTree(s.root, h)
	}
	if len(h) <= maxInlineHost {
		var buf [maxInlineHost]byte
		n := copy(buf[:], h)
		foldASCII(buf[:n])
		return matchTreeBytes(s.root, buf[:n])
	}
	return matchTree(s.root, strings.ToLower(h))
}

// Len reports the number of distinct entries in the set. An Any set reports 0
// entries even though it matches everything.
func (s *HostSet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.count
}

// Reload re-reads every file in Files and atomically replaces the set contents.
// Entries added with Add are not preserved, and a set with no files is left
// untouched. A missing file whose name ends in "-user.txt" is skipped (flowseal
// ships those as optional user overrides); any other read error leaves the
// current contents in place and is returned.
func (s *HostSet) Reload() error {
	s.mu.RLock()
	files := slices.Clone(s.Files)
	s.mu.RUnlock()
	if len(files) == 0 {
		return nil
	}
	fresh := NewHostSet()
	for _, p := range files {
		if err := fresh.LoadFile(p); err != nil {
			if isOptionalMissing(p, err) {
				continue
			}
			return err
		}
	}
	s.mu.Lock()
	s.root, s.count, s.Any, s.Files = fresh.root, fresh.count, fresh.Any, files
	s.mu.Unlock()
	return nil
}

// addLocked inserts an already-normalised entry. The caller holds s.mu.
func (s *HostSet) addLocked(e string) {
	if s.root == nil {
		s.root = &node{}
	}
	n := s.root
	// Labels are inserted right to left so that a suffix shares one path with
	// every domain under it.
	for i := len(e); ; {
		j := strings.LastIndexByte(e[:i], '.')
		label := e[j+1 : i]
		if label == "" {
			return // malformed entry such as "a..b"
		}
		kid := n.kids[label]
		if kid == nil {
			if n.kids == nil {
				n.kids = make(map[string]*node, 2)
			}
			kid = &node{}
			n.kids[label] = kid
		}
		n = kid
		if j < 0 {
			break
		}
		i = j
	}
	if !n.terminal {
		n.terminal = true
		s.count++
	}
}

// clearAny turns off the "empty list matches everything" flag. Used for
// self-learning lists, where an empty file must match nothing.
func (s *HostSet) clearAny() {
	s.mu.Lock()
	s.Any = false
	s.mu.Unlock()
}

// domains returns every entry of the set in sorted order, reconstructed from the
// reversed-label tree. Used to persist a self-learning list.
func (s *HostSet) domains() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, s.count)
	if s.root == nil {
		return out
	}
	var walk func(n *node, suffix string)
	walk = func(n *node, suffix string) {
		for label, kid := range n.kids {
			d := label
			if suffix != "" {
				d = label + "." + suffix
			}
			if kid.terminal {
				out = append(out, d)
			}
			if len(kid.kids) > 0 {
				walk(kid, d)
			}
		}
	}
	walk(s.root, "")
	slices.Sort(out)
	return out
}

// matchTree walks h right to left through the label tree.
func matchTree(root *node, h string) bool {
	n := root
	for i := len(h); i > 0; {
		j := strings.LastIndexByte(h[:i], '.')
		label := h[j+1 : i]
		if label == "" {
			return false
		}
		kid := n.kids[label]
		if kid == nil {
			return false
		}
		if kid.terminal {
			return true // an entry is a suffix of h
		}
		n = kid
		if j < 0 {
			break
		}
		i = j
	}
	return false
}

// matchTreeBytes is matchTree over a case-folded stack buffer.
func matchTreeBytes(root *node, h []byte) bool {
	n := root
	for i := len(h); i > 0; {
		j := bytes.LastIndexByte(h[:i], '.')
		label := h[j+1 : i]
		if len(label) == 0 {
			return false
		}
		// The compiler turns m[string(bytes)] into a lookup without copying.
		kid := n.kids[string(label)]
		if kid == nil {
			return false
		}
		if kid.terminal {
			return true
		}
		n = kid
		if j < 0 {
			break
		}
		i = j
	}
	return false
}

// normalizeHostEntry canonicalises one hostlist entry. ok is false when the line
// carries no entry (blank, comment, or non-domain junk).
func normalizeHostEntry(raw string) (entry string, ok bool) {
	e := raw
	if i := strings.IndexByte(e, '#'); i >= 0 {
		e = e[:i] // '#' starts a comment; it can never appear in a domain
	}
	e = strings.TrimSpace(e)
	// "*.example.com" and ".example.com" both mean "example.com and below",
	// which is already how every entry is matched.
	e = strings.TrimPrefix(e, "*")
	e = strings.Trim(e, ".")
	if e == "" {
		return "", false
	}
	if strings.ContainsAny(e, " \t\v\f\r/\\") {
		return "", false
	}
	for i := 0; i < len(e); i++ {
		if e[i] < 0x20 || e[i] == 0x7f {
			return "", false
		}
	}
	return strings.ToLower(e), true
}

// trimHostname strips surrounding whitespace and trailing dots without
// allocating.
func trimHostname(h string) string {
	for len(h) > 0 && isSpaceByte(h[0]) {
		h = h[1:]
	}
	for len(h) > 0 && (isSpaceByte(h[len(h)-1]) || h[len(h)-1] == '.') {
		h = h[:len(h)-1]
	}
	return h
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'
}

func hasASCIIUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

func foldASCII(b []byte) {
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
}
