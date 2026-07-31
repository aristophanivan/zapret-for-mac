package lists

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
)

// noneSentinel is flowseal's "ipset none" marker. 203.0.113.113 is in TEST-NET-3
// (RFC 5737), so the entry is a normal prefix that can never match real traffic;
// IsNone only reports its presence so the CLI can show the tri-state.
var noneSentinel = netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, 113}), 32)

// NewCIDRSet returns an empty CIDRSet. It matches nothing until prefixes are
// added or a file is loaded.
func NewCIDRSet() *CIDRSet {
	return &CIDRSet{sorted: true}
}

// Add inserts one prefix. The prefix is canonicalised: host bits are zeroed, a
// zone is dropped, and a 4-in-6 prefix (::ffff:a.b.c.d/N, N >= 96) becomes the
// equivalent IPv4 prefix so it matches unmapped addresses. Invalid prefixes and
// 4-in-6 prefixes shorter than /96 are ignored.
func (s *CIDRSet) Add(p netip.Prefix) {
	s.mu.Lock()
	s.addLocked(p)
	s.mu.Unlock()
}

// LoadFile parses path and adds its prefixes; it is additive, so several files
// can be merged into one set. Accepted line forms are "1.2.3.0/24", a bare
// "1.2.3.4" (treated as /32), and the same for IPv6 with or without a prefix
// length. Blank lines, '#' comments and unparsable junk are skipped.
//
// A file with no usable entries sets Any, flowseal's "ipset any" state, and
// Match then returns true for every address.
func (s *CIDRSet) LoadFile(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	parsed := 0
	err := forEachLine(path, func(line []byte) {
		p, ok := parsePrefixLine(line)
		if !ok {
			return
		}
		parsed++
		s.addLocked(p)
	})
	if err != nil {
		return err
	}
	s.Files = append(s.Files, path)
	if parsed == 0 {
		s.Any = true
	}
	// Bulk load: sort once at the end instead of once per prefix.
	s.sortLocked()
	return nil
}

// Match reports whether a is inside any prefix of the set. A 4-in-6 address is
// unmapped first, so ::ffff:1.2.3.4 matches 1.2.3.0/24. An Any set matches every
// valid address.
func (s *CIDRSet) Match(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	if a.Zone() != "" {
		a = a.WithZone("")
	}
	s.ensureSorted()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.Any {
		return true
	}
	ps := s.v6
	if a.Is4() {
		ps = s.v4
	}
	if !s.sorted {
		// An Add raced in between ensureSorted and this read lock. Rare (Add is
		// a configuration-time call), so fall back to a correct linear scan
		// rather than binary-searching unsorted data.
		return containsLinear(ps, a)
	}
	return containsSorted(ps, a)
}

// Len reports the number of distinct prefixes in the set. An Any set reports 0
// even though it matches everything.
func (s *CIDRSet) Len() int {
	s.ensureSorted()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.count
}

// IsNone reports whether the set is flowseal's "none" state: exactly one entry,
// the 203.0.113.113/32 sentinel. Such a set matches no real address.
func (s *CIDRSet) IsNone() bool {
	s.ensureSorted()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.Any && s.count == 1 && len(s.v4) == 1 && s.v4[0] == noneSentinel
}

// Reload re-reads every file in Files and atomically replaces the set contents.
// Prefixes added with Add are not preserved, and a set with no files is left
// untouched. A missing "-user.txt" file is skipped; any other read error leaves
// the current contents in place and is returned. Concurrent Match calls keep
// working against the old contents until the swap.
func (s *CIDRSet) Reload() error {
	s.mu.RLock()
	files := slices.Clone(s.Files)
	s.mu.RUnlock()
	if len(files) == 0 {
		return nil
	}
	fresh := NewCIDRSet()
	for _, p := range files {
		if err := fresh.LoadFile(p); err != nil {
			if isOptionalMissing(p, err) {
				continue
			}
			return err
		}
	}
	s.mu.Lock()
	s.v4, s.v6, s.count, s.Any, s.Files, s.sorted = fresh.v4, fresh.v6, fresh.count, fresh.Any, files, fresh.sorted
	s.mu.Unlock()
	return nil
}

// addLocked appends a canonicalised prefix. The caller holds s.mu.
func (s *CIDRSet) addLocked(p netip.Prefix) {
	p, ok := canonPrefix(p)
	if !ok {
		return
	}
	if p.Addr().Is4() {
		s.v4 = append(s.v4, p)
	} else {
		s.v6 = append(s.v6, p)
	}
	s.count++
	s.sorted = false
}

// ensureSorted sorts and de-duplicates the prefix slices if a previous Add left
// them dirty.
func (s *CIDRSet) ensureSorted() {
	s.mu.RLock()
	sorted := s.sorted
	s.mu.RUnlock()
	if sorted {
		return
	}
	s.mu.Lock()
	if !s.sorted {
		s.sortLocked()
	}
	s.mu.Unlock()
}

// sortLocked orders both families by (bits, address) and drops duplicates. That
// order is what containsSorted binary-searches. The caller holds s.mu for write.
func (s *CIDRSet) sortLocked() {
	s.v4 = sortPrefixes(s.v4)
	s.v6 = sortPrefixes(s.v6)
	s.count = len(s.v4) + len(s.v6)
	s.sorted = true
}

func sortPrefixes(ps []netip.Prefix) []netip.Prefix {
	slices.SortFunc(ps, comparePrefix)
	return slices.CompactFunc(ps, func(a, b netip.Prefix) bool { return a == b })
}

func comparePrefix(a, b netip.Prefix) int {
	if c := cmp.Compare(a.Bits(), b.Bits()); c != 0 {
		return c
	}
	return a.Addr().Compare(b.Addr())
}

// containsSorted tests membership over prefixes sorted by (bits, address).
//
// It walks the distinct prefix lengths present in ps from longest to shortest —
// each step's length comes straight out of the slice, so absent lengths cost
// nothing — and for every length masks a to that length and binary-searches the
// length's contiguous run. That is O(distinct lengths * log n) with no
// allocation; the real ipset-all.txt has 24 IPv4 and 28 IPv6 lengths over 32k
// prefixes.
func containsSorted(ps []netip.Prefix, a netip.Addr) bool {
	hi := len(ps)
	for hi > 0 {
		bits := ps[hi-1].Bits()
		lo := lowerBoundBits(ps, hi, bits)
		want := netip.PrefixFrom(a, bits).Masked().Addr()
		if want.IsValid() {
			if i := lowerBoundAddr(ps, lo, hi, want); i < hi && ps[i].Addr() == want {
				return true
			}
		}
		hi = lo
	}
	return false
}

// containsLinear is the unsorted fallback.
func containsLinear(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// lowerBoundBits returns the first index in ps[:hi] whose prefix length is >= bits.
func lowerBoundBits(ps []netip.Prefix, hi, bits int) int {
	lo := 0
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if ps[mid].Bits() < bits {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

// lowerBoundAddr returns the first index in ps[lo:hi] whose network address is
// >= want. All entries in that range share one prefix length.
func lowerBoundAddr(ps []netip.Prefix, lo, hi int, want netip.Addr) int {
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if ps[mid].Addr().Compare(want) < 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

// canonPrefix zeroes host bits, drops a zone and folds 4-in-6 into IPv4.
func canonPrefix(p netip.Prefix) (netip.Prefix, bool) {
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	a, bits := p.Addr(), p.Bits()
	if a.Is4In6() {
		if bits < 96 {
			// Shorter than the mapped range: not expressible as an IPv4 prefix.
			return netip.Prefix{}, false
		}
		a, bits = a.Unmap(), bits-96
	}
	if a.Zone() != "" {
		a = a.WithZone("")
	}
	np := netip.PrefixFrom(a, bits)
	if !np.IsValid() {
		return netip.Prefix{}, false
	}
	return np.Masked(), true
}

// parsePrefixLine parses one ipset line. ok is false for blank lines, comments
// and anything that is not an address or prefix.
func parsePrefixLine(line []byte) (netip.Prefix, bool) {
	s := string(line)
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, false
	}
	if strings.IndexByte(s, '/') >= 0 {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p, true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	// A bare address is a single host: /32 for IPv4, /128 for IPv6.
	return netip.PrefixFrom(a, a.BitLen()), true
}
