// Package lists implements zapret's hostlist and ipset matching:
// suffix-matched domain sets and CIDR sets, with the tri-state
// loaded / none / any semantics flowseal's service.bat exposes.
//
// CONTRACT FILE — types only.
package lists

import (
	"net/netip"
	"sync"
)

// HostSet is a domain set matched by suffix, the way zapret does it: an entry
// "discord.com" matches "discord.com" and "cdn.discord.com" but not
// "notdiscord.com". A line starting with '#' is a comment.
type HostSet struct {
	mu    sync.RWMutex
	root  *node
	count int
	// Any is true when the set was loaded from an empty file, which zapret
	// treats as "match everything" (flowseal's `ipset any` equivalent).
	Any bool
	// Files records the paths this set was loaded from, for reload.
	Files []string
}

// node is one label of the reversed-domain tree.
type node struct {
	kids     map[string]*node
	terminal bool
}

// CIDRSet is a set of IPv4/IPv6 prefixes with longest-prefix membership.
// A set loaded from an empty file matches everything (Any), matching the
// tri-state ipset switch; a set containing only the sentinel 203.0.113.113/32
// is flowseal's "none".
type CIDRSet struct {
	mu     sync.RWMutex
	v4     []netip.Prefix
	v6     []netip.Prefix
	count  int
	Any    bool
	Files  []string
	sorted bool
}

// Set is the collection of lists a strategy references, keyed by file name so
// two profiles naming the same file share one parsed copy.
type Set struct {
	mu    sync.Mutex
	dir   string
	hosts map[string]*HostSet
	cidrs map[string]*CIDRSet
}

// AutoList is --hostlist-auto: a self-learning blocklist. Hosts are added when
// a flow fails FailThreshold times within FailTime, or shows RetransThreshold
// client retransmissions.
type AutoList struct {
	mu   sync.Mutex
	path string

	FailThreshold    int // default 3
	FailTimeSeconds  int // default 60
	RetransThreshold int // default 3

	hosts map[string]*autoEntry
	set   *HostSet
	dirty bool
}

type autoEntry struct {
	fails   int
	retrans int
	firstNs int64
}
