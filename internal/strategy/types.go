// Package strategy loads TOML strategy files (the macOS equivalent of
// flowseal's *.bat winws command lines) and compiles them into profiles the
// desync engine can execute.
//
// CONTRACT FILE — types only.
package strategy

import (
	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/lists"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// ---------- on-disk schema (TOML) ----------

// File is one strategy file: a global port window plus an ordered profile
// chain. The chain is winws' `--new`-separated profile list; first match wins.
type File struct {
	Name        string        `toml:"name"`
	Description string        `toml:"description"`
	Source      string        `toml:"source"` // upstream .bat this was converted from
	Window      WindowSpec    `toml:"window"`
	Profiles    []ProfileSpec `toml:"profile"`
}

// WindowSpec is --wf-tcp / --wf-udp: the set of ports the transport steers into
// userspace at all. Entries are "443" or "19294-19344".
type WindowSpec struct {
	TCP []string `toml:"tcp"`
	UDP []string `toml:"udp"`
}

// ProfileSpec is one --new section.
type ProfileSpec struct {
	Name          string     `toml:"name"`
	Filter        FilterSpec `toml:"filter"`
	Cutoff        string     `toml:"cutoff"`         // --dpi-desync-cutoff, e.g. "n3", "d2", "s5000"
	Start         string     `toml:"start"`          // --dpi-desync-start
	OnUnsupported string     `toml:"on_unsupported"` // degrade|skip|error (default degrade)
	Ops           []OpSpec   `toml:"ops"`
}

// FilterSpec is the --filter-*/--hostlist*/--ipset* set of one profile.
type FilterSpec struct {
	Proto                  string   `toml:"proto"` // tcp|udp|any
	Ports                  []string `toml:"ports"`
	L3                     string   `toml:"l3"` // ipv4|ipv6|any
	L7                     []string `toml:"l7"`
	Hostlist               []string `toml:"hostlist"`
	HostlistDomains        []string `toml:"hostlist_domains"`
	HostlistExclude        []string `toml:"hostlist_exclude"`
	HostlistExcludeDomains []string `toml:"hostlist_exclude_domains"`
	HostlistAuto           string   `toml:"hostlist_auto"`
	IPSet                  []string `toml:"ipset"`
	IPSetExclude           []string `toml:"ipset_exclude"`
}

// OpSpec is one desync technique with its knobs. `op` names match zapret's
// --dpi-desync modes plus the pseudo-ops "ip_id", "wssize", "block".
type OpSpec struct {
	Op      string   `toml:"op"`
	Repeats int      `toml:"repeats"`
	TTL     string   `toml:"ttl"` // "5" | "auto" | "auto:-1:3-20" | "hops:-1"
	Fooling []string `toml:"fooling"`

	BadSeqIncrement *int32 `toml:"badseq_increment"`
	BadAckIncrement *int32 `toml:"badack_increment"`
	TSIncrement     *int32 `toml:"ts_increment"`

	Pos           []string `toml:"pos"` // --dpi-desync-split-pos entries
	Seqovl        int      `toml:"seqovl"`
	SeqovlPattern string   `toml:"seqovl_pattern"` // fake file name or "0xDEADBEEF"
	Pattern       string   `toml:"pattern"`        // fakedsplit filler

	Fake   FakeSpec          `toml:"fake"`
	TLSMod string            `toml:"tls_mod"` // "rnd,dupsid,sni=www.google.com"
	Mod    map[string]string `toml:"mod"`     // hostfakesplit: host=, altorder=, midhost=

	UDPLenIncrement int    `toml:"udplen_increment"`
	UDPLenPattern   string `toml:"udplen_pattern"`

	WSSize  string `toml:"wssize"` // "128:6"
	Mode    string `toml:"mode"`   // ip_id: zero|seq|random
	FragPos int    `toml:"frag_pos"`

	AnyProtocol bool `toml:"any_protocol"`
}

// FakeSpec names the fake payload blobs an op uses. Values are either a file
// name resolved against the fakes directory, or an inline "0x..." literal.
type FakeSpec struct {
	TLS        string   `toml:"tls"`
	HTTP       string   `toml:"http"`
	QUIC       string   `toml:"quic"`
	Discord    []string `toml:"discord"`
	STUN       []string `toml:"stun"`
	UnknownUDP []string `toml:"unknown_udp"`
	SynData    string   `toml:"syndata"`
}

// ---------- compiled form ----------

// PortRange is an inclusive port range; Lo==Hi for a single port.
type PortRange struct{ Lo, Hi uint16 }

// PortSet is a set of ranges. Nil/empty means "any port".
type PortSet []PortRange

// Has reports whether p is in the set (empty set matches everything).
func (s PortSet) Has(p uint16) bool {
	if len(s) == 0 {
		return true
	}
	for _, r := range s {
		if p >= r.Lo && p <= r.Hi {
			return true
		}
	}
	return false
}

// Counter is a --dpi-desync-start/-cutoff bound: 'n' = packet number,
// 'd' = data-packet number, 's' = relative sequence number.
type Counter struct {
	Kind byte // 'n', 'd', 's' or 0 for unset
	N    int
}

// Filter is the compiled match condition of a profile.
type Filter struct {
	Proto uint8 // 0 = any, else IPProtoTCP/IPProtoUDP
	Ports PortSet
	L3    uint8    // 0 = any, 4, 6
	L7    proto.L7 // 0 = any

	Hostlist        *lists.HostSet // nil = unrestricted
	HostlistExclude *lists.HostSet
	IPSet           *lists.CIDRSet
	IPSetExclude    *lists.CIDRSet

	AutoHostlist string // path of the self-learning list, "" = off
}

// CompiledOp pairs an op implementation with its validated parameters.
type CompiledOp struct {
	Op     desync.Op
	Params desync.OpParams
	Spec   OpSpec // kept for diagnostics / `zaprctl show`
}

// Profile is one compiled --new chain element.
type Profile struct {
	Name          string
	Filter        Filter
	Ops           []CompiledOp
	Cutoff        Counter
	Start         Counter
	OnUnsupported desync.Unsupported
}

// Strategy is a fully compiled strategy file.
type Strategy struct {
	Name        string
	Description string
	Source      string
	WindowTCP   PortSet
	WindowUDP   PortSet
	Profiles    []*Profile
}

// LoadOpts controls path resolution while compiling.
type LoadOpts struct {
	ListsDir string // where hostlist/ipset files live
	FakesDir string // where fake *.bin blobs live
	Caps     desync.Caps
}
