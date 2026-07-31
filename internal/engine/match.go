package engine

import (
	"net/netip"

	"github.com/naladwepo/zapret-for-mac/internal/lists"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// matchInput is one packet/flow reduced to the fields a filter looks at.
type matchInput struct {
	Proto uint8
	Port  uint16
	L3    uint8 // 4 or 6
	L7    proto.L7
	Host  string
	Dst   netip.Addr
	// AutoSet is the live contents of the filter's --hostlist-auto file, when
	// one is configured AND registered with Engine.SetAutoList. It is unioned
	// with Filter.Hostlist: a host the engine has learned is treated exactly
	// like one written in a static list.
	AutoSet *lists.HostSet
}

// MatchFilter evaluates a compiled filter, in the same order nfqws does:
// L3/proto/port first (cheap), then L7, then hostlist, then ipset. Exclusions
// win over inclusions.
//
// Semantics that matter for parity:
//   - an empty PortSet matches any port;
//   - Filter.L7 == 0 means unconstrained;
//   - a hostlist-gated filter cannot match a flow with no known hostname
//     (the engine retries on later packets instead);
//   - a filter carrying --hostlist-auto is gated on the learned list the same
//     way, so an unlearned host does not match (the engine then monitors the
//     flow instead of desyncing it — see Engine.pick);
//   - a CIDRSet loaded from an empty file matches every address (flowseal's
//     `ipset any`), which CIDRSet.Match reports via its Any flag.
func MatchFilter(f *strategy.Filter, in matchInput) bool {
	if !matchCheap(f, in) {
		return false
	}
	if f.IPSetExclude != nil && in.Dst.IsValid() && f.IPSetExclude.Match(in.Dst) {
		return false
	}
	if f.HostlistExclude != nil && in.Host != "" && f.HostlistExclude.Match(in.Host) {
		return false
	}
	if f.Hostlist != nil || in.AutoSet != nil {
		if in.Host == "" {
			return false
		}
		listed := f.Hostlist != nil && f.Hostlist.Match(in.Host)
		if !listed && in.AutoSet != nil {
			listed = in.AutoSet.Match(in.Host)
		}
		if !listed {
			return false
		}
	}
	if f.IPSet != nil {
		if !in.Dst.IsValid() || !f.IPSet.Match(in.Dst) {
			return false
		}
	}
	return true
}

// MatchFilterIgnoringHost evaluates every criterion of a filter EXCEPT the
// hostname-based ones (Hostlist, HostlistExclude and the learned list).
//
// It answers one question the profile chain needs: "could this filter still
// match once a hostname becomes known?" That is what lets the engine keep a
// flow's profile decision open across the SYN, so a ClientHello can still reach
// a hostlist-gated profile that sits earlier in the chain.
func MatchFilterIgnoringHost(f *strategy.Filter, in matchInput) bool {
	if !matchCheap(f, in) {
		return false
	}
	if f.IPSetExclude != nil && in.Dst.IsValid() && f.IPSetExclude.Match(in.Dst) {
		return false
	}
	if f.IPSet != nil {
		if !in.Dst.IsValid() || !f.IPSet.Match(in.Dst) {
			return false
		}
	}
	return true
}

// matchCheap is the L3/proto/port/L7 prefix both matchers share.
func matchCheap(f *strategy.Filter, in matchInput) bool {
	if f.Proto != 0 && f.Proto != in.Proto {
		return false
	}
	if f.L3 != 0 && f.L3 != in.L3 {
		return false
	}
	if !f.Ports.Has(in.Port) {
		return false
	}
	if f.L7 != 0 && in.L7&f.L7 == 0 {
		return false
	}
	return true
}
