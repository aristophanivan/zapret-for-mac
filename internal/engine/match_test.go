package engine

import (
	"net/netip"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/lists"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// MatchFilter is the hot path of profile selection, so it is pinned here as a
// truth table over hand-built filters rather than through compiled strategies:
// the loader can only produce a subset of the filter shapes MatchFilter has to
// answer for (an `Any` list, for one, which it deliberately compiles away).

// hostSet builds a HostSet from the given entries.
func hostSet(entries ...string) *lists.HostSet {
	hs := lists.NewHostSet()
	for _, e := range entries {
		hs.Add(e)
	}
	return hs
}

// anyHostSet is zapret's "empty hostlist matches everything" set.
func anyHostSet() *lists.HostSet {
	hs := lists.NewHostSet()
	hs.Any = true
	return hs
}

// cidrSet builds a CIDRSet from prefix strings.
func cidrSet(t *testing.T, prefixes ...string) *lists.CIDRSet {
	t.Helper()
	cs := lists.NewCIDRSet()
	for _, p := range prefixes {
		pre, err := netip.ParsePrefix(p)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", p, err)
		}
		cs.Add(pre)
	}
	return cs
}

// anyCIDRSet is flowseal's `ipset any`: loaded from an empty file, matches every
// address.
func anyCIDRSet() *lists.CIDRSet {
	cs := lists.NewCIDRSet()
	cs.Any = true
	return cs
}

func ip(t *testing.T, s string) netip.Addr {
	t.Helper()
	return mustAddr(t, s)
}

// TestMatchFilterTruthTable walks every branch of MatchFilter, in the order the
// function evaluates them.
func TestMatchFilterTruthTable(t *testing.T) {
	v4 := ip(t, "142.250.1.1")
	v6 := ip(t, "2a00:1450:4001:81b::200e")

	tcp443 := matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 4, L7: proto.L7TLS, Host: "www.google.com", Dst: v4}

	tests := []struct {
		name string
		f    strategy.Filter
		in   matchInput
		want bool
	}{
		// ---- proto ----
		{
			name: "proto_any_matches_tcp",
			f:    strategy.Filter{},
			in:   tcp443,
			want: true,
		},
		{
			name: "proto_mismatch",
			f:    strategy.Filter{Proto: proto.IPProtoUDP},
			in:   tcp443,
			want: false,
		},
		{
			name: "proto_match",
			f:    strategy.Filter{Proto: proto.IPProtoTCP},
			in:   tcp443,
			want: true,
		},

		// ---- L3 ----
		{
			name: "l3_any_matches_ipv6",
			f:    strategy.Filter{Proto: proto.IPProtoTCP},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 6, L7: proto.L7TLS, Dst: v6},
			want: true,
		},
		{
			name: "l3_mismatch",
			f:    strategy.Filter{L3: 4},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 6, Dst: v6},
			want: false,
		},
		{
			name: "l3_match_ipv6",
			f:    strategy.Filter{L3: 6},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 6, Dst: v6},
			want: true,
		},

		// ---- ports ----
		{
			name: "empty_portset_matches_every_port",
			f:    strategy.Filter{Proto: proto.IPProtoTCP},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 12345, L3: 4, Dst: v4},
			want: true,
		},
		{
			name: "port_mismatch",
			f:    strategy.Filter{Ports: strategy.PortSet{{Lo: 80, Hi: 80}, {Lo: 8443, Hi: 8443}}},
			in:   tcp443,
			want: false,
		},
		{
			name: "port_in_second_range",
			f:    strategy.Filter{Ports: strategy.PortSet{{Lo: 80, Hi: 80}, {Lo: 443, Hi: 443}}},
			in:   tcp443,
			want: true,
		},
		{
			name: "port_range_low_edge",
			f:    strategy.Filter{Ports: strategy.PortSet{{Lo: 50000, Hi: 50100}}},
			in:   matchInput{Proto: proto.IPProtoUDP, Port: 50000, L3: 4, Dst: v4},
			want: true,
		},
		{
			name: "port_range_high_edge",
			f:    strategy.Filter{Ports: strategy.PortSet{{Lo: 50000, Hi: 50100}}},
			in:   matchInput{Proto: proto.IPProtoUDP, Port: 50100, L3: 4, Dst: v4},
			want: true,
		},
		{
			name: "port_just_past_range",
			f:    strategy.Filter{Ports: strategy.PortSet{{Lo: 50000, Hi: 50100}}},
			in:   matchInput{Proto: proto.IPProtoUDP, Port: 50101, L3: 4, Dst: v4},
			want: false,
		},

		// ---- L7 ----
		{
			name: "l7_zero_is_unconstrained",
			f:    strategy.Filter{Proto: proto.IPProtoTCP, Ports: strategy.PortSet{{Lo: 443, Hi: 443}}},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 4, L7: proto.L7HTTP, Dst: v4},
			want: true,
		},
		{
			name: "l7_zero_matches_unclassified_flow",
			f:    strategy.Filter{Proto: proto.IPProtoTCP},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 4, Dst: v4},
			want: true,
		},
		{
			name: "l7_mismatch",
			f:    strategy.Filter{L7: proto.L7TLS},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 4, L7: proto.L7HTTP, Dst: v4},
			want: false,
		},
		{
			name: "l7_mask_matches_either_bit",
			f:    strategy.Filter{L7: proto.L7Discord | proto.L7STUN},
			in:   matchInput{Proto: proto.IPProtoUDP, Port: 50001, L3: 4, L7: proto.L7STUN, Dst: v4},
			want: true,
		},
		{
			name: "l7_unknown_is_a_real_class",
			f:    strategy.Filter{L7: proto.L7Unknown},
			in:   matchInput{Proto: proto.IPProtoUDP, Port: 12, L3: 4, L7: proto.L7Unknown, Dst: v4},
			want: true,
		},
		{
			name: "l7_unknown_filter_rejects_a_classified_flow",
			f:    strategy.Filter{L7: proto.L7Unknown},
			in:   matchInput{Proto: proto.IPProtoUDP, Port: 443, L3: 4, L7: proto.L7QUIC, Dst: v4},
			want: false,
		},
		{
			name: "l7_filter_rejects_a_flow_with_no_l7_yet",
			f:    strategy.Filter{L7: proto.L7TLS},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 4, Dst: v4},
			want: false,
		},

		// ---- hostlists ----
		{
			name: "hostlist_suffix_match",
			f:    strategy.Filter{Hostlist: hostSet("google.com")},
			in:   tcp443,
			want: true,
		},
		{
			name: "hostlist_no_match",
			f:    strategy.Filter{Hostlist: hostSet("discord.com")},
			in:   tcp443,
			want: false,
		},
		{
			name: "hostlist_is_not_a_substring_match",
			f:    strategy.Filter{Hostlist: hostSet("google.com")},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 4, Host: "notgoogle.com", Dst: v4},
			want: false,
		},
		{
			name: "hostlist_gated_filter_refuses_an_empty_host",
			f:    strategy.Filter{Hostlist: hostSet("google.com")},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 4, Dst: v4},
			want: false,
		},
		{
			// Even a match-everything hostlist cannot decide a flow with no
			// hostname: the gate is checked before the set is consulted, which is
			// what lets the engine retry on a later packet.
			name: "any_hostlist_still_refuses_an_empty_host",
			f:    strategy.Filter{Hostlist: anyHostSet()},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 4, Dst: v4},
			want: false,
		},
		{
			name: "any_hostlist_matches_any_known_host",
			f:    strategy.Filter{Hostlist: anyHostSet()},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 4, Host: "whatever.example", Dst: v4},
			want: true,
		},
		{
			name: "hostlist_exclude_wins_over_inclusion",
			f: strategy.Filter{
				Hostlist:        hostSet("google.com"),
				HostlistExclude: hostSet("www.google.com"),
			},
			in:   tcp443,
			want: false,
		},
		{
			name: "hostlist_exclude_suffix_wins_over_inclusion",
			f: strategy.Filter{
				Hostlist:        hostSet("google.com"),
				HostlistExclude: hostSet("google.com"),
			},
			in:   tcp443,
			want: false,
		},
		{
			name: "hostlist_exclude_of_another_host_is_harmless",
			f: strategy.Filter{
				Hostlist:        hostSet("google.com"),
				HostlistExclude: hostSet("yandex.ru"),
			},
			in:   tcp443,
			want: true,
		},
		{
			// An exclusion cannot fire on a flow whose hostname is unknown; the
			// inclusion side (here an ipset) still decides.
			name: "hostlist_exclude_skipped_when_host_unknown",
			f: strategy.Filter{
				HostlistExclude: anyHostSet(),
				IPSet:           cidrSet(t, "142.250.0.0/16"),
			},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 4, Dst: v4},
			want: true,
		},

		// ---- ipsets ----
		{
			name: "ipset_match",
			f:    strategy.Filter{IPSet: cidrSet(t, "142.250.0.0/16")},
			in:   tcp443,
			want: true,
		},
		{
			name: "ipset_no_match",
			f:    strategy.Filter{IPSet: cidrSet(t, "10.0.0.0/8")},
			in:   tcp443,
			want: false,
		},
		{
			name: "ipset_any_matches_every_v4_address",
			f:    strategy.Filter{IPSet: anyCIDRSet()},
			in:   tcp443,
			want: true,
		},
		{
			name: "ipset_any_matches_every_v6_address",
			f:    strategy.Filter{IPSet: anyCIDRSet()},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 6, Dst: v6},
			want: true,
		},
		{
			name: "ipset_refuses_an_invalid_address",
			f:    strategy.Filter{IPSet: anyCIDRSet()},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 4},
			want: false,
		},
		{
			name: "ipset_exclude_wins_over_ipset_inclusion",
			f: strategy.Filter{
				IPSet:        anyCIDRSet(),
				IPSetExclude: cidrSet(t, "142.250.0.0/16"),
			},
			in:   tcp443,
			want: false,
		},
		{
			name: "ipset_exclude_wins_over_hostlist_inclusion",
			f: strategy.Filter{
				Hostlist:     hostSet("google.com"),
				IPSetExclude: cidrSet(t, "142.250.1.1/32"),
			},
			in:   tcp443,
			want: false,
		},
		{
			name: "ipset_exclude_of_another_prefix_is_harmless",
			f: strategy.Filter{
				Hostlist:     hostSet("google.com"),
				IPSetExclude: cidrSet(t, "10.0.0.0/8"),
			},
			in:   tcp443,
			want: true,
		},
		{
			// The exclusion needs a valid address to fire, so an address-less
			// input is not excluded.
			name: "ipset_exclude_skipped_for_an_invalid_address",
			f: strategy.Filter{
				IPSetExclude: anyCIDRSet(),
				Hostlist:     hostSet("google.com"),
			},
			in:   matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 4, Host: "www.google.com"},
			want: true,
		},

		// ---- everything at once ----
		{
			name: "all_conditions_satisfied",
			f: strategy.Filter{
				Proto:           proto.IPProtoTCP,
				Ports:           strategy.PortSet{{Lo: 80, Hi: 80}, {Lo: 443, Hi: 443}},
				L3:              4,
				L7:              proto.L7TLS | proto.L7HTTP,
				Hostlist:        hostSet("google.com", "discord.com"),
				HostlistExclude: hostSet("yandex.ru"),
				IPSet:           cidrSet(t, "142.250.0.0/16", "2a00:1450::/32"),
				IPSetExclude:    cidrSet(t, "10.0.0.0/8"),
			},
			in:   tcp443,
			want: true,
		},
		{
			name: "all_conditions_but_the_port",
			f: strategy.Filter{
				Proto:           proto.IPProtoTCP,
				Ports:           strategy.PortSet{{Lo: 80, Hi: 80}},
				L3:              4,
				L7:              proto.L7TLS,
				Hostlist:        hostSet("google.com"),
				HostlistExclude: hostSet("yandex.ru"),
				IPSet:           cidrSet(t, "142.250.0.0/16"),
			},
			in:   tcp443,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.f
			if got := MatchFilter(&f, tc.in); got != tc.want {
				t.Fatalf("MatchFilter(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestMatchFilterHostMatchIsCaseInsensitive pins that a hostname the L7 parser
// handed over verbatim still matches a lower-case list entry.
func TestMatchFilterHostMatchIsCaseInsensitive(t *testing.T) {
	f := strategy.Filter{Hostlist: hostSet("google.com")}
	for _, host := range []string{"WWW.Google.COM", "www.google.com.", "www.google.com"} {
		in := matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 4, Host: host, Dst: ip(t, "142.250.1.1")}
		if !MatchFilter(&f, in) {
			t.Fatalf("MatchFilter did not match host %q", host)
		}
	}
}

// TestMatchFilterIPv4MappedAddress pins the mapped-address case: the flow key of
// an IPv4 connection recovered through the proxy transport can carry a
// ::ffff:a.b.c.d address, which must still match an IPv4 ipset.
func TestMatchFilterIPv4MappedAddress(t *testing.T) {
	f := strategy.Filter{IPSet: cidrSet(t, "142.250.0.0/16")}
	in := matchInput{
		Proto: proto.IPProtoTCP, Port: 443, L3: 4, Host: "www.google.com",
		Dst: netip.AddrFrom16(ip(t, "142.250.1.1").As16()),
	}
	if !MatchFilter(&f, in) {
		t.Fatal("an IPv4-mapped destination did not match an IPv4 ipset")
	}
}

// TestMatchFilterEvaluationOrderIsCheapFirst pins that the cheap L3/L4 tests
// decide on their own: a packet outside the port set is rejected even when every
// list in the filter would have matched it.
func TestMatchFilterEvaluationOrderIsCheapFirst(t *testing.T) {
	// Ports that cannot match, plus lists that match everything.
	f := strategy.Filter{
		Ports:    strategy.PortSet{{Lo: 12, Hi: 12}},
		Hostlist: anyHostSet(),
		IPSet:    anyCIDRSet(),
	}
	in := matchInput{Proto: proto.IPProtoTCP, Port: 443, L3: 4, Host: "a.example", Dst: ip(t, "142.250.1.1")}
	if MatchFilter(&f, in) {
		t.Fatal("a filter whose port set excludes the packet matched anyway")
	}
	// And with the port fixed, the same filter matches: the lists above are the
	// permissive ones, so this proves the port test alone decided the case above.
	in.Port = 12
	if !MatchFilter(&f, in) {
		t.Fatal("the same filter did not match once the port agreed")
	}
}
