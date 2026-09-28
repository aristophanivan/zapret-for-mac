//go:build darwin

package main

import (
	"net"
	"net/netip"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
)

func TestSameUplink(t *testing.T) {
	base := netcfg.Route{
		Iface: "en0", IfIndex: 4,
		Local: netip.MustParseAddr("192.0.2.2"), Gateway: netip.MustParseAddr("192.0.2.1"),
		MAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, GatewayMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11},
		MTU: 1500,
	}
	clone := func() netcfg.Route {
		r := base
		r.MAC = append(net.HardwareAddr(nil), base.MAC...)
		r.GatewayMAC = append(net.HardwareAddr(nil), base.GatewayMAC...)
		return r
	}
	if !sameUplink(base, clone()) {
		t.Fatal("identical routes reported an uplink change")
	}
	tests := []struct {
		name string
		edit func(*netcfg.Route)
	}{
		{"interface", func(r *netcfg.Route) { r.Iface, r.IfIndex = "en5", 11 }},
		{"local address", func(r *netcfg.Route) { r.Local = netip.MustParseAddr("198.51.100.2") }},
		{"gateway", func(r *netcfg.Route) { r.Gateway = netip.MustParseAddr("198.51.100.1") }},
		{"gateway mac", func(r *netcfg.Route) { r.GatewayMAC[5]++ }},
		{"mtu", func(r *netcfg.Route) { r.MTU = 1420 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := clone()
			tc.edit(&r)
			if sameUplink(base, r) {
				t.Fatal("changed route was treated as the same uplink")
			}
		})
	}
}

func TestReplacementUplinkKeepsHealthyInterfaceSticky(t *testing.T) {
	en0 := netcfg.Route{
		Iface: "en0", IfIndex: 4, Local: netip.MustParseAddr("172.20.10.3"),
		Gateway: netip.MustParseAddr("172.20.10.1"), MAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, MTU: 1500,
	}
	en6 := netcfg.Route{
		Iface: "en6", IfIndex: 12, Local: netip.MustParseAddr("172.20.10.14"),
		Gateway: netip.MustParseAddr("172.20.10.1"), MAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, MTU: 1500,
	}
	if next, changed := replacementUplink(en0, []netcfg.Route{en6, en0}); changed {
		t.Fatalf("healthy en0 was replaced by %+v merely because en6 sorted first", next)
	}
	if next, changed := replacementUplink(en0, []netcfg.Route{en6}); !changed || next.Iface != "en6" {
		t.Fatalf("missing en0 replacement = (%+v, %t), want en6", next, changed)
	}
}
