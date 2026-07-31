//go:build darwin

package divert

import (
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
)

// TestTunnelDefaultIface pins the check that stops the packet datapath from
// running under a full-tunnel VPN.
//
// This is a regression test for a real incident: netcfg.DefaultRoute4 sorts
// non-tunnel routes first, so it answered "en0" while AmneziaVPN held the actual
// default route on utun4. The datapath started, pf handed us packets whose
// source address belonged to the tunnel (198.18.0.1), we re-emitted them on the
// physical link, and every steered connection died — including uncensored ones.
// The fix looks at the WHOLE default-route set, which is what this test locks in.
func TestTunnelDefaultIface(t *testing.T) {
	tests := []struct {
		name   string
		routes []netcfg.Route
		want   string
	}{
		{
			name:   "no routes at all",
			routes: nil,
			want:   "",
		},
		{
			name:   "physical only",
			routes: []netcfg.Route{{Iface: "en0", IsTunnel: false}},
			want:   "",
		},
		{
			// Exactly the incident: DefaultRoutes4 sorts en0 first because it is
			// not a tunnel, but utun4 is still a default route and the kernel
			// picks source addresses from it.
			name: "physical sorted first, tunnel still present",
			routes: []netcfg.Route{
				{Iface: "en0", IsTunnel: false},
				{Iface: "utun4", IsTunnel: true},
			},
			want: "utun4",
		},
		{
			name:   "tunnel only",
			routes: []netcfg.Route{{Iface: "utun4", IsTunnel: true}},
			want:   "utun4",
		},
		{
			name: "several tunnels reports the first",
			routes: []netcfg.Route{
				{Iface: "utun2", IsTunnel: true},
				{Iface: "utun4", IsTunnel: true},
			},
			want: "utun2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tunnelDefaultIface(tt.routes); got != tt.want {
				t.Fatalf("tunnelDefaultIface = %q, want %q", got, tt.want)
			}
		})
	}
}
