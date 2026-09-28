package netcfg

import "testing"

func TestPreferredDefault(t *testing.T) {
	wifi := Route{Iface: "en0", IfIndex: 4}
	usb := Route{Iface: "en5", IfIndex: 11}
	if !preferredDefault(wifi, usb) || preferredDefault(usb, wifi) {
		t.Fatal("physical defaults must use stable ifindex order instead of flapping on route flags")
	}
	tunnel := Route{Iface: "utun8", IfIndex: 20, IsTunnel: true}
	if !preferredDefault(wifi, tunnel) || preferredDefault(tunnel, wifi) {
		t.Fatal("the physical fallback must stay ahead of a tunnel default for BPF injection")
	}
}
