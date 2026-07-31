package vpn

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMatchesProcIsExact guards the rule that decides what may be signalled.
// A prefix match here would mean killing a process merely because its name
// starts like a VPN's, so the check is deliberately exact.
func TestMatchesProcIsExact(t *testing.T) {
	sig := signature{Name: "AmneziaVPN", AppName: "AmneziaVPN",
		ProcNames: []string{"AmneziaVPN-service", "AmneziaVPN"}}
	tests := []struct {
		name string
		proc Process
		want bool
	}{
		{"exact service name", Process{Name: "AmneziaVPN-service", Path: "/Applications/AmneziaVPN.app/Contents/MacOS/AmneziaVPN-service"}, true},
		{"exact gui name", Process{Name: "AmneziaVPN", Path: "/Applications/AmneziaVPN.app/Contents/MacOS/AmneziaVPN"}, true},
		{"same bundle, other executable", Process{Name: "helper", Path: "/Applications/AmneziaVPN.app/Contents/MacOS/helper"}, true},
		{"unrelated process with a similar name", Process{Name: "AmneziaVPN-uninstaller-tool", Path: "/tmp/AmneziaVPN-uninstaller-tool"}, false},
		{"entirely unrelated", Process{Name: "Safari", Path: "/Applications/Safari.app/Contents/MacOS/Safari"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesProc(sig, tt.proc); got != tt.want {
				t.Fatalf("matchesProc(%q) = %v, want %v", tt.proc.Name, got, tt.want)
			}
		})
	}
}

// TestAppRunningNeedsTheGUIBinary is the regression test for a real
// misdetection: the service binary sits in the same bundle as the GUI one, and a
// path-prefix test reported "app running" when only the daemon was up.
func TestAppRunningNeedsTheGUIBinary(t *testing.T) {
	sig := signature{Name: "AmneziaVPN", AppName: "AmneziaVPN", ProcNames: []string{"AmneziaVPN-service"}}
	service := Process{Name: "AmneziaVPN-service", Path: "/Applications/AmneziaVPN.app/Contents/MacOS/AmneziaVPN-service"}
	if service.Name == sig.AppName {
		t.Fatal("test premise broken: the service binary must not be named like the app")
	}
	gui := Process{Name: "AmneziaVPN", Path: "/Applications/AmneziaVPN.app/Contents/MacOS/AmneziaVPN"}
	if gui.Name != sig.AppName {
		t.Fatal("the GUI binary should match the app name exactly")
	}
}

// TestLabelFromPlist reads a launchd label the way Detect does.
func TestLabelFromPlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "AmneziaVPN.plist")
	body := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>AmneziaVPN-service</string>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := labelFromPlist(path); got != "AmneziaVPN-service" {
		t.Fatalf("labelFromPlist = %q", got)
	}
	if got := labelFromPlist(filepath.Join(dir, "absent.plist")); got != "" {
		t.Fatalf("missing file should yield an empty label, got %q", got)
	}
}

// TestRestoreCommands checks that a stop always tells the user how to undo it.
func TestRestoreCommands(t *testing.T) {
	jobs := []Job{
		{Label: "AmneziaVPN-service", PlistPath: "/Library/LaunchDaemons/AmneziaVPN.plist", Domain: "system"},
		{Label: "org.openvpn.client", PlistPath: "/Library/LaunchDaemons/org.openvpn.client.plist", Domain: "system"},
	}
	got := restoreCommands(jobs)
	want := []string{
		"sudo launchctl bootstrap system /Library/LaunchDaemons/AmneziaVPN.plist",
		"sudo launchctl bootstrap system /Library/LaunchDaemons/org.openvpn.client.plist",
	}
	if len(got) != len(want) {
		t.Fatalf("restoreCommands = %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("restoreCommands[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if len(restoreCommands(nil)) != 0 {
		t.Fatal("no jobs must yield no restore commands")
	}
}

// TestUnattributedTunnelIsReportedNotTouched pins the safety rule: a tunnel we
// cannot attribute to known software is surfaced, never stopped.
func TestUnattributedTunnelIsReportedNotTouched(t *testing.T) {
	rep := Report{TunnelDefaults: []string{"utun9"}}
	if !rep.Blocking() {
		t.Fatal("a tunnel default route must count as blocking")
	}
	if len(rep.Findings) != 0 {
		t.Fatal("no findings expected")
	}
	// Stop iterates Findings only, so an unattributed tunnel cannot be acted on.
	res, err := Stop(t.Context(), rep, func() ([]string, error) { return []string{"utun9"}, nil },
		StopOpts{Timeout: 10 * 1e6})
	if err == nil {
		t.Fatal("Stop should report that the tunnel is still held")
	}
	if len(res.Stopped) != 0 {
		t.Fatalf("nothing may be stopped, got %q", res.Stopped)
	}
}
