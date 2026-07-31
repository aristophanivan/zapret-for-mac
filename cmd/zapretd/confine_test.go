//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression tests for the control-socket argument confinement (review finding 20)
// and for the instance lock (finding 2). Everything here is unprivileged.

// TestCheckStrategyNameRefusesPaths: every member of group `admin` can reach the
// control socket, so `use /some/path.toml` would make the ROOT daemon read a file
// of that user's choosing and report its parse errors back. `use` takes a name.
func TestCheckStrategyNameRefusesPaths(t *testing.T) {
	for _, ok := range []string{"", "general", "general-alt2", "general (ALT2)", "general.toml"} {
		if err := checkStrategyName(ok); err != nil {
			t.Errorf("checkStrategyName(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"/etc/passwd",
		"/tmp/evil.toml",
		"../../../etc/shadow",
		"sub/dir.toml",
		"..",
	} {
		if err := checkStrategyName(bad); err == nil {
			t.Errorf("checkStrategyName(%q) = nil, want a refusal", bad)
		}
	}
}

// TestUnderDir is the second half of the same guard: even a bare name must resolve
// inside the installed strategies directory.
func TestUnderDir(t *testing.T) {
	root := t.TempDir()
	strategies := filepath.Join(root, "strategies")
	if err := os.MkdirAll(filepath.Join(strategies, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(strategies, "general.toml")
	if err := os.WriteFile(inside, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "elsewhere.toml")
	if err := os.WriteFile(outside, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if !underDir(strategies, inside) {
		t.Error("a file in the strategies directory was reported as outside it")
	}
	if !underDir(strategies, filepath.Join(strategies, "nested", "x.toml")) {
		t.Error("a nested file was reported as outside the strategies directory")
	}
	if underDir(strategies, outside) {
		t.Error("a file outside the strategies directory was reported as inside it")
	}
	if underDir(strategies, filepath.Join(root, "..", "etc", "passwd")) {
		t.Error("a traversal escaped the strategies directory")
	}
}

// TestCheckProbeHost: the root daemon must not be usable as a way to reach services
// on this machine or on link-local space.
func TestCheckProbeHost(t *testing.T) {
	for _, ok := range []string{
		"", "example.com", "example.com:443", "1.1.1.1", "1.1.1.1:80",
		"192.168.1.10", "[2606:4700:4700::1111]:443", "2606:4700:4700::1111",
	} {
		if err := checkProbeHost(ok); err != nil {
			t.Errorf("checkProbeHost(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"127.0.0.1", "127.0.0.1:8080", "::1", "[::1]:443",
		"169.254.169.254", "169.254.169.254:80", "fe80::1",
		"0.0.0.0", "224.0.0.1",
	} {
		if err := checkProbeHost(bad); err == nil {
			t.Errorf("checkProbeHost(%q) = nil, want a refusal", bad)
		}
	}
}

// TestInstanceLockIsExclusive: the lock has to be what stops a second daemon from
// rolling back the live one's changes, so it must actually be exclusive and must be
// released when the holder lets go.
func TestInstanceLockIsExclusive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")

	first, err := acquireInstanceLock(dir)
	if err != nil {
		t.Fatalf("first acquireInstanceLock: %v", err)
	}
	// The lock file must name the holder, so the refusal message can too.
	if got := readLockHolder(filepath.Join(dir, instanceLockName)); got == "" {
		t.Error("the lock file does not record the holding pid")
	}

	// flock is per open file description, so a second acquire from THIS process
	// still contends: os.OpenFile creates a new description.
	if _, err := acquireInstanceLock(dir); err == nil {
		t.Fatal("a second acquireInstanceLock succeeded; the lock is not exclusive")
	}

	first.Release()
	second, err := acquireInstanceLock(dir)
	if err != nil {
		t.Fatalf("acquireInstanceLock after Release: %v", err)
	}
	second.Release()
	// Release is idempotent: the daemon defers it and the error paths may run it.
	second.Release()
}

// TestAcquireInstanceLockRejectsAnEmptyDir keeps a misconfigured --data from
// silently locking the process' working directory.
func TestAcquireInstanceLockRejectsAnEmptyDir(t *testing.T) {
	if _, err := acquireInstanceLock("   "); err == nil {
		t.Error("acquireInstanceLock(\"\") succeeded")
	}
}
