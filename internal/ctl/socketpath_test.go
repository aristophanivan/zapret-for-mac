package ctl

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMaxSocketPathMatchesTheKernel measures the real sun_path limit instead of
// trusting the constant, so an OS change is caught here rather than as an
// unexplained "bind: invalid argument" in the field.
//
// It needs a short base directory: the default TMPDIR on macOS is itself ~50
// bytes, which leaves too little room to walk past the limit.
func TestMaxSocketPathMatchesTheKernel(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "ctlsock")
	if err != nil {
		t.Skipf("no short temp dir to measure with: %v", err)
	}
	defer os.RemoveAll(dir)
	base := dir + string(filepath.Separator)
	if len(base) > MaxSocketPath-8 {
		t.Skipf("temp dir %q is already %d bytes, too long to measure the limit", base, len(base))
	}

	longest := 0
	for n := len(base) + 1; n <= MaxSocketPath+8; n++ {
		p := base + strings.Repeat("s", n-len(base))
		ln, lerr := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
		if lerr != nil {
			continue
		}
		if n > longest {
			longest = n
		}
		_ = ln.Close()
		_ = os.Remove(p)
	}
	if longest != MaxSocketPath {
		t.Errorf("the kernel binds paths up to %d bytes, but MaxSocketPath says %d", longest, MaxSocketPath)
	}
}

// TestListenRefusesAnOverLongSocketPath pins the diagnosis. bind(2) answers
// EINVAL, which Go renders as "invalid argument"; a daemon that dies with that
// and nothing else tells the operator nothing, and --socket is operator-supplied.
func TestListenRefusesAnOverLongSocketPath(t *testing.T) {
	dir := t.TempDir()
	// One byte past the budget Listen actually has, since it binds at path+".tmp".
	budget := MaxSocketPath - len(socketTmpSuffix)
	name := strings.Repeat("p", budget) // certainly longer than budget once joined
	path := filepath.Join(dir, name)
	if len(path) <= budget {
		t.Fatalf("test setup: %d-byte path is not over the %d-byte budget", len(path), budget)
	}

	s := NewServer(&fakeHandler{}, ServerOpts{Path: path})
	err := s.Listen()
	if err == nil {
		_ = s.Close()
		t.Fatalf("Listen accepted a %d-byte socket path; the budget is %d", len(path), budget)
	}
	for _, want := range []string{"socket path", "Darwin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "invalid argument") {
		t.Errorf("error is still the bare errno text: %v", err)
	}
	// Nothing may be left behind by a refused Listen.
	if _, serr := os.Stat(path); !errors.Is(serr, os.ErrNotExist) {
		t.Errorf("a refused Listen created %s (stat: %v)", path, serr)
	}
	if _, serr := os.Stat(path + socketTmpSuffix); !errors.Is(serr, os.ErrNotExist) {
		t.Errorf("a refused Listen left the temp socket behind (stat: %v)", serr)
	}
}

// TestListenAcceptsAPathAtTheBudget is the other half: the check must not be
// off by one and reject a path that would in fact have bound.
func TestListenAcceptsAPathAtTheBudget(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "ctlsock")
	if err != nil {
		t.Skipf("no short temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	budget := MaxSocketPath - len(socketTmpSuffix)
	base := dir + string(filepath.Separator)
	if len(base) >= budget {
		t.Skipf("temp dir %q leaves no room for a socket name", base)
	}
	path := base + strings.Repeat("s", budget-len(base))
	if len(path) != budget {
		t.Fatalf("test setup: path is %d bytes, want exactly the %d-byte budget", len(path), budget)
	}

	s := NewServer(&fakeHandler{}, ServerOpts{Path: path})
	if lerr := s.Listen(); lerr != nil {
		t.Fatalf("Listen refused a path exactly at the %d-byte budget: %v", budget, lerr)
	}
	defer s.Close()
	if got := s.Path(); got != path {
		t.Errorf("Path() = %q, want %q", got, path)
	}
	if _, serr := os.Stat(path); serr != nil {
		t.Errorf("socket was not created at %s: %v", path, serr)
	}
}
