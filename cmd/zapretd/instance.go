//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// instanceLockName is the file, inside the state directory, whose advisory lock
// makes "one daemon per state directory" a mechanical fact rather than a hope.
const instanceLockName = "zapretd.lock"

// errAlreadyRunning reports that another process holds the instance lock.
var errAlreadyRunning = errors.New("another zapretd already owns this data directory")

// instanceLock is an exclusive flock(2) on <state>/zapretd.lock.
//
// WHY it has to be the FIRST thing Run does: the journal, the pf token, the
// byte-exact backups and the pf anchor are all shared per state directory, and
// the daemon's very first act after opening them is rollbackPrevious() — which
// undoes whatever a "previous" run left behind. The only single-instance guard
// used to be ctl.Server.Listen, five steps later, so a second daemon started to
// debug the first (`sudo zapretd --foreground`, which main.go explicitly allows)
// would read the LIVE daemon's journal, flush its steering rules, drop its pf
// reference, re-patch /etc/pf.conf and load its own probe rule into the live
// anchor — silently killing the bypass — and only then fail to bind the socket.
//
// flock is advisory but process-scoped and released automatically by the kernel
// when the holder dies, which is exactly the semantics a crash-safe lock needs:
// no stale lock file to clean up after a SIGKILL.
type instanceLock struct {
	path string
	f    *os.File
}

// acquireInstanceLock takes the exclusive lock for dir, or reports who holds it.
func acquireInstanceLock(dir string) (*instanceLock, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("instance lock: state directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("instance lock: create %s: %w", dir, err)
	}
	path := filepath.Join(dir, instanceLockName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("instance lock: open %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		holder := readLockHolder(path)
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (%s%s); stop it first with `sudo launchctl bootout system/io.zapretmac.zapretd` "+
				"or `sudo zaprctl stop`, or point this one at a different --data directory",
				errAlreadyRunning, path, holder)
		}
		return nil, fmt.Errorf("instance lock: flock %s: %w", path, err)
	}
	// Record who holds it. Truncate first: a shorter pid must not leave digits of
	// a longer one behind.
	if err := f.Truncate(0); err == nil {
		if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err == nil {
			_ = f.Sync()
		}
	}
	return &instanceLock{path: path, f: f}, nil
}

// Release drops the lock. The file is left in place: its existence means nothing,
// only the kernel's lock does, and removing it would race a second daemon that
// has already opened it.
func (l *instanceLock) Release() {
	if l == nil || l.f == nil {
		return
	}
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}

// readLockHolder renders ", pid N" when the lock file names a pid.
func readLockHolder(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	pid := strings.TrimSpace(string(b))
	if pid == "" {
		return ""
	}
	if _, err := strconv.Atoi(pid); err != nil {
		return ""
	}
	return ", held by pid " + pid
}
