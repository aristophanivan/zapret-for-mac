//go:build darwin

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
)

// The dead-man's switch.
//
// THE HAZARD. The divert transport's steering rule is
//
//	pass out quick route-to (utunN 198.18.0.2) inet proto tcp ... no state
//
// A utun exists only while its kernel-control socket is open, so the interface
// dies with the daemon's process — but the pf rules do not. xnu's pf_route() sends
// a packet whose route-to interface has no ifp to `bad:` and m_freem()s it, so the
// packet is DROPPED, not passed. A `kill -9` on the daemon therefore black-holes
// every outbound TCP connection on the strategy's port window (and its UDP window)
// until something flushes the anchor. `sudo zapretd --foreground` killed with -9
// has no automatic recovery path at all: there is no launchd job to restart.
//
// THE SWITCH. `zapretd guard` is a one-shot command that:
//
//  1. tries to take the daemon's instance lock (flock on <state>/zapretd.lock);
//  2. if it CANNOT, a daemon is alive and owns the anchor — do nothing;
//  3. if it CAN, nobody owns the anchor. If the anchor still holds rules, flush
//     them and release the pf reference, then exit.
//
// launchd runs it every launchd.GuardInterval seconds (see `install-daemon`), so
// the worst-case black-hole is that interval rather than "until reboot". It is
// deliberately a separate job: launchd's KeepAlive restart of the daemon cannot
// help when the daemon's own job has been switched off in Login Items, and it does
// not help at all when the daemon is wedged rather than dead.
//
// It is also safe to run by hand, which is the documented manual recovery:
//
//	sudo zapretd guard --verbose
//	sudo pfctl -a zapret-mac -F all      # the same thing without this binary

// runGuard implements the `guard` subcommand.
func runGuard(args []string, stdout, stderr io.Writer) int {
	opts := defaultOptions()
	fs := flag.NewFlagSet("zapretd guard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	verbose := fs.Bool("verbose", false, "report what was found even when nothing had to be undone")
	fs.StringVar(&opts.dataDir, "data", opts.dataDir, "data directory whose state/ holds the instance lock")
	fs.StringVar(&opts.anchor, "anchor", opts.anchor, "pf anchor to flush when no daemon owns it")
	fs.StringVar(&opts.pfConfPath, "pf-conf", opts.pfConfPath, "main pf ruleset (only read)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "zapretd guard — flush the pf anchor when no daemon owns it (the dead-man's switch)\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "zapretd guard: unexpected argument %q\n", fs.Arg(0))
		return exitError
	}
	if os.Geteuid() != 0 {
		fmt.Fprintf(stderr, "zapretd guard: must run as root; pf cannot be read or flushed otherwise\n")
		return exitNotRoot
	}

	state := filepath.Join(strings.TrimSpace(opts.dataDir), "state")
	logf := func(format string, a ...any) {
		if *verbose {
			fmt.Fprintf(stdout, "zapretd guard: "+format+"\n", a...)
		}
	}

	// Step 1: is a daemon alive? The lock is the authority — a socket file can be
	// stale and a pidfile can be wrong, but flock is released by the kernel when
	// the holder dies.
	lockPath := filepath.Join(state, instanceLockName)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		// No state directory at all means nothing was ever installed here.
		logf("cannot open %s (%v); nothing to guard", lockPath, err)
		return exitOK
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			logf("a daemon holds %s%s; leaving the anchor alone", lockPath, readLockHolder(lockPath))
			return exitOK
		}
		fmt.Fprintf(stderr, "zapretd guard: flock %s: %v\n", lockPath, err)
		return exitError
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()

	// Step 2: nobody owns the anchor. If it is empty there is nothing to undo,
	// which is the overwhelmingly common case (this runs every few seconds).
	pf := netcfg.NewPF(opts.anchor, netcfg.PFOpts{
		PfConfPath: opts.pfConfPath,
		StateDir:   state,
		Logf:       logf,
	})
	defer pf.Close()

	rules, rerr := pf.Rules()
	nat, nerr := pf.NatRules()
	if rerr != nil && nerr != nil {
		// pf is probably disabled, which means nothing of ours can be dropping
		// packets. Not an error worth waking anybody for.
		logf("cannot read anchor %q (%v); pf is most likely disabled", opts.anchor, rerr)
		return exitOK
	}
	if strings.TrimSpace(rules) == "" && strings.TrimSpace(nat) == "" {
		logf("no daemon and an empty anchor %q: nothing to do", opts.anchor)
		return exitOK
	}

	// Step 3: orphaned rules. THIS is the black hole — flush it.
	fmt.Fprintf(stdout, "zapretd guard: anchor %q still holds %d filter and %d translation rule(s) but no daemon "+
		"owns it; flushing so pf stops dropping the port window\n",
		opts.anchor, countRuleLines(rules), countRuleLines(nat))
	code := exitOK
	if err := pf.FlushRules(); err != nil {
		fmt.Fprintf(stderr, "zapretd guard: flushing anchor %q failed: %v\n"+
			"  run this by hand NOW: sudo pfctl -a %s -F all\n", opts.anchor, err, opts.anchor)
		code = exitError
	}
	// The orphaned `pfctl -E` reference keeps pf enabled for the rest of uptime;
	// the token file is the only record of it.
	if err := pf.Release(); err != nil {
		fmt.Fprintf(stderr, "zapretd guard: releasing the leaked pf reference failed: %v\n", err)
		code = exitError
	}
	return code
}

// countRuleLines counts non-empty lines, for the guard's one-line report.
func countRuleLines(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}
