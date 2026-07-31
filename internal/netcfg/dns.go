package netcfg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Stock locations of the two utilities a DNS cache flush needs on macOS.
const (
	// DscacheutilPath clears the Directory Service / DNS cache.
	DscacheutilPath = "/usr/bin/dscacheutil"
	// KillallPath is used to SIGHUP mDNSResponder, which is what actually
	// drops the unicast DNS cache on modern macOS.
	KillallPath = "/usr/bin/killall"
	// MDNSResponderName is the process to signal.
	MDNSResponderName = "mDNSResponder"
)

// dnsFlushTimeout bounds each helper invocation. mDNSResponder occasionally
// takes a moment to answer a SIGHUP; anything longer than this is wedged.
const dnsFlushTimeout = 15 * time.Second

// FlushDNSCache drops the system DNS cache, the way Apple documents it:
//
//	dscacheutil -flushcache
//	killall -HUP mDNSResponder
//
// Both steps are needed on macOS — dscacheutil alone does not clear
// mDNSResponder's unicast cache — and both are tolerated as absent: on a system
// where either binary has been removed, or where mDNSResponder is not running
// (a container, a stripped install), that is not an error the caller can act on.
//
// An error is returned only when a tool that IS present failed for a reason
// other than "no matching processes". Callers should invoke this after
// Hosts.Apply or Hosts.Remove, since the resolver caches answers that a changed
// hosts file must override.
func FlushDNSCache() error {
	var errs []error

	if err := runDNSHelper(DscacheutilPath, "-flushcache"); err != nil {
		errs = append(errs, err)
	}
	if err := runDNSHelper(KillallPath, "-HUP", MDNSResponderName); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// runDNSHelper executes one flush helper, treating a missing binary as success
// and "no matching processes" from killall as success too.
func runDNSHelper(path string, args ...string) error {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Mode().Perm()&0o111 == 0 {
		// Absent or not executable: nothing to do, by design.
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsFlushTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		combined := out.String() + errb.String()
		// killall exits non-zero when the process is simply not running.
		if strings.Contains(combined, "No matching processes") ||
			strings.Contains(combined, "no process found") {
			return nil
		}
		return fmt.Errorf("netcfg: %s %s: %w: %s", path, strings.Join(args, " "),
			err, strings.TrimSpace(combined))
	}
	return nil
}
