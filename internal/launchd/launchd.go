// Package launchd writes and manages the LaunchDaemon property list that keeps
// zapretd running: it is the macOS replacement for flowseal's
// `sc create ... start=auto` service registration.
//
// Two facts about modern macOS shape this package:
//
//   - Since macOS 13 (Ventura) every LaunchDaemon shows up in System Settings >
//     General > Login Items & Extensions, listed by its signing identity (for an
//     ad-hoc signed binary: the developer name is absent and the entry shows the
//     program name). It is ENABLED by default — appearing there is disclosure,
//     not an approval gate, so `make install` does not need the user to click
//     anything. The user can, however, switch it off there, and that switch
//     survives reboots: if the daemon mysteriously stops starting, that toggle is
//     the first thing to check.
//   - `launchctl load/unload` is deprecated. The supported spelling is
//     `launchctl bootstrap system <plist>` / `launchctl bootout system/<label>`,
//     which is what this package uses. Both need root and both fail loudly (they
//     do not silently no-op the way `load` did).
//
// Everything here is reversible: WritePlist is atomic and Bootout removes the
// service without touching any other file.
package launchd

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultLabel is the daemon's launchd label, also its service name in the
// system domain (system/io.zapretmac.zapretd).
const DefaultLabel = "io.zapretmac.zapretd"

// DefaultPlistPath is where a system-wide LaunchDaemon must live to be
// bootstrapped into the system domain.
const DefaultPlistPath = "/Library/LaunchDaemons/" + DefaultLabel + ".plist"

// Default log paths. launchd creates the files itself (as root) the first time
// the job runs, so nothing has to pre-create them.
const (
	DefaultStdoutPath = "/var/log/zapretd.log"
	DefaultStderrPath = "/var/log/zapretd.err.log"
)

// LaunchctlPath is the launchctl binary. It is an absolute path on purpose: a
// root daemon must never resolve a helper through $PATH.
const LaunchctlPath = "/bin/launchctl"

// PlutilPath is used to lint a plist before it is installed.
const PlutilPath = "/usr/bin/plutil"

// launchctlTimeout bounds a launchctl invocation. bootstrap can take a moment on
// a busy machine; anything past this is a hung launchd.
const launchctlTimeout = 30 * time.Second

var (
	// ErrAlreadyLoaded means the service is already bootstrapped.
	ErrAlreadyLoaded = errors.New("launchd: service is already loaded")
	// ErrNotLoaded means the service is not bootstrapped.
	ErrNotLoaded = errors.New("launchd: service is not loaded")
	// ErrNeedRoot means launchctl refused because we are not root.
	ErrNeedRoot = errors.New("launchd: the system domain needs root")
)

// Plist is the subset of the LaunchDaemon schema this project uses.
//
// KeepAlive is deliberately not a plain bool: it is written as
// <dict><key>SuccessfulExit</key><false/></dict>, i.e. "restart it when it exits
// non-zero, leave it alone when it exits 0". A plain <true/> would fight with
// `zaprctl stop`-then-exit and with `launchctl bootout`, restarting the daemon
// the operator just stopped.
type Plist struct {
	// Label is the service name; it must match the plist's file name to keep
	// `launchctl print` and the Login Items list readable.
	Label string
	// Program is the absolute path of the executable.
	Program string
	// ProgramArguments is the full argv INCLUDING argv[0]. When it is empty,
	// launchd runs Program with no arguments.
	ProgramArguments []string
	// RunAtLoad starts the job as soon as it is bootstrapped (and at boot).
	RunAtLoad bool
	// KeepAlive writes the SuccessfulExit=false dictionary described above.
	KeepAlive bool
	// StandardOutPath / StandardErrorPath capture the daemon's plain-text log.
	StandardOutPath   string
	StandardErrorPath string
	// EnvironmentVariables is written sorted by key so two installs of the same
	// configuration produce byte-identical plists.
	EnvironmentVariables map[string]string
	// WorkingDirectory is optional.
	WorkingDirectory string
	// ProcessType is "Interactive" for this daemon: the packet datapath is
	// latency sensitive and must not be throttled the way a "Background" job is
	// (App Nap style CPU limits).
	ProcessType string
	// ThrottleInterval is the minimum seconds between automatic restarts.
	// launchd's default is 10; 0 leaves the key out.
	ThrottleInterval int
	// StartInterval runs the job every N seconds instead of keeping it alive. It
	// is what the anchor guard uses; 0 leaves the key out.
	StartInterval int
	// MaxFileDescriptors sets SoftResourceLimits/NumberOfFiles. launchd's default
	// is 256, which a long-running datapath that reopens descriptors on every
	// restart can exhaust; 0 leaves the key out.
	MaxFileDescriptors int
	// SessionCreate and Nice are intentionally absent: neither is meaningful
	// for a root network daemon.
}

// Default returns a Plist for zapretd: program plus arguments, restarted on
// crash, logging to /var/log.
func Default(program string, args ...string) Plist {
	argv := append([]string{program}, args...)
	return Plist{
		Label:             DefaultLabel,
		Program:           program,
		ProgramArguments:  argv,
		RunAtLoad:         true,
		KeepAlive:         true,
		StandardOutPath:   DefaultStdoutPath,
		StandardErrorPath: DefaultStderrPath,
		ProcessType:       "Interactive",
		ThrottleInterval:  10,
		// launchd's default soft limit is 256 descriptors. The datapath opens a
		// utun, a BPF injector, a BPF tap, /dev/pf and the control socket, and a
		// persistent late-stage failure loop reopens all of them every backoff
		// period; 4096 turns "fd exhaustion after a couple of hours" into a
		// non-event.
		MaxFileDescriptors: 4096,
	}
}

// GuardLabel is the launchd label of the anchor guard: a tiny periodic job whose
// only purpose is to flush our pf anchor when no daemon owns it.
const GuardLabel = DefaultLabel + ".guard"

// GuardPlistPath is where the guard's plist lives.
const GuardPlistPath = "/Library/LaunchDaemons/" + GuardLabel + ".plist"

// GuardInterval is how often the guard runs, in seconds. It bounds how long a
// SIGKILLed daemon can leave pf route-to'ing the port window at a dead utun.
const GuardInterval = 5

// Guard returns the plist for the anchor guard.
//
// WHY this job exists: the steering rule is
// `pass out quick route-to (utunN peer) ... no state`. The utun dies with the
// daemon's process, but the pf rules do not — and xnu's pf_route() drops a packet
// whose route-to interface has gone away. A `kill -9` therefore black-holes every
// outbound connection on the strategy's port window until something flushes the
// anchor. This job is that something: it runs every GuardInterval seconds,
// notices that nobody holds the daemon's instance lock, and flushes.
//
// It is deliberately a separate job from the daemon: launchd's KeepAlive restart
// of the daemon itself cannot help when the job has been switched off in Login
// Items, or when the daemon is wedged rather than dead.
func Guard(program string, args ...string) Plist {
	argv := append([]string{program}, args...)
	return Plist{
		Label:            GuardLabel,
		Program:          program,
		ProgramArguments: argv,
		RunAtLoad:        true,
		// No KeepAlive: this job is supposed to exit immediately every time.
		StartInterval:      GuardInterval,
		StandardOutPath:    DefaultStdoutPath,
		StandardErrorPath:  DefaultStderrPath,
		ProcessType:        "Background",
		MaxFileDescriptors: 64,
	}
}

// Validate rejects a plist launchd would refuse or that would be unmanageable.
func (p Plist) Validate() error {
	if strings.TrimSpace(p.Label) == "" {
		return errors.New("launchd: Label must not be empty")
	}
	if strings.ContainsAny(p.Label, " \t\n/") {
		return fmt.Errorf("launchd: Label %q must not contain whitespace or '/'", p.Label)
	}
	if !filepath.IsAbs(p.Program) {
		return fmt.Errorf("launchd: Program %q must be an absolute path", p.Program)
	}
	for i, a := range p.ProgramArguments {
		if strings.Contains(a, "\x00") {
			return fmt.Errorf("launchd: ProgramArguments[%d] contains a NUL byte", i)
		}
	}
	if p.StandardOutPath != "" && !filepath.IsAbs(p.StandardOutPath) {
		return fmt.Errorf("launchd: StandardOutPath %q must be absolute", p.StandardOutPath)
	}
	if p.StandardErrorPath != "" && !filepath.IsAbs(p.StandardErrorPath) {
		return fmt.Errorf("launchd: StandardErrorPath %q must be absolute", p.StandardErrorPath)
	}
	if p.WorkingDirectory != "" && !filepath.IsAbs(p.WorkingDirectory) {
		return fmt.Errorf("launchd: WorkingDirectory %q must be absolute", p.WorkingDirectory)
	}
	if p.ThrottleInterval < 0 {
		return fmt.Errorf("launchd: ThrottleInterval %d must not be negative", p.ThrottleInterval)
	}
	if p.StartInterval < 0 {
		return fmt.Errorf("launchd: StartInterval %d must not be negative", p.StartInterval)
	}
	if p.MaxFileDescriptors < 0 {
		return fmt.Errorf("launchd: MaxFileDescriptors %d must not be negative", p.MaxFileDescriptors)
	}
	return nil
}

// XML renders the plist. The output is deterministic (fixed key order, sorted
// environment) so an unchanged configuration rewrites byte-identical bytes and
// `git diff` on a backup stays readable.
func (p Plist) XML() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n")
	b.WriteString("<dict>\n")

	str := func(key, val string) {
		if val == "" {
			return
		}
		writeKey(&b, key)
		b.WriteString("\t<string>")
		escape(&b, val)
		b.WriteString("</string>\n")
	}
	boolean := func(key string, val bool) {
		writeKey(&b, key)
		if val {
			b.WriteString("\t<true/>\n")
		} else {
			b.WriteString("\t<false/>\n")
		}
	}

	str("Label", p.Label)
	str("Program", p.Program)
	if len(p.ProgramArguments) > 0 {
		writeKey(&b, "ProgramArguments")
		b.WriteString("\t<array>\n")
		for _, a := range p.ProgramArguments {
			b.WriteString("\t\t<string>")
			escape(&b, a)
			b.WriteString("</string>\n")
		}
		b.WriteString("\t</array>\n")
	}
	boolean("RunAtLoad", p.RunAtLoad)
	if p.KeepAlive {
		// SuccessfulExit=false: restart only after a failure, so a deliberate
		// clean shutdown stays shut down.
		writeKey(&b, "KeepAlive")
		b.WriteString("\t<dict>\n")
		b.WriteString("\t\t<key>SuccessfulExit</key>\n")
		b.WriteString("\t\t<false/>\n")
		b.WriteString("\t</dict>\n")
	}
	str("StandardOutPath", p.StandardOutPath)
	str("StandardErrorPath", p.StandardErrorPath)
	str("WorkingDirectory", p.WorkingDirectory)
	str("ProcessType", p.ProcessType)
	if p.ThrottleInterval > 0 {
		writeKey(&b, "ThrottleInterval")
		fmt.Fprintf(&b, "\t<integer>%d</integer>\n", p.ThrottleInterval)
	}
	if p.StartInterval > 0 {
		writeKey(&b, "StartInterval")
		fmt.Fprintf(&b, "\t<integer>%d</integer>\n", p.StartInterval)
	}
	if p.MaxFileDescriptors > 0 {
		writeKey(&b, "SoftResourceLimits")
		b.WriteString("\t<dict>\n")
		b.WriteString("\t\t<key>NumberOfFiles</key>\n")
		fmt.Fprintf(&b, "\t\t<integer>%d</integer>\n", p.MaxFileDescriptors)
		b.WriteString("\t</dict>\n")
	}
	if len(p.EnvironmentVariables) > 0 {
		keys := make([]string, 0, len(p.EnvironmentVariables))
		for k := range p.EnvironmentVariables {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		writeKey(&b, "EnvironmentVariables")
		b.WriteString("\t<dict>\n")
		for _, k := range keys {
			b.WriteString("\t\t<key>")
			escape(&b, k)
			b.WriteString("</key>\n\t\t<string>")
			escape(&b, p.EnvironmentVariables[k])
			b.WriteString("</string>\n")
		}
		b.WriteString("\t</dict>\n")
	}

	b.WriteString("</dict>\n")
	b.WriteString("</plist>\n")
	return b.Bytes(), nil
}

func writeKey(b *bytes.Buffer, key string) {
	b.WriteString("\t<key>")
	escape(b, key)
	b.WriteString("</key>\n")
}

// escape writes s as XML character data. xml.EscapeText is used rather than a
// hand-rolled replacer so a '&' or a non-UTF8 byte in a path cannot produce a
// plist launchd refuses to parse.
func escape(b *bytes.Buffer, s string) {
	_ = xml.EscapeText(b, []byte(s))
}

// WritePlist renders p and installs it at path, atomically, owned root:wheel
// with mode 0644 (what launchd requires of a system daemon plist: it refuses a
// group- or world-writable file).
//
// The rendered XML is linted with plutil at a temporary path first, so a
// malformed plist never lands in /Library/LaunchDaemons where the next boot
// would trip over it. An unchanged file is left completely untouched, which
// keeps `make reinstall` from bumping its mtime for no reason.
func WritePlist(path string, p Plist) error {
	data, err := p.XML()
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("launchd: plist path %q must be absolute", path)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("launchd: create %s: %w", dir, err)
	}

	if old, rerr := os.ReadFile(path); rerr == nil && bytes.Equal(old, data) {
		if err := fixPlistOwnership(path); err != nil {
			return err
		}
		return nil
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".zapret-*")
	if err != nil {
		return fmt.Errorf("launchd: create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("launchd: write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("launchd: fsync %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		cleanup()
		return fmt.Errorf("launchd: chmod %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("launchd: close %s: %w", tmpName, err)
	}
	if err := lint(tmpName); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	// root:wheel. Only root can do this, and only root can install a daemon at
	// all, so a failure here is fatal rather than best effort.
	if os.Geteuid() == 0 {
		if err := os.Chown(tmpName, 0, 0); err != nil {
			_ = os.Remove(tmpName)
			return fmt.Errorf("launchd: chown %s to root:wheel: %w", tmpName, err)
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("launchd: rename %s -> %s: %w", tmpName, path, err)
	}
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// fixPlistOwnership re-asserts root:wheel 0644 on an already-correct file.
func fixPlistOwnership(path string) error {
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("launchd: chmod %s: %w", path, err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 0, 0); err != nil {
			return fmt.Errorf("launchd: chown %s to root:wheel: %w", path, err)
		}
	}
	return nil
}

// lint runs plutil over a candidate plist. A missing plutil is not an error:
// the file is generated from a validated struct, and plutil is only a second
// opinion.
func lint(path string) error {
	if _, err := os.Stat(PlutilPath); err != nil {
		return nil
	}
	out, err := run(PlutilPath, "-lint", path)
	if err != nil {
		return fmt.Errorf("launchd: the generated plist does not parse: %w\n%s", err, strings.TrimSpace(out))
	}
	return nil
}

// RemovePlist deletes the plist file. A missing file is not an error.
func RemovePlist(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("launchd: remove %s: %w", path, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// launchctl
// ---------------------------------------------------------------------------

// Bootstrap loads the plist into the system domain and, with RunAtLoad, starts
// it. Returns ErrAlreadyLoaded when the service is already there.
func Bootstrap(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("launchd: %s: %w", path, err)
	}
	out, err := run(LaunchctlPath, "bootstrap", "system", path)
	if err == nil {
		return nil
	}
	low := strings.ToLower(out)
	switch {
	case strings.Contains(low, "already loaded"), strings.Contains(low, "service already bootstrapped"),
		strings.Contains(low, "operation already in progress"), strings.Contains(low, "bootstrap failed: 37"):
		return fmt.Errorf("%w: %s", ErrAlreadyLoaded, path)
	case strings.Contains(low, "operation not permitted"), strings.Contains(low, "permission denied"):
		return fmt.Errorf("%w: bootstrapping %s: %s", ErrNeedRoot, path, strings.TrimSpace(out))
	}
	return fmt.Errorf("launchd: launchctl bootstrap system %s: %w\n%s", path, err, strings.TrimSpace(out))
}

// Bootout removes the service from the system domain. A service that is not
// loaded is reported as ErrNotLoaded, so callers can treat uninstall as
// idempotent without parsing launchctl's output themselves.
func Bootout(label string) error {
	if strings.TrimSpace(label) == "" {
		return errors.New("launchd: Bootout needs a label")
	}
	out, err := run(LaunchctlPath, "bootout", "system/"+label)
	if err == nil {
		return nil
	}
	low := strings.ToLower(out)
	switch {
	case strings.Contains(low, "could not find specified service"),
		strings.Contains(low, "no such process"),
		strings.Contains(low, "boot-out failed: 3:"),
		strings.Contains(low, "boot-out failed: 113:"):
		return fmt.Errorf("%w: system/%s", ErrNotLoaded, label)
	case strings.Contains(low, "operation not permitted"), strings.Contains(low, "permission denied"):
		return fmt.Errorf("%w: booting out system/%s: %s", ErrNeedRoot, label, strings.TrimSpace(out))
	}
	return fmt.Errorf("launchd: launchctl bootout system/%s: %w\n%s", label, err, strings.TrimSpace(out))
}

// Loaded reports whether the service exists in the system domain.
//
// `launchctl print` is used rather than the deprecated `launchctl list` because
// it distinguishes "no such service" from "launchctl could not be asked" —
// which matters when the answer decides whether we are about to bootstrap a
// second copy of a packet interceptor.
func Loaded(label string) (bool, error) {
	if strings.TrimSpace(label) == "" {
		return false, errors.New("launchd: Loaded needs a label")
	}
	out, err := run(LaunchctlPath, "print", "system/"+label)
	if err == nil {
		return true, nil
	}
	low := strings.ToLower(out)
	if strings.Contains(low, "could not find service") || strings.Contains(low, "could not find specified service") ||
		strings.Contains(low, "no such process") {
		return false, nil
	}
	if strings.Contains(low, "operation not permitted") || strings.Contains(low, "permission denied") {
		return false, fmt.Errorf("%w: querying system/%s: %s", ErrNeedRoot, label, strings.TrimSpace(out))
	}
	return false, fmt.Errorf("launchd: launchctl print system/%s: %w\n%s", label, err, strings.TrimSpace(out))
}

// PID returns the running job's pid, or 0 when the service is loaded but not
// running. It parses `launchctl print`, whose "pid = N" line is stable across
// every macOS release that has the subcommand.
func PID(label string) (int, error) {
	out, err := run(LaunchctlPath, "print", "system/"+label)
	if err != nil {
		low := strings.ToLower(out)
		if strings.Contains(low, "could not find service") || strings.Contains(low, "could not find specified service") {
			return 0, fmt.Errorf("%w: system/%s", ErrNotLoaded, label)
		}
		return 0, fmt.Errorf("launchd: launchctl print system/%s: %w", label, err)
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.TrimSpace(line)
		if !strings.HasPrefix(f, "pid = ") {
			continue
		}
		var pid int
		if _, serr := fmt.Sscanf(f, "pid = %d", &pid); serr == nil {
			return pid, nil
		}
	}
	return 0, nil
}

// Kickstart starts the service now (and restarts it when kill is true). This is
// what `zaprctl start` uses when the daemon process itself is not running.
func Kickstart(label string, kill bool) error {
	args := []string{"kickstart"}
	if kill {
		args = append(args, "-k")
	}
	args = append(args, "system/"+label)
	out, err := run(LaunchctlPath, args...)
	if err == nil {
		return nil
	}
	low := strings.ToLower(out)
	switch {
	case strings.Contains(low, "could not find service"), strings.Contains(low, "could not find specified service"):
		return fmt.Errorf("%w: system/%s", ErrNotLoaded, label)
	case strings.Contains(low, "operation not permitted"), strings.Contains(low, "permission denied"):
		return fmt.Errorf("%w: kickstarting system/%s: %s", ErrNeedRoot, label, strings.TrimSpace(out))
	}
	return fmt.Errorf("launchd: launchctl kickstart system/%s: %w\n%s", label, err, strings.TrimSpace(out))
}

// run executes a helper and returns its combined output. The output is part of
// every error this package returns, because launchctl's exit codes alone
// ("Bootstrap failed: 5") are not actionable.
func run(prog string, args ...string) (string, error) {
	if _, err := os.Stat(prog); err != nil {
		return "", fmt.Errorf("launchd: %s is not available: %w", prog, err)
	}
	cmd := exec.Command(prog, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("launchd: start %s: %w", prog, err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(launchctlTimeout):
		_ = cmd.Process.Kill()
		<-done
		return buf.String(), fmt.Errorf("launchd: %s %s did not finish within %s", prog, strings.Join(args, " "), launchctlTimeout)
	}
}
