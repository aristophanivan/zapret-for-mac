package netcfg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Stock macOS locations. /etc/pf.conf is the only system file this package
// edits; /dev/pf is 0600 root:wheel, so everything here needs euid 0.
const (
	// DefaultPfConfPath is the main pf ruleset macOS loads at boot.
	DefaultPfConfPath = "/etc/pf.conf"
	// DefaultPfctlPath is the pf control utility.
	DefaultPfctlPath = "/sbin/pfctl"
	// PfDevicePath is the pf character device (0600 root:wheel).
	PfDevicePath = "/dev/pf"
	// DefaultDnctlPath is dummynet's control utility, present since 10.7.
	DefaultDnctlPath = "/usr/sbin/dnctl"
	// PfTokenName is the file, inside the state directory, holding the
	// `pfctl -E` token so a crashed daemon can still release it.
	PfTokenName = "pf.token"
	// BackupDirName is the sub-directory of the state directory that holds
	// byte-exact backups of the system files we patch.
	BackupDirName = "backup"
	// PfConfSumName is the file, inside the state directory, holding the SHA-256
	// of the main pf ruleset as WE last wrote it.
	//
	// It deliberately lives outside the journal. The journal is cleared on every
	// clean shutdown (its records describe changes the process owns), so after the
	// first clean stop the drift check had nothing to compare against and
	// ErrPfConfDrift — the documented "somebody else edited this file" signal —
	// could never fire again. This file is never cleared.
	PfConfSumName = "pf.conf.sha256"
)

// pfctlTimeout bounds every pfctl invocation. Replacing a 32k-entry table is
// the slowest operation and completes in well under a second, so a generous
// ceiling here only guards against pfctl blocking on a wedged /dev/pf.
const pfctlTimeout = 30 * time.Second

// Sentinel errors callers match with errors.Is.
var (
	// ErrNotRoot means euid is not 0; /dev/pf cannot be opened and pfctl
	// cannot change anything.
	ErrNotRoot = errors.New("netcfg: must run as root")
	// ErrPfctlMissing means /sbin/pfctl is absent or not executable.
	ErrPfctlMissing = errors.New("netcfg: pfctl not available")
	// ErrPfConfDrift means the main pf configuration file changed after we
	// patched it. RemoveAnchorStatements still removes our own block and
	// reports this, because blanket-restoring the backup would destroy the
	// third party's edit.
	ErrPfConfDrift = errors.New("netcfg: pf.conf changed since it was patched")
	// ErrRulesDrift means our anchor no longer holds the ruleset we loaded —
	// an OS update or a VPN running `pfctl -f /etc/pf.conf` wipes it.
	ErrRulesDrift = errors.New("netcfg: anchor ruleset drifted")
	// ErrAnchorUnreferenced means the main ruleset no longer names our
	// anchor, so nothing inside it is evaluated.
	ErrAnchorUnreferenced = errors.New("netcfg: main ruleset no longer references our anchor")
	// ErrPfDisabled means pf is not currently enabled.
	ErrPfDisabled = errors.New("netcfg: pf is disabled")
	// ErrDryRun is returned by operations that cannot even be simulated
	// without touching the kernel.
	ErrDryRun = errors.New("netcfg: refusing to act in dry-run mode")
)

// Logf is the logging hook. A nil Logf discards output.
type Logf func(format string, args ...any)

// PFOpts configures a PF.
type PFOpts struct {
	// PfConfPath is the main pf ruleset. Defaults to /etc/pf.conf.
	PfConfPath string
	// StateDir is where the pf token, the rollback journal and byte-exact
	// backups live. Required for anything that must be reversible.
	StateDir string
	// DryRun makes every mutating operation validate and log without
	// changing anything. Preflight downgrades its root and /dev/pf checks to
	// warnings so `zaprctl doctor` can run unprivileged.
	DryRun bool
	// PfctlPath overrides /sbin/pfctl (tests, unusual installs).
	PfctlPath string
	// ForcePfConfAnchor disables the wildcard sub-anchor path and insists on a
	// top-level anchor referenced from /etc/pf.conf, even when the sub-anchor
	// would work. Use it only when the wildcard anchor point is missing or when
	// borrowing Apple's namespace is unacceptable.
	ForcePfConfAnchor bool
	// Logf receives progress messages.
	Logf Logf
}

// AnchorMode says how our rules reach pf's evaluation path.
type AnchorMode string

const (
	// AnchorModeUnresolved means ResolveAnchor has not run yet.
	AnchorModeUnresolved AnchorMode = ""
	// AnchorModeWildcard loads rules into "com.apple/<anchor>", a sub-anchor of
	// the wildcard anchor point a stock /etc/pf.conf already declares. Nothing
	// on disk is modified; the sub-anchor exists only while it holds rules.
	AnchorModeWildcard AnchorMode = "wildcard-subanchor"
	// AnchorModePfConf uses a top-level anchor, which only works if
	// /etc/pf.conf references it — so this mode requires patching that file.
	AnchorModePfConf AnchorMode = "pf.conf-anchor"
)

// PF drives pf for one anchor: it patches the main ruleset so the anchor is
// evaluated at all, holds the `pfctl -E` reference, loads and verifies the
// anchor's rules and maintains the anchor's tables.
//
// All methods are safe for concurrent use.
type PF struct {
	anchor     string
	pfConfPath string
	stateDir   string
	pfctlPath  string
	dryRun     bool
	logf       Logf

	forcePfConf bool

	mu sync.Mutex
	// effAnchor is the anchor path actually passed to `pfctl -a`. It is
	// "com.apple/<anchor>" in AnchorModeWildcard and <anchor> otherwise.
	effAnchor string
	// mode records how the anchor reaches pf; see ResolveAnchor.
	mode AnchorMode
	// token is the live `pfctl -E` reference, "" when we hold none.
	token string
	// baseFilter/baseNat are `pfctl -a <anchor> -s rules|nat` as pf rendered
	// them immediately after LoadRules succeeded. Verify compares against
	// these rather than against the text we submitted, because pfctl
	// normalises rules on load.
	baseFilter string
	baseNat    string
	haveBase   bool
	// journal is opened lazily; nil in dry-run or when StateDir is empty.
	journal *Journal

	lastPreflight PreflightResult
}

// NewPF returns a PF for the named anchor. The anchor name must be a plain pf
// identifier (no '/', quotes or whitespace) so it can never break out of the
// statements we write into the main ruleset.
func NewPF(anchor string, opts PFOpts) *PF {
	p := &PF{
		anchor:      anchor,
		pfConfPath:  opts.PfConfPath,
		stateDir:    opts.StateDir,
		pfctlPath:   opts.PfctlPath,
		dryRun:      opts.DryRun,
		forcePfConf: opts.ForcePfConfAnchor,
		logf:        opts.Logf,
	}
	if p.pfConfPath == "" {
		p.pfConfPath = DefaultPfConfPath
	}
	if p.pfctlPath == "" {
		p.pfctlPath = DefaultPfctlPath
	}
	if p.logf == nil {
		p.logf = func(string, ...any) {}
	}
	return p
}

// ResolveAnchor decides how our rules will reach pf, and returns the mode.
//
// A stock /etc/pf.conf declares `anchor "com.apple/*"` plus its scrub/nat/rdr
// siblings. The trailing /* means pf evaluates EVERY sub-anchor nested at that
// point, and a sub-anchor springs into existence simply by having rules loaded
// into it. So loading into "com.apple/<anchor>" gets our rules evaluated with no
// edit to /etc/pf.conf at all — which is also how Apple's own services inject
// their runtime rules (Internet Sharing NAT, AirDrop).
//
// That is strictly preferable to patching /etc/pf.conf: nothing on disk changes,
// so there is nothing to restore, nothing an OS update can clobber, and no
// window in which a half-written system file exists. The trade-off is that we
// borrow Apple's namespace — anything flushing com.apple/* wholesale would take
// our rules with it, which Verify detects and the daemon repairs.
//
// Falls back to AnchorModePfConf when the wildcard anchor point is missing
// (a customised /etc/pf.conf) or when PFOpts.ForcePfConfAnchor was set.
func (p *PF) ResolveAnchor() (AnchorMode, error) {
	if err := p.validateAnchor(); err != nil {
		return AnchorModeUnresolved, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.resolveAnchorLocked()
}

func (p *PF) resolveAnchorLocked() (AnchorMode, error) {
	if p.mode != AnchorModeUnresolved {
		return p.mode, nil
	}
	if p.forcePfConf {
		p.mode, p.effAnchor = AnchorModePfConf, p.anchor
		return p.mode, nil
	}

	sub := appleSubAnchorFor(p.anchor)
	filterRules, _, ferr := p.run("", "-s", "rules")
	natRules, _, nerr := p.run("", "-s", "nat")
	if ferr != nil || nerr != nil {
		// Without a readable main ruleset we cannot prove the wildcard exists;
		// the pf.conf path is the safe assumption because it verifies itself.
		p.mode, p.effAnchor = AnchorModePfConf, p.anchor
		return p.mode, nil
	}
	if WildcardAnchorCovers(filterRules, sub) && WildcardAnchorCovers(natRules, sub) {
		p.mode, p.effAnchor = AnchorModeWildcard, sub
		p.logf("netcfg: using wildcard sub-anchor %q; %s will not be modified", sub, p.pfConfPath)
		return p.mode, nil
	}
	p.mode, p.effAnchor = AnchorModePfConf, p.anchor
	return p.mode, nil
}

// Mode reports the resolved anchor mode (AnchorModeUnresolved before
// ResolveAnchor or EnsureAnchorStatements has run).
func (p *PF) Mode() AnchorMode {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mode
}

// EffectiveAnchor is the anchor path handed to `pfctl -a`.
func (p *PF) EffectiveAnchor() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.effAnchorLocked()
}

// effAnchorLocked returns the anchor path for pfctl. The caller holds p.mu.
func (p *PF) effAnchorLocked() string {
	if p.effAnchor != "" {
		return p.effAnchor
	}
	return p.anchor
}

// appleSubAnchorFor nests our anchor under the wildcard anchor point.
func appleSubAnchorFor(anchor string) string { return "com.apple/" + anchor }

// Anchor returns the anchor name.
func (p *PF) Anchor() string { return p.anchor }

// PfConfPath returns the main ruleset path this PF patches.
func (p *PF) PfConfPath() string { return p.pfConfPath }

// StateDir returns the directory holding the token, journal and backups.
func (p *PF) StateDir() string { return p.stateDir }

// DryRun reports whether mutations are suppressed.
func (p *PF) DryRun() bool { return p.dryRun }

// reAnchorName rejects anchor names that could escape the quoted statement or
// address a nested anchor path we do not own.
var reAnchorName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// validateAnchor checks the anchor name once, before it is used in a system
// file or a pfctl argument.
func (p *PF) validateAnchor() error {
	if !reAnchorName.MatchString(p.anchor) {
		return fmt.Errorf("netcfg: invalid anchor name %q: want [A-Za-z0-9][A-Za-z0-9._-]{0,63}", p.anchor)
	}
	return nil
}

// ---------------------------------------------------------------------------
// pfctl plumbing
// ---------------------------------------------------------------------------

// PfctlError carries a failed pfctl invocation with its output verbatim. pf
// syntax errors are only actionable if the operator sees pfctl's own message,
// so nothing here is summarised or rewritten.
type PfctlError struct {
	// Args is the argument vector, without the program name.
	Args []string
	// Stdout and Stderr are pfctl's output, unmodified.
	Stdout string
	Stderr string
	// Err is the underlying exec error (usually *exec.ExitError).
	Err error
}

// Error renders the invocation and pfctl's own diagnostics.
func (e *PfctlError) Error() string {
	var sb strings.Builder
	sb.WriteString("pfctl ")
	sb.WriteString(strings.Join(e.Args, " "))
	sb.WriteString(": ")
	if e.Err != nil {
		sb.WriteString(e.Err.Error())
	} else {
		sb.WriteString("failed")
	}
	if s := strings.TrimRight(e.Stderr, "\n"); s != "" {
		sb.WriteString("\n--- pfctl stderr ---\n")
		sb.WriteString(s)
	}
	if s := strings.TrimRight(e.Stdout, "\n"); s != "" {
		sb.WriteString("\n--- pfctl stdout ---\n")
		sb.WriteString(s)
	}
	return sb.String()
}

// Unwrap exposes the exec error.
func (e *PfctlError) Unwrap() error { return e.Err }

// pfctlNoise is the three-line advisory pfctl prints on every `-f` regardless
// of success. It is stripped only from log output, never from PfctlError.
var pfctlNoise = regexp.MustCompile(`(?m)^pfctl: Use of -f option, could result in flushing of rules\n?|^present in the main ruleset added by the system at startup\.\n?|^See /etc/pf\.conf for further details\.\n?`)

// run executes pfctl with args, feeding stdin when non-empty.
func (p *PF) run(stdin string, args ...string) (stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), pfctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.pfctlPath, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	runErr := cmd.Run()
	stdout, stderr = out.String(), errb.String()
	if runErr != nil {
		return stdout, stderr, &PfctlError{Args: args, Stdout: stdout, Stderr: stderr, Err: runErr}
	}
	return stdout, stderr, nil
}

// ---------------------------------------------------------------------------
// journal
// ---------------------------------------------------------------------------

// Journal returns (opening on first use) the rollback journal in StateDir.
// It returns nil when no StateDir is configured — in that case changes are
// still made but cannot be repaired after a crash, so callers that care should
// always configure one.
func (p *PF) Journal() *Journal {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.journalLocked()
}

// journalLocked opens the journal on demand. The caller holds p.mu.
func (p *PF) journalLocked() *Journal {
	if p.journal != nil {
		return p.journal
	}
	if p.stateDir == "" || p.dryRun {
		return nil
	}
	j, err := OpenJournal(p.stateDir)
	if err != nil {
		p.logf("netcfg: cannot open rollback journal: %v", err)
		return nil
	}
	p.journal = j
	return j
}

// record appends a rollback record, logging (never failing) on error: losing a
// journal entry must not abort the operation it describes, but the operator
// needs to know that automatic repair is degraded.
func (p *PF) recordLocked(step string, data map[string]string) {
	j := p.journalLocked()
	if j == nil {
		return
	}
	if err := j.Record(step, data); err != nil {
		p.logf("netcfg: journal record %s failed: %v", step, err)
	}
}

// backupDir is the directory byte-exact backups are written to.
func (p *PF) backupDir() string {
	if p.stateDir == "" {
		return ""
	}
	return filepath.Join(p.stateDir, BackupDirName)
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

// PreflightResult is everything Preflight learned. It is filled in even when
// Preflight returns an error, so `zaprctl doctor` can print a full picture.
type PreflightResult struct {
	// UID is the effective uid the daemon runs as.
	UID int
	// Root is UID == 0.
	Root bool
	// PfctlPath is the pfctl binary that was probed, and PfctlOK whether it
	// exists and is executable.
	PfctlPath string
	PfctlOK   bool
	// PfDevOpenable reports whether /dev/pf could be opened O_RDWR;
	// PfDevErr is the failure reason when it could not.
	PfDevOpenable bool
	PfDevErr      string
	// DnctlPath is set when /usr/sbin/dnctl is present.
	DnctlPath string
	// PfConfPath is the main ruleset that was inspected, PfConfExists
	// whether it is readable.
	PfConfPath   string
	PfConfExists bool
	// PfEnabled is `pfctl -s info` reporting "Status: Enabled". Only
	// meaningful when running as root.
	PfEnabled bool
	// PfEnabledKnown is false when pf's status could not be queried.
	PfEnabledKnown bool
	// AnchorReferenced reports whether the main ruleset already names our
	// anchor (both the rdr-anchor and the filter anchor).
	AnchorReferenced bool
	// ForeignAnchors lists anchors in the main ruleset that are neither ours
	// nor Apple's — most often another bypass tool ("zapret") or a VPN.
	ForeignAnchors []string
	// DefaultIface, DefaultGateway describe the current IPv4 default route.
	DefaultIface   string
	DefaultGateway string
	// VPNActive is true when the default route points at a tunnel interface.
	// The daemon warns on this: the divert transport re-emits packets with a
	// BPF write on a physical interface, which a VPN's utun does not provide.
	VPNActive bool
	// Warnings are non-fatal findings, human readable.
	Warnings []string
}

// Preflight checks that this process can drive pf at all, and surveys the
// environment for conditions the daemon must warn about.
//
// Hard requirements (an error unless DryRun is set): euid 0, an executable
// pfctl, an openable /dev/pf, a readable main ruleset. Everything else —
// foreign anchors, an active VPN, pf already enabled by another component — is
// reported as a warning and through LastPreflight.
func (p *PF) Preflight() error {
	res := PreflightResult{
		UID:        os.Geteuid(),
		PfctlPath:  p.pfctlPath,
		PfConfPath: p.pfConfPath,
	}
	res.Root = res.UID == 0

	var hard []error

	if err := p.validateAnchor(); err != nil {
		hard = append(hard, err)
	}

	if st, err := os.Stat(p.pfctlPath); err != nil {
		hard = append(hard, fmt.Errorf("%w: %s: %v", ErrPfctlMissing, p.pfctlPath, err))
	} else if st.IsDir() || st.Mode().Perm()&0o111 == 0 {
		hard = append(hard, fmt.Errorf("%w: %s is not executable", ErrPfctlMissing, p.pfctlPath))
	} else {
		res.PfctlOK = true
	}

	if !res.Root {
		if p.dryRun {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("running as uid %d, not root: pf cannot be changed (dry run)", res.UID))
		} else {
			hard = append(hard, fmt.Errorf("%w (euid %d)", ErrNotRoot, res.UID))
		}
	}

	if fd, err := unix.Open(PfDevicePath, unix.O_RDWR, 0); err != nil {
		res.PfDevErr = err.Error()
		msg := fmt.Errorf("netcfg: open %s O_RDWR: %w (it is 0600 root:wheel)", PfDevicePath, err)
		if p.dryRun {
			res.Warnings = append(res.Warnings, msg.Error())
		} else {
			hard = append(hard, msg)
		}
	} else {
		res.PfDevOpenable = true
		_ = unix.Close(fd)
	}

	if st, err := os.Stat(DefaultDnctlPath); err == nil && !st.IsDir() {
		res.DnctlPath = DefaultDnctlPath
	} else {
		res.Warnings = append(res.Warnings, DefaultDnctlPath+" is missing: dummynet rules unavailable")
	}

	conf, ok, err := readFileIfExists(p.pfConfPath)
	switch {
	case err != nil:
		hard = append(hard, fmt.Errorf("netcfg: read %s: %w", p.pfConfPath, err))
	case !ok:
		hard = append(hard, fmt.Errorf("netcfg: %s does not exist; refusing to create a main pf ruleset", p.pfConfPath))
	default:
		res.PfConfExists = true
		res.AnchorReferenced = AnchorStatementsPresent(conf, p.anchor)
		for _, name := range AnchorNames(conf) {
			if name == p.anchor || strings.HasPrefix(name, "com.apple") {
				continue
			}
			res.ForeignAnchors = append(res.ForeignAnchors, name)
		}
	}

	// pf status and the live anchor list need /dev/pf, so only try when we
	// actually opened it.
	if res.PfctlOK && res.PfDevOpenable {
		if on, err := p.Enabled(); err == nil {
			res.PfEnabled = on
			res.PfEnabledKnown = true
			if on {
				res.Warnings = append(res.Warnings,
					"pf is already enabled by another component: we will take a reference with -E and release it with -X, never -d")
			}
		} else {
			res.Warnings = append(res.Warnings, "cannot query pf status: "+err.Error())
		}
		if live, err := p.liveAnchors(); err == nil {
			for _, name := range live {
				if name == p.anchor || strings.HasPrefix(name, "com.apple") {
					continue
				}
				if !containsString(res.ForeignAnchors, name) {
					res.ForeignAnchors = append(res.ForeignAnchors, name)
				}
			}
		}
	}
	if len(res.ForeignAnchors) > 0 {
		res.Warnings = append(res.Warnings,
			"foreign pf anchors present (another bypass tool or VPN may own rules): "+
				strings.Join(res.ForeignAnchors, ", "))
	}

	if iface, gw, _, _, err := DefaultRoute(); err == nil {
		res.DefaultIface = iface
		if gw.IsValid() {
			res.DefaultGateway = gw.String()
		}
		if IsTunnelInterface(iface) {
			res.VPNActive = true
			res.Warnings = append(res.Warnings,
				"the IPv4 default route points at tunnel interface "+iface+
					": a VPN is active, and the divert transport needs a physical uplink for its BPF re-emit")
		}
	} else {
		res.Warnings = append(res.Warnings, "cannot read the IPv4 default route: "+err.Error())
	}

	p.mu.Lock()
	p.lastPreflight = res
	p.mu.Unlock()

	for _, w := range res.Warnings {
		p.logf("netcfg: preflight warning: %s", w)
	}
	return errors.Join(hard...)
}

// LastPreflight returns the result of the most recent Preflight call.
func (p *PF) LastPreflight() PreflightResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastPreflight
}

// liveAnchors lists the anchors currently loaded in the kernel
// (`pfctl -s Anchors`).
func (p *PF) liveAnchors() ([]string, error) {
	out, _, err := p.run("", "-s", "Anchors")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		names = append(names, strings.TrimPrefix(t, "/"))
	}
	return names, nil
}

// containsString reports membership.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// main ruleset patching
// ---------------------------------------------------------------------------

// EnsureAnchorStatements idempotently inserts our anchor statements into the
// main pf configuration file so the anchor is actually evaluated:
//
//	# >>> zapret-mac >>>
//	rdr-anchor "zapret-mac"
//	# <<< zapret-mac <<<
//	...
//	# >>> zapret-mac >>>
//	anchor "zapret-mac"
//	# <<< zapret-mac <<<
//
// The rdr-anchor is placed at the head of pf's translation section and the
// filter anchor at the head of the filter section — both ahead of the com.apple
// anchors, which is what zapret's common/pf.sh does on macOS. They cannot be a
// single contiguous block: macOS pf enforces the section order options,
// normalization, queueing, translation, filtering, and rejects the file
// outright otherwise.
//
// Safety sequence: plan -> `pfctl -n -f` on a temp copy -> byte-exact backup
// with its SHA-256 in the journal -> atomic replace preserving mode and owner
// -> re-read and byte-compare -> `pfctl -n -f` on the real path -> reload the
// main ruleset. Any failure after the write restores the backup before
// returning. Foreign lines are never reordered or removed.
//
// patched reports whether the file was (or, under DryRun, would be) changed.
func (p *PF) EnsureAnchorStatements() (patched bool, err error) {
	if err := p.validateAnchor(); err != nil {
		return false, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	// Resolve first: in wildcard mode the rules are evaluated through the
	// anchor point /etc/pf.conf already declares, so there is nothing to patch
	// and no system file to put at risk.
	if mode, merr := p.resolveAnchorLocked(); merr != nil {
		return false, merr
	} else if mode == AnchorModeWildcard {
		p.logf("netcfg: anchor %q reached through the wildcard point; %s left untouched",
			p.effAnchorLocked(), p.pfConfPath)
		return false, nil
	}

	orig, ok, err := readFileIfExists(p.pfConfPath)
	if err != nil {
		return false, fmt.Errorf("netcfg: read %s: %w", p.pfConfPath, err)
	}
	if !ok {
		return false, fmt.Errorf("netcfg: %s does not exist; refusing to create a main pf ruleset", p.pfConfPath)
	}
	st, err := os.Stat(p.pfConfPath)
	if err != nil {
		return false, fmt.Errorf("netcfg: stat %s: %w", p.pfConfPath, err)
	}

	plan := planPfConf(orig, p.anchor)
	if !plan.Changed {
		p.logf("netcfg: %s %s", p.pfConfPath, plan.Note)
		return false, nil
	}

	// Parse-check the candidate at a scratch path first, so a rejected
	// ruleset never reaches /etc/pf.conf at all.
	if err := p.checkCandidate(plan.Content); err != nil {
		// Distinguish "our insertion broke it" from "it never parsed". A CRLF
		// pf.conf, or one truncated by a failed edit, cannot be loaded by pf at
		// all — telling the operator that WE broke it sends them hunting the wrong
		// bug while the daemon crash-loops.
		if oerr := p.checkCandidate(orig); oerr != nil {
			return false, fmt.Errorf("netcfg: %s does not parse even without our changes "+
				"(CRLF line endings? a truncated edit? a missing final newline?); fix it first, "+
				"pf cannot load it either way: %w", p.pfConfPath, oerr)
		}
		return false, fmt.Errorf("netcfg: refusing to patch %s, the result does not parse: %w", p.pfConfPath, err)
	}

	if p.dryRun {
		p.logf("netcfg: dry run: would patch %s (%s)", p.pfConfPath, plan.Note)
		return true, nil
	}

	backup, sumBefore, err := p.backupPfConf(orig, st)
	if err != nil {
		return false, err
	}
	sumAfter := sha256Hex(plan.Content)
	data := map[string]string{
		"path":          p.pfConfPath,
		"backup":        backup,
		"sha256_before": sumBefore,
		"sha256_after":  sumAfter,
		"anchor":        p.anchor,
	}
	if real := SymlinkTarget(p.pfConfPath); real != "" {
		// The patch lands on the link's target, not on the link. Record it so
		// `zaprctl doctor` can name the file that actually changed.
		data["symlink"] = real
		p.logf("netcfg: %s is a symlink to %s; patching the target and keeping the link",
			p.pfConfPath, real)
	}
	p.recordLocked(StepPfConf, data)
	p.writePfConfSumLocked(sumAfter)

	if err := writeFileAtomic(p.pfConfPath, plan.Content, st.Mode().Perm(), st); err != nil {
		return false, err
	}

	// Verify by re-reading, then by asking pfctl to parse the real file.
	if verr := p.verifyPfConf(plan.Content); verr != nil {
		rerr := p.restorePfConf(orig, st)
		if rerr != nil {
			return false, fmt.Errorf("netcfg: %s verification failed (%v) AND restoring the backup %s failed: %w; "+
				"restore it by hand before rebooting", p.pfConfPath, verr, backup, rerr)
		}
		return false, fmt.Errorf("netcfg: %s verification failed, backup restored from %s: %w", p.pfConfPath, backup, verr)
	}

	p.logf("netcfg: patched %s (%s), backup %s", p.pfConfPath, plan.Note, backup)

	// The kernel still holds the pre-patch main ruleset (macOS loads
	// /etc/pf.conf once at boot; `pfctl -E` does not reload it), so the
	// anchor is not evaluated until we reload. This does flush anchors that
	// system services inserted dynamically at runtime — unavoidable, and what
	// upstream's pf_anchor_root_reload does too.
	if err := p.reloadMainLocked(); err != nil {
		return true, fmt.Errorf("netcfg: %s patched but reloading the main ruleset failed: %w", p.pfConfPath, err)
	}
	return true, nil
}

// RemoveAnchorStatements deletes only our marker-delimited blocks (and any bare
// `anchor "<name>"` / `rdr-anchor "<name>"` line naming our anchor) from the
// main pf configuration file.
//
// If the file drifted since we patched it — an OS update, a VPN, or the
// operator editing it — the block is STILL removed and a non-nil error wrapping
// ErrPfConfDrift is returned. Blanket-restoring our backup over someone else's
// edit would be the more destructive choice, so we never do it. When that error
// is returned the removal has already happened; it is a report, not a failure.
func (p *PF) RemoveAnchorStatements() error {
	if err := p.validateAnchor(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	// In wildcard mode we never wrote to the file, so there is nothing to undo.
	// Still strip a block left by an earlier pf.conf-mode install, so switching
	// modes does not orphan statements in a system file.
	if p.mode == AnchorModeWildcard {
		if conf, ok, err := readFileIfExists(p.pfConfPath); err == nil && ok &&
			!AnchorStatementsPresent(conf, p.anchor) {
			return nil
		}
	}

	orig, ok, err := readFileIfExists(p.pfConfPath)
	if err != nil {
		return fmt.Errorf("netcfg: read %s: %w", p.pfConfPath, err)
	}
	if !ok {
		// Nothing to clean up.
		return nil
	}

	plan := planPfConfRemoval(orig, p.anchor)
	if !plan.Changed {
		// Nothing of ours is in the file, so there is nothing to reconcile and
		// nothing to report: this is the clean second-call case.
		return nil
	}
	drift := p.detectPfConfDriftLocked(orig)
	if p.dryRun {
		p.logf("netcfg: dry run: would unpatch %s (%s)", p.pfConfPath, plan.Note)
		return drift
	}

	st, err := os.Stat(p.pfConfPath)
	if err != nil {
		return fmt.Errorf("netcfg: stat %s: %w", p.pfConfPath, err)
	}
	if err := p.checkCandidate(plan.Content); err != nil {
		return fmt.Errorf("netcfg: refusing to unpatch %s, the result does not parse: %w", p.pfConfPath, err)
	}
	backup, _, err := p.backupPfConf(orig, st)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(p.pfConfPath, plan.Content, st.Mode().Perm(), st); err != nil {
		return err
	}
	if verr := p.verifyPfConf(plan.Content); verr != nil {
		if rerr := p.restorePfConf(orig, st); rerr != nil {
			return fmt.Errorf("netcfg: unpatching %s failed (%v) AND restoring %s failed: %w",
				p.pfConfPath, verr, backup, rerr)
		}
		return fmt.Errorf("netcfg: unpatching %s failed, backup restored from %s: %w", p.pfConfPath, backup, verr)
	}
	p.logf("netcfg: unpatched %s (%s), backup %s", p.pfConfPath, plan.Note, backup)
	if err := p.reloadMainLocked(); err != nil {
		p.logf("netcfg: %s unpatched but reloading the main ruleset failed: %v", p.pfConfPath, err)
	}
	return drift
}

// detectPfConfDriftLocked compares the current file against the hash recorded
// when we patched it. The caller holds p.mu.
//
// It reads the journal WITHOUT taking the journal's mutex, because it runs inside
// Journal.Rollback's handler on the daemon's startup path (Rollback -> our
// StepPfConf handler -> RemoveAnchorStatements -> here) and that mutex is already
// held by this goroutine. See Journal.entriesUnlocked.
func (p *PF) detectPfConfDriftLocked(current []byte) error {
	// The persistent sum file first: it outlives the journal, which a clean
	// shutdown empties.
	want := p.readPfConfSumLocked()
	if want == "" {
		if j := p.journalLocked(); j != nil {
			if entries, err := j.entriesUnlocked(); err == nil {
				// The newest pf.conf record wins.
				for _, e := range entries {
					if e.Step == StepPfConf && e.Data["path"] == p.pfConfPath {
						want = e.Data["sha256_after"]
					}
				}
			}
		}
	}
	if want == "" {
		return nil
	}
	if got := sha256Hex(current); got != want {
		return fmt.Errorf("%w: %s is now %s, we wrote %s; removed only our own block and left every foreign line untouched",
			ErrPfConfDrift, p.pfConfPath, got[:12], want[:12])
	}
	return nil
}

// backupPfConf writes a byte-exact copy of the current file into the state
// directory. The caller holds p.mu.
//
// It re-reads the real file first and refuses when the content no longer matches
// what the caller planned against. Between the read in EnsureAnchorStatements and
// this point we fork `pfctl -n -f` on a scratch copy, which takes tens of
// milliseconds — long enough for an OS updater's or a VPN's postinstall script to
// rewrite the file. Without this check the "byte-exact backup" would hold OUR
// stale read, and the third party's edit would be unrecoverable. Hosts.backupLocked
// has always guarded exactly this; pf.conf did not.
func (p *PF) backupPfConf(orig []byte, st os.FileInfo) (path, sum string, err error) {
	dir := p.backupDir()
	if dir == "" {
		return "", "", errors.New("netcfg: no StateDir configured; refusing to patch a system file without a backup")
	}
	now, _, rerr := readFileIfExists(p.pfConfPath)
	if rerr != nil {
		return "", "", fmt.Errorf("netcfg: re-read %s before backing it up: %w", p.pfConfPath, rerr)
	}
	if !bytesEqual(now, orig) {
		return "", "", fmt.Errorf("netcfg: %s changed while it was being backed up (%s -> %s); "+
			"another process is editing it, so nothing was written",
			p.pfConfPath, shortSum(orig), shortSum(now))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("netcfg: create backup dir %s: %w", dir, err)
	}
	name := fmt.Sprintf("%s.%d.bak", filepath.Base(p.pfConfPath), time.Now().UTC().UnixNano())
	path = filepath.Join(dir, name)
	if err := writeFileAtomic(path, orig, st.Mode().Perm(), nil); err != nil {
		return "", "", err
	}
	// A backup nothing ever reads back is a promise, not a safeguard: verify the
	// copy on disk hashes to the same bytes we intended to preserve.
	back, berr := os.ReadFile(path)
	if berr != nil {
		return "", "", fmt.Errorf("netcfg: re-read the backup %s: %w", path, berr)
	}
	if !bytesEqual(back, orig) {
		return "", "", fmt.Errorf("netcfg: the backup %s does not match %s byte for byte; refusing to patch",
			path, p.pfConfPath)
	}
	p.pruneBackupsLocked(dir, filepath.Base(p.pfConfPath))
	return path, sha256Hex(orig), nil
}

// shortSum is the first 12 hex characters of a SHA-256, for messages.
func shortSum(b []byte) string {
	s := sha256Hex(b)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// maxKeptBackups is how many timestamped copies of one patched system file are
// retained. Every patch (and every rollback-then-repatch cycle) writes one, and
// nothing else ever removes them.
const maxKeptBackups = 5

// pruneBackupsLocked keeps only the newest maxKeptBackups copies of prefix in dir.
// Failures are logged, never fatal: an un-pruned backup directory is untidy, a
// failed patch is not.
func (p *PF) pruneBackupsLocked(dir, prefix string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, prefix+".") || !strings.HasSuffix(n, ".bak") {
			continue
		}
		names = append(names, n)
	}
	if len(names) <= maxKeptBackups {
		return
	}
	// The names embed a zero-padded-free UnixNano, but they are all the same
	// length for any realistic timestamp, so a lexical sort is chronological.
	sort.Strings(names)
	for _, n := range names[:len(names)-maxKeptBackups] {
		if err := os.Remove(filepath.Join(dir, n)); err != nil {
			p.logf("netcfg: cannot prune old backup %s: %v", n, err)
		}
	}
}

// restorePfConf puts the original bytes back and confirms they landed.
func (p *PF) restorePfConf(orig []byte, st os.FileInfo) error {
	if err := writeFileAtomic(p.pfConfPath, orig, st.Mode().Perm(), st); err != nil {
		return err
	}
	back, err := os.ReadFile(p.pfConfPath)
	if err != nil {
		return fmt.Errorf("netcfg: re-read %s after restore: %w", p.pfConfPath, err)
	}
	if !bytesEqual(back, orig) {
		return fmt.Errorf("netcfg: %s still differs from the backup after restore", p.pfConfPath)
	}
	return nil
}

// verifyPfConf re-reads the file, byte-compares it against what we intended,
// and has pfctl parse it.
func (p *PF) verifyPfConf(want []byte) error {
	got, err := os.ReadFile(p.pfConfPath)
	if err != nil {
		return fmt.Errorf("re-read: %w", err)
	}
	if !bytesEqual(got, want) {
		return fmt.Errorf("re-read content differs from what was written (%d vs %d bytes)", len(got), len(want))
	}
	if _, _, err := p.run("", "-n", "-f", p.pfConfPath); err != nil {
		return err
	}
	return nil
}

// checkCandidate parse-checks candidate content without touching the real path,
// by writing it to a scratch file. The scratch file goes into StateDir when one
// is configured (so it is on the same trusted, root-owned filesystem) and the
// OS temp directory otherwise.
func (p *PF) checkCandidate(content []byte) error {
	dir := p.stateDir
	if dir == "" {
		dir = os.TempDir()
	} else if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, "pf.conf.candidate-*")
	if err != nil {
		return fmt.Errorf("create scratch file in %s: %w", dir, err)
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(content); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	_, _, err = p.run("", "-n", "-f", name)
	return err
}

// ReloadMain reloads the main pf configuration file so anchor statements added
// to it take effect. It is exported because `zaprctl doctor --repair` needs it
// after fixing the file by hand.
//
// Reloading the main ruleset flushes anchors that system services inserted at
// runtime; that is inherent to pf on macOS and is what /etc/pf.conf's own
// comment warns about.
func (p *PF) ReloadMain() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reloadMainLocked()
}

// reloadMainLocked implements ReloadMain. The caller holds p.mu.
func (p *PF) reloadMainLocked() error {
	if p.dryRun {
		p.logf("netcfg: dry run: would reload %s", p.pfConfPath)
		return nil
	}
	// `pfctl -f X` installs X AS the kernel's main ruleset. macOS only ever
	// boots /etc/pf.conf, so loading any other path would replace the live
	// ruleset with a file the system does not use — a way to break networking,
	// not to apply our patch. Managing a non-default path is therefore
	// patch-only by design.
	if p.pfConfPath != DefaultPfConfPath {
		p.logf("netcfg: not reloading the main ruleset: %s is not %s, so it is not what the system boots",
			p.pfConfPath, DefaultPfConfPath)
		return nil
	}
	_, stderr, err := p.run("", "-f", p.pfConfPath)
	if err != nil {
		return err
	}
	if s := strings.TrimSpace(pfctlNoise.ReplaceAllString(stderr, "")); s != "" {
		p.logf("netcfg: reload %s: %s", p.pfConfPath, s)
	}
	p.logf("netcfg: reloaded %s", p.pfConfPath)
	return nil
}

// ---------------------------------------------------------------------------
// enable / release
// ---------------------------------------------------------------------------

// pfTokenRe matches the reference token `pfctl -E` prints.
var pfTokenRe = regexp.MustCompile(`(?m)^\s*Token\s*:\s*(\d+)\s*$`)

// tokenPath is where the live token is persisted.
func (p *PF) tokenPath() string {
	if p.stateDir == "" {
		return ""
	}
	return filepath.Join(p.stateDir, PfTokenName)
}

// Enable takes a reference on pf with `pfctl -E` and persists the token it
// returns.
//
// `pfctl -E` enables pf and increments a kernel reference count; `pfctl -X
// <token>` drops one reference and only actually disables pf when the last one
// goes away. That is why this package never calls `pfctl -e` or `pfctl -d`:
// either would fight with any other component that needs pf.
//
// If a token from a previous run is still on disk it is released first, so a
// crashed daemon does not leak references across restarts.
func (p *PF) Enable() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.token != "" {
		return nil
	}
	if p.dryRun {
		p.logf("netcfg: dry run: would run pfctl -E")
		return nil
	}

	// A token left behind by a crashed daemon is ours to release.
	if stale := p.readTokenFileLocked(); stale != "" {
		p.logf("netcfg: releasing stale pf token %s from a previous run", stale)
		if _, _, err := p.run("", "-X", stale); err != nil {
			p.logf("netcfg: releasing stale pf token %s failed (it may already be gone): %v", stale, err)
		}
		p.clearTokenFileLocked()
	}

	stdout, stderr, err := p.run("", "-E")
	if err != nil {
		return err
	}
	m := pfTokenRe.FindStringSubmatch(stdout + "\n" + stderr)
	if m == nil {
		// pf is enabled but we have no handle to release. Report it rather
		// than silently leaking a reference for the rest of uptime.
		return fmt.Errorf("netcfg: pfctl -E printed no token; refusing to continue with an unreleasable pf reference (output: %q / %q)",
			strings.TrimSpace(stdout), strings.TrimSpace(stderr))
	}
	p.token = m[1]
	p.recordLocked(StepPfToken, map[string]string{"token": p.token})
	if err := p.writeTokenFileLocked(p.token); err != nil {
		// A pf reference we cannot record is a change the journal contract forbids:
		// a SIGKILL would then lose the token and keep pf enabled for the rest of
		// uptime with nobody able to release it. Release it again and fail.
		if _, _, rerr := p.run("", "-X", p.token); rerr != nil {
			p.logf("netcfg: could not release token %s after failing to persist it: %v", p.token, rerr)
		}
		token := p.token
		p.token = ""
		return fmt.Errorf("netcfg: pf was enabled (token %s) but the token could not be persisted to %s: %w; "+
			"the reference has been released again, because an unrecordable change to pf is exactly what "+
			"the rollback journal exists to prevent", token, p.tokenPath(), err)
	}
	p.logf("netcfg: pf enabled, token %s", p.token)
	return nil
}

// Release drops the pf reference taken by Enable. It is safe to call twice and
// safe to call after a crash: the token is read back from the state directory
// when this process never called Enable.
func (p *PF) Release() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	token := p.token
	if token == "" {
		token = p.readTokenFileLocked()
	}
	if token == "" {
		return nil
	}
	if p.dryRun {
		p.logf("netcfg: dry run: would run pfctl -X %s", token)
		return nil
	}
	wasEnabledBefore := p.lastPreflight.PfEnabledKnown && p.lastPreflight.PfEnabled
	if _, _, err := p.run("", "-X", token); err != nil {
		// Keep the token on disk so a later repair run can retry: a
		// reference we cannot account for keeps pf enabled forever.
		return fmt.Errorf("netcfg: releasing pf token %s failed: %w", token, err)
	}
	p.token = ""
	p.clearTokenFileLocked()
	p.logf("netcfg: released pf token %s", token)
	// `pfctl -e` does NOT take a reference. If another component enabled pf that
	// way, our -E made the count 1 and our -X just took it to 0, stopping pf and
	// silently un-enforcing that component's rules. We must not re-enable pf
	// behind the operator's back, but they have to be told.
	if wasEnabledBefore {
		if on, err := p.Enabled(); err == nil && !on {
			p.logf("netcfg: WARNING: pf was enabled before we started and is DISABLED now. "+
				"Another component had enabled it with `pfctl -e`, which takes no reference, so our "+
				"`pfctl -X %s` dropped the last one. Its firewall rules are no longer enforced — "+
				"re-enable pf with `sudo pfctl -E` (or restart that component).", token)
		}
	}
	return nil
}

// Token returns the live pf reference token, or "" when none is held.
func (p *PF) Token() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.token != "" {
		return p.token
	}
	return p.readTokenFileLocked()
}

// readTokenFileLocked reads the persisted token, "" when absent or malformed.
func (p *PF) readTokenFileLocked() string {
	path := p.tokenPath()
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	t := strings.TrimSpace(string(b))
	for _, c := range t {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return t
}

// writeTokenFileLocked persists the token with an fsync, so it survives the
// SIGKILL that makes it matter.
func (p *PF) writeTokenFileLocked(token string) error {
	path := p.tokenPath()
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(token+"\n"), 0o600, nil)
}

// pfConfSumPath is where the hash of our last pf.conf write is kept.
func (p *PF) pfConfSumPath() string {
	if p.stateDir == "" {
		return ""
	}
	return filepath.Join(p.stateDir, PfConfSumName)
}

// readPfConfSumLocked returns the recorded hash of our last pf.conf write, "" when
// there is none or it is not a hex digest for this path. The caller holds p.mu.
func (p *PF) readPfConfSumLocked() string {
	path := p.pfConfSumPath()
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// Format: "<sha256hex> <path>\n". The path is stored so a --pf-conf override
	// cannot be compared against the hash of a different file.
	fields := strings.Fields(strings.TrimSpace(string(b)))
	if len(fields) < 2 || len(fields[0]) != 64 || strings.Join(fields[1:], " ") != p.pfConfPath {
		return ""
	}
	for _, c := range fields[0] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return ""
		}
	}
	return fields[0]
}

// writePfConfSumLocked records the hash of what we just wrote. A failure is logged
// and not fatal: it only degrades the drift report. The caller holds p.mu.
func (p *PF) writePfConfSumLocked(sum string) {
	path := p.pfConfSumPath()
	if path == "" || p.dryRun {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		p.logf("netcfg: cannot record the pf.conf hash: %v", err)
		return
	}
	if err := writeFileAtomic(path, []byte(sum+" "+p.pfConfPath+"\n"), 0o600, nil); err != nil {
		p.logf("netcfg: cannot record the pf.conf hash: %v", err)
	}
}

// clearTokenFileLocked removes the persisted token.
func (p *PF) clearTokenFileLocked() {
	if path := p.tokenPath(); path != "" {
		_ = os.Remove(path)
	}
}

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------

// LoadRules installs rules into our anchor.
//
// The ruleset is dry-run first with `pfctl -a <anchor> -n -f -`; only if that
// succeeds is it loaded with `pfctl -a <anchor> -f -`. A pf syntax error is
// returned as a *PfctlError carrying pfctl's stderr verbatim, because that
// message is the only actionable diagnostic there is.
func (p *PF) LoadRules(rules string) error {
	if err := p.validateAnchor(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, _, err := p.run(rules, "-a", p.effAnchorLocked(), "-n", "-f", "-"); err != nil {
		return fmt.Errorf("netcfg: ruleset for anchor %q does not parse: %w", p.anchor, err)
	}
	if p.dryRun {
		p.logf("netcfg: dry run: ruleset for anchor %q parses (%d line(s)), not loading",
			p.anchor, countLines(rules))
		return nil
	}
	if _, stderr, err := p.run(rules, "-a", p.effAnchorLocked(), "-f", "-"); err != nil {
		return fmt.Errorf("netcfg: loading ruleset into anchor %q failed: %w", p.anchor, err)
	} else if s := strings.TrimSpace(pfctlNoise.ReplaceAllString(stderr, "")); s != "" {
		p.logf("netcfg: pfctl warning while loading anchor %q: %s", p.anchor, s)
	}

	p.recordLocked(StepPfRules, map[string]string{
		"anchor": p.anchor,
		"sha256": sha256Hex([]byte(rules)),
	})

	// Snapshot pf's own rendering of what it now holds: that, not our
	// submitted text, is what Verify has to compare against later.
	p.baseFilter, _ = p.showLocked("rules")
	p.baseNat, _ = p.showLocked("nat")
	p.haveBase = true
	p.logf("netcfg: loaded %d rule line(s) into anchor %q", countLines(rules), p.anchor)
	return nil
}

// FlushRules removes everything from our anchor with `pfctl -a <anchor> -F all`.
// That includes the anchor's tables, which is what shutdown wants; use
// TableFlush if only a table should be emptied.
func (p *PF) FlushRules() error {
	if err := p.validateAnchor(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dryRun {
		p.logf("netcfg: dry run: would run pfctl -a %s -F all", p.anchor)
		return nil
	}
	if _, _, err := p.run("", "-a", p.effAnchorLocked(), "-F", "all"); err != nil {
		return fmt.Errorf("netcfg: flushing anchor %q failed: %w", p.anchor, err)
	}
	p.baseFilter, p.baseNat, p.haveBase = "", "", false
	p.logf("netcfg: flushed anchor %q", p.anchor)
	return nil
}

// Rules returns the filter rules currently in our anchor
// (`pfctl -a <anchor> -s rules`).
func (p *PF) Rules() (string, error) {
	if err := p.validateAnchor(); err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.showLocked("rules")
}

// NatRules returns the translation rules currently in our anchor
// (`pfctl -a <anchor> -s nat`). rdr rules do not show up under -s rules, so
// Verify needs both views.
func (p *PF) NatRules() (string, error) {
	if err := p.validateAnchor(); err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.showLocked("nat")
}

// showLocked runs `pfctl -a <anchor> -s <what>`. The caller holds p.mu.
func (p *PF) showLocked(what string) (string, error) {
	out, _, err := p.run("", "-a", p.effAnchorLocked(), "-s", what)
	if err != nil {
		return "", err
	}
	return normaliseRuleText(out), nil
}

// Enabled reports whether pf is currently enabled (`pfctl -s info`).
func (p *PF) Enabled() (bool, error) {
	stdout, stderr, err := p.run("", "-s", "info")
	if err != nil {
		return false, err
	}
	return strings.Contains(stdout, "Status: Enabled") || strings.Contains(stderr, "Status: Enabled"), nil
}

// Verify re-reads our anchor and reports drift. The daemon calls it
// periodically because anything that runs `pfctl -f /etc/pf.conf` — a macOS
// update, a VPN client, Internet Sharing — silently wipes both our anchor
// statements and the rules inside the anchor.
//
// It checks, in order: pf is still enabled, the main ruleset still names our
// anchor, and the anchor still holds exactly the rules LoadRules installed.
// The returned error wraps ErrPfDisabled, ErrAnchorUnreferenced or
// ErrRulesDrift so the caller can decide whether to re-apply.
func (p *PF) Verify() error {
	if err := p.validateAnchor(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.dryRun {
		return nil
	}

	var errs []error

	if on, err := p.Enabled(); err != nil {
		errs = append(errs, fmt.Errorf("netcfg: cannot query pf status: %w", err))
	} else if !on {
		errs = append(errs, ErrPfDisabled)
	}

	// How the anchor is reached decides what "still referenced" means. In
	// wildcard mode /etc/pf.conf is irrelevant: what must still hold is that the
	// wildcard anchor point covering our sub-anchor is present in the LIVE
	// ruleset, because a `pfctl -f /etc/pf.conf` by an OS update or a VPN
	// re-creates it while flushing what it contained.
	if p.mode == AnchorModeWildcard {
		sub := p.effAnchorLocked()
		filterRules, _, ferr := p.run("", "-s", "rules")
		natRules, _, nerr := p.run("", "-s", "nat")
		switch {
		case ferr != nil || nerr != nil:
			errs = append(errs, fmt.Errorf("netcfg: cannot read the main ruleset to verify the anchor point"))
		case !WildcardAnchorCovers(filterRules, sub) || !WildcardAnchorCovers(natRules, sub):
			errs = append(errs, fmt.Errorf("%w: no wildcard anchor point covering %q is loaded",
				ErrAnchorUnreferenced, sub))
		}
	} else if conf, ok, err := readFileIfExists(p.pfConfPath); err != nil {
		errs = append(errs, fmt.Errorf("netcfg: read %s: %w", p.pfConfPath, err))
	} else if !ok || !AnchorStatementsPresent(conf, p.anchor) {
		errs = append(errs, fmt.Errorf("%w: %s no longer contains both statements for %q",
			ErrAnchorUnreferenced, p.pfConfPath, p.anchor))
	}

	if p.haveBase {
		nowFilter, ferr := p.showLocked("rules")
		nowNat, nerr := p.showLocked("nat")
		switch {
		case ferr != nil:
			errs = append(errs, fmt.Errorf("netcfg: reading anchor %q filter rules: %w", p.anchor, ferr))
		case nerr != nil:
			errs = append(errs, fmt.Errorf("netcfg: reading anchor %q translation rules: %w", p.anchor, nerr))
		case nowFilter != p.baseFilter:
			errs = append(errs, fmt.Errorf("%w: anchor %q filter rules changed\n--- loaded ---\n%s\n--- now ---\n%s",
				ErrRulesDrift, p.anchor, p.baseFilter, nowFilter))
		case nowNat != p.baseNat:
			errs = append(errs, fmt.Errorf("%w: anchor %q translation rules changed\n--- loaded ---\n%s\n--- now ---\n%s",
				ErrRulesDrift, p.anchor, p.baseNat, nowNat))
		}
	}
	return errors.Join(errs...)
}

// normaliseRuleText trims trailing whitespace from each line and drops blank
// lines, so two `pfctl -s` snapshots of identical rulesets compare equal.
func normaliseRuleText(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimRight(line, " \t\r")
		if strings.TrimSpace(t) == "" {
			continue
		}
		out = append(out, t)
	}
	return strings.Join(out, "\n")
}

// countLines counts non-empty lines, for log messages.
func countLines(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// Close releases everything this PF still owns: the pf reference and the
// journal handle. It does not flush the anchor or unpatch the main ruleset —
// those are separate, explicit decisions.
func (p *PF) Close() error {
	err := p.Release()
	p.mu.Lock()
	j := p.journal
	p.journal = nil
	p.mu.Unlock()
	if j != nil {
		if cerr := j.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}
