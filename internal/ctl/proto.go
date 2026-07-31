// Package ctl is the control plane between the root daemon (zapretd) and the
// user-facing CLI (zaprctl): a JSON-lines RPC over a unix socket.
//
// The wire format is deliberately the simplest thing that cannot desynchronise:
// one JSON object per line, request then response, newline as the frame
// delimiter. There is no length prefix, so both sides cap the line length and
// both sides set deadlines — a control socket that can block forever is a
// control socket that can wedge a daemon.
//
// The socket lives at DefaultSocketPath, owned by root, group admin, mode 0660,
// so a member of the admin group (i.e. the machine's own administrator) can ask
// for status or switch strategy without sudo, while everybody else gets EACCES
// from the kernel before a single byte is parsed.
//
// Every payload type in this file is a plain DTO: this package imports nothing
// from the datapath, so the JSON shape stays stable no matter how the transports
// or the desync engine are refactored. The daemon converts its internal state
// into these structs; zaprctl renders them.
package ctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// DefaultSocketPath is the control socket. /var/run is root-owned on macOS, so
// the path itself cannot be hijacked by an unprivileged user.
const DefaultSocketPath = "/var/run/zapret-mac.sock"

// SocketGroup is the group given rw access to the socket. On every macOS
// install "admin" is gid 80 and contains the first (administrator) account,
// which is exactly the audience allowed to flip strategies.
const SocketGroup = "admin"

// SocketGroupGID is the fallback gid used when the group database cannot be
// read. "admin" is gid 80 on every macOS release.
const SocketGroupGID = 80

// SocketMode is the socket's permission bits: rw for owner (root) and for the
// admin group, nothing for anybody else.
const SocketMode = 0o660

// MaxLine is the largest request or response line accepted, in bytes. A status
// response with a long warning list is a few kilobytes; a megabyte means either
// a bug or somebody probing the socket, and either way the connection is
// answered with an error and closed rather than buffered.
const MaxLine = 1 << 20

// DefaultTimeout bounds a single request/response exchange.
const DefaultTimeout = 15 * time.Second

// SelftestTimeout bounds the selftest command, which makes real network
// connections and therefore needs more room than DefaultTimeout.
const SelftestTimeout = 90 * time.Second

// Command names. They are the only strings the two binaries have to agree on.
const (
	CmdStatus      = "status"
	CmdStart       = "start"
	CmdStop        = "stop"
	CmdReload      = "reload"
	CmdUse         = "use"
	CmdList        = "list"
	CmdStats       = "stats"
	CmdCaps        = "caps"
	CmdDoctor      = "doctor"
	CmdSelftest    = "selftest"
	CmdHostsApply  = "hosts-apply"
	CmdHostsRemove = "hosts-remove"
	CmdIPSet       = "ipset"
	CmdVPN         = "vpn"
	CmdLogtail     = "logtail"
	CmdVersion     = "version"
)

// Commands lists every command the server dispatches, in help order.
var Commands = []string{
	CmdStatus, CmdStart, CmdStop, CmdReload, CmdUse, CmdList, CmdStats,
	CmdCaps, CmdDoctor, CmdSelftest, CmdHostsApply, CmdHostsRemove,
	CmdIPSet, CmdVPN, CmdLogtail, CmdVersion,
}

// VPNData is the payload of the "vpn" command: what VPN software is present,
// what currently holds a tunnel default route (the thing that blocks the packet
// datapath), and — after a stop — what was done and how to undo it.
type VPNData struct {
	Providers      []VPNProvider `json:"providers"`
	TunnelDefaults []string      `json:"tunnel_defaults"`
	Unattributed   []string      `json:"unattributed,omitempty"`
	Blocking       bool          `json:"blocking"`
	Actions        []string      `json:"actions,omitempty"`
	Restore        []string      `json:"restore,omitempty"`
}

// VPNProvider is one detected VPN product.
type VPNProvider struct {
	Name       string   `json:"name"`
	Jobs       []string `json:"jobs,omitempty"`
	PIDs       []int    `json:"pids,omitempty"`
	AppRunning bool     `json:"app_running"`
}

// Request is one command invocation. Args is a flat string map so the wire
// format never has to change when a command grows an option.
type Request struct {
	Cmd  string            `json:"cmd"`
	Args map[string]string `json:"args,omitempty"`
}

// Arg returns the named argument, or "" when it is absent.
func (r Request) Arg(name string) string {
	if r.Args == nil {
		return ""
	}
	return r.Args[name]
}

// Bool reports whether the named argument is a true-ish flag ("1", "true",
// "yes", "on"). Anything else, including absence, is false.
func (r Request) Bool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(r.Arg(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Response is one reply. Exactly one of Error / Data is meaningful.
//
// More is set on every chunk of a streaming reply except the last, so a client
// knows whether to keep reading without relying on the connection closing.
type Response struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
	More  bool            `json:"more,omitempty"`
}

// Err returns the response's error as a Go error, or nil when OK.
func (r Response) Err() error {
	if r.OK {
		return nil
	}
	if r.Error == "" {
		return errors.New("ctl: request failed without a reason")
	}
	return errors.New(r.Error)
}

// Decode unmarshals the response payload into v.
func (r Response) Decode(v any) error {
	if len(r.Data) == 0 {
		return fmt.Errorf("ctl: response carries no data")
	}
	if err := json.Unmarshal(r.Data, v); err != nil {
		return fmt.Errorf("ctl: cannot decode response payload: %w", err)
	}
	return nil
}

// newResponse marshals v into a successful response.
func newResponse(v any) Response {
	if v == nil {
		return Response{OK: true}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return Response{OK: false, Error: fmt.Sprintf("ctl: cannot encode response payload: %v", err)}
	}
	return Response{OK: true, Data: b}
}

// errResponse builds a failed response.
func errResponse(err error) Response {
	if err == nil {
		return Response{OK: false, Error: "ctl: unspecified error"}
	}
	return Response{OK: false, Error: err.Error()}
}

// ---------------------------------------------------------------------------
// payload types
// ---------------------------------------------------------------------------

// VersionData answers CmdVersion.
type VersionData struct {
	Version string `json:"version"`
	Go      string `json:"go,omitempty"`
	PID     int    `json:"pid"`
	// Started is when the daemon process began, RFC3339.
	Started string `json:"started,omitempty"`
	// Binary is the daemon executable path, so `zaprctl version` can tell a
	// stale /usr/local/libexec copy from the one just built.
	Binary string `json:"binary,omitempty"`
}

// StatsData mirrors transport.Stats plus the engine's own counters. Every field
// is a monotone counter except FlowsActive.
type StatsData struct {
	Transport   string `json:"transport"`
	FlowsActive int64  `json:"flows_active"`
	FlowsTotal  int64  `json:"flows_total"`
	PktsIn      int64  `json:"pkts_in"`
	PktsOut     int64  `json:"pkts_out"`
	PktsInject  int64  `json:"pkts_inject"`
	PktsDropped int64  `json:"pkts_dropped"`
	BytesIn     int64  `json:"bytes_in"`
	BytesOut    int64  `json:"bytes_out"`
	Matched     int64  `json:"matched"`
	Desyncs     int64  `json:"desyncs"`
	Degraded    int64  `json:"degraded"`
	Errors      int64  `json:"errors"`
	QueueDrop   int64  `json:"queue_drop"`
	// Restarts counts how often the supervisor had to restart the datapath.
	Restarts int64 `json:"restarts"`
}

// CapsData is the capability matrix of the running transport, together with the
// consequences for the active strategy.
//
// Unsupported is the whole point of reporting caps to a human: a user must never
// believe a fake-based strategy is active when the transport cannot inject a
// single packet.
type CapsData struct {
	Transport    string   `json:"transport"`
	Reason       string   `json:"reason,omitempty"`
	Strategy     string   `json:"strategy,omitempty"`
	Inject       bool     `json:"inject"`
	Seq          bool     `json:"seq"`
	DropOriginal bool     `json:"drop_original"`
	PerPacketTTL bool     `json:"per_packet_ttl"`
	Fooling      bool     `json:"fooling"`
	IPID         bool     `json:"ip_id"`
	UDP          bool     `json:"udp"`
	IPv6ExtHdr   bool     `json:"ipv6_exthdr"`
	Frag         bool     `json:"frag"`
	Segment      bool     `json:"segment"`
	TLSRec       bool     `json:"tlsrec"`
	Unsupported  []string `json:"unsupported,omitempty"`
}

// CapsRow is one line of the rendered capability matrix.
type CapsRow struct {
	Name string `json:"name"`
	Have bool   `json:"have"`
	What string `json:"what"`
}

// Rows renders the matrix in a fixed order with a plain-language explanation of
// what each capability buys, so `zaprctl caps` is readable without the source.
func (c CapsData) Rows() []CapsRow {
	return []CapsRow{
		{"inject", c.Inject, "put synthetic packets on the wire (fake, rst, syndata)"},
		{"seq", c.Seq, "choose TCP sequence numbers (seqovl, overlapping splits)"},
		{"drop-original", c.DropOriginal, "suppress the application's own packet"},
		{"per-packet-ttl", c.PerPacketTTL, "set TTL per packet instead of per socket"},
		{"fooling", c.Fooling, "own the TCP/IP header: badsum, badseq, md5sig, ts"},
		{"ip-id", c.IPID, "choose the IPv4 identification field"},
		{"udp", c.UDP, "see UDP at all (QUIC, Discord voice, STUN)"},
		{"ipv6-exthdr", c.IPv6ExtHdr, "add hop-by-hop / destination-option headers"},
		{"frag", c.Frag, "emit IP fragments"},
		{"segment", c.Segment, "control payload segmentation"},
		{"tlsrec", c.TLSRec, "rewrite the TLS record layer"},
	}
}

// PFData is the pf-side view `zaprctl status` prints.
type PFData struct {
	Anchor           string `json:"anchor"`
	Enabled          bool   `json:"enabled"`
	AnchorReferenced bool   `json:"anchor_referenced"`
	Token            string `json:"token,omitempty"`
	RuleLines        int    `json:"rule_lines"`
	// Drift is empty when the ruleset is exactly what we loaded; otherwise it
	// is the reason Verify gave.
	Drift string `json:"drift,omitempty"`
	// LastVerify is when the drift watcher last ran, RFC3339.
	LastVerify string `json:"last_verify,omitempty"`
}

// StatusData answers CmdStatus: everything a human needs in one screen.
type StatusData struct {
	Version string `json:"version"`
	PID     int    `json:"pid"`
	// Running reports whether the datapath (not the process) is active.
	Running           bool     `json:"running"`
	Transport         string   `json:"transport"`
	TransportReason   string   `json:"transport_reason,omitempty"`
	Strategy          string   `json:"strategy"`
	StrategyPath      string   `json:"strategy_path,omitempty"`
	Profiles          int      `json:"profiles"`
	WindowTCP         []string `json:"window_tcp,omitempty"`
	WindowUDP         []string `json:"window_udp,omitempty"`
	UptimeSec         float64  `json:"uptime_sec"`
	DatapathUptimeSec float64  `json:"datapath_uptime_sec"`
	Caps              CapsData `json:"caps"`
	// Unsupported repeats Caps.Unsupported at the top level because it is the
	// single most important warning in the output.
	Unsupported []string  `json:"unsupported,omitempty"`
	Stats       StatsData `json:"stats"`
	PF          PFData    `json:"pf"`
	// IPSet is flowseal's tri-state switch: loaded|none|any|unknown.
	IPSet string `json:"ipset"`
	// HostsEntries is how many /etc/hosts pins our block currently holds.
	HostsEntries int      `json:"hosts_entries"`
	BlockQUIC    bool     `json:"block_quic"`
	LogPath      string   `json:"log_path,omitempty"`
	DataDir      string   `json:"data_dir,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

// StrategyInfo is one row of CmdList.
type StrategyInfo struct {
	Name        string   `json:"name"`
	Path        string   `json:"path,omitempty"`
	Description string   `json:"description,omitempty"`
	Summary     string   `json:"summary"`
	Profiles    int      `json:"profiles"`
	Ops         []string `json:"ops,omitempty"`
	// Unsupported names the ops the ACTIVE transport cannot honour.
	Unsupported []string `json:"unsupported,omitempty"`
	Active      bool     `json:"active"`
}

// ListData answers CmdList.
type ListData struct {
	Active     string         `json:"active,omitempty"`
	Transport  string         `json:"transport,omitempty"`
	Dir        string         `json:"dir,omitempty"`
	Strategies []StrategyInfo `json:"strategies"`
}

// UseData answers CmdUse.
type UseData struct {
	Strategy    string   `json:"strategy"`
	Path        string   `json:"path,omitempty"`
	Restarted   bool     `json:"restarted"`
	Unsupported []string `json:"unsupported,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

// Severity levels for a Check.
const (
	SevInfo  = "info"
	SevWarn  = "warn"
	SevError = "error"
)

// Check is one diagnostic finding.
type Check struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Severity string `json:"severity"`
	Detail   string `json:"detail,omitempty"`
	// Fix is the exact command or action that resolves the finding.
	Fix string `json:"fix,omitempty"`
}

// DoctorData answers CmdDoctor.
type DoctorData struct {
	Version       string   `json:"version"`
	UID           int      `json:"uid"`
	Root          bool     `json:"root"`
	DaemonRunning bool     `json:"daemon_running"`
	Transport     string   `json:"transport,omitempty"`
	Checks        []Check  `json:"checks"`
	Repaired      []string `json:"repaired,omitempty"`
	JournalPath   string   `json:"journal_path,omitempty"`
	// JournalPending is the number of unreverted journal records.
	JournalPending int `json:"journal_pending"`
}

// Problems counts checks that failed.
func (d DoctorData) Problems() (errs, warns int) {
	for _, c := range d.Checks {
		if c.OK {
			continue
		}
		switch c.Severity {
		case SevError:
			errs++
		default:
			warns++
		}
	}
	return errs, warns
}

// TestTarget is one row of the connectivity self-test.
type TestTarget struct {
	Target string `json:"target"`
	SNI    string `json:"sni,omitempty"`
	OK     bool   `json:"ok"`
	MS     int64  `json:"ms"`
	Detail string `json:"detail,omitempty"`
	// Desynced reports whether the daemon saw the flow match a profile and
	// fire, which is what distinguishes "the site loads" from "we did anything".
	Desynced bool `json:"desynced"`
}

// SelftestData answers CmdSelftest.
type SelftestData struct {
	Strategy  string       `json:"strategy,omitempty"`
	Transport string       `json:"transport,omitempty"`
	OK        bool         `json:"ok"`
	Targets   []TestTarget `json:"targets"`
	Warnings  []string     `json:"warnings,omitempty"`
}

// HostsData answers CmdHostsApply / CmdHostsRemove.
type HostsData struct {
	Path       string `json:"path"`
	SourcePath string `json:"source_path,omitempty"`
	Applied    bool   `json:"applied"`
	Entries    int    `json:"entries"`
	Names      int    `json:"names"`
	DNSFlushed bool   `json:"dns_flushed"`
	// Warnings carries anything the operation could not do silently: unparseable
	// lines in the source file, a DNS cache that could not be flushed, or the
	// fact that a dry run wrote nothing at all.
	Warnings []string `json:"warnings,omitempty"`
}

// IPSet modes, flowseal's tri-state switch.
const (
	// IPSetLoaded means the real ipset-all.txt is in place: only the listed
	// destinations are desynced.
	IPSetLoaded = "loaded"
	// IPSetNone means the list holds only the documentation sentinel
	// 203.0.113.113/32, so ipset-gated profiles never match.
	IPSetNone = "none"
	// IPSetAny means the list is empty, which zapret reads as "no ipset
	// restriction": every destination is eligible.
	IPSetAny = "any"
	// IPSetUnknown is reported when the list file cannot be read.
	IPSetUnknown = "unknown"
)

// IPSetSentinel is the RFC 5737 documentation address flowseal writes into
// ipset-all.txt to express "match nothing".
const IPSetSentinel = "203.0.113.113/32"

// IPSetData answers CmdIPSet.
type IPSetData struct {
	Mode string `json:"mode"`
	// Previous is the mode before the switch, empty when only queried.
	Previous string `json:"previous,omitempty"`
	Path     string `json:"path"`
	Entries  int    `json:"entries"`
	Backup   bool   `json:"backup_present"`
	Reloaded bool   `json:"reloaded"`
}

// LogChunk is one streamed piece of CmdLogtail.
type LogChunk struct {
	Lines []string `json:"lines"`
}

// ---------------------------------------------------------------------------
// helpers shared by both binaries
// ---------------------------------------------------------------------------

// SortedUnique returns v sorted with duplicates removed. Used for warning and
// op lists so the JSON output of two runs compares equal.
func SortedUnique(v []string) []string {
	if len(v) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(v))
	out := make([]string, 0, len(v))
	for _, s := range v {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// FormatDuration renders a duration the way the CLI prints uptimes: "3d4h12m",
// "12m07s", "8.4s". Go's own String() prints "1h0m0s" and microseconds, which
// is noise in a status table.
func FormatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		days := int(d.Hours()) / 24
		return fmt.Sprintf("%dd%02dh%02dm", days, int(d.Hours())%24, int(d.Minutes())%60)
	}
}
