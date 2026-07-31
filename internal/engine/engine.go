// Package engine ties strategy profiles, flow state and the desync ops
// together. It is transport-agnostic: both the packet-level (divert) and the
// socket-level (proxy) datapaths call into it.
//
// This file is the authoritative semantics of profile selection, flow
// accounting, start/cutoff counters and autottl. It mirrors nfqws' behaviour:
//
//   - profiles are tried in order, first match wins (winws' --new chain);
//   - a flow's profile is decided once the L7 host is known, then cached;
//   - --dpi-desync-start / -cutoff gate on packet number ('n'), data-packet
//     number ('d') or relative sequence ('s');
//   - autottl derives the fake TTL from the hop count inferred from an inbound
//     packet's TTL, clamped to [min,max].
package engine

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/lists"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// ErrNoProfile means no profile matched; the caller must forward untouched.
var ErrNoProfile = errors.New("no profile matched")

// flowTTL is how long an idle flow entry is kept.
const flowTTL = 2 * time.Minute

// Flow-table bounds. The soft cap triggers an opportunistic sweep of idle
// entries; the hard cap is a real ceiling enforced by evicting the
// least-recently-seen entries, because a burst of thousands of *fresh* flows
// (a wide UDP window plus peer churn, where there is no FIN to Forget on)
// frees nothing in a TTL-based sweep. sweepMinInterval keeps the O(n) scan from
// running on every single insertion once the table sits above the soft cap.
const (
	flowSoftCap       = 4096
	flowHardCap       = 8192
	sweepMinInterval  = 250 * time.Millisecond
	hardCapKeepFactor = 8 // evict down to hardCap*7/8 so the next insert is cheap
)

// Engine is safe for concurrent use. Two locks and one per-flow lock:
//
//	mu       guards strat/caps/fakes/gen and the auto-hostlist registry;
//	flowsMu  guards the flow map itself (lookup, insert, eviction);
//	flowEntry.mu guards one flow's desync.Flow for the whole duration of a
//	         handler call, which is what gives the datapath and the inbound tap
//	         a happens-before edge on every field of Flow (Hops in particular).
//
// Statistics are atomics rather than plain fields: the proxy transport runs one
// goroutine per accepted connection, so read-modify-write on a shared int64
// would both race and lose increments.
type Engine struct {
	mu    sync.RWMutex
	strat *strategy.Strategy
	// gen is bumped by Reload. A flow's cached profile index is only meaningful
	// for the generation it was decided in: after a strategy swap the same index
	// can name a completely different profile, so the decision is remade.
	gen   uint64
	caps  desync.Caps
	fakes desync.FakeSet

	flowsMu   sync.Mutex
	flows     map[desync.FlowKey]*flowEntry
	lastSweep time.Time

	auto map[string]*lists.AutoList

	cnt counters
}

// counters is the engine's internal, race-free statistics block.
type counters struct {
	matched    atomic.Int64
	desyncs    atomic.Int64
	degraded   atomic.Int64
	errs       atomic.Int64
	flowsTotal atomic.Int64
}

// Counters are engine-level statistics, read by transports for Stats(). It is a
// plain snapshot value: obtain one with Engine.Counters().
type Counters struct {
	Matched    int64
	Desyncs    int64
	Degraded   int64
	Errors     int64
	FlowsTotal int64
}

// Counters returns a consistent-enough snapshot of the engine's statistics.
// Each field is read atomically; the five reads are not one atomic operation,
// which is fine for a statistics display and is why nothing derives control
// flow from them.
func (e *Engine) Counters() Counters {
	return Counters{
		Matched:    e.cnt.matched.Load(),
		Desyncs:    e.cnt.desyncs.Load(),
		Degraded:   e.cnt.degraded.Load(),
		Errors:     e.cnt.errs.Load(),
		FlowsTotal: e.cnt.flowsTotal.Load(),
	}
}

// flowEntry is one tracked flow plus the bookkeeping the engine keeps outside
// the transport-visible desync.Flow.
type flowEntry struct {
	// mu guards f. It is held for the whole of OnTCP/OnUDP/PlanStream/OnInbound.
	mu   sync.Mutex
	f    desync.Flow
	seen time.Time // guarded by Engine.flowsMu
	// gen is the strategy generation f.ProfileIdx was decided against.
	gen uint64
	// monitorAuto is the --hostlist-auto file of a profile that would match this
	// flow if its hostname were on that list. It is set when no profile matched
	// but such a candidate exists: nfqws then desyncs nothing and merely watches
	// for the signature of blocking, which is what makes the list self-learning.
	monitorAuto string
}

// New builds an engine for a compiled strategy and a transport's capabilities.
func New(s *strategy.Strategy, caps desync.Caps, fakes desync.FakeSet) *Engine {
	return &Engine{
		strat: s,
		gen:   1,
		caps:  caps,
		fakes: fakes,
		flows: make(map[desync.FlowKey]*flowEntry, 512),
		auto:  make(map[string]*lists.AutoList),
	}
}

// Reload swaps the strategy.
//
// Every existing flow re-runs profile selection on its next packet. Keeping the
// cached index would be actively dangerous: the index was assigned against the
// previous profile list, and after a swap the same slot can hold an unrelated
// profile (a TCP flow executing a `block` op meant for UDP, for instance), so a
// live connection would be broken by a `zaprctl use`.
func (e *Engine) Reload(s *strategy.Strategy) {
	e.mu.Lock()
	e.strat = s
	e.gen++
	e.mu.Unlock()
}

// Strategy returns the active compiled strategy.
func (e *Engine) Strategy() *strategy.Strategy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.strat
}

// Caps reports the transport capabilities the engine was built with.
func (e *Engine) Caps() desync.Caps { return e.caps }

// SetAutoList registers a self-learning hostlist under the path the compiled
// filter names (strategy.Filter.AutoHostlist, i.e. already resolved against the
// lists directory). Profiles carrying that path then treat the list as an extra
// inclusion hostlist, and the engine feeds client retransmissions into it.
func (e *Engine) SetAutoList(path string, al *lists.AutoList) {
	e.mu.Lock()
	e.auto[path] = al
	e.mu.Unlock()
}

// autoList looks up a registered self-learning hostlist.
func (e *Engine) autoList(path string) *lists.AutoList {
	if path == "" {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.auto[path]
}

// FlushAutoLists persists every registered self-learning hostlist. The daemon
// calls it periodically and at shutdown; a list with nothing new to write does
// no I/O.
func (e *Engine) FlushAutoLists() error {
	e.mu.RLock()
	all := make([]*lists.AutoList, 0, len(e.auto))
	for _, al := range e.auto {
		all = append(all, al)
	}
	e.mu.RUnlock()
	var errs []error
	for _, al := range all {
		if err := al.Flush(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// FlowCount reports the number of tracked flows.
func (e *Engine) FlowCount() int {
	e.flowsMu.Lock()
	defer e.flowsMu.Unlock()
	return len(e.flows)
}

// flow returns the tracked entry for key, creating it if needed. The returned
// entry's mu is NOT held; every caller takes it before touching entry.f.
func (e *Engine) flow(key desync.FlowKey) *flowEntry {
	now := time.Now()
	e.flowsMu.Lock()
	defer e.flowsMu.Unlock()
	fe, ok := e.flows[key]
	if !ok {
		fe = &flowEntry{f: desync.Flow{Key: key, ProfileIdx: -1}}
		e.flows[key] = fe
		e.cnt.flowsTotal.Add(1)
	}
	// Stamp BEFORE any sweep: the sweep must never collect the entry that
	// triggered it, or the caller would work on state nobody can find again.
	fe.seen = now
	if len(e.flows) > flowSoftCap && now.Sub(e.lastSweep) >= sweepMinInterval {
		e.lastSweep = now
		e.gcLocked()
		if len(e.flows) > flowHardCap {
			e.trimLocked(flowHardCap * (hardCapKeepFactor - 1) / hardCapKeepFactor)
		}
	}
	return fe
}

// Forget drops a flow's state (called when the transport sees FIN/RST or a
// relay connection closes).
func (e *Engine) Forget(key desync.FlowKey) {
	e.flowsMu.Lock()
	delete(e.flows, key)
	e.flowsMu.Unlock()
}

// gcLocked evicts entries idle for longer than flowTTL. The caller holds
// flowsMu.
func (e *Engine) gcLocked() {
	cutoff := time.Now().Add(-flowTTL)
	for k, fe := range e.flows {
		if fe.seen.Before(cutoff) {
			delete(e.flows, k)
		}
	}
}

// trimLocked enforces a hard ceiling by evicting the least-recently-seen
// entries until at most keep remain. It is the bound a TTL sweep cannot give:
// with thousands of flows younger than flowTTL, gcLocked frees nothing.
//
// Evicting a live flow only costs it its cached profile decision and counters —
// the next packet re-creates the entry — which is strictly better than an
// unbounded table on the datapath goroutine. The caller holds flowsMu.
func (e *Engine) trimLocked(keep int) {
	if keep < 1 {
		keep = 1
	}
	for len(e.flows) > keep {
		// One pass per eviction would be O(n^2); instead compute a cutoff from a
		// single scan and delete everything older than it, repeating only if the
		// scan's median was unlucky.
		var oldest, newest time.Time
		for _, fe := range e.flows {
			if oldest.IsZero() || fe.seen.Before(oldest) {
				oldest = fe.seen
			}
			if fe.seen.After(newest) {
				newest = fe.seen
			}
		}
		if !newest.After(oldest) {
			// Every entry shares one timestamp: drop arbitrary ones.
			for k := range e.flows {
				if len(e.flows) <= keep {
					break
				}
				delete(e.flows, k)
			}
			return
		}
		cut := oldest.Add(newest.Sub(oldest) / 2)
		removed := 0
		for k, fe := range e.flows {
			if len(e.flows) <= keep {
				break
			}
			if !fe.seen.After(cut) {
				delete(e.flows, k)
				removed++
			}
		}
		if removed == 0 {
			// Nothing was older than the midpoint (all timestamps clustered at
			// the top): fall back to arbitrary eviction rather than spin.
			for k := range e.flows {
				if len(e.flows) <= keep {
					break
				}
				delete(e.flows, k)
			}
			return
		}
	}
}

// GC evicts idle flows; call periodically from the daemon.
func (e *Engine) GC() {
	e.flowsMu.Lock()
	e.lastSweep = time.Now()
	e.gcLocked()
	if len(e.flows) > flowHardCap {
		e.trimLocked(flowHardCap * (hardCapKeepFactor - 1) / hardCapKeepFactor)
	}
	e.flowsMu.Unlock()
}

// OnInbound feeds a server->client packet to the engine. Its only job is
// inferring the hop count for autottl; the flow's own retransmission counting
// happens in OnTCP, which is the direction that can see it.
func (e *Engine) OnInbound(p *proto.Pkt) {
	key := desync.FlowKey{Src: p.Dst, Dst: p.Src, SrcPort: p.DstPort, DstPort: p.SrcPort, Proto: p.Proto}
	e.flowsMu.Lock()
	fe, ok := e.flows[key]
	e.flowsMu.Unlock()
	if !ok {
		return
	}
	// Under the entry's own lock, so the datapath's read of Flow.Hops in
	// applyTTL has a happens-before edge with this write.
	fe.mu.Lock()
	if fe.f.Hops == 0 {
		fe.f.Hops = HopsFromTTL(p.TTL)
	}
	fe.mu.Unlock()
}

// HopsFromTTL infers the hop count from an observed TTL by assuming the sender
// started from the nearest standard initial value (SpoofDPI's estimateHops).
func HopsFromTTL(ttl uint8) uint8 {
	switch {
	case ttl == 0:
		return 0
	case ttl <= 64:
		return 64 - ttl
	case ttl <= 128:
		return 128 - ttl
	default:
		return 255 - ttl
	}
}

// OnTCP is the divert-transport entry point for a client->server TCP packet.
//
// Returns (nil, nil) when the packet must be forwarded unchanged.
func (e *Engine) OnTCP(p *proto.Pkt) (*desync.Plan, error) {
	e.mu.RLock()
	strat, caps, fakes, gen := e.strat, e.caps, e.fakes, e.gen
	e.mu.RUnlock()
	if strat == nil {
		return nil, nil
	}

	fe := e.flow(desync.FlowKey{Src: p.Src, Dst: p.Dst, SrcPort: p.SrcPort, DstPort: p.DstPort, Proto: proto.IPProtoTCP})
	fe.mu.Lock()
	defer fe.mu.Unlock()
	f := &fe.f
	e.reviseGeneration(fe, gen)

	payload := p.Payload()
	syn := p.Flags&proto.TCPSyn != 0 && p.Flags&proto.TCPAck == 0

	if syn {
		// A SYN on a tracked 4-tuple is a NEW connection reusing the port, so
		// every piece of the previous one has to go — including the L7 view and
		// the hostname, which are sticky within a connection but must never be
		// inherited across one (they are what profile selection keys on).
		f.ISN = p.Seq
		f.HaveISN = true
		f.Pkts = 0
		f.DataPkts = 0
		f.LastSeq = 0
		f.Retrans = 0
		f.L7 = 0
		f.Host = ""
		f.Desynced = false
		f.FastPath = false
		f.Matched = false
		f.ProfileIdx = -1
		fe.monitorAuto = ""
	}
	f.Pkts++
	retrans := false
	if len(payload) > 0 {
		if p.Seq == f.LastSeq && f.LastSeq != 0 {
			f.Retrans++
			retrans = true
		}
		f.LastSeq = p.Seq
		f.DataPkts++
	}
	f.LastAck = p.Ack
	f.LastWindow = p.Window
	if ts, echo, ok := proto.TCPTimestamps(p.TCPOpts); ok {
		f.TSVal, f.TSEcho = ts, echo
	}

	// Retransmission monitoring runs even on a fast-pathed flow: the whole point
	// of --hostlist-auto is to learn from connections we are NOT desyncing.
	if retrans && fe.monitorAuto != "" {
		e.feedAuto(fe.monitorAuto, f.Host)
	}

	if f.FastPath {
		return nil, nil
	}
	if len(payload) == 0 && !syn {
		return nil, nil
	}

	info := proto.Classify(payload, p.DstPort, proto.IPProtoTCP)
	if info.Host != "" {
		f.Host = info.Host
	}
	if info.Proto != proto.L7Unknown {
		f.L7 = info.Proto
	}

	prof := e.selectProfile(strat, fe, p)
	if prof == nil {
		// Only a FINAL "no profile" verdict earns the fast path. While the
		// hostname is still unknown the decision is deliberately open, and
		// short-circuiting here would stop the ClientHello that follows a SYN
		// from ever reaching a hostlist-gated profile. A monitored flow may still
		// take the fast path: the --hostlist-auto counter above runs before it.
		if f.Matched {
			f.FastPath = true
		}
		return nil, nil
	}
	if retrans {
		e.feedAuto(prof.Filter.AutoHostlist, f.Host)
	}
	if !e.inWindow(prof, f, p) {
		return nil, nil
	}

	plan, err := e.run(prof, &desync.Ctx{
		Flow: f, Payload: payload, Info: info, Caps: caps, Fakes: fakes, SynPkt: syn,
	})
	if err != nil {
		e.cnt.errs.Add(1)
		return nil, err
	}
	if plan != nil && (len(plan.Segs) > 0 || plan.DropOriginal) {
		f.Desynced = true
		e.cnt.desyncs.Add(1)
	}
	return plan, nil
}

// OnUDP is the divert-transport entry point for a client->server UDP datagram.
func (e *Engine) OnUDP(p *proto.Pkt) (*desync.Plan, error) {
	e.mu.RLock()
	strat, caps, fakes, gen := e.strat, e.caps, e.fakes, e.gen
	e.mu.RUnlock()
	if strat == nil || !caps.UDP {
		return nil, nil
	}

	fe := e.flow(desync.FlowKey{Src: p.Src, Dst: p.Dst, SrcPort: p.SrcPort, DstPort: p.DstPort, Proto: proto.IPProtoUDP})
	fe.mu.Lock()
	defer fe.mu.Unlock()
	f := &fe.f
	e.reviseGeneration(fe, gen)

	f.Pkts++
	payload := p.Payload()
	if len(payload) == 0 {
		return nil, nil
	}
	f.DataPkts++
	if f.FastPath {
		return nil, nil
	}

	info := proto.Classify(payload, p.DstPort, proto.IPProtoUDP)
	if info.Host != "" {
		f.Host = info.Host
	}
	if info.Proto != proto.L7Unknown {
		f.L7 = info.Proto
	}

	prof := e.selectProfile(strat, fe, p)
	if prof == nil {
		if f.Matched {
			f.FastPath = true
		}
		return nil, nil
	}
	if !e.inWindow(prof, f, p) {
		return nil, nil
	}

	plan, err := e.run(prof, &desync.Ctx{
		Flow: f, Payload: payload, Info: info, Caps: caps, Fakes: fakes,
	})
	if err != nil {
		e.cnt.errs.Add(1)
		return nil, err
	}
	if plan != nil && (len(plan.Dgrams) > 0 || plan.DropOriginal) {
		f.Desynced = true
		e.cnt.desyncs.Add(1)
	}
	return plan, nil
}

// PlanStream is the proxy-transport entry point: the first client payload of an
// accepted connection, with the original destination already recovered via
// DIOCNATLOOK. It returns a plan whose Segs are pure byte ranges (SeqOff is the
// offset inside payload, never negative under ProxyCaps).
func (e *Engine) PlanStream(key desync.FlowKey, payload []byte) (*desync.Plan, error) {
	e.mu.RLock()
	strat, caps, fakes, gen := e.strat, e.caps, e.fakes, e.gen
	e.mu.RUnlock()
	if strat == nil {
		return nil, ErrNoProfile
	}

	fe := e.flow(key)
	fe.mu.Lock()
	defer fe.mu.Unlock()
	f := &fe.f
	e.reviseGeneration(fe, gen)

	f.Pkts++
	f.DataPkts++

	info := proto.Classify(payload, key.DstPort, proto.IPProtoTCP)
	if info.Host != "" {
		f.Host = info.Host
	}
	if info.Proto != proto.L7Unknown {
		f.L7 = info.Proto
	}

	prof := e.selectProfileStream(strat, fe, key)
	if prof == nil {
		return nil, ErrNoProfile
	}
	return e.run(prof, &desync.Ctx{
		Flow: f, Payload: payload, Info: info, Caps: caps, Fakes: fakes,
	})
}

// reviseGeneration discards a profile decision that was made against an older
// strategy. The caller holds fe.mu.
func (e *Engine) reviseGeneration(fe *flowEntry, gen uint64) {
	if fe.gen == gen {
		return
	}
	fe.gen = gen
	fe.f.Matched = false
	fe.f.ProfileIdx = -1
	fe.f.FastPath = false
}

// selectProfile picks the first profile whose filter matches, caching the
// decision on the flow.
//
// The decision is only cached once it is FINAL. While the hostname is unknown a
// profile that is gated on a hostlist cannot match, so a match found here may
// still be superseded by an earlier, hostlist-gated profile as soon as the
// ClientHello arrives. In that case the profile is returned for this packet but
// not remembered — which is what makes flowseal's `general.toml` select
// p4-tcp-443 for a googlevideo flow instead of settling on the ipset-only
// p7-tcp-80_443_8443 at the SYN.
func (e *Engine) selectProfile(s *strategy.Strategy, fe *flowEntry, p *proto.Pkt) *strategy.Profile {
	f := &fe.f
	if f.Matched {
		if f.ProfileIdx < 0 || f.ProfileIdx >= len(s.Profiles) {
			return nil
		}
		return s.Profiles[f.ProfileIdx]
	}
	l3 := uint8(4)
	if p.Ver == 6 {
		l3 = 6
	}
	// f.Host is sticky: once a ClientHello named the host, later packets of the
	// same flow keep matching against it.
	in := matchInput{
		Proto: p.Proto, Port: p.DstPort, L3: l3, L7: f.L7,
		Host: f.Host, Dst: p.Dst,
	}
	return e.pick(s, fe, in)
}

func (e *Engine) selectProfileStream(s *strategy.Strategy, fe *flowEntry, key desync.FlowKey) *strategy.Profile {
	f := &fe.f
	if f.Matched {
		if f.ProfileIdx < 0 || f.ProfileIdx >= len(s.Profiles) {
			return nil
		}
		return s.Profiles[f.ProfileIdx]
	}
	l3 := uint8(4)
	if key.Dst.Is6() {
		l3 = 6
	}
	in := matchInput{
		Proto: proto.IPProtoTCP, Port: key.DstPort, L3: l3, L7: f.L7,
		Host: f.Host, Dst: key.Dst,
	}
	prof := e.pick(s, fe, in)
	if prof == nil && !f.Matched {
		// A relay sees the whole first payload in one go: there is no later
		// packet that could bring a hostname, so the verdict is final here.
		f.Matched = true
		f.ProfileIdx = -1
	}
	return prof
}

// pick is the shared profile-chain walk. It sets f.Matched/f.ProfileIdx only
// when the verdict cannot change later, and records the --hostlist-auto file to
// monitor when nothing matched but a self-learning profile is a candidate.
func (e *Engine) pick(s *strategy.Strategy, fe *flowEntry, in matchInput) *strategy.Profile {
	f := &fe.f
	hostUnknown := in.Host == ""
	for i, prof := range s.Profiles {
		if !e.matchProfile(prof, in) {
			continue
		}
		if hostUnknown && hostGatedBefore(s, i, in) {
			// Provisional: run it now, decide later.
			return prof
		}
		f.Matched = true
		f.ProfileIdx = i
		e.cnt.matched.Add(1)
		return prof
	}
	// Nothing matched. A profile carrying --hostlist-auto that matches on
	// everything but the hostname means "watch this flow": nfqws desyncs nothing
	// until the host has earned its place on the list.
	fe.monitorAuto = autoCandidate(s, in)
	if fe.monitorAuto != "" {
		// The verdict stays open on purpose: the host can join the learned list
		// at any moment (this flow's own retransmissions may be what puts it
		// there), and from that packet on the profile must fire. Finalising here
		// would arm the fast path and make the list unusable within a flow.
		return nil
	}
	// The verdict is final only when no future packet could change it, i.e. when
	// the hostname is already known (or no host-gated profile is waiting for one).
	if !hostUnknown || !hostGatedBefore(s, len(s.Profiles), in) {
		f.Matched = true
		f.ProfileIdx = -1
	}
	return nil
}

// matchProfile evaluates one profile's filter, unioning any registered
// self-learning hostlist into the filter's own inclusion list.
func (e *Engine) matchProfile(prof *strategy.Profile, in matchInput) bool {
	if al := e.autoList(prof.Filter.AutoHostlist); al != nil {
		in.AutoSet = al.Set()
	}
	return MatchFilter(&prof.Filter, in)
}

// hostGatedBefore reports whether any profile with index < upto is gated on a
// hostname (a static hostlist or a self-learning one) and matches on every other
// criterion. Such a profile would take precedence (first match wins) the moment
// a hostname becomes known, so the current match must not be cached.
func hostGatedBefore(s *strategy.Strategy, upto int, in matchInput) bool {
	if upto > len(s.Profiles) {
		upto = len(s.Profiles)
	}
	for i := 0; i < upto; i++ {
		f := &s.Profiles[i].Filter
		if f.Hostlist == nil && f.AutoHostlist == "" {
			continue
		}
		if MatchFilterIgnoringHost(f, in) {
			return true
		}
	}
	return false
}

// autoCandidate returns the --hostlist-auto file of the first profile that would
// match this flow if its hostname were on that list, "" when there is none.
func autoCandidate(s *strategy.Strategy, in matchInput) string {
	for _, prof := range s.Profiles {
		f := &prof.Filter
		if f.AutoHostlist == "" {
			continue
		}
		if MatchFilterIgnoringHost(f, in) {
			return f.AutoHostlist
		}
	}
	return ""
}

// feedAuto reports one client retransmission to a --hostlist-auto list. nfqws
// treats RetransThreshold retransmissions of the same request as proof the
// handshake is being dropped for that hostname.
func (e *Engine) feedAuto(path, host string) {
	if path == "" || host == "" {
		return
	}
	if al := e.autoList(path); al != nil {
		al.Retrans(host)
	}
}

// inWindow applies --dpi-desync-start / --dpi-desync-cutoff. When the cutoff is
// passed the flow is marked FastPath so later packets skip parsing entirely.
func (e *Engine) inWindow(prof *strategy.Profile, f *desync.Flow, p *proto.Pkt) bool {
	if c := prof.Start; c.Kind != 0 {
		if counterValue(c.Kind, f, p) < c.N {
			return false
		}
	}
	if c := prof.Cutoff; c.Kind != 0 {
		if counterValue(c.Kind, f, p) > c.N {
			f.FastPath = true
			return false
		}
	}
	return true
}

func counterValue(kind byte, f *desync.Flow, p *proto.Pkt) int {
	switch kind {
	case 'n':
		return f.Pkts
	case 'd':
		return f.DataPkts
	case 's':
		if p == nil || !f.HaveISN {
			// Without the SYN there is no base for a relative sequence number,
			// and the raw absolute value would be ~2^31 — which silently excludes
			// the whole flow from a cutoff and trivially satisfies a start.
			// nfqws likewise cannot apply a seq-relative bound without a ctrack
			// entry, so "before the window" is the honest answer.
			return 0
		}
		return int(p.Seq - f.ISN)
	}
	return 0
}

// run executes a profile's ops in phase order, honouring Caps and the
// on_unsupported policy.
func (e *Engine) run(prof *strategy.Profile, c *desync.Ctx) (*desync.Plan, error) {
	plan := &desync.Plan{}
	for _, co := range prof.Ops {
		c.Params = co.Params
		if e.applyTTL(c) {
			// autottl resolved into Params.TTL
		}
		if missing, ok := capsSatisfied(c.Caps, co.Op.Requires()); !ok {
			switch prof.OnUnsupported {
			case desync.UnsupError:
				return nil, &UnsupportedError{Op: co.Op.Name(), Missing: missing}
			case desync.UnsupSkip:
				plan.Degraded = append(plan.Degraded, co.Op.Name())
				e.cnt.degraded.Add(1)
				continue
			default: // UnsupDegrade
				if d, okd := co.Op.(desync.Degrader); okd {
					if err := d.Degrade(c, plan); err != nil {
						return nil, err
					}
				}
				plan.Degraded = append(plan.Degraded, co.Op.Name())
				e.cnt.degraded.Add(1)
				continue
			}
		}
		if err := co.Op.Apply(c, plan); err != nil {
			return nil, err
		}
	}
	if len(plan.Segs) > 0 || len(plan.Dgrams) > 0 {
		plan.DropOriginal = true
	}
	return plan, nil
}

// applyTTL resolves an autottl spec into a concrete TTL for this flow.
// Returns true when Params.TTL was rewritten.
func (e *Engine) applyTTL(c *desync.Ctx) bool {
	p := &c.Params
	if !p.TTLAuto {
		return false
	}
	hops := c.Flow.Hops
	if hops == 0 {
		// No inbound sample yet (first datagram of a QUIC/voice flow):
		// fall back to the midpoint of the allowed range.
		p.TTL = clampTTL(uint8(int(p.TTLMin)+int(p.TTLMax-p.TTLMin)/2), p.TTLMin, p.TTLMax)
		return true
	}
	v := int(hops) + int(p.TTLDelta)
	p.TTL = clampTTL(uint8(max(v, 1)), p.TTLMin, p.TTLMax)
	return true
}

func clampTTL(v, lo, hi uint8) uint8 {
	if lo == 0 {
		lo = 3
	}
	if hi == 0 {
		hi = 20
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// UnsupportedError is returned when on_unsupported="error" and the transport
// cannot honour an op.
type UnsupportedError struct {
	Op      string
	Missing []string
}

func (u *UnsupportedError) Error() string {
	s := "op " + u.Op + " needs capabilities this transport lacks:"
	for _, m := range u.Missing {
		s += " " + m
	}
	return s
}

// capsSatisfied reports whether have covers need, listing what is missing.
func capsSatisfied(have, need desync.Caps) ([]string, bool) {
	var missing []string
	check := func(n, h bool, name string) {
		if n && !h {
			missing = append(missing, name)
		}
	}
	check(need.Inject, have.Inject, "inject")
	check(need.Seq, have.Seq, "seq")
	check(need.DropOriginal, have.DropOriginal, "drop")
	check(need.PerPacketTTL, have.PerPacketTTL, "per-packet-ttl")
	check(need.Fooling, have.Fooling, "fooling")
	check(need.IPID, have.IPID, "ip-id")
	check(need.UDP, have.UDP, "udp")
	check(need.IPv6ExtHdr, have.IPv6ExtHdr, "ipv6-exthdr")
	check(need.Frag, have.Frag, "frag")
	check(need.Segment, have.Segment, "segment")
	check(need.TLSRec, have.TLSRec, "tlsrec")
	return missing, len(missing) == 0
}
