// Package desync is the transport-agnostic DPI-desync engine: it turns
// (matched profile + payload + flow state) into a plan of segments/datagrams
// that some transport then puts on the wire.
//
// The split between this package and internal/transport is the whole point of
// the design: the same strategy file drives both the packet-level transport
// (utun + BPF injection, full winws parity) and the socket-level one
// (pf rdr + userspace relay, tpws-class subset), with Caps deciding what a
// given transport can honour.
//
// CONTRACT FILE — types and interfaces only.
package desync

import (
	"net/netip"

	"github.com/naladwepo/zapret-for-mac/internal/proto"
)

// Caps describes what a transport is physically able to do. Ops declare what
// they need via Op.Requires(); the engine compares the two and either runs the
// op, degrades it, skips it, or fails the profile (see Profile.OnUnsupported).
type Caps struct {
	Inject       bool // can put synthetic packets on the wire (fake, rst, syndata)
	Seq          bool // can choose TCP sequence numbers (seqovl, overlapping splits)
	DropOriginal bool // can suppress the application's own packet
	PerPacketTTL bool // can set TTL per packet, not per socket
	Fooling      bool // owns the TCP/IP header: badsum, badseq, md5sig, ts, datanoack
	IPID         bool // can choose the IPv4 identification field
	UDP          bool // sees UDP at all
	IPv6ExtHdr   bool // can add hop-by-hop / destination-option headers
	Frag         bool // can emit IP fragments
	Segment      bool // can control payload segmentation (true for every transport)
	TLSRec       bool // can rewrite the TLS record layer (true for every transport)
}

// FullCaps is what the divert (utun + BPF) transport provides.
func FullCaps() Caps {
	return Caps{
		Inject: true, Seq: true, DropOriginal: true, PerPacketTTL: true,
		Fooling: true, IPID: true, UDP: true, IPv6ExtHdr: true, Frag: true,
		Segment: true, TLSRec: true,
	}
}

// ProxyCaps is what the socket-level (pf rdr + relay) transport provides:
// byte-level tricks only. See docs/limits.md.
func ProxyCaps() Caps {
	return Caps{Segment: true, TLSRec: true, DropOriginal: true}
}

// Fooling is the set of --dpi-desync-fooling modes applied to injected packets.
type Fooling uint16

const (
	FoolNone      Fooling = 0
	FoolBadSum    Fooling = 1 << 0
	FoolBadSeq    Fooling = 1 << 1
	FoolMD5Sig    Fooling = 1 << 2
	FoolTS        Fooling = 1 << 3
	FoolDataNoAck Fooling = 1 << 4
	FoolHopByHop  Fooling = 1 << 5
	FoolHopByHop2 Fooling = 1 << 6
)

// FoolNames maps zapret's --dpi-desync-fooling tokens to their bit.
var FoolNames = map[string]Fooling{
	"none": FoolNone, "badsum": FoolBadSum, "badseq": FoolBadSeq,
	"md5sig": FoolMD5Sig, "ts": FoolTS, "datanoack": FoolDataNoAck,
	"hopbyhop": FoolHopByHop, "hopbyhop2": FoolHopByHop2,
}

// FoolParams carries the numeric increments the fooling modes need.
// Defaults match zapret: badseq -10000, badack -66000, ts -600000.
type FoolParams struct {
	BadSeqIncrement int32
	BadAckIncrement int32
	TSIncrement     int32
}

// DefaultFoolParams returns zapret's defaults.
func DefaultFoolParams() FoolParams {
	return FoolParams{BadSeqIncrement: -10000, BadAckIncrement: -66000, TSIncrement: -600000}
}

// IPIDMode implements --ip-id.
type IPIDMode uint8

const (
	IPIDDefault IPIDMode = iota
	IPIDZero
	IPIDRandom
	// IPIDSeq numbers the emitted packets sequentially; multidisorder counts
	// DOWN so that a reassembling DPI sees a plausible ascending order.
	IPIDSeq
	// IPIDSeqGroup makes a synthetic replacement packet reuse the ip_id of the
	// original part it stands in for. nfqws uses this for the faked-split
	// family so the fake and the real segment look like one retransmission.
	IPIDSeqGroup
	// IPIDSame copies the ip_id of the intercepted packet onto everything the
	// plan emits.
	IPIDSame
)

// SegKind tells the transport what a segment is for.
type SegKind uint8

const (
	SegData    SegKind = iota // real application bytes
	SegFake                   // decoy, must not reach the server intact
	SegRST                    // injected RST / RST+ACK
	SegSynData                // payload carried on the SYN
)

// Seg is one TCP unit of a desync plan, in transmit order.
//
// SeqOff is the byte offset, relative to the start of the original application
// payload, at which Data begins. It is negative for --dpi-desync-split-seqovl
// (sequence overlap): the segment is sent below the current window so the
// server's TCP discards the prefix while a naive DPI reassembler swallows it.
type Seg struct {
	Kind    SegKind
	Data    []byte
	SeqOff  int32
	TTL     uint8 // 0 = leave to the transport (real TTL)
	Fool    Fooling
	FoolP   FoolParams
	Repeats int   // >1 means send this segment N times (fake repeats)
	Flags   uint8 // TCP flag override; 0 => PSH|ACK for data, RST for SegRST
	IPID    IPIDMode
	Frag    int // >0: emit as IPv4 fragments split at this offset (multiple of 8)

	// Window, when non-zero, overrides the TCP window of this segment
	// (--wssize). WindowScale is the window-scale shift to advertise; it only
	// matters on a SYN, where the option lives.
	Window      uint16
	WindowScale uint8
}

// Dgram is one UDP unit of a desync plan, in transmit order.
type Dgram struct {
	Kind    SegKind
	Data    []byte
	TTL     uint8
	Fool    Fooling
	FoolP   FoolParams
	Repeats int
	// Frag > 0 emits this datagram as IPv4 fragments split at that payload
	// offset (--dpi-desync=ipfrag1/ipfrag2, --dpi-desync-ipfrag-pos-udp).
	Frag int
}

// Plan is the engine's output for one intercepted payload.
type Plan struct {
	Segs   []Seg
	Dgrams []Dgram
	// DropOriginal tells the transport not to forward the packet it handed in.
	// Always true when the plan re-emits the payload itself.
	DropOriginal bool
	// Degraded lists ops that could not be honoured with the transport's Caps.
	Degraded []string
}

// FlowKey identifies a connection (client-side 4-tuple, client->server order).
type FlowKey struct {
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Proto            uint8
}

// Flow is per-connection state: what zapret keeps in its conntrack.
type Flow struct {
	Key FlowKey

	ISN uint32 // client initial sequence number (from SYN)
	// HaveISN reports whether ISN was actually observed. It is false for every
	// flow that was already established when the datapath came up, and without
	// it a "relative sequence" bound ('s') would silently compare against 0 and
	// see the absolute sequence number instead.
	HaveISN    bool
	LastSeq    uint32
	LastAck    uint32
	LastWindow uint16
	TSVal      uint32 // last observed TCP timestamp value, 0 if unavailable
	TSEcho     uint32

	Hops uint8 // hop count to the peer, inferred from an inbound TTL (0 = unknown)

	Pkts     int // client->server packets seen
	DataPkts int // client->server packets carrying payload

	L7   proto.L7
	Host string

	ProfileIdx int  // index of the matched profile, -1 if none
	Matched    bool // profile selection already done
	Desynced   bool // at least one op has fired
	FastPath   bool // past cutoff: forward without parsing

	// Retrans counts client retransmissions, feeding --hostlist-auto.
	Retrans int
}

// Phase orders ops within one profile, mirroring nfqws' desync phases.
type Phase uint8

const (
	PhaseSyn    Phase = iota // syndata: rides on the SYN
	PhaseFake                // fake/rst: injected before the real payload
	PhaseSplit               // multisplit/multidisorder/fakedsplit/hostfakesplit
	PhaseModify              // tamper/udplen/wssize/ip-id: mutate what is already planned
)

// Ctx is the input an Op works on.
type Ctx struct {
	Flow    *Flow
	Payload []byte       // original application payload (client -> server)
	Info    proto.L7Info // parsed L7 view of Payload
	Caps    Caps
	Fakes   FakeSet
	// Params is the op's own configuration, already validated by the loader.
	Params OpParams
	// SynPkt is true when the intercepted packet is a bare SYN.
	SynPkt bool
}

// OpParams is the union of every knob any op takes; the strategy loader fills
// only the fields the named op reads. Keeping it flat avoids an interface{}
// soup and lets the loader validate before the datapath runs.
type OpParams struct {
	Repeats        int
	TTL            uint8
	TTLAuto        bool
	TTLDelta       int8
	TTLMin, TTLMax uint8

	Fool  Fooling
	FoolP FoolParams

	SplitPos      []PosSpec // --dpi-desync-split-pos
	Seqovl        int
	SeqovlPattern []byte // bytes prepended below the window

	Pattern []byte // --dpi-desync-fakedsplit-pattern / fake filler

	FakeTLS        []byte
	FakeHTTP       []byte
	FakeQUIC       []byte
	FakeDiscord    [][]byte
	FakeSTUN       [][]byte
	FakeUnknownUDP [][]byte
	FakeSynData    []byte
	TLSMod         TLSMod

	HostFakeHost string // --dpi-desync-hostfakesplit-mod=host=
	AltOrder     int    // ...,altorder=N
	// MidHost is --dpi-desync-hostfakesplit-midhost, a full position spec in
	// zapret (not a flag); MidHostSet says whether it was given at all.
	MidHost    PosSpec
	MidHostSet bool

	// Tamper carries the in-place L7 mangling knobs for the tamper op
	// (--hostcase, --hostspell, --hostdot, --hostpad, --domcase, ...).
	Tamper proto.TamperOpts

	UDPLenIncrement int
	UDPLenPattern   []byte

	WSSize      int
	WSSizeScale int
	// WSSizeCutoffKind/N mirror --wssize-cutoff ('n' packets, 'd' data packets,
	// 's' relative sequence); kind 0 means "until the flow ends".
	WSSizeCutoffKind byte
	WSSizeCutoffN    int

	IPID IPIDMode

	FragPosTCP int
	FragPosUDP int

	AnyProtocol bool
}

// PosSpec is one entry of --dpi-desync-split-pos: a marker plus a signed offset.
type PosSpec struct {
	Marker proto.HostlistMarker
	Offset int
}

// TLSMod implements --dpi-desync-fake-tls-mod.
type TLSMod struct {
	None     bool
	Rnd      bool   // randomise the ClientHello random + session id
	RndSNI   bool   // randomise the SNI hostname
	SNI      string // force this SNI
	DupSID   bool   // duplicate the session id
	PadEncap bool
}

// FakeSet holds the loaded fake payload blobs (bin/*.bin equivalents).
type FakeSet struct {
	TLS        []byte
	HTTP       []byte
	QUIC       []byte
	Discord    [][]byte
	STUN       [][]byte
	UnknownUDP [][]byte
	SynData    []byte
}

// Op is one desync technique (one --dpi-desync= mode).
type Op interface {
	Name() string
	Phase() Phase
	// Requires reports the capabilities the op needs; a Caps field set to true
	// here must be true in the transport's Caps for Apply to be called.
	Requires() Caps
	Apply(c *Ctx, p *Plan) error
}

// Degrader is implemented by ops that have a meaningful socket-level
// approximation (e.g. multisplit -> plain send() boundaries).
type Degrader interface {
	Degrade(c *Ctx, p *Plan) error
}

// Unsupported is the policy for an op the transport cannot run.
type Unsupported uint8

const (
	UnsupDegrade Unsupported = iota // run Degrade if available, else skip
	UnsupSkip
	UnsupError
)
