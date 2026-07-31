// Package proto contains packet parsing/building (IPv4, IPv6, TCP, UDP) and
// L7 classification (TLS, HTTP, QUIC, STUN, Discord voice, WireGuard, DHT)
// equivalent to zapret's nfq/protocol.c + nfq/darkmagic.c.
//
// CONTRACT FILE — types and constants only. Do not change existing signatures;
// add new ones if needed.
package proto

import "net/netip"

// IP protocol numbers we care about.
const (
	IPProtoICMP   = 1
	IPProtoTCP    = 6
	IPProtoUDP    = 17
	IPProtoICMPv6 = 58
	IPProtoHopOpt = 0
	IPProtoDstOpt = 60
	IPProtoFrag   = 44
)

// TCP flags. ECE and CWR are named because a re-emitted real segment has to carry
// the client's own flag byte verbatim: dropping them silently disables ECN for the
// connection and makes our segments distinguishable from the ones we forward.
const (
	TCPFin uint8 = 1 << 0
	TCPSyn uint8 = 1 << 1
	TCPRst uint8 = 1 << 2
	TCPPsh uint8 = 1 << 3
	TCPAck uint8 = 1 << 4
	TCPUrg uint8 = 1 << 5
	TCPEce uint8 = 1 << 6
	TCPCwr uint8 = 1 << 7
)

// L7 is the application protocol recognised in a packet payload.
// Mirrors zapret's --filter-l7 values.
type L7 uint16

// L7Unknown is a real bit, not the zero value: a filter of 0 means "protocol
// not constrained", while L7Unknown means "explicitly the unrecognised class"
// (zapret's --filter-l7=unknown).
const (
	L7HTTP      L7 = 1 << 0
	L7TLS       L7 = 1 << 1
	L7QUIC      L7 = 1 << 2
	L7WireGuard L7 = 1 << 3
	L7DHT       L7 = 1 << 4
	L7Discord   L7 = 1 << 5
	L7STUN      L7 = 1 << 6
	L7Unknown   L7 = 1 << 7
	L7Any       L7 = 0xffff
)

// L7Names maps the zapret spelling of every --filter-l7 token to its bit.
var L7Names = map[string]L7{
	"http": L7HTTP, "tls": L7TLS, "quic": L7QUIC, "wireguard": L7WireGuard,
	"dht": L7DHT, "discord": L7Discord, "stun": L7STUN, "unknown": L7Unknown,
	"any": L7Any,
}

// Pkt is a parsed view over one complete IP packet. All slices alias Raw —
// never retain a Pkt past the lifetime of the buffer it was parsed from.
type Pkt struct {
	Raw []byte // complete IP packet, header included

	Ver   uint8 // 4 or 6
	Proto uint8 // final protocol (IPProtoTCP / IPProtoUDP / ...) after ext headers
	TTL   uint8 // IPv4 TTL or IPv6 hop limit
	IPID  uint16
	DF    bool
	// TrafficClass is the IPv4 TOS byte (DSCP in the top 6 bits, ECN in the
	// bottom 2) or the IPv6 traffic class, which occupies the same 8 bits. It is
	// carried so a re-emitted segment keeps the flow's ECN marking: stripping it
	// from some packets of a connection and not others both disables ECN and
	// gives a DPI fingerprinter something to key on.
	TrafficClass uint8
	// FlowLabel is the IPv6 flow label (20 bits), 0 for IPv4. The kernel picks
	// one per connection, so re-emitting a segment without it is another
	// avoidable inconsistency.
	FlowLabel uint32

	Src, Dst netip.Addr

	// L3Len is the length of the IP header chain (offset of the L4 header in Raw).
	L3Len int
	// L4Len is the length of the L4 header (TCP with options, or 8 for UDP).
	L4Len int

	SrcPort, DstPort uint16

	// TCP-only fields, zero for UDP.
	Seq, Ack uint32
	Flags    uint8
	Window   uint16
	TCPOpts  []byte // options only (no padding trimming)
}

// Payload returns the L7 bytes of the packet (may be empty).
func (p *Pkt) Payload() []byte {
	off := p.L3Len + p.L4Len
	if off > len(p.Raw) {
		return nil
	}
	return p.Raw[off:]
}

// IsTCP / IsUDP are convenience predicates.
func (p *Pkt) IsTCP() bool { return p.Proto == IPProtoTCP }
func (p *Pkt) IsUDP() bool { return p.Proto == IPProtoUDP }

// Tmpl is a packet template used to synthesise outgoing packets (fakes, splits,
// RSTs, SYN-data). Marshal produces a complete, checksummed IP packet.
//
// Every desync trick that needs bytes the kernel would otherwise own is
// expressed here: Seq (seqovl), TTL (fake), IPID (--ip-id=zero|seq),
// BadSum/BadSeq/MD5Sig/NoAck/TSIncrement (--dpi-desync-fooling).
type Tmpl struct {
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16

	// TCP
	Seq, Ack uint32
	Flags    uint8  // default PSH|ACK when zero and IsTCP
	Window   uint16 // 0 -> copy from the flow's last observed window
	TCPOpts  []byte // raw option bytes appended verbatim (already padded)

	TTL uint8 // 0 -> 64
	// TrafficClass is the IPv4 TOS byte / IPv6 traffic class to emit. Copy it
	// from the intercepted packet for real segments; a decoy may use 0.
	TrafficClass uint8
	// FlowLabel is the IPv6 flow label to emit (bits above 20 are ignored).
	FlowLabel uint32
	IPID      uint16
	DF        bool
	Payload   []byte

	UDP bool // build a UDP packet instead of TCP

	// Fooling knobs, applied by Marshal.
	BadSum bool // deliberately wrong L4 checksum
	MD5Sig bool // append a bogus TCP MD5 signature option (kind 19, len 18)
	NoAck  bool // clear the ACK flag
}

// Frag describes one IPv4 fragment produced by IPFragment.
type Frag struct{ Raw []byte }

// HostlistMarker is a split-position marker in --dpi-desync-split-pos grammar.
type HostlistMarker uint8

const (
	MarkerAbs HostlistMarker = iota // absolute offset
	MarkerMethod
	MarkerHost
	MarkerEndHost
	MarkerSLD
	MarkerEndSLD
	MarkerMidSLD
	MarkerSNIExt
)

// MarkerNames maps zapret's marker spellings to their constant.
var MarkerNames = map[string]HostlistMarker{
	"method": MarkerMethod, "host": MarkerHost, "endhost": MarkerEndHost,
	"sld": MarkerSLD, "endsld": MarkerEndSLD, "midsld": MarkerMidSLD,
	"sniext": MarkerSNIExt,
}

// TamperOpts is the set of in-place L7 mangling knobs (zapret's --hostcase,
// --hostspell, --hostnospace, --hostdot, --hosttab, --hostpad, --domcase,
// --methodspace, --methodeol, --unixeol). Applied to HTTP requests only,
// except DomCase which also touches the TLS SNI.
type TamperOpts struct {
	HostCase    bool
	HostSpell   string // explicit spelling of the header name, e.g. "hoSt"
	HostNoSpace bool
	HostDot     bool
	HostTab     bool
	HostPad     int
	DomCase     bool
	MethodSpace bool
	MethodEOL   bool
	UnixEOL     bool
}

// L7Info is everything the engine needs to know about a payload to place
// splits and decide filters. Offsets are relative to the start of the payload.
type L7Info struct {
	Proto L7
	Host  string // SNI for TLS/QUIC, Host: header for HTTP, "" otherwise

	HostOff, HostLen int // offset/length of the hostname bytes in the payload
	SLDOff, SLDLen   int // second-level domain inside the hostname
	MethodOff        int // HTTP method start (0 for TLS)
	SNIExtOff        int // offset of the SNI extension header in a ClientHello
}
