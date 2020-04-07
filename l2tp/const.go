package l2tp

import (
	"github.com/katalix/go-l2tp/internal/nll2tp"
	"time"
)

// ProtocolVersion is the version of the L2TP protocol to use
type ProtocolVersion int

const (
	// ProtocolVersion3Fallback is used for RFC3931 fallback mode
	ProtocolVersion3Fallback = 1
	// ProtocolVersion2 is used for RFC2661
	ProtocolVersion2 = nll2tp.ProtocolVersion2
	// ProtocolVersion3 is used for RFC3931
	ProtocolVersion3 = nll2tp.ProtocolVersion3
)

// ControlConnID is a generic identifier used for RFC2661 tunnel
// and session IDs as well as RFC3931 control connection IDs.
type ControlConnID uint32

const (
	v2TidSidMax = ControlConnID(^uint16(0))
)

// EncapType is the lower-level encapsulation to use for a tunnel
type EncapType int

const (
	// EncapTypeUDP is used for RFC2661 and RFC3931 tunnels using UDP encapsulation
	EncapTypeUDP = nll2tp.EncaptypeUdp
	// EncapTypeIP is used for RFC3931 tunnels using IP encapsulation
	EncapTypeIP = nll2tp.EncaptypeIp
)

func (e EncapType) String() string {
	switch e {
	case EncapTypeIP:
		return "IP"
	case EncapTypeUDP:
		return "UDP"
	}
	panic("unhandled encap type")
}

// FramingCapability describes the type of framing which a peer supports.
// It should be specified as a bitwise OR of FramingCap* values.
type FramingCapability uint32

const (
	// FramingCapSync indicates synchronous framing is supported
	FramingCapSync = 0x1
	// FramingCapAsync indicates asynchronous framing is supported
	FramingCapAsync = 0x2
)

// PseudowireType is the session type for a given session.
// RFC2661 is PPP-only; whereas RFC3931 supports multiple types.
type PseudowireType int

const (
	// PseudowireTypePPP specifies a PPP pseudowire
	PseudowireTypePPP = nll2tp.PwtypePpp
	// PseudowireTypeEth specifies an Ethernet pseudowire
	PseudowireTypeEth = nll2tp.PwtypeEth
)

// DebugFlags is used for kernel-space tunnel and session logging control.
// Logging is emitted using the kernel's printk facility, and may be viewed
// using dmesg, syslog, or the systemd journal depending on distro configuration.
// Multiple flags may be combined to enable different log messages.
type DebugFlags uint32

const (
	// DebugFlagsControl enables logging of userspace/kernelspace API interactions
	DebugFlagsControl = nll2tp.MsgControl
	// DebugFlagsSeq enables logging of data sequence numbers if enabled for a given session
	DebugFlagsSeq = nll2tp.MsgSeq
	// DebugFlagsData enables logging of session data messages
	DebugFlagsData = nll2tp.MsgData
)

// L2SpecType defines the Layer 2 specific sublayer for data packets as per RFC3931 section 3.2.2.
type L2SpecType int32

const (
	// L2SpecTypeNone defines no sublayer is to be used
	L2SpecTypeNone = nll2tp.L2spectypeNone
	// L2SpecTypeDefault defines use of the default sublayer
	L2SpecTypeDefault = nll2tp.L2spectypeDefault
)

// TunnelType define the runtime behaviour of a tunnel instance.
type TunnelType int

const (
	// TunnelTypeDynamic runs the L2TPv2 (RFC2661) or L2TPv3 (RFC3931) control
	// protocol to instantiate the tunnel instance.
	TunnelTypeDynamic = iota
	// TunnelTypeAcquiescent runs a minimal tunnel control protocol transport
	// which will ACK control messages and optionally send periodic HELLO messages.
	TunnelTypeAcquiescent
	// TunnelTypeStatic runs no control protocol, and instantiates the data plane
	// only.
	TunnelTypeStatic
)

// TunnelConfig encapsulates tunnel configuration for a single
// connection between two L2TP hosts.  Each tunnel may contain
// multiple sessions.
type TunnelConfig struct {
	Local        string
	Peer         string
	Encap        EncapType
	Version      ProtocolVersion
	TunnelID     ControlConnID
	PeerTunnelID ControlConnID
	WindowSize   uint16
	HelloTimeout time.Duration
	RetryTimeout time.Duration
	MaxRetries   uint
	HostName     string
	FramingCaps  FramingCapability
}

// SessionConfig encapsulates session configuration for a pseudowire
// connection within a tunnel between two L2TP hosts.
type SessionConfig struct {
	SessionID      ControlConnID
	PeerSessionID  ControlConnID
	Pseudowire     PseudowireType
	SeqNum         bool
	ReorderTimeout time.Duration
	Cookie         []byte
	PeerCookie     []byte
	InterfaceName  string
	L2SpecType     L2SpecType
}
