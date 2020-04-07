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
//
// Not every configuration option applies to all tunnel types.
// Refer to the documentation for specific tunnel creation functions
// for more information.
type TunnelConfig struct {
	// The local address that the tunnel should bind its socket to.
	// This must be specified for static and quiescent tunnels.
	// For dynamic tunnels this can be left blank and the kernel
	// will autobind the socket when connecting to the peer.
	Local string

	// The address of the L2TP peer to connect to.
	Peer string

	// The encapsulation type to be used by the tunnel instance.
	// L2TPv2 tunnels support UDP encapsulation only.
	Encap EncapType

	// The version of the L2TP protocol to use for the tunnel.
	Version ProtocolVersion

	// The local tunnel ID for the tunnel instance.  Tunnel
	// IDs must be unique to the host, and must be non-zero.
	// The tunnel ID must be specified for static and quiescent tunnels.
	// For dynamic tunnels the tunnel ID can set to zero and
	// the L2TP context will autogenerate an ID.
	TunnelID ControlConnID

	// The peer's tunnel ID for the tunnel instance.
	// The peer's ID must be specified for static and quiescent tunnels.
	PeerTunnelID ControlConnID

	// The initial window size to use for the L2TP reliable transport
	// algorithm.  The window size dictates how many control messages the
	// tunnel may have "in flight" (i.e. pending an ACK from the peer)
	// at any one time.
	// Tuning the window size can allow high-volume L2TP servers
	// to improve performance.  Generally it won't be necessary to change
	// this from the default value of 4.
	WindowSize uint16

	// The hello timeout, if set, enables transmission of L2TP keep-alive
	// (HELLO) messages.
	// A hello message is sent N milliseconds after the last control
	// message was sent or received.  It allows for early detection of
	// tunnel failure on quiet connections.
	// By default no keep-alive messages are sent.
	HelloTimeout time.Duration

	// The retry timeout specifies the starting retry timeout for the
	// reliable transport algorithm used for L2TP control messages.
	// The algorithm uses an exponential backoff when retrying messages.
	// By default a starting retry timeout of 1000ms is used.
	RetryTimeout time.Duration

	// MaxRetries sets how many times a given control message may be
	// retried before the transport considers the message transmission to
	// have failed.
	// It may be useful to tune this value on unreliable network connections
	// to avoid suprious tunnel failure, or conversely to allow for quicker
	// tunnel failure detection on reliable links.
	// The default is 3 retries.
	MaxRetries uint

	// HostName sets the host name the tunnel will advertise in the
	// Host Name AVP per RFC2661.
	// If unset the host's name will be queried and the returned value used.
	HostName string

	// FramingCaps sets the framing capabilites the tunnel will advertise
	// in the Framing Capabilites AVP per RFC2661.
	// The default is to advertise both sync and async framing.
	FramingCaps FramingCapability
}

// SessionConfig encapsulates session configuration for a pseudowire
// connection within a tunnel between two L2TP hosts.
type SessionConfig struct {
	// SessionID specifies the local session ID of the session.
	// Session IDs must be unique to the tunnel for L2TPv2, or unique to
	// the peer for L2TPv3.
	// The session ID must be specified for sessions in static or
	// quiescent tunnels.
	SessionID ControlConnID

	// PeerSessionID specifies the peer's session ID for the session.
	// The peer session ID must be specified for sessions in static or
	// quiescent tunnels.
	PeerSessionID ControlConnID

	// Pseudowire specifies the type of layer 2 frames carried by the session.
	// L2TPv2 tunnels support PPP pseudowires only.
	Pseudowire PseudowireType

	// SeqNum, if set, enables the transmission of sequence numbers with
	// L2TP data messages.  Use of sequence numbers enables the data plane
	// to reorder data packets to ensure they are delivered in sequence.
	// By default sequence numbers are not used.
	SeqNum bool

	// ReorderTimeout, if set, specifies the length of time to queue out
	// of sequence data packets before discarding them.
	// This parameter is not currently implemented and should not be used.
	ReorderTimeout time.Duration

	// Cookie, if set, specifies the local L2TPv3 cookie for the session.
	// Cookies are a data verification mechanism intended to allow misdirected
	// data packets to be detected and rejected.
	// Transmitted data packets will include the local cookie in their header.
	// Cookies may be either 4 or 8 bytes long, and contain aribrary data.
	// By default no local cookie is set.
	Cookie []byte

	// PeerCookie, if set, specifies the L2TPv3 cookie the peer will send in
	// the header of its data messages.
	// Messages received without the peer's cookie (or with the wrong cookie)
	// will be rejected.
	// By default no peer cookie is set.
	PeerCookie []byte

	// InterfaceName, if set, specifies the network interface name to be
	// used for the session instance.
	// Setting the interface name can be useful when you need to be certain
	// of the interface name a given session will use.
	// By default the Linux kernel autogenerates an interface name specific to
	// the pseudowire type, e.g. "l2tpeth0", "ppp0".
	InterfaceName string

	// L2SpecType specifies the L2TPv3 Layer 2 specific sublayer field to
	// be used in data packet headers as per RFC3931 section 3.2.2.
	// By default no Layer 2 specific sublayer is used.
	L2SpecType L2SpecType
}
