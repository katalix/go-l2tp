package l2tp

import (
	"fmt"
	"net"

	"github.com/katalix/sl2tpd/internal/nll2tp"
	"golang.org/x/sys/unix"
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

// QuiescentTunnel creates a user space socket for the
// L2TP control plane, but does not run the control protocol
// beyond acknowledging messages and optionally sending HELLO
// messages.
// The data plane is established on creation of the tunnel instance.
type QuiescentTunnel struct {
	cp *l2tpControlPlane
	dp *l2tpDataPlane
}

// QuiescentTunnelConfig encapsulates configuration for a "quiescent"
// L2TP tunnel.  Quiescent tunnels may be either L2TPv2 or L2TPv3.
// For L2TPv2, set the TunnelID and PeerTunnelID fields.
type QuiescentTunnelConfig struct {
	LocalAddress      string
	RemoteAddress     string
	Version           ProtocolVersion
	ControlConnID     ControlConnID
	PeerControlConnID ControlConnID
	Encap             EncapType
}

// StaticTunnel does not run any control protocol
// and instead merely instantiates the data plane in the
// kernel.  This is equivalent to the Linux 'ip l2tp'
// command(s).
// Static L2TPv2 tunnels are not practically useful,
// so NewStaticTunnel only supports creation of L2TPv3
// unmanaged tunnel instances.
type StaticTunnel struct {
	dp *l2tpDataPlane
}

// StaticTunnelConfig encapsulates configuration for a static
// L2TP tunnel.  Static tunnels are L2TPv3 only.
type StaticTunnelConfig struct {
	LocalAddress      string
	RemoteAddress     string
	ControlConnID     ControlConnID
	PeerControlConnID ControlConnID
	Encap             EncapType
}

// Session is an interface representing an L2TP session.
type Session interface {
	Close()
}

// Tunnel is an interface representing an L2TP tunnel.
type Tunnel interface {
	//NewSession(name string, cfg *SessionConfig) (Session, error)
	//FindSessionByName(name string) (Session, error)
	Close()
}

func (e EncapType) String() string {
	switch e {
	case EncapTypeIP:
		return "IP"
	case EncapTypeUDP:
		return "UDP"
	}
	panic("unhandled encap type")
}

// NewQuiescentTunnel creates a new "quiescent" L2TP tunnel.
func NewQuiescentTunnel(nl *nll2tp.Conn, cfg *QuiescentTunnelConfig) (tunl Tunnel, err error) {

	var sal, sap unix.Sockaddr

	if nl == nil || cfg == nil {
		return nil, fmt.Errorf("invalid nil argument(s) to NewQuiescentTunnel")
	}

	// Sanity check the configuration
	if cfg.Version != ProtocolVersion3 && cfg.Encap == EncapTypeIP {
		return nil, fmt.Errorf("IP encapsulation only supported for L2TPv3 tunnels")
	}
	if cfg.Version == ProtocolVersion2 {
		if cfg.ControlConnID == 0 || cfg.ControlConnID > 65535 {
			return nil, fmt.Errorf("L2TPv2 connection ID %v out of range", cfg.ControlConnID)
		} else if cfg.PeerControlConnID == 0 || cfg.PeerControlConnID > 65535 {
			return nil, fmt.Errorf("L2TPv2 peer connection ID %v out of range", cfg.PeerControlConnID)
		}
	} else {
		if cfg.ControlConnID == 0 || cfg.PeerControlConnID == 0 {
			return nil, fmt.Errorf("L2TPv3 tunnel IDs %v and %v must both be > 0",
				cfg.ControlConnID, cfg.PeerControlConnID)
		}
	}

	// Initialise tunnel address structures
	switch cfg.Encap {
	case EncapTypeUDP:
		sal, sap, err = newUDPAddressPair(cfg.LocalAddress, cfg.RemoteAddress)
	case EncapTypeIP:
		sal, sap, err = newIPAddressPair(cfg.LocalAddress, cfg.ControlConnID,
			cfg.RemoteAddress, cfg.PeerControlConnID)
	default:
		err = fmt.Errorf("unrecognised encapsulation type %v", cfg.Encap)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to initialise tunnel addresses: %v", err)
	}

	return newQuiescentTunnel(nl, sal, sap, cfg)
}

// NewSession adds a session to the tunnel
func (qt *QuiescentTunnel) NewSession(name string, cfg *SessionConfig) (Session, error) {
	return nil, fmt.Errorf("QuiescentTunnel: NewSession not implemented")
}

// Close closes the tunnel, releasing allocated resources.
func (qt *QuiescentTunnel) Close() {
	if qt != nil {
		if qt.cp != nil {
			qt.cp.Close()
		}
		if qt.dp != nil {
			qt.dp.Close()
		}
	}
}

func newQuiescentTunnel(nl *nll2tp.Conn, sal, sap unix.Sockaddr, cfg *QuiescentTunnelConfig) (qt *QuiescentTunnel, err error) {
	qt = &QuiescentTunnel{}

	// Initialise the control plane.
	// We bind/connect immediately since we're not runnning most of the control protocol.
	qt.cp, err = newL2tpControlPlane(sal, sap)
	if err != nil {
		qt.Close()
		return nil, err
	}

	err = qt.cp.Bind()
	if err != nil {
		qt.Close()
		return nil, err
	}

	err = qt.cp.Connect()
	if err != nil {
		qt.Close()
		return nil, err
	}

	qt.dp, err = newL2tpDataPlane(nl, sal, sap, &nll2tp.TunnelConfig{
		Tid:     nll2tp.L2tpTunnelID(cfg.ControlConnID),
		Ptid:    nll2tp.L2tpTunnelID(cfg.PeerControlConnID),
		Version: nll2tp.L2tpProtocolVersion(cfg.Version),
		Encap:   nll2tp.L2tpEncapType(cfg.Encap),
		// TODO: do we want/need to enable kernel debug?
		DebugFlags: nll2tp.L2tpDebugFlags(0)})
	if err != nil {
		qt.Close()
		return nil, err
	}

	err = qt.dp.Up(qt.cp.fd)
	if err != nil {
		qt.Close()
		return nil, err
	}

	return
}

// NewStaticTunnel creates a new unmanaged L2TP tunnel.
func NewStaticTunnel(nl *nll2tp.Conn, cfg *StaticTunnelConfig) (tunl Tunnel, err error) {

	var sal, sap unix.Sockaddr

	if nl == nil || cfg == nil {
		return nil, fmt.Errorf("invalid nil argument(s) to NewQuiescentTunnel")
	}

	// Sanity check  the configuration
	if cfg.ControlConnID == 0 || cfg.PeerControlConnID == 0 {
		return nil, fmt.Errorf("L2TPv3 tunnel IDs %v and %v must both be > 0",
			cfg.ControlConnID, cfg.PeerControlConnID)
	}

	// Initialise tunnel address structures
	switch cfg.Encap {
	case EncapTypeUDP:
		sal, sap, err = newUDPAddressPair(cfg.LocalAddress, cfg.RemoteAddress)
	case EncapTypeIP:
		sal, sap, err = newIPAddressPair(cfg.LocalAddress, cfg.ControlConnID,
			cfg.RemoteAddress, cfg.PeerControlConnID)
	default:
		err = fmt.Errorf("unrecognised encapsulation type %v", cfg.Encap)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to initialise tunnel addresses: %v", err)
	}

	return newStaticTunnel(nl, sal, sap, cfg)
}

// NewSession adds a session to the tunnel
func (st *StaticTunnel) NewSession(name string, cfg *SessionConfig) (Session, error) {
	return nil, fmt.Errorf("StaticTunnel: NewSession not implemented")
}

// Close closes the tunnel, releasing allocated resources.
func (st *StaticTunnel) Close() {
	if st != nil {
		if st.dp != nil {
			st.dp.Close()
		}
	}
}

func newStaticTunnel(nl *nll2tp.Conn, sal, sap unix.Sockaddr, cfg *StaticTunnelConfig) (st *StaticTunnel, err error) {
	st = &StaticTunnel{}

	// Initialise the data plane.
	st.dp, err = newL2tpDataPlane(nl, sal, sap, &nll2tp.TunnelConfig{
		Tid:     nll2tp.L2tpTunnelID(cfg.ControlConnID),
		Ptid:    nll2tp.L2tpTunnelID(cfg.PeerControlConnID),
		Version: nll2tp.ProtocolVersion3,
		Encap:   nll2tp.L2tpEncapType(cfg.Encap),
		// TODO: do we want/need to enable kernel debug?
		DebugFlags: nll2tp.L2tpDebugFlags(0)})
	if err != nil {
		st.Close()
		return nil, err
	}

	err = st.dp.UpStatic()
	if err != nil {
		st.Close()
		return nil, err
	}

	return
}

func newUDPTunnelAddress(address string) (unix.Sockaddr, error) {

	u, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve %v: %v", address, err)
	}

	if b := u.IP.To4(); b != nil {
		return &unix.SockaddrInet4{
			Port: u.Port,
			Addr: [4]byte{b[0], b[1], b[2], b[3]},
		}, nil
	} else if b := u.IP.To16(); b != nil {
		// TODO: SockaddrInet6 has a uint32 ZoneId, while UDPAddr
		// has a Zone string.  How to convert between the two?
		return &unix.SockaddrInet6{
			Port: u.Port,
			Addr: [16]byte{
				b[0], b[1], b[2], b[3],
				b[4], b[5], b[6], b[7],
				b[8], b[9], b[10], b[11],
				b[12], b[13], b[14], b[15],
			},
			// ZoneId
		}, nil
	}

	return nil, fmt.Errorf("unhandled address family")
}

func newUDPAddressPair(local, remote string) (sal, sap unix.Sockaddr, err error) {
	sal, err = newUDPTunnelAddress(local)
	if err != nil {
		return nil, nil, err
	}
	sap, err = newUDPTunnelAddress(remote)
	if err != nil {
		return nil, nil, err
	}
	return sal, sap, nil
}

func newIPTunnelAddress(address string, ccid ControlConnID) (unix.Sockaddr, error) {

	u, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve %v: %v", address, err)
	}

	if b := u.IP.To4(); b != nil {
		return &unix.SockaddrL2TPIP{
			Addr:   [4]byte{b[0], b[1], b[2], b[3]},
			ConnId: uint32(ccid),
		}, nil
	} else if b := u.IP.To16(); b != nil {
		// TODO: SockaddrInet6 has a uint32 ZoneId, while UDPAddr
		// has a Zone string.  How to convert between the two?
		return &unix.SockaddrL2TPIP6{
			Addr: [16]byte{
				b[0], b[1], b[2], b[3],
				b[4], b[5], b[6], b[7],
				b[8], b[9], b[10], b[11],
				b[12], b[13], b[14], b[15],
			},
			// ZoneId
			ConnId: uint32(ccid),
		}, nil
	}

	return nil, fmt.Errorf("unhandled address family")
}

func newIPAddressPair(local string, ccid ControlConnID, remote string, pccid ControlConnID) (sal, sap unix.Sockaddr, err error) {
	sal, err = newIPTunnelAddress(local, ccid)
	if err != nil {
		return nil, nil, err
	}
	sap, err = newIPTunnelAddress(remote, pccid)
	if err != nil {
		return nil, nil, err
	}
	return sal, sap, nil
}
