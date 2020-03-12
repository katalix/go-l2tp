package l2tp

import (
	"fmt"
	"net"

	"github.com/katalix/sl2tpd/internal/nll2tp"
	"golang.org/x/sys/unix"
)

// ProtocolVersion is the version of the L2TP protocol to use
type ProtocolVersion int

// TunnelID is the local L2TPv2 tunnel identifier which must be unique
// to the system.
type TunnelID uint16

// SessionID is the local L2TPv2 session identifier which must be unique
// to the parent tunnel.
type SessionID uint16

// ControlConnID is the local L2TPv3 contol connection identifier which
// must be unique to the system, and may represent either a tunnel or a
// session instance.
type ControlConnID uint32

const (
	// ProtocolVersion3Fallback is used for RFC3931 fallback mode
	ProtocolVersion3Fallback = 1
	// ProtocolVersion2 is used for RFC2661
	ProtocolVersion2 = nll2tp.ProtocolVersion2
	// ProtocolVersion3 is used for RFC3931
	ProtocolVersion3 = nll2tp.ProtocolVersion3
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

// Tunnel represents a tunnel instance, combining both the
// control plane and the data plane.
type Tunnel struct {
	dp *l2tpDataPlane
	cp *l2tpControlPlane
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

// QuiescentTunnelConfig encapsulates configuration for a "quiescent"
// L2TP tunnel.  Quiescent tunnels may be either L2TPv2 or L2TPv3.
// For L2TPv2, set the TunnelID and PeerTunnelID fields.
type QuiescentTunnelConfig struct {
	LocalAddress      string
	RemoteAddress     string
	Version           ProtocolVersion
	TunnelID          TunnelID
	PeerTunnelID      TunnelID
	ControlConnID     ControlConnID
	PeerControlConnID ControlConnID
	Encap             EncapType
}

// NewQuiescentTunnel creates a new "quiescent" L2TP tunnel.
// A quiescent tunnel creates a user space socket for the
// L2TP control plane, but does not run the control protocol
// beyond acknowledging messages and optionally sending HELLO
// messages.
// The data plane is established on creation of the tunnel instance.
func NewQuiescentTunnel(nl *nll2tp.Conn, cfg *QuiescentTunnelConfig) (tunl *Tunnel, err error) {

	var sal, sap unix.Sockaddr
	var tid, ptid nll2tp.L2tpTunnelID

	// Sanity check the configuration
	if cfg.Version != ProtocolVersion3 && cfg.Encap == EncapTypeIP {
		return nil, fmt.Errorf("IP encapsulation only supported for L2TPv3 tunnels")
	}
	if cfg.Version == ProtocolVersion2 {
		if cfg.TunnelID == 0 || cfg.PeerTunnelID == 0 {
			return nil, fmt.Errorf("L2TPv2 tunnel IDs %v and %v must both be > 0",
				cfg.TunnelID, cfg.PeerTunnelID)
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

	// Initialise the control plane.
	// For quiescent tunnels we bind/connect immediately since we're not
	// runnning most of the control protocol.
	cp, err := newL2tpControlPlane(sal, sap)
	if err != nil {
		return nil, err
	}

	err = cp.Bind()
	if err != nil {
		return nil, err
	}

	err = cp.Connect()
	if err != nil {
		return nil, err
	}

	// Initialise the data plane.
	if cfg.Version == ProtocolVersion2 {
		tid = nll2tp.L2tpTunnelID(cfg.TunnelID)
		ptid = nll2tp.L2tpTunnelID(cfg.PeerTunnelID)
	} else {
		tid = nll2tp.L2tpTunnelID(cfg.ControlConnID)
		ptid = nll2tp.L2tpTunnelID(cfg.PeerControlConnID)
	}

	dp, err := newL2tpDataPlane(nl, cfg.LocalAddress, cfg.RemoteAddress, &nll2tp.TunnelConfig{
		Tid:     tid,
		Ptid:    ptid,
		Version: nll2tp.L2tpProtocolVersion(cfg.Version),
		Encap:   nll2tp.L2tpEncapType(cfg.Encap),
		// TODO: do we want/need to enable kernel debug?
		DebugFlags: nll2tp.L2tpDebugFlags(0)})
	if err != nil {
		cp.Close()
		return nil, err
	}

	err = dp.Up(cp.fd)
	if err != nil {
		cp.Close()
		dp.Close()
		return nil, err
	}

	return &Tunnel{
		dp: dp,
		cp: cp,
	}, nil
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

// NewStaticTunnel creates a new unmanaged L2TP tunnel.
// An unmanaged tunnel does not run any control protocol
// and instead merely instantiates the data plane in the
// kernel.  This is equivalent to the Linux 'ip l2tp'
// command(s).
// Unmanaged L2TPv2 tunnels are not practically useful,
// so NewStaticTunnel only supports creation of L2TPv3
// unmanaged tunnel instances.
func NewStaticTunnel(nl *nll2tp.Conn, cfg *StaticTunnelConfig) (tunl *Tunnel, err error) {

	dp, err := newL2tpDataPlane(nl, cfg.LocalAddress, cfg.RemoteAddress, &nll2tp.TunnelConfig{
		Tid:     nll2tp.L2tpTunnelID(cfg.ControlConnID),
		Ptid:    nll2tp.L2tpTunnelID(cfg.PeerControlConnID),
		Version: nll2tp.ProtocolVersion3,
		Encap:   nll2tp.L2tpEncapType(cfg.Encap),
		// TODO: do we want/need to enable kernel debug?
		DebugFlags: nll2tp.L2tpDebugFlags(0)})
	if err != nil {
		return nil, err
	}

	err = dp.UpStatic()
	if err != nil {
		dp.Close()
		return nil, err
	}

	return &Tunnel{dp: dp}, nil
}

// Close an L2TP tunnel.
func (t *Tunnel) Close() error {
	if t.cp != nil {
		if err := t.cp.Close(); err != nil {
			return err
		}
	}
	if t.dp != nil {
		if err := t.dp.Close(); err != nil {
			return err
		}
	}
	return nil
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
