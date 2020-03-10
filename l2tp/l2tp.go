package l2tp

import (
	"errors"

	"github.com/katalix/sl2tpd/internal/nll2tp"
)

// ProtocolVersion is the version of the L2TP protocol to use
type ProtocolVersion int

// TunnelID is the local tunnel identifier which must be unique
// to the system.
type TunnelID uint32

// SessionID is the local session identifier which must be unique
// to the parent tunnel for RFC2661, or the system for RFC3931.
type SessionID uint32

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

// NewClientTunnel creates a new client-mode managed L2TP tunnel.
// Client-mode tunnels take the LAC role in tunnel establishment,
// initiating the control protocol bringup using the SCCRQ message.
// Once the tunnel control protocol has established, the data plane
// will be instantiated in the kernel.
func NewClientTunnel(nl *nll2tp.Conn,
	localAddr, remoteAddr string,
	version ProtocolVersion,
	encap EncapType,
	dbgFlags DebugFlags) (*Tunnel, error) {
	// TODO: need protocol implementation
	return nil, errors.New("not implemented")
}

// NewQuiescentTunnel creates a new "quiescent" L2TP tunnel.
// A quiescent tunnel creates a user space socket for the
// L2TP control plane, but does not run the control protocol
// beyond acknowledging messages and optionally sending HELLO
// messages.
// The data plane is established on creation of the tunnel instance.
func NewQuiescentTunnel(nl *nll2tp.Conn,
	localAddr, remoteAddr string,
	tid, ptid TunnelID,
	version ProtocolVersion,
	encap EncapType,
	dbgFlags DebugFlags) (*Tunnel, error) {

	cp, err := newL2tpControlPlane(localAddr, remoteAddr, true)
	if err != nil {
		return nil, err
	}

	dp, err := newL2tpDataPlane(nl, localAddr, remoteAddr, &nll2tp.TunnelConfig{
		Tid:        nll2tp.L2tpTunnelID(tid),
		Ptid:       nll2tp.L2tpTunnelID(ptid),
		Version:    nll2tp.L2tpProtocolVersion(version),
		Encap:      nll2tp.L2tpEncapType(encap),
		DebugFlags: nll2tp.L2tpDebugFlags(dbgFlags)})
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

// NewStaticTunnel creates a new unmanaged L2TP tunnel.
// An unmanaged tunnel does not run any control protocol
// and instead merely instantiates the data plane in the
// kernel.  This is equivalent to the Linux 'ip l2tp'
// command(s).
// Unmanaged L2TPv2 tunnels are not practically useful,
// so NewStaticTunnel only supports creation of L2TPv3
// unmanaged tunnel instances.
func NewStaticTunnel(nl *nll2tp.Conn,
	localAddr, remoteAddr string,
	tid, ptid TunnelID,
	encap EncapType,
	dbgFlags DebugFlags) (*Tunnel, error) {

	dp, err := newL2tpDataPlane(nl, localAddr, remoteAddr, &nll2tp.TunnelConfig{
		Tid:        nll2tp.L2tpTunnelID(tid),
		Ptid:       nll2tp.L2tpTunnelID(ptid),
		Version:    nll2tp.ProtocolVersion3,
		Encap:      nll2tp.L2tpEncapType(encap),
		DebugFlags: nll2tp.L2tpDebugFlags(dbgFlags)})
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
