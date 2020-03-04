package l2tp

import (
	"errors"
	"fmt"
	"net"

	"github.com/katalix/sl2tpd/internal/nll2tp"
	"golang.org/x/sys/unix"
)

// ProtocolVersion is the version of the L2TP protocol to use
type ProtocolVersion int

const (
	// ProtocolVersion3Fallback is used for RFC3931 fallback mode
	ProtocolVersion3Fallback ProtocolVersion = 1
	// ProtocolVersion2 is used for RFC2661
	ProtocolVersion2 ProtocolVersion = 2
	// ProtocolVersion3 is used for RFC3931
	ProtocolVersion3 ProtocolVersion = 3
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
	version nll2tp.L2tpProtocolVersion,
	encap nll2tp.L2tpEncapType,
	dbgFlags nll2tp.L2tpDebugFlags) (*Tunnel, error) {
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
	tid, ptid nll2tp.L2tpTunnelID,
	version nll2tp.L2tpProtocolVersion,
	encap nll2tp.L2tpEncapType,
	dbgFlags nll2tp.L2tpDebugFlags) (*Tunnel, error) {

	cp, err := newL2tpControlPlane(localAddr, remoteAddr, true)
	if err != nil {
		return nil, err
	}

	dp, err := newL2tpDataPlane(nl, localAddr, remoteAddr, &nll2tp.TunnelConfig{
		Tid:        tid,
		Ptid:       ptid,
		Version:    version,
		Encap:      encap,
		DebugFlags: dbgFlags})
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
	tid, ptid nll2tp.L2tpTunnelID,
	encap nll2tp.L2tpEncapType,
	dbgFlags nll2tp.L2tpDebugFlags) (*Tunnel, error) {

	dp, err := newL2tpDataPlane(nl, localAddr, remoteAddr, &nll2tp.TunnelConfig{
		Tid:        tid,
		Ptid:       ptid,
		Version:    nll2tp.ProtocolVersion3,
		Encap:      encap,
		DebugFlags: dbgFlags})
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

func initTunnelAddr(localAddr, remoteAddr string) (local, remote *net.UDPAddr, err error) {
	// TODO: we need to handle the possibility of the local address being
	// unset (i.e. autobind).  This code will "work" for localAddr having a
	// len() of 0, yielding INADDR_ANY semantics.  Which is probably not what
	// we want: better to avoid the bind call if we want to autobind.
	ul, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve %v: %v", localAddr, err)
	}

	up, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve %v: %v", remoteAddr, err)
	}

	if ipAddrLen(&ul.IP) != ipAddrLen(&up.IP) {
		return nil, nil, errors.New("tunnel local and peer addresses must be of the same address family")
	}

	return ul, up, nil
}

func tunnelSocket(local, remote *net.UDPAddr, connect bool) (fd int, err error) {
	var family int

	switch ipAddrLen(&local.IP) {
	case 4:
		family = unix.AF_INET
	case 16:
		family = unix.AF_INET6
	default:
		panic("Unexpected IP address length")
	}

	addr, err := netAddrToUnix(local)
	if err != nil {
		return -1, err
	}

	// TODO: L2TPIP
	fd, err = unix.Socket(family, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		return -1, fmt.Errorf("socket: %v", err)
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("failed to set socket nonblocking: %v", err)
	}

	err = unix.Bind(fd, addr)
	if err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind: %v", err)
	}

	if connect {
		err = tunnelSocketConnect(fd, remote)
		if err != nil {
			unix.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}

func tunnelSocketConnect(fd int, remote *net.UDPAddr) error {
	addr, err := netAddrToUnix(remote)
	if err != nil {
		return err
	}
	return unix.Connect(fd, addr)
}
