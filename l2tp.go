package main

import (
	"errors"
	"net"
	"os"

	"github.com/katalix/sl2tpd/internal/nll2tp"
	"golang.org/x/sys/unix"
)

type L2tpTunnel struct {
	local, remote *net.UDPAddr
	fd            int
	file          *os.File
	nl            *nll2tp.Conn
	cfg           nll2tp.TunnelConfig
}

// Create a new client-mode managed L2TP tunnel.
// A managed tunnel creates the tunnel socket in userspace
// and runs the control protocol over that socket as per
// RFC2661 (L2TPv2) or RFC3931 (L2TPv3).
func NewClientL2tpTunnel(nl *nll2tp.Conn,
	local_addr, remote_addr string,
	version nll2tp.L2tpProtocolVersion,
	encap nll2tp.L2tpEncapType,
	dbg_flags nll2tp.L2tpDebugFlags) (*L2tpTunnel, error) {
	return nil, errors.New("not implemented")
}

// Create a new "quiescent" L2TP tunnel.
// A quescent tunnel creates a user space socket for the
// L2TP control plane, but does not run the control protocol
// beyond acknowledging messages and optionally sending HELLO
// messages.
func NewQuiescentL2tpTunnel(nl *nll2tp.Conn,
	local_addr, remote_addr string,
	version nll2tp.L2tpProtocolVersion,
	encap nll2tp.L2tpEncapType,
	dbg_flags nll2tp.L2tpDebugFlags) (*L2tpTunnel, error) {
	return nil, errors.New("not implemented")
}

// Create a new unmanaged L2TP tunnel.
// An unmanaged tunnel does not run any control protocol
// and instead merely instantiates the data plane in the
// kernel.  This is equivalent to the Linux 'ip l2tp'
// command(s).
// L2TPv3 only is supported since unmanaged L2TPv2 tunnels
// are not practically useful.
func NewStaticL2tpTunnel(nl *nll2tp.Conn,
	local_addr, remote_addr string,
	tid nll2tp.L2tpTunnelID,
	ptid nll2tp.L2tpTunnelID,
	encap nll2tp.L2tpEncapType,
	dbg_flags nll2tp.L2tpDebugFlags) (*L2tpTunnel, error) {

	nlcfg := nll2tp.TunnelConfig{
		Tid:         tid,
		Ptid:        ptid,
		Version:     nll2tp.ProtocolVersion3,
		Encap:       encap,
		Debug_flags: dbg_flags}

	local, remote, err := initTunnelAddr(local_addr, remote_addr)
	if err != nil {
		return nil, err
	}

	// since this is a static tunnel we don't create a socket
	err = nl.CreateStaticTunnel(&local.IP, uint16(local.Port),
		&remote.IP, uint16(remote.Port),
		&nlcfg)
	if err != nil {
		return nil, err
	}

	return &L2tpTunnel{
		local:  local,
		remote: remote,
		fd:     -1,
		nl:     nl,
		cfg:    nlcfg}, nil
}

// Close an L2TP tunnel.
func (t *L2tpTunnel) Close() {
	t.nl.DeleteTunnel(&t.cfg)
	if t.file != nil {
		t.file.Close() // TODO: closes underlying fd?
	}
}

func netAddrToUnix(addr *net.UDPAddr) (unix.Sockaddr, error) {
	if addr != nil {
		if b := addr.IP.To4(); b != nil {
			return &unix.SockaddrInet4{
				Port: addr.Port,
				Addr: [4]byte{b[0], b[1], b[2], b[3]},
			}, nil
		} else if b := addr.IP.To16(); b != nil {
			return &unix.SockaddrInet6{
				Port: addr.Port,
				Addr: [16]byte{
					b[0], b[1], b[2], b[3],
					b[4], b[5], b[6], b[7],
					b[8], b[9], b[10], b[11],
					b[12], b[13], b[14], b[15],
				},
			}, nil
		}
	}
	return nil, errors.New("Unhandled address family")
}

func ipAddrLen(addr *net.IP) uint {
	switch {
	case addr == nil:
		return 0
	case addr.To4() != nil:
		return 4
	case addr.To16() != nil:
		return 16
	default:
		panic("Unexpected IP address length")
	}
}

func initTunnelAddr(local_addr, peer_addr string) (local, remote *net.UDPAddr, err error) {
	ul, err := net.ResolveUDPAddr("udp", local_addr)
	if err != nil {
		return nil, nil, err
	}

	up, err := net.ResolveUDPAddr("udp", peer_addr)
	if err != nil {
		return nil, nil, err
	}

	if ipAddrLen(&ul.IP) != ipAddrLen(&up.IP) {
		return nil, nil, errors.New("Tunnel local and peer addresses must be of the same address family")
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
		return -1, err
	}

	err = unix.Bind(fd, addr)
	if err != nil {
		unix.Close(fd)
		return -1, err
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
