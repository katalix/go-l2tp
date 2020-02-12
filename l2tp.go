package main

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/katalix/sl2tpd/internal/nll2tp"
	"golang.org/x/sys/unix"
)

type l2tpControlPlane struct {
	local, remote *net.UDPAddr
	fd            int
	file          *os.File
}

type l2tpDataPlane struct {
	local, remote *net.UDPAddr
	nl            *nll2tp.Conn
	cfg           *nll2tp.TunnelConfig
	isUp          bool
}

type L2tpTunnel struct {
	dp *l2tpDataPlane
	cp *l2tpControlPlane
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
	// TODO: need protocol implementation
	return nil, errors.New("not implemented")
}

// Create a new "quiescent" L2TP tunnel.
// A quescent tunnel creates a user space socket for the
// L2TP control plane, but does not run the control protocol
// beyond acknowledging messages and optionally sending HELLO
// messages.
func NewQuiescentL2tpTunnel(nl *nll2tp.Conn,
	local_addr, remote_addr string,
	tid, ptid nll2tp.L2tpTunnelID,
	version nll2tp.L2tpProtocolVersion,
	encap nll2tp.L2tpEncapType,
	dbg_flags nll2tp.L2tpDebugFlags) (*L2tpTunnel, error) {

	cp, err := newL2tpControlPlane(local_addr, remote_addr, false)
	if err != nil {
		return nil, err
	}

	dp, err := newL2tpDataPlane(nl, local_addr, remote_addr, &nll2tp.TunnelConfig{
		Tid:         tid,
		Ptid:        ptid,
		Version:     version,
		Encap:       encap,
		Debug_flags: dbg_flags})
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

	return &L2tpTunnel{
		dp: dp,
		cp: cp,
	}, nil
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
	tid, ptid nll2tp.L2tpTunnelID,
	encap nll2tp.L2tpEncapType,
	dbg_flags nll2tp.L2tpDebugFlags) (*L2tpTunnel, error) {

	dp, err := newL2tpDataPlane(nl, local_addr, remote_addr, &nll2tp.TunnelConfig{
		Tid:         tid,
		Ptid:        ptid,
		Version:     nll2tp.ProtocolVersion3,
		Encap:       encap,
		Debug_flags: dbg_flags})
	if err != nil {
		return nil, err
	}

	err = dp.UpStatic()
	if err != nil {
		dp.Close()
		return nil, err
	}

	return &L2tpTunnel{dp: dp}, nil
}

// Obtain local address
func (cp *l2tpControlPlane) LocalAddr() net.Addr {
	return cp.local
}

// Obtain remote address
func (cp *l2tpControlPlane) RemoteAddr() net.Addr {
	return cp.remote
}

// Read data from the connection.
func (cp *l2tpControlPlane) Read(b []byte) (n int, err error) {
	return cp.file.Read(b)
}

// Write data to the connection
func (cp *l2tpControlPlane) Write(b []byte) (n int, err error) {
	return cp.file.Write(b)
}

// Set deadline for read and write operations
func (cp *l2tpControlPlane) SetDeadline(t time.Time) error {
	return cp.file.SetDeadline(t)
}

// Set deadline for read operations
func (cp *l2tpControlPlane) SetReadDeadline(t time.Time) error {
	return cp.file.SetReadDeadline(t)
}

// Set deadline for write operations
func (cp *l2tpControlPlane) SetWriteDeadline(t time.Time) error {
	return cp.file.SetWriteDeadline(t)
}

// Close the control plane
func (cp *l2tpControlPlane) Close() error {
	// TODO: kick the protocol to shut down
	return cp.file.Close() // TODO: verify this closes the underlying fd
}

// SyscallConn interface for control plane
func (cp *l2tpControlPlane) SyscallConn() (syscall.RawConn, error) {
	return cp.file.SyscallConn()
}

// Close the data plane
func (dp *l2tpDataPlane) Close() error {
	if dp.isUp {
		return dp.nl.DeleteTunnel(dp.cfg)
	}
	return nil
}

// Close an L2TP tunnel.
func (t *L2tpTunnel) Close() error {
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

// Bring up the data plane: managed tunnel
func (dp *l2tpDataPlane) Up(tunnel_sk int) error {
	err := dp.nl.CreateManagedTunnel(tunnel_sk, dp.cfg)
	if err == nil {
		dp.isUp = true
	}
	return err
}

// Bring up the data plane: unmanaged tunnel
func (dp *l2tpDataPlane) UpStatic() error {
	err := dp.nl.CreateStaticTunnel(
		&dp.local.IP, uint16(dp.local.Port),
		&dp.remote.IP, uint16(dp.remote.Port),
		dp.cfg)
	if err == nil {
		dp.isUp = true
	}
	return err
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

	if err = unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
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

func newL2tpControlPlane(local_addr, remote_addr string, connect bool) (*l2tpControlPlane, error) {

	local, remote, err := initTunnelAddr(local_addr, remote_addr)
	if err != nil {
		return nil, err
	}

	fd, err := tunnelSocket(local, remote, connect)
	if err != nil {
		return nil, err
	}

	return &l2tpControlPlane{
		local:  local,
		remote: remote,
		fd:     fd,
		file:   os.NewFile(uintptr(fd), "l2tp"),
	}, nil
}

func newL2tpDataPlane(nl *nll2tp.Conn,
	local_addr, remote_addr string,
	cfg *nll2tp.TunnelConfig) (*l2tpDataPlane, error) {

	local, remote, err := initTunnelAddr(local_addr, remote_addr)
	if err != nil {
		return nil, err
	}

	return &l2tpDataPlane{
		local:  local,
		remote: remote,
		nl:     nl,
		cfg:    cfg,
	}, nil
}
