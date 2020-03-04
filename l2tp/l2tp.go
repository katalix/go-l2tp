package l2tp

import (
	"errors"
	"fmt"
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
	rc            syscall.RawConn
	connected     bool
}

type l2tpDataPlane struct {
	local, remote *net.UDPAddr
	nl            *nll2tp.Conn
	cfg           *nll2tp.TunnelConfig
	isUp          bool
}

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
	n, _, err = cp.ReadFrom(b)
	return n, err
}

// Read data and sender address from the connection
func (cp *l2tpControlPlane) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, sa, err := cp.recvfrom(p)
	if err != nil {
		return n, nil, err
	}

	addr, err = unixToNetAddr(sa)
	if err != nil {
		return n, nil, err
	}

	return n, addr, nil
}

func (cp *l2tpControlPlane) recvfrom(p []byte) (n int, addr unix.Sockaddr, err error) {
	cerr := cp.rc.Read(func(fd uintptr) bool {
		n, addr, err = unix.Recvfrom(int(fd), p, unix.MSG_NOSIGNAL)
		return err != unix.EAGAIN && err != unix.EWOULDBLOCK
	})
	if err != nil {
		return n, addr, err
	}
	return n, addr, cerr
}

// Write data to the connection
func (cp *l2tpControlPlane) Write(b []byte) (n int, err error) {
	if cp.connected {
		return cp.file.Write(b)
	}
	return cp.WriteTo(b, cp.remote)
}

// WriteTo writes a packet with payload p to addr.
func (cp *l2tpControlPlane) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	uaddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, unix.EINVAL
	}
	sa, err := netAddrToUnix(uaddr)
	if err != nil {
		return 0, err
	}
	return len(p), cp.sendto(p, sa)
}

func (cp *l2tpControlPlane) sendto(p []byte, to unix.Sockaddr) (err error) {
	cerr := cp.rc.Write(func(fd uintptr) bool {
		err = unix.Sendto(int(fd), p, unix.MSG_NOSIGNAL, to)
		return err != unix.EAGAIN && err != unix.EWOULDBLOCK
	})
	if err != nil {
		return err
	}
	return cerr
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

// Close the data plane
func (dp *l2tpDataPlane) Close() error {
	if dp.isUp {
		return dp.nl.DeleteTunnel(dp.cfg)
	}
	return nil
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

// Bring up the data plane: managed tunnel
func (dp *l2tpDataPlane) Up(tunnelSk int) error {
	err := dp.nl.CreateManagedTunnel(tunnelSk, dp.cfg)
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

func unixToNetAddr(addr unix.Sockaddr) (*net.UDPAddr, error) {
	if addr != nil {
		if sa4, ok := addr.(*unix.SockaddrInet4); ok {
			return &net.UDPAddr{
				IP:   net.IP{sa4.Addr[0], sa4.Addr[1], sa4.Addr[2], sa4.Addr[3]},
				Port: sa4.Port,
			}, nil
		} else if sa6, ok := addr.(*unix.SockaddrInet6); ok {
			// TODO: SockaddrInet6 has a uint32 ZoneId, while UDPAddr
			// has a Zone string.  How to convert between the two?
			return &net.UDPAddr{
				IP: net.IP{
					sa6.Addr[0], sa6.Addr[1], sa6.Addr[2], sa6.Addr[3],
					sa6.Addr[4], sa6.Addr[5], sa6.Addr[6], sa6.Addr[7],
					sa6.Addr[8], sa6.Addr[9], sa6.Addr[10], sa6.Addr[11],
					sa6.Addr[12], sa6.Addr[13], sa6.Addr[14], sa6.Addr[15]},
				Port: sa6.Port,
			}, nil
		}
	}
	return nil, errors.New("unhandled address family")
}

func netAddrToUnix(addr *net.UDPAddr) (unix.Sockaddr, error) {
	if addr != nil {
		if b := addr.IP.To4(); b != nil {
			return &unix.SockaddrInet4{
				Port: addr.Port,
				Addr: [4]byte{b[0], b[1], b[2], b[3]},
			}, nil
		} else if b := addr.IP.To16(); b != nil {
			// TODO: SockaddrInet6 has a uint32 ZoneId, while UDPAddr
			// has a Zone string.  How to convert between the two?
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
	return nil, errors.New("unhandled address family")
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

func newL2tpControlPlane(localAddr, remoteAddr string, connect bool) (*l2tpControlPlane, error) {

	local, remote, err := initTunnelAddr(localAddr, remoteAddr)
	if err != nil {
		return nil, err
	}

	fd, err := tunnelSocket(local, remote, connect)
	if err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "l2tp")
	sc, err := file.SyscallConn()
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	return &l2tpControlPlane{
		local:     local,
		remote:    remote,
		fd:        fd,
		file:      file,
		rc:        sc,
		connected: connect,
	}, nil
}

func newL2tpDataPlane(nl *nll2tp.Conn,
	localAddr, remoteAddr string,
	cfg *nll2tp.TunnelConfig) (*l2tpDataPlane, error) {

	local, remote, err := initTunnelAddr(localAddr, remoteAddr)
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
