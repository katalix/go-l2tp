package l2tp

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type l2tpControlPlane struct {
	local, remote *net.UDPAddr
	fd            int
	file          *os.File
	rc            syscall.RawConn
	connected     bool
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

// Connect the control plane socket to the peer
func (cp *l2tpControlPlane) Connect() error {
	err := tunnelSocketConnect(cp.fd, cp.remote)
	if err == nil {
		cp.connected = true
	}
	return err
}

// Bind the control plane socket to local address
func (cp *l2tpControlPlane) Bind() error {
	return tunnelSocketBind(cp.fd, cp.local)
}

func tunnelSocket2(family, protocol int) (fd int, err error) {

	fd, err = unix.Socket(family, unix.SOCK_DGRAM, protocol)
	if err != nil {
		return -1, fmt.Errorf("socket: %v", err)
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("failed to set socket nonblocking: %v", err)
	}

	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("fcntl(F_GETFD): %v", err)
	}

	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC)
	if err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("fcntl(F_SETFD, FD_CLOEXEC): %v", err)
	}

	return fd, nil
}

func tunnelSocketBind(fd int, local *net.UDPAddr) error {
	addr, err := netAddrToUnix(local)
	if err != nil {
		return err
	}
	return unix.Bind(fd, addr)
}

func tunnelSocketConnect(fd int, remote *net.UDPAddr) error {
	addr, err := netAddrToUnix(remote)
	if err != nil {
		return err
	}
	return unix.Connect(fd, addr)
}

func newL2tpControlPlane(localAddr, remoteAddr string, encap EncapType) (*l2tpControlPlane, error) {

	var family int

	// TODO: we need to handle the possibility of the local address being
	// unset (i.e. autobind).  This code will "work" for localAddr having a
	// len() of 0, yielding INADDR_ANY semantics.  Which is probably not what
	// we want: better to avoid the bind call if we want to autobind.
	local, remote, err := initTunnelAddr(localAddr, remoteAddr)
	if err != nil {
		return nil, err
	}

	switch ipAddrLen(&remote.IP) {
	case 4:
		family = unix.AF_INET
	case 16:
		family = unix.AF_INET6
	default:
		panic("Unexpected IP address length")
	}

	fd, err := tunnelSocket2(family, unix.IPPROTO_UDP)
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
		connected: false,
	}, nil
}
