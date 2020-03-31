package l2tp

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type controlPlane struct {
	local, remote unix.Sockaddr
	fd            int
	file          *os.File
	rc            syscall.RawConn
	connected     bool
}

func (cp *controlPlane) recvFrom(p []byte) (n int, addr unix.Sockaddr, err error) {
	cerr := cp.rc.Read(func(fd uintptr) bool {
		n, addr, err = unix.Recvfrom(int(fd), p, unix.MSG_NOSIGNAL)
		return err != unix.EAGAIN && err != unix.EWOULDBLOCK
	})
	if err != nil {
		return n, addr, err
	}
	return n, addr, cerr
}

func (cp *controlPlane) write(b []byte) (n int, err error) {
	if cp.connected {
		return cp.file.Write(b)
	}
	return cp.writeTo(b, cp.remote)
}

func (cp *controlPlane) writeTo(p []byte, addr unix.Sockaddr) (n int, err error) {
	return len(p), cp.sendto(p, addr)
}

func (cp *controlPlane) sendto(p []byte, to unix.Sockaddr) (err error) {
	cerr := cp.rc.Write(func(fd uintptr) bool {
		err = unix.Sendto(int(fd), p, unix.MSG_NOSIGNAL, to)
		return err != unix.EAGAIN && err != unix.EWOULDBLOCK
	})
	if err != nil {
		return err
	}
	return cerr
}

func (cp *controlPlane) close() (err error) {
	if cp.file != nil {
		err = cp.file.Close()
		cp.file = nil
	}
	return
}

func (cp *controlPlane) connect() error {
	err := unix.Connect(cp.fd, cp.remote)
	if err == nil {
		cp.connected = true
	}
	return err
}

func (cp *controlPlane) connectTo(sa unix.Sockaddr) error {
	cp.remote = sa
	return cp.connect()
}

func (cp *controlPlane) bind() error {
	return unix.Bind(cp.fd, cp.local)
}

func tunnelSocket(family, protocol int) (fd int, err error) {

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

func newL2tpControlPlane(localAddr, remoteAddr unix.Sockaddr) (*controlPlane, error) {

	var family, protocol int

	switch localAddr.(type) {
	case *unix.SockaddrInet4:
		family = unix.AF_INET
		protocol = unix.IPPROTO_UDP
	case *unix.SockaddrInet6:
		family = unix.AF_INET6
		protocol = unix.IPPROTO_UDP
	case *unix.SockaddrL2TPIP:
		family = unix.AF_INET
		protocol = unix.IPPROTO_L2TP
	case *unix.SockaddrL2TPIP6:
		family = unix.AF_INET6
		protocol = unix.IPPROTO_L2TP
	default:
		return nil, fmt.Errorf("unexpected address type %T", localAddr)
	}

	fd, err := tunnelSocket(family, protocol)
	if err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "l2tp")
	sc, err := file.SyscallConn()
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	return &controlPlane{
		local:     localAddr,
		remote:    remoteAddr,
		fd:        fd,
		file:      file,
		rc:        sc,
		connected: false,
	}, nil
}
