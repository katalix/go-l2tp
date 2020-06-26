package pppoe

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type PPPoEConn struct {
	iface *net.Interface
	fd    int
	file  *os.File
	rc    syscall.RawConn
}

func newRawSocket(protocol int) (fd int, err error) {

	// raw socket since we want to read/write link-level packets
	fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, protocol)
	if err != nil {
		return -1, fmt.Errorf("socket: %v", err)
	}

	// make the socket nonblocking so we can use it with the runtime poller
	if err = unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("failed to set socket nonblocking: %v", err)
	}

	// set the socket CLOEXEC to prevent passing it to child processes
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

	// allow broadcast
	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
	if err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("setsockopt(SO_BROADCAST): %v", err)
	}

	return
}

func NewDiscoveryConnection(ifname string) (conn *PPPoEConn, err error) {

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain details of interface \"%s\": %v", ifname, err)
	}

	fd, err := newRawSocket(int(ethTypeDiscoveryNetUint16()))
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %v", err)
	}

	// bind to the interface specified
	sa := unix.SockaddrLinklayer{
		Protocol: ethTypeDiscoveryNetUint16(),
		Ifindex:  iface.Index,
	}
	err = unix.Bind(fd, &sa)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to bind socket: %v", err)
	}

	// register the socket with the runtime
	file := os.NewFile(uintptr(fd), "pppoe")
	rc, err := file.SyscallConn()
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	return &PPPoEConn{
		iface: iface,
		fd:    fd,
		file:  file,
		rc:    rc,
	}, nil
}

func (c *PPPoEConn) Close() (err error) {
	if c.file != nil {
		err = c.file.Close()
		c.file = nil
	}
	return
}

func (c *PPPoEConn) Send(b []byte) (n int, err error) {
	return c.file.Write(b)
}

func (c *PPPoEConn) Recv(b []byte) (n int, err error) {
	return c.file.Read(b)
}

func (c *PPPoEConn) HWAddr() (addr [6]byte) {
	if len(c.iface.HardwareAddr) >= 6 {
		return [6]byte{
			c.iface.HardwareAddr[0],
			c.iface.HardwareAddr[1],
			c.iface.HardwareAddr[2],
			c.iface.HardwareAddr[3],
			c.iface.HardwareAddr[4],
			c.iface.HardwareAddr[5],
		}
	}
	return [6]byte{}
}
