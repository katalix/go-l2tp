package l2tp

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

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
