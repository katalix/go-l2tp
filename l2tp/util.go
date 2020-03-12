package l2tp

import (
	"errors"
	"fmt"
	"net"
)

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
