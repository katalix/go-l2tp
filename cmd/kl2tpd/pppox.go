package main

// #include <stdio.h>
// #include <unistd.h>
// #include <linux/if_pppox.h>
import "C"

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/katalix/go-l2tp/l2tp"
)

/*
struct sockaddr_pppox uses the gcc attribute "packed", so cgo isn't
able to infer the fields of the structure.  We have to manually pack it.

typedef __be16 sid_t;
struct pppoe_addr {
	sid_t         sid;
	unsigned char remote[ETH_ALEN];
	char          dev[IFNAMSIZ];
};

struct sockaddr_pppox {
	__kernel_sa_family_t sa_family;
	unsigned int    sa_protocol;
	union {
		struct pppoe_addr  pppoe;
		struct pptp_addr   pptp;
	} sa_addr;
} __attribute__((packed));
*/
func newSockaddrPPPoE(sessionID uint16, destHWAddr [6]byte, interfaceName string) (
	addr *C.struct_sockaddr,
	addrLen C.socklen_t,
	err error) {
	if sessionID == 0 {
		return nil, 0, fmt.Errorf("session ID must be greater than zero")
	}
	if interfaceName == "" {
		return nil, 0, fmt.Errorf("interface name cannot be empty")
	}
	if len(interfaceName) > C.IFNAMSIZ-1 {
		return nil, 0, fmt.Errorf("interface name length cannot be greater than IFNAMSIZ")
	}

	var sa C.struct_sockaddr_pppox
	buf := (*[C.sizeof_struct_sockaddr_pppox]byte)(unsafe.Pointer(&sa))
	idx := 0

	// struct sockaddr_pppox -> sa_family
	*(*C.ushort)(unsafe.Pointer(&buf[idx])) = C.AF_PPPOX
	idx += C.sizeof_ushort

	// struct sockaddr_pppox -> sa_protocol
	*(*C.uint)(unsafe.Pointer(&buf[idx])) = C.PX_PROTO_OE
	idx += C.sizeof_uint

	// struct sockaddr_pppox -> sa_addr -> pppoe -> sid
	binary.BigEndian.PutUint16(buf[idx:idx+C.sizeof___u16], sessionID)
	idx += C.sizeof___u16

	// struct sockaddr_pppox -> sa_addr -> pppoe -> remote
	copy(buf[idx:idx+len(destHWAddr)], destHWAddr[:])
	idx += len(destHWAddr)

	// struct sockaddr_pppox -> sa_addr -> pppoe -> dev
	copy(buf[idx:], interfaceName)

	return (*C.struct_sockaddr)(unsafe.Pointer(&sa)), C.sizeof_struct_sockaddr_pppox, nil
}

/*
struct sockaddr_pppol2tp uses the gcc attribute "packed", so cgo isn't
able to infer the fields of the structure.  We have to manually pack it.

struct pppol2tp_addr {
	__kernel_pid_t	pid;
	int	fd;
	struct sockaddr_in addr;
	__u16 s_tunnel, s_session;
	__u16 d_tunnel, d_session;
};

struct sockaddr_pppol2tp {
	__kernel_sa_family_t sa_family;
	unsigned int    sa_protocol;
	struct pppol2tp_addr pppol2tp;
} __attribute__((packed));
*/
func newSockaddrPPPoL2TP4(tunnelID, sessionID, peerTunnelID, peerSessionID l2tp.ControlConnID) (
	addr *C.struct_sockaddr,
	addrLen C.socklen_t,
	err error) {
	if tunnelID == 0 || tunnelID > 65535 {
		return nil, 0, fmt.Errorf("tunnel ID %v out of range", tunnelID)
	}
	if sessionID == 0 || sessionID > 65535 {
		return nil, 0, fmt.Errorf("session ID %v out of range", sessionID)
	}
	if peerTunnelID == 0 || peerTunnelID > 65535 {
		return nil, 0, fmt.Errorf("peerTunnel ID %v out of range", peerTunnelID)
	}
	if peerSessionID == 0 || peerSessionID > 65535 {
		return nil, 0, fmt.Errorf("peerSession ID %v out of range", peerSessionID)
	}

	var sa C.struct_sockaddr_pppol2tp
	buf := (*[C.sizeof_struct_sockaddr_pppol2tp]byte)(unsafe.Pointer(&sa))
	idx := 0

	// struct sockaddr_pppol2tp -> sa_family
	*(*C.ushort)(unsafe.Pointer(&buf[idx])) = C.AF_PPPOX
	idx += C.sizeof_ushort

	// struct sockaddr_pppol2tp -> sa_protocol
	*(*C.uint)(unsafe.Pointer(&buf[idx])) = C.PX_PROTO_OL2TP
	idx += C.sizeof_uint

	// struct pppol2tp_addr -> pid
	*(*C.int)(unsafe.Pointer(&buf[idx])) = C.int(0)
	idx += C.sizeof_int

	// struct pppol2tp_addr -> fd
	*(*C.int)(unsafe.Pointer(&buf[idx])) = C.int(-1)
	idx += C.sizeof_int

	// struct pppol2tp_addr -> addr
	idx += C.sizeof_struct_sockaddr_in

	// struct pppol2tp_addr -> s_tunnel
	*(*C.__u16)(unsafe.Pointer(&buf[idx])) = C.__u16(tunnelID)
	idx += C.sizeof___u16

	// struct pppol2tp_addr -> s_session
	*(*C.__u16)(unsafe.Pointer(&buf[idx])) = C.__u16(sessionID)
	idx += C.sizeof___u16

	// struct pppol2tp_addr -> d_tunnel
	*(*C.__u16)(unsafe.Pointer(&buf[idx])) = C.__u16(peerTunnelID)
	idx += C.sizeof___u16

	// struct pppol2tp_addr -> d_session
	*(*C.__u16)(unsafe.Pointer(&buf[idx])) = C.__u16(peerSessionID)
	idx += C.sizeof___u16

	return (*C.struct_sockaddr)(unsafe.Pointer(&sa)), C.sizeof_struct_sockaddr_pppol2tp, nil
}

func socketPPPoL2TPv4(tunnelID, sessionID, peerTunnelID, peerSessionID l2tp.ControlConnID) (int, error) {
	addr, addrLen, err := newSockaddrPPPoL2TP4(tunnelID, sessionID, peerTunnelID, peerSessionID)
	if err != nil {
		return -1, fmt.Errorf("failed to build struct sockaddr_pppol2tp: %v", err)
	}

	fd, err := C.socket(C.AF_PPPOX, C.SOCK_DGRAM, C.PX_PROTO_OL2TP)
	if fd < 0 {
		return -1, fmt.Errorf("failed to open pppox socket: %v", err)
	}

	ret, err := C.connect(fd, addr, addrLen)
	if ret < 0 {
		C.close(fd)
		return -1, fmt.Errorf("failed to connect pppox socket: %v", err)
	}
	return int(fd), nil
}

func socketPPPoE(sessionID uint16, destHWAddr [6]byte, interfaceName string) (int, error) {
	addr, addrLen, err := newSockaddrPPPoE(sessionID, destHWAddr, interfaceName)
	if err != nil {
		return -1, fmt.Errorf("failed to build struct sockaddr_pppox: %v", err)
	}

	fd, err := C.socket(C.AF_PPPOX, C.SOCK_DGRAM, C.PX_PROTO_OE)
	if fd < 0 {
		return -1, fmt.Errorf("failed to open pppox socket: %v", err)
	}

	ret, err := C.connect(fd, addr, addrLen)
	if ret < 0 {
		C.close(fd)
		return -1, fmt.Errorf("failed to connect pppox socket: %v", err)
	}
	return int(fd), nil
}
