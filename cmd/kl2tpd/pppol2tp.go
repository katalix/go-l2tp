package main

// #include <stdio.h>
// #include <linux/if_pppox.h>
import "C"

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"github.com/katalix/go-l2tp/l2tp"
)

type pppol2tp struct {
	session   l2tp.Session
	fd        int
	file      *os.File
	pppd      *exec.Cmd
	stdoutBuf *bytes.Buffer
	stderrBuf *bytes.Buffer
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

func newPPPoL2TP(session l2tp.Session, tunnelID, sessionID, peerTunnelID, peerSessionID l2tp.ControlConnID) (*pppol2tp, error) {
	addr, addrLen, err := newSockaddrPPPoL2TP4(tunnelID, sessionID, peerTunnelID, peerSessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to build struct sockaddr_pppol2tp: %v", err)
	}

	fd, err := C.socket(C.AF_PPPOX, C.SOCK_DGRAM, C.PX_PROTO_OL2TP)
	if fd < 0 {
		return nil, fmt.Errorf("failed to open pppox socket: %v", err)
	}

	ret, err := C.connect(fd, addr, addrLen)
	if ret < 0 {
		return nil, fmt.Errorf("failed to connect pppox socket: %v", err)
	}

	var stdout, stderr bytes.Buffer
	file := os.NewFile(uintptr(fd), "pppol2tp")
	pppd := exec.Command(
		"/usr/sbin/pppd",
		"plugin", "pppol2tp.so",
		"pppol2tp", "3",
		"pppol2tp_tunnel_id", fmt.Sprintf("%v", tunnelID),
		"pppol2tp_session_id", fmt.Sprintf("%v", sessionID),
		"nodetach")
	pppd.Stdout = &stdout
	pppd.Stderr = &stderr
	pppd.ExtraFiles = append(pppd.ExtraFiles, file)

	return &pppol2tp{
		session:   session,
		fd:        int(fd),
		file:      file,
		pppd:      pppd,
		stdoutBuf: &stdout,
		stderrBuf: &stderr,
	}, nil
}

func pppdExitCodeString(err error) string {
	// ref: pppd(8) section EXIT STATUS
	switch err.Error() {
	case "exit status 0":
		return "pppd established successfully and terminated at peer's request"
	case "exit status 1":
		return "immediately fatal error (e.g. essential system call failed, or out of memory)"
	case "exit status 2":
		return "error detected during options parsing/processing"
	case "exit status 3":
		return "pppd is not setuid-root and the invoking user is not root"
	case "exit status 4":
		return "the kernel does not support PPP (possibly the module is not loaded or unavailable)"
	case "exit status 5":
		return "pppd terminated due to SIGINT, SIGTERM, or SIGHUP signal"
	case "exit status 6":
		return "the serial port could not be locked"
	case "exit status 7":
		return "the serial port could not be opened"
	case "exit status 8":
		return "the connect script returned a non-zero exit status"
	case "exit status 9":
		return "the command specified as an argument to the pty option could not be run"
	case "exit status 10":
		return "PPP negotiation failed (that is, didn't reach the point where at least one network protocol was running)"
	case "exit status 11":
		return "the peer system failed or refused to authenticate itself"
	case "exit status 12":
		return "the link was established successfully and terminated because it was idle"
	case "exit status 13":
		return "the link was established successfully and terminated because the connect time limit was reached"
	case "exit status 14":
		return "callback was negotiated and an incoming call should arrive shortly"
	case "exit status 15":
		return "the link was terminated because the peer is not responding to echo requests"
	case "exit status 16":
		return "the link was terminated by the modem hanging up"
	case "exit status 17":
		return "the ppp negotiation failed because serial loopback was detected"
	case "exit status 18":
		return "the init script returned a non-zero exit status"
	case "exit status 19":
		return "we failed to authenticate ourselves to the peer"
	}
	return err.Error()
}
