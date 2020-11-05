package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/katalix/go-l2tp/l2tp"
)

type pppDaemon struct {
	session   l2tp.Session
	fd        int
	file      *os.File
	cmd       *exec.Cmd
	stdoutBuf *bytes.Buffer
	stderrBuf *bytes.Buffer
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

func newPPPDaemon(session l2tp.Session, tunnelID, sessionID, peerTunnelID, peerSessionID l2tp.ControlConnID) (*pppDaemon, error) {

	fd, err := socketPPPoL2TPv4(tunnelID, sessionID, peerTunnelID, peerSessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to create PPPoL2TP socket: %v", err)
	}

	var stdout, stderr bytes.Buffer
	file := os.NewFile(uintptr(fd), "pppol2tp")
	cmd := exec.Command(
		"/usr/sbin/pppd",
		"plugin", "pppol2tp.so",
		"pppol2tp", "3",
		"pppol2tp_tunnel_id", fmt.Sprintf("%v", tunnelID),
		"pppol2tp_session_id", fmt.Sprintf("%v", sessionID),
		"nodetach")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.ExtraFiles = append(cmd.ExtraFiles, file)

	return &pppDaemon{
		session:   session,
		fd:        int(fd),
		file:      file,
		cmd:       cmd,
		stdoutBuf: &stdout,
		stderrBuf: &stderr,
	}, nil
}
