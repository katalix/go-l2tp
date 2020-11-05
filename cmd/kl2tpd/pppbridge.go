package main

import (
	"fmt"

	"github.com/katalix/go-l2tp/l2tp"
	"golang.org/x/sys/unix"
)

var _ pseudowire = (*pppBridge)(nil)

type pppBridge struct {
	session         l2tp.Session
	pppoe, pppol2tp *pppChannel
}

func newPPPBridge(session l2tp.Session, tunnelID, sessionID, peerTunnelID, peerSessionID l2tp.ControlConnID, pppoeSessionID uint16, pppoePeerMAC [6]byte, pppoeInterfaceName string) (*pppBridge, error) {

	pppoeSk, err := socketPPPoE(pppoeSessionID, pppoePeerMAC, pppoeInterfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to create PPPoE socket: %v", err)
	}

	pppoeChan, err := newPPPChannel(pppoeSk)
	if err != nil {
		unix.Close(pppoeSk)
		return nil, fmt.Errorf("failed to create PPPoE channel: %v", err)
	}

	pppol2tpSk, err := socketPPPoL2TPv4(tunnelID, sessionID, peerTunnelID, peerSessionID)
	if err != nil {
		pppoeChan.close()
		return nil, fmt.Errorf("failed to create PPPoL2TP socket: %v", err)
	}

	pppol2tpChan, err := newPPPChannel(pppol2tpSk)
	if err != nil {
		pppoeChan.close()
		return nil, fmt.Errorf("failed to create PPPoL2TP channel: %v", err)
	}

	err = pppoeChan.bridge(pppol2tpChan)
	if err != nil {
		pppoeChan.close()
		pppol2tpChan.close()
		return nil, fmt.Errorf("failed to bridge PPPoE to PPPoL2TP channel: %v", err)
	}

	return &pppBridge{
		session:  session,
		pppoe:    pppoeChan,
		pppol2tp: pppol2tpChan,
	}, nil
}

func (pb *pppBridge) close() {
	if pb.pppoe != nil {
		pb.pppoe.close()
	}
	if pb.pppol2tp != nil {
		pb.pppol2tp.close()
	}
}

func (pb *pppBridge) getSession() l2tp.Session {
	return pb.session
}
