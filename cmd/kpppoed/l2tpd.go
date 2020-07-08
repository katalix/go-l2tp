package main

import (
	"github.com/go-kit/kit/log"
	"github.com/katalix/go-l2tp/pppoe"
)

type l2tpSessionUp struct {
	pppoeSessionID pppoe.PPPoESessionID
	l2tpTunnelID   uint32
	l2tpSessionID  uint32
}

type l2tpSessionDown struct {
	pppoeSessionID pppoe.PPPoESessionID
	l2tpTunnelID   uint32
	l2tpSessionID  uint32
}

type l2tpEventHandler interface {
	handleEvent(event interface{})
}

type l2tpdRunner interface {
	spawn(sessionID pppoe.PPPoESessionID, lnsIPAddr string, logger log.Logger, eventHandler l2tpEventHandler) (l2tpd, error)
}

type l2tpd interface {
	wait() error
	terminate()
}
