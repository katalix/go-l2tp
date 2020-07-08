package main

import (
	"github.com/go-kit/kit/log"
	"github.com/katalix/go-l2tp/pppoe"
)

var _ l2tpdRunner = (*nilL2tpdRunner)(nil)
var _ l2tpd = (*nilL2tpd)(nil)

type nilL2tpdRunner struct {
}

type nilL2tpd struct {
}

func (runner *nilL2tpdRunner) spawn(sessionID pppoe.PPPoESessionID, lnsIPAddr string, logger log.Logger, eventHandler l2tpEventHandler) (l2tpd, error) {
	return &nilL2tpd{}, nil
}

func (l2tpd *nilL2tpd) wait() error {
	return nil
}

func (l2tpd *nilL2tpd) terminate() {

}
