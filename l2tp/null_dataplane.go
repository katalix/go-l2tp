package l2tp

import (
	"golang.org/x/sys/unix"
)

var _ DataPlane = (*nullDataPlane)(nil)
var _ TunnelDataPlane = (*nullTunnelDataPlane)(nil)
var _ SessionDataPlane = (*nullSessionDataPlane)(nil)

type nullDataPlane struct {
}

type nullTunnelDataPlane struct {
}

type nullSessionDataPlane struct {
}

func (ndp *nullDataPlane) NewTunnel(tcfg *TunnelConfig, sal, sap unix.Sockaddr, fd int) (TunnelDataPlane, error) {
	return &nullTunnelDataPlane{}, nil
}

func (ndp *nullDataPlane) NewSession(tid, ptid ControlConnID, scfg *SessionConfig) (SessionDataPlane, error) {
	return &nullSessionDataPlane{}, nil
}

func (ndp *nullDataPlane) Close() {
}

func (tdp *nullTunnelDataPlane) Down() error {
	return nil
}

func (tdp *nullSessionDataPlane) Down() error {
	return nil
}
