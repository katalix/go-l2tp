package l2tp

import (
	"net"

	"github.com/katalix/sl2tpd/internal/nll2tp"
)

type l2tpDataPlane struct {
	local, remote *net.UDPAddr
	nl            *nll2tp.Conn
	cfg           *nll2tp.TunnelConfig
	isUp          bool
}

// Bring up the data plane: managed tunnel
func (dp *l2tpDataPlane) Up(tunnelSk int) error {
	err := dp.nl.CreateManagedTunnel(tunnelSk, dp.cfg)
	if err == nil {
		dp.isUp = true
	}
	return err
}

// Bring up the data plane: unmanaged tunnel
func (dp *l2tpDataPlane) UpStatic() error {
	err := dp.nl.CreateStaticTunnel(
		&dp.local.IP, uint16(dp.local.Port),
		&dp.remote.IP, uint16(dp.remote.Port),
		dp.cfg)
	if err == nil {
		dp.isUp = true
	}
	return err
}

// Close the data plane
func (dp *l2tpDataPlane) Close() error {
	if dp.isUp {
		return dp.nl.DeleteTunnel(dp.cfg)
	}
	return nil
}

func newL2tpDataPlane(nl *nll2tp.Conn,
	localAddr, remoteAddr string,
	cfg *nll2tp.TunnelConfig) (*l2tpDataPlane, error) {

	local, remote, err := initTunnelAddr(localAddr, remoteAddr)
	if err != nil {
		return nil, err
	}

	return &l2tpDataPlane{
		local:  local,
		remote: remote,
		nl:     nl,
		cfg:    cfg,
	}, nil
}
