package l2tp

import (
	"fmt"

	"github.com/katalix/sl2tpd/internal/nll2tp"
	"golang.org/x/sys/unix"
)

type l2tpDataPlane struct {
	local, remote unix.Sockaddr
	nl            *nll2tp.Conn
	cfg           *TunnelConfig
	isUp          bool
}

func tunnelCfgToNl(cfg *TunnelConfig) *nll2tp.TunnelConfig {
	// TODO: facilitate kernel level debug
	return &nll2tp.TunnelConfig{
		Tid:        nll2tp.L2tpTunnelID(cfg.TunnelID),
		Ptid:       nll2tp.L2tpTunnelID(cfg.PeerTunnelID),
		Version:    nll2tp.L2tpProtocolVersion(cfg.Version),
		Encap:      nll2tp.L2tpEncapType(cfg.Encap),
		DebugFlags: nll2tp.L2tpDebugFlags(0)}
}

func sockaddrAddrPort(sa unix.Sockaddr) (addr []byte, port uint16, err error) {
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		return sa.Addr[:], uint16(sa.Port), nil
	case *unix.SockaddrInet6:
		return sa.Addr[:], uint16(sa.Port), nil
	case *unix.SockaddrL2TPIP:
		return sa.Addr[:], 0, nil
	case *unix.SockaddrL2TPIP6:
		return sa.Addr[:], 0, nil
	}
	return []byte{}, 0, fmt.Errorf("unexpected address type %T", addr)
}

// Bring up the data plane: managed tunnel
func (dp *l2tpDataPlane) Up(tunnelSk int) error {
	err := dp.nl.CreateManagedTunnel(tunnelSk, tunnelCfgToNl(dp.cfg))
	if err == nil {
		dp.isUp = true
	}
	return err
}

// Bring up the data plane: unmanaged tunnel
func (dp *l2tpDataPlane) UpStatic() error {

	la, lp, err := sockaddrAddrPort(dp.local)
	if err != nil {
		return fmt.Errorf("invalid local address %v: %v", dp.local, err)
	}

	ra, rp, err := sockaddrAddrPort(dp.remote)
	if err != nil {
		return fmt.Errorf("invalid remote address %v: %v", dp.remote, err)
	}

	err = dp.nl.CreateStaticTunnel(la, lp, ra, rp, tunnelCfgToNl(dp.cfg))
	if err == nil {
		dp.isUp = true
	}
	return err
}

// Close the data plane
func (dp *l2tpDataPlane) Close() error {
	if dp.isUp {
		return dp.nl.DeleteTunnel(tunnelCfgToNl(dp.cfg))
	}
	return nil
}

func newL2tpDataPlane(nl *nll2tp.Conn, local, remote unix.Sockaddr, cfg *TunnelConfig) (*l2tpDataPlane, error) {
	return &l2tpDataPlane{
		local:  local,
		remote: remote,
		nl:     nl,
		cfg:    cfg,
	}, nil
}
