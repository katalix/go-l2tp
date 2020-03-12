package l2tp

import (
	"fmt"

	"github.com/katalix/sl2tpd/internal/nll2tp"
	"golang.org/x/sys/unix"
)

type l2tpDataPlane struct {
	local, remote unix.Sockaddr
	nl            *nll2tp.Conn
	cfg           *nll2tp.TunnelConfig
	isUp          bool
}

func sockaddrAddrPort(sa unix.Sockaddr) (addr []byte, port uint16, err error) {
	switch sa.(type) {
	case *unix.SockaddrInet4:
		sa4, _ := sa.(*unix.SockaddrInet4)
		return sa4.Addr[:], uint16(sa4.Port), nil
	case *unix.SockaddrInet6:
		sa6, _ := sa.(*unix.SockaddrInet6)
		return sa6.Addr[:], uint16(sa6.Port), nil
	case *unix.SockaddrL2TPIP:
		l2tpip4, _ := sa.(*unix.SockaddrL2TPIP)
		return l2tpip4.Addr[:], 0, nil
	case *unix.SockaddrL2TPIP6:
		l2tpip6, _ := sa.(*unix.SockaddrL2TPIP6)
		return l2tpip6.Addr[:], 0, nil
	}
	return []byte{}, 0, fmt.Errorf("unexpected address type %T", addr)
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

	la, lp, err := sockaddrAddrPort(dp.local)
	if err != nil {
		return fmt.Errorf("invalid local address %v: %v", dp.local, err)
	}

	ra, rp, err := sockaddrAddrPort(dp.remote)
	if err != nil {
		return fmt.Errorf("invalid remote address %v: %v", dp.remote, err)
	}

	err = dp.nl.CreateStaticTunnel(la, lp, ra, rp, dp.cfg)
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

func newL2tpDataPlane(nl *nll2tp.Conn, local, remote unix.Sockaddr, cfg *nll2tp.TunnelConfig) (*l2tpDataPlane, error) {
	return &l2tpDataPlane{
		local:  local,
		remote: remote,
		nl:     nl,
		cfg:    cfg,
	}, nil
}
