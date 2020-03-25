package l2tp

import (
	"fmt"

	"github.com/katalix/l2tp/internal/nll2tp"
	"github.com/tklauser/go-sysconf"
	"golang.org/x/sys/unix"
)

type dataPlane interface {
	close(nl *nll2tp.Conn)
}

type tunnelDataPlane struct {
	cfg *nll2tp.TunnelConfig
}

type sessionDataPlane struct {
	cfg *nll2tp.SessionConfig
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

func tunnelCfgToNl(cfg *TunnelConfig) (*nll2tp.TunnelConfig, error) {
	// TODO: facilitate kernel level debug
	return &nll2tp.TunnelConfig{
		Tid:        nll2tp.L2tpTunnelID(cfg.TunnelID),
		Ptid:       nll2tp.L2tpTunnelID(cfg.PeerTunnelID),
		Version:    nll2tp.L2tpProtocolVersion(cfg.Version),
		Encap:      nll2tp.L2tpEncapType(cfg.Encap),
		DebugFlags: nll2tp.L2tpDebugFlags(0)}, nil
}

func sessionCfgToNl(tid, ptid ControlConnID, cfg *SessionConfig) (*nll2tp.SessionConfig, error) {
	reorderTimeout := uint64(0)

	if cfg.ReorderTimeout != 0 {
		// TODO: we could ideally do this once since HZ isn't going to change
		clktck, err := sysconf.Sysconf(sysconf.SC_CLK_TCK)
		if err != nil {
			return nil, fmt.Errorf("failed to determine system clock tick rate: %v", err)
		}
		reorderTimeout = uint64(cfg.ReorderTimeout.Seconds() * float64(clktck))
	}

	// TODO: facilitate kernel level debug
	// TODO: IsLNS defaulting to false allows the peer to decide,
	// not sure whether this is a good idea or not really.
	return &nll2tp.SessionConfig{
		Tid:            nll2tp.L2tpTunnelID(tid),
		Ptid:           nll2tp.L2tpTunnelID(ptid),
		Sid:            nll2tp.L2tpSessionID(cfg.SessionID),
		Psid:           nll2tp.L2tpSessionID(cfg.PeerSessionID),
		PseudowireType: nll2tp.L2tpPwtype(cfg.Pseudowire),
		SendSeq:        cfg.SeqNum,
		RecvSeq:        cfg.SeqNum,
		IsLNS:          false,
		ReorderTimeout: reorderTimeout,
		LocalCookie:    cfg.Cookie,
		PeerCookie:     cfg.PeerCookie,
		IfName:         cfg.InterfaceName,
		L2SpecType:     nll2tp.L2tpL2specType(cfg.L2SpecType),
		DebugFlags:     nll2tp.L2tpDebugFlags(0)}, nil
}

func newStaticTunnelDataPlane(nl *nll2tp.Conn, local, peer unix.Sockaddr, cfg *TunnelConfig) (dataPlane, error) {

	nlcfg, err := tunnelCfgToNl(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert tunnel config for netlink use: %v", err)
	}

	la, lp, err := sockaddrAddrPort(local)
	if err != nil {
		return nil, fmt.Errorf("invalid local address %v: %v", local, err)
	}

	ra, rp, err := sockaddrAddrPort(peer)
	if err != nil {
		return nil, fmt.Errorf("invalid remote address %v: %v", peer, err)
	}

	err = nl.CreateStaticTunnel(la, lp, ra, rp, nlcfg)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate tunnel via. netlink: %v", err)
	}

	return &tunnelDataPlane{nlcfg}, nil
}

func newManagedTunnelDataPlane(nl *nll2tp.Conn, fd int, cfg *TunnelConfig) (dataPlane, error) {
	nlcfg, err := tunnelCfgToNl(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert tunnel config for netlink use: %v", err)
	}

	err = nl.CreateManagedTunnel(fd, nlcfg)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate tunnel via. netlink: %v", err)
	}

	return &tunnelDataPlane{nlcfg}, nil
}

func newSessionDataPlane(nl *nll2tp.Conn, tid, ptid ControlConnID, cfg *SessionConfig) (dataPlane, error) {
	nlcfg, err := sessionCfgToNl(tid, ptid, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert session config for netlink use: %v", err)
	}

	err = nl.CreateSession(nlcfg)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate session via. netlink: %v", err)
	}

	return &sessionDataPlane{nlcfg}, nil
}

func (t *tunnelDataPlane) close(nl *nll2tp.Conn) {
	_ = nl.DeleteTunnel(t.cfg)
}

func (s *sessionDataPlane) close(nl *nll2tp.Conn) {
	_ = nl.DeleteSession(s.cfg)
}
