package l2tp

import (
	"fmt"

	"github.com/katalix/go-l2tp/internal/nll2tp"
	"golang.org/x/sys/unix"
)

var _ DataPlane = (*nlDataPlane)(nil)
var _ TunnelDataPlane = (*nlTunnelDataPlane)(nil)
var _ SessionDataPlane = (*nlSessionDataPlane)(nil)

type nlDataPlane struct {
	nlconn *nll2tp.Conn
}

type nlTunnelDataPlane struct {
	f   *nlDataPlane
	cfg *nll2tp.TunnelConfig
}

type nlSessionDataPlane struct {
	f             *nlDataPlane
	cfg           *nll2tp.SessionConfig
	interfaceName string
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

	// In kernel-land, the PPP/AC pseudowire is implemented using
	// an l2tp_ppp session, and a pppol2tp channel bridged to a
	// pppoe channel.  Hence we should ask for a PPP pseudowire here.
	pwtype := nll2tp.L2tpPwtype(cfg.Pseudowire)
	if pwtype == nll2tp.PwtypePppAc {
		pwtype = nll2tp.PwtypePpp
	}

	// TODO: facilitate kernel level debug
	// TODO: IsLNS defaulting to false allows the peer to decide,
	// not sure whether this is a good idea or not really.
	return &nll2tp.SessionConfig{
		Tid:            nll2tp.L2tpTunnelID(tid),
		Ptid:           nll2tp.L2tpTunnelID(ptid),
		Sid:            nll2tp.L2tpSessionID(cfg.SessionID),
		Psid:           nll2tp.L2tpSessionID(cfg.PeerSessionID),
		PseudowireType: pwtype,
		SendSeq:        cfg.SeqNum,
		RecvSeq:        cfg.SeqNum,
		IsLNS:          false,
		ReorderTimeout: uint64(cfg.ReorderTimeout.Milliseconds()),
		LocalCookie:    cfg.Cookie,
		PeerCookie:     cfg.PeerCookie,
		IfName:         cfg.InterfaceName,
		L2SpecType:     nll2tp.L2tpL2specType(cfg.L2SpecType),
		DebugFlags:     nll2tp.L2tpDebugFlags(0),
	}, nil
}

func (dpf *nlDataPlane) NewTunnel(tcfg *TunnelConfig, sal, sap unix.Sockaddr, fd int) (TunnelDataPlane, error) {

	nlcfg, err := tunnelCfgToNl(tcfg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert tunnel config for netlink use: %v", err)
	}

	// If the tunnel has a socket FD, create a managed tunnel dataplane.
	// Otherwise, create a static dataplane.
	if fd >= 0 {
		err = dpf.nlconn.CreateManagedTunnel(fd, nlcfg)
	} else {
		var la, ra []byte
		var lp, rp uint16

		la, lp, err = sockaddrAddrPort(sal)
		if err != nil {
			return nil, fmt.Errorf("invalid local address %v: %v", sal, err)
		}

		ra, rp, err = sockaddrAddrPort(sap)
		if err != nil {
			return nil, fmt.Errorf("invalid remote address %v: %v", sap, err)
		}

		err = dpf.nlconn.CreateStaticTunnel(la, lp, ra, rp, nlcfg)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate tunnel via. netlink: %v", err)
	}
	return &nlTunnelDataPlane{f: dpf, cfg: nlcfg}, nil
}

func (dpf *nlDataPlane) NewSession(tid, ptid ControlConnID, scfg *SessionConfig) (SessionDataPlane, error) {

	nlcfg, err := sessionCfgToNl(tid, ptid, scfg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert session config for netlink use: %v", err)
	}

	err = dpf.nlconn.CreateSession(nlcfg)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate session via. netlink: %v", err)
	}
	return &nlSessionDataPlane{f: dpf, cfg: nlcfg}, nil
}

func (dpf *nlDataPlane) Close() {

	if dpf.nlconn != nil {
		dpf.nlconn.Close()
	}
}

func (tdp *nlTunnelDataPlane) Down() error {
	return tdp.f.nlconn.DeleteTunnel(tdp.cfg)
}

func (sdp *nlSessionDataPlane) GetStatistics() (*SessionDataPlaneStatistics, error) {
	info, err := sdp.f.nlconn.GetSessionInfo(sdp.cfg)
	if err != nil {
		return nil, err
	}
	return &SessionDataPlaneStatistics{
		TxPackets: info.Statistics.TxPacketCount,
		TxBytes:   info.Statistics.TxBytes,
		TxErrors:  info.Statistics.TxErrorCount,
		RxPackets: info.Statistics.RxPacketCount,
		RxBytes:   info.Statistics.RxBytes,
		RxErrors:  info.Statistics.RxErrorCount,
	}, nil
}

func (sdp *nlSessionDataPlane) GetInterfaceName() (string, error) {
	if sdp.interfaceName == "" {
		info, err := sdp.f.nlconn.GetSessionInfo(sdp.cfg)
		if err != nil {
			return "", err
		}
		sdp.interfaceName = info.IfName
	}
	return sdp.interfaceName, nil
}

func (sdp *nlSessionDataPlane) Down() error {
	return sdp.f.nlconn.DeleteSession(sdp.cfg)
}

func newNetlinkDataPlane() (DataPlane, error) {

	nlconn, err := nll2tp.Dial()
	if err != nil {
		return nil, fmt.Errorf("failed to establish a netlink/L2TP connection: %v", err)
	}

	return &nlDataPlane{
		nlconn: nlconn,
	}, nil
}
