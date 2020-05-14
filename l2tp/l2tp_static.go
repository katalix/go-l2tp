package l2tp

import (
	"fmt"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"golang.org/x/sys/unix"
)

type staticTunnel struct {
	*baseTunnel
	dp TunnelDataPlane
}

type staticSession struct {
	*baseSession
	dp     SessionDataPlane
	ifname string
}

func (st *staticTunnel) NewSession(name string, cfg *SessionConfig) (Session, error) {

	// Must have configuration
	if cfg == nil {
		return nil, fmt.Errorf("invalid nil config")
	}

	// Must have a non-zero session ID and peer session ID
	if cfg.SessionID == 0 {
		return nil, fmt.Errorf("session ID must be non-zero")
	}
	if cfg.PeerSessionID == 0 {
		return nil, fmt.Errorf("peer session ID must be non-zero")
	}

	// Clashes of name or session ID are not allowed
	if _, ok := st.findSessionByName(name); ok {
		return nil, fmt.Errorf("already have session %q", name)
	}

	if _, ok := st.findSessionByID(cfg.SessionID); ok {
		return nil, fmt.Errorf("already have session %q", cfg.SessionID)
	}

	// Duplicate the configuration so we don't modify the user's copy
	myCfg := *cfg
	s, err := newStaticSession(name, st, &myCfg)
	if err != nil {
		return nil, err
	}

	st.linkSession(s)

	return s, nil
}

func (st *staticTunnel) Close() {
	if st != nil {

		st.baseTunnel.closeAllSessions()

		if st.dp != nil {
			err := st.dp.Down()
			if err != nil {
				level.Error(st.logger).Log("message", "dataplane down failed", "error", err)
			}
		}

		st.parent.unlinkTunnel(st)

		level.Info(st.logger).Log("message", "close")
	}
}

func newStaticTunnel(name string, parent *Context, sal, sap unix.Sockaddr, cfg *TunnelConfig) (st *staticTunnel, err error) {
	st = &staticTunnel{
		baseTunnel: newBaseTunnel(
			log.With(parent.logger, "tunnel_name", name),
			name,
			parent,
			cfg),
	}

	st.dp, err = parent.dp.NewTunnel(st.cfg, sal, sap, -1)
	if err != nil {
		st.Close()
		return nil, err
	}

	level.Info(st.logger).Log(
		"message", "new static tunnel",
		"version", cfg.Version,
		"encap", cfg.Encap,
		"local", cfg.Local,
		"peer", cfg.Peer,
		"tunnel_id", cfg.TunnelID,
		"peer_tunnel_id", cfg.PeerTunnelID)

	return
}

func newStaticSession(name string, parent tunnel, cfg *SessionConfig) (ss *staticSession, err error) {

	tid := parent.getCfg().TunnelID
	ptid := parent.getCfg().PeerTunnelID

	ss = &staticSession{
		baseSession: newBaseSession(
			log.With(parent.getLogger(), "session_name", name),
			name,
			parent,
			cfg),
	}

	ss.dp, err = parent.getDP().NewSession(tid, ptid, ss.cfg)
	if err != nil {
		return nil, err
	}

	ss.ifname, err = ss.dp.GetInterfaceName()
	if err != nil {
		ss.dp.Down()
		return nil, err
	}

	level.Info(ss.logger).Log(
		"message", "new static session",
		"session_id", ss.cfg.SessionID,
		"peer_session_id", ss.cfg.PeerSessionID,
		"pseudowire", ss.cfg.Pseudowire)

	ss.parent.handleUserEvent(&SessionUpEvent{
		TunnelName:    ss.parent.getName(),
		Tunnel:        ss.parent,
		TunnelConfig:  ss.parent.getCfg(),
		SessionName:   ss.getName(),
		Session:       ss,
		SessionConfig: ss.cfg,
		InterfaceName: ss.ifname,
	})

	return
}

func (ss *staticSession) Close() {
	if ss.dp != nil {
		err := ss.dp.Down()
		if err != nil {
			level.Error(ss.logger).Log("message", "dataplane down failed", "error", err)
		}
	}

	ss.parent.handleUserEvent(&SessionDownEvent{
		TunnelName:    ss.parent.getName(),
		Tunnel:        ss.parent,
		TunnelConfig:  ss.parent.getCfg(),
		SessionName:   ss.getName(),
		Session:       ss,
		SessionConfig: ss.cfg,
		InterfaceName: ss.ifname,
	})

	ss.parent.unlinkSession(ss)
	level.Info(ss.logger).Log("message", "close")
}

func (ss *staticSession) kill() {
	ss.Close()
}
