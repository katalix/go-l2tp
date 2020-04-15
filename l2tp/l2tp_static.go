package l2tp

import (
	"fmt"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"golang.org/x/sys/unix"
)

type staticTunnel struct {
	logger   log.Logger
	name     string
	parent   *Context
	cfg      *TunnelConfig
	dp       TunnelDataPlane
	sessions map[string]Session
}

type staticSession struct {
	logger log.Logger
	name   string
	parent tunnel
	cfg    *SessionConfig
	dp     SessionDataPlane
}

func (st *staticTunnel) NewSession(name string, cfg *SessionConfig) (Session, error) {

	if _, ok := st.sessions[name]; ok {
		return nil, fmt.Errorf("already have session %q", name)
	}

	s, err := newStaticSession(name, st, cfg)

	if err != nil {
		return nil, err
	}

	st.sessions[name] = s

	return s, nil
}

func (st *staticTunnel) Close() {
	if st != nil {

		for name, session := range st.sessions {
			session.Close()
			st.unlinkSession(name)
		}

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

func (dt *staticTunnel) getName() string {
	return dt.name
}

func (st *staticTunnel) getCfg() *TunnelConfig {
	return st.cfg
}

func (st *staticTunnel) getDP() DataPlane {
	return st.parent.dp
}

func (st *staticTunnel) getLogger() log.Logger {
	return st.logger
}

func (st *staticTunnel) unlinkSession(name string) {
	delete(st.sessions, name)
}

func newStaticTunnel(name string, parent *Context, sal, sap unix.Sockaddr, cfg *TunnelConfig) (st *staticTunnel, err error) {
	st = &staticTunnel{
		logger:   log.With(parent.logger, "tunnel_name", name),
		name:     name,
		parent:   parent,
		cfg:      cfg,
		sessions: make(map[string]Session),
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
		logger: log.With(parent.getLogger(), "session_name", name),
		name:   name,
		parent: parent,
		cfg:    cfg,
	}

	ss.dp, err = parent.getDP().NewSession(tid, ptid, ss.cfg)
	if err != nil {
		return nil, err
	}

	level.Info(ss.logger).Log(
		"message", "new static session",
		"session_id", cfg.SessionID,
		"peer_session_id", cfg.PeerSessionID,
		"pseudowire", cfg.Pseudowire)

	return
}

func (ss *staticSession) Close() {
	if ss.dp != nil {
		err := ss.dp.Down()
		if err != nil {
			level.Error(ss.logger).Log("message", "dataplane down failed", "error", err)
		}
	}
	ss.parent.unlinkSession(ss.name)
	level.Info(ss.logger).Log("message", "close")
}
