package l2tp

import (
	"fmt"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/katalix/go-l2tp/internal/nll2tp"
	"golang.org/x/sys/unix"
)

type staticTunnel struct {
	logger   log.Logger
	name     string
	parent   *Context
	cfg      *TunnelConfig
	dp       dataPlane
	sessions map[string]Session
}

type staticSession struct {
	logger log.Logger
	name   string
	parent tunnel
	cfg    *SessionConfig
	dp     dataPlane
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
			st.dp.close(st.getNLConn())
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

func (st *staticTunnel) getNLConn() *nll2tp.Conn {
	return st.parent.nlconn
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

	st.dp, err = newStaticTunnelDataPlane(parent.nlconn, sal, sap, cfg)
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
	// Since we're static we instantiate the session in the
	// dataplane at the point of creation.
	dp, err := newSessionDataPlane(parent.getNLConn(), parent.getCfg().TunnelID, parent.getCfg().PeerTunnelID, cfg)
	if err != nil {
		return
	}

	ss = &staticSession{
		logger: log.With(parent.getLogger(), "session_name", name),
		name:   name,
		parent: parent,
		cfg:    cfg,
		dp:     dp,
	}

	level.Info(ss.logger).Log(
		"message", "new static session",
		"session_id", cfg.SessionID,
		"peer_session_id", cfg.PeerSessionID,
		"pseudowire", cfg.Pseudowire)

	return
}

func (ss *staticSession) Close() {
	ss.dp.close(ss.parent.getNLConn())
	ss.parent.unlinkSession(ss.name)
	level.Info(ss.logger).Log("message", "close")
}
