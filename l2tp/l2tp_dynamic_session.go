package l2tp

import (
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type dynamicSession struct {
	logger log.Logger
	name   string
	parent tunnel
	cfg    *SessionConfig
	dp     SessionDataPlane
}

func (ds *dynamicSession) Close() {
	// TODO
}

// Create a new client/LAC mode session instance
func newDynamicSession(name string, parent tunnel, cfg *SessionConfig) (ds *dynamicSession, err error) {

	ds = &dynamicSession{
		logger: log.With(parent.getLogger(), "session_name", name),
		name:   name,
		parent: parent,
		cfg:    cfg,
	}

	/* TODO: once we've established the session
	tid := parent.getCfg().TunnelID
	ptid := parent.getCfg().PeerTunnelID

	ds.dp, err = parent.getDP().NewSession(tid, ptid, ss.cfg)
	if err != nil {
		return nil, err
	}
	*/

	level.Info(ds.logger).Log(
		"message", "new static session",
		"session_id", ds.cfg.SessionID,
		"peer_session_id", ds.cfg.PeerSessionID,
		"pseudowire", ds.cfg.Pseudowire)

	return
}
