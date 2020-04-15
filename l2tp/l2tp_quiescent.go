package l2tp

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/katalix/go-l2tp/internal/nll2tp"
	"golang.org/x/sys/unix"
)

type quiescentTunnel struct {
	logger    log.Logger
	name      string
	parent    *Context
	cfg       *TunnelConfig
	cp        *controlPlane
	xport     *transport
	dp        dataPlane
	closeChan chan bool
	wg        sync.WaitGroup
	sessions  map[string]Session
}

func (qt *quiescentTunnel) NewSession(name string, cfg *SessionConfig) (Session, error) {

	if _, ok := qt.sessions[name]; ok {
		return nil, fmt.Errorf("already have session %q", name)
	}

	s, err := newStaticSession(name, qt, cfg)
	if err != nil {
		return nil, err
	}

	qt.sessions[name] = s

	return s, nil
}

func (qt *quiescentTunnel) Close() {
	if qt != nil {
		close(qt.closeChan)
		qt.wg.Wait()
		qt.close()
	}
}

func (qt *quiescentTunnel) close() {
	if qt != nil {
		for name, session := range qt.sessions {
			session.Close()
			qt.unlinkSession(name)
		}

		if qt.xport != nil {
			qt.xport.close()
		}
		if qt.cp != nil {
			qt.cp.close()
		}
		if qt.dp != nil {
			qt.dp.close(qt.getNLConn())
		}

		qt.parent.unlinkTunnel(qt)

		level.Info(qt.logger).Log("message", "close")
	}
}

func (dt *quiescentTunnel) getName() string {
	return dt.name
}

func (qt *quiescentTunnel) getCfg() *TunnelConfig {
	return qt.cfg
}

func (qt *quiescentTunnel) getNLConn() *nll2tp.Conn {
	return qt.parent.nlconn
}

func (qt *quiescentTunnel) getLogger() log.Logger {
	return qt.logger
}

func (qt *quiescentTunnel) unlinkSession(name string) {
	delete(qt.sessions, name)
}

func (qt *quiescentTunnel) xportReader() {
	// Although we're not running the control protocol we do need
	// to drain messages from the transport to avoid the receive
	// path blocking.
	defer qt.wg.Done()
	for {
		select {
		case <-qt.closeChan:
			return
		case _, ok := <-qt.xport.recvChan:
			if !ok {
				qt.close()
				return
			}
		}
	}
}

func newQuiescentTunnel(name string, parent *Context, sal, sap unix.Sockaddr, cfg *TunnelConfig) (qt *quiescentTunnel, err error) {
	qt = &quiescentTunnel{
		logger:    log.With(parent.logger, "tunnel_name", name),
		name:      name,
		parent:    parent,
		cfg:       cfg,
		closeChan: make(chan bool),
		sessions:  make(map[string]Session),
	}

	// Initialise the control plane.
	// We bind/connect immediately since we're not runnning most of the control protocol.
	qt.cp, err = newL2tpControlPlane(sal, sap)
	if err != nil {
		qt.Close()
		return nil, err
	}

	err = qt.cp.bind()
	if err != nil {
		qt.Close()
		return nil, err
	}

	err = qt.cp.connect()
	if err != nil {
		qt.Close()
		return nil, err
	}

	qt.dp, err = newManagedTunnelDataPlane(parent.nlconn, qt.cp.fd, cfg)
	if err != nil {
		qt.Close()
		return nil, err
	}

	qt.xport, err = newTransport(qt.logger, qt.cp, transportConfig{
		HelloTimeout:      cfg.HelloTimeout,
		TxWindowSize:      cfg.WindowSize,
		MaxRetries:        cfg.MaxRetries,
		RetryTimeout:      cfg.RetryTimeout,
		AckTimeout:        time.Millisecond * 100,
		Version:           cfg.Version,
		PeerControlConnID: cfg.PeerTunnelID,
	})
	if err != nil {
		qt.Close()
		return nil, err
	}

	qt.wg.Add(1)
	go qt.xportReader()

	level.Info(qt.logger).Log(
		"message", "new quiescent tunnel",
		"version", cfg.Version,
		"encap", cfg.Encap,
		"local", cfg.Local,
		"peer", cfg.Peer,
		"tunnel_id", cfg.TunnelID,
		"peer_tunnel_id", cfg.PeerTunnelID)

	return
}
