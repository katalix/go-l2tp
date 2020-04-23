package l2tp

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"golang.org/x/sys/unix"
)

type quiescentTunnel struct {
	*baseTunnel
	sal, sap  unix.Sockaddr
	cp        *controlPlane
	xport     *transport
	dp        TunnelDataPlane
	closeChan chan bool
	wg        sync.WaitGroup
}

func (qt *quiescentTunnel) NewSession(name string, cfg *SessionConfig) (Session, error) {

	// Must have configuration
	if cfg == nil {
		return nil, fmt.Errorf("invalid nil config")
	}

	// Duplicate the configuration so we don't modify the user's copy
	myCfg := *cfg

	if _, ok := qt.findSessionByName(name); ok {
		return nil, fmt.Errorf("already have session %q", name)
	}

	if _, ok := qt.findSessionByID(cfg.SessionID); ok {
		return nil, fmt.Errorf("already have session %q", cfg.SessionID)
	}

	s, err := newStaticSession(name, qt, &myCfg)
	if err != nil {
		return nil, err
	}

	qt.linkSession(s)

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
		qt.baseTunnel.closeAllSessions()

		if qt.xport != nil {
			qt.xport.close()
		}
		if qt.cp != nil {
			qt.cp.close()
		}
		if qt.dp != nil {
			err := qt.dp.Down()
			level.Error(qt.logger).Log("message", "dataplane down failed", "error", err)
		}

		qt.parent.unlinkTunnel(qt)

		level.Info(qt.logger).Log("message", "close")
	}
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
		baseTunnel: newBaseTunnel(
			log.With(parent.logger, "tunnel_name", name),
			name,
			parent,
			cfg),
		sal:       sal,
		sap:       sap,
		closeChan: make(chan bool),
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

	qt.dp, err = parent.dp.NewTunnel(qt.cfg, qt.sal, qt.sap, qt.cp.fd)
	if err != nil {
		qt.Close()
		return nil, err
	}

	qt.xport, err = newTransport(qt.logger, qt.cp, transportConfig{
		HelloTimeout:      qt.cfg.HelloTimeout,
		TxWindowSize:      qt.cfg.WindowSize,
		MaxRetries:        qt.cfg.MaxRetries,
		RetryTimeout:      qt.cfg.RetryTimeout,
		AckTimeout:        time.Millisecond * 100,
		Version:           qt.cfg.Version,
		PeerControlConnID: qt.cfg.PeerTunnelID,
	})
	if err != nil {
		qt.Close()
		return nil, err
	}

	qt.wg.Add(1)
	go qt.xportReader()

	level.Info(qt.logger).Log(
		"message", "new quiescent tunnel",
		"version", qt.cfg.Version,
		"encap", qt.cfg.Encap,
		"local", qt.cfg.Local,
		"peer", qt.cfg.Peer,
		"tunnel_id", qt.cfg.TunnelID,
		"peer_tunnel_id", qt.cfg.PeerTunnelID)

	return
}
