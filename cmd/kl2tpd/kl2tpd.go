package main

import (
	"flag"
	"fmt"
	stdlog "log"
	"os"
	"os/signal"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/katalix/go-l2tp/config"
	"github.com/katalix/go-l2tp/l2tp"
	"golang.org/x/sys/unix"
)

type application struct {
	config   *config.Config
	logger   log.Logger
	l2tpCtx  *l2tp.Context
	sigChan  chan os.Signal
	shutdown bool
	wg       sync.WaitGroup
}

func newApplication(configPath string, verbose, nullDataplane bool) (*application, error) {

	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, unix.SIGINT, unix.SIGTERM)

	dataplane := l2tp.LinuxNetlinkDataPlane

	config, err := config.LoadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %v", err)
	}

	logger := log.NewLogfmtLogger(os.Stderr)
	if verbose {
		logger = level.NewFilter(logger, level.AllowDebug())
	} else {
		logger = level.NewFilter(logger, level.AllowInfo())
	}

	if nullDataplane {
		dataplane = nil
	}

	l2tpCtx, err := l2tp.NewContext(dataplane, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create L2TP context: %v", err)
	}

	return &application{
		config:  config,
		logger:  logger,
		l2tpCtx: l2tpCtx,
		sigChan: sigChan,
	}, nil
}

func (app *application) HandleEvent(event interface{}) {
	switch ev := event.(type) {
	case *l2tp.SessionUpEvent:

		level.Info(app.logger).Log(
			"message", "session up",
			"tunnel_id", ev.TunnelConfig.TunnelID,
			"session_id", ev.SessionConfig.SessionID,
			"peer_tunnel_id", ev.TunnelConfig.PeerTunnelID,
			"peer_session_id", ev.SessionConfig.PeerSessionID)

		pppd, err := newPPPoL2TP(ev.TunnelConfig.TunnelID,
			ev.SessionConfig.SessionID,
			ev.TunnelConfig.PeerTunnelID,
			ev.SessionConfig.PeerSessionID)
		if err != nil {
			level.Error(app.logger).Log(
				"message", "failed to create pppol2tp instance",
				"error", err)
			app.closeSession(ev.Session)
			break
		}
		err = pppd.run()
		if err != nil {
			level.Error(app.logger).Log(
				"message", "failed to run pppd",
				"error", err,
				"stderr", pppd.stderrBuf.String())
			app.closeSession(ev.Session)
			break
		}
	}
}

func (app *application) closeSession(s l2tp.Session) {
	app.wg.Add(1)
	go func() {
		defer app.wg.Done()
		s.Close()
	}()
}

func (app *application) run() int {

	defer app.l2tpCtx.Close()

	// Listen for L2TP events
	app.l2tpCtx.RegisterEventHandler(app)

	// Instantiate tunnels and sessions from the config file
	for _, tcfg := range app.config.Tunnels {

		// Only support l2tpv2/ppp
		if tcfg.Config.Version != l2tp.ProtocolVersion2 {
			level.Error(app.logger).Log(
				"message", "unsupported tunnel protocol version",
				"version", tcfg.Config.Version)
			return 1
		}

		tunl, err := app.l2tpCtx.NewDynamicTunnel(tcfg.Name, tcfg.Config)
		if err != nil {
			level.Error(app.logger).Log(
				"message", "failed to create tunnel",
				"tunnel_name", tcfg.Name,
				"error", err)
			return 1
		}

		for _, scfg := range tcfg.Sessions {
			_, err := tunl.NewSession(scfg.Name, scfg.Config)
			if err != nil {
				level.Error(app.logger).Log(
					"message", "failed to create session",
					"session_name", scfg.Name,
					"error", err)
				return 1
			}
		}
	}

	for !app.shutdown {
		select {
		case <-app.sigChan:
			level.Info(app.logger).Log("message", "received signal, shutting down")
			app.shutdown = true
		}
	}

	app.wg.Wait()

	return 0
}

func main() {
	cfgPathPtr := flag.String("config", "/etc/kl2tpd/kl2tpd.toml", "specify configuration file path")
	verbosePtr := flag.Bool("verbose", false, "toggle verbose log output")
	nullDataPlanePtr := flag.Bool("null", false, "toggle null data plane")
	flag.Parse()

	app, err := newApplication(*cfgPathPtr, *verbosePtr, *nullDataPlanePtr)
	if err != nil {
		stdlog.Fatalf("failed to instantiate application: %v", err)
	}

	os.Exit(app.run())
}
