package main

import (
	"bufio"
	"flag"
	"fmt"
	stdlog "log"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/katalix/go-l2tp/config"
	"github.com/katalix/go-l2tp/l2tp"
	"golang.org/x/sys/unix"
)

type application struct {
	config  *config.Config
	logger  log.Logger
	l2tpCtx *l2tp.Context
	// sessionPPPoL2TP[tunnel_name][session_name]
	sessionPPPoL2TP map[string]map[string]*pppol2tp
	// sessionPPPdArgs[tunnel_name][session_name]
	sessionPPPdArgs map[string]map[string][]string
	sigChan         chan os.Signal
	pppCompleteChan chan *pppol2tp
	closeChan       chan interface{}
	wg              sync.WaitGroup
}

func newApplication(configPath string, verbose, nullDataplane bool) (app *application, err error) {

	app = &application{
		sigChan:         make(chan os.Signal, 1),
		sessionPPPoL2TP: make(map[string]map[string]*pppol2tp),
		sessionPPPdArgs: make(map[string]map[string][]string),
		pppCompleteChan: make(chan *pppol2tp),
		closeChan:       make(chan interface{}),
	}

	signal.Notify(app.sigChan, unix.SIGINT, unix.SIGTERM)

	app.config, err = config.LoadFileWithCustomParser(configPath, app)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %v", err)
	}

	logger := log.NewLogfmtLogger(os.Stderr)
	if verbose {
		app.logger = level.NewFilter(logger, level.AllowDebug())
	} else {
		app.logger = level.NewFilter(logger, level.AllowInfo())
	}

	dataplane := l2tp.LinuxNetlinkDataPlane
	if nullDataplane {
		dataplane = nil
	}

	app.l2tpCtx, err = l2tp.NewContext(dataplane, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create L2TP context: %v", err)
	}

	return app, nil
}

func readPPPdArgsFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return []string{}, fmt.Errorf("failed to open pppd arguments file %q: %v", path, err)
	}
	defer file.Close()

	args := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		args = append(args, strings.Split(scanner.Text(), " ")...)
	}
	return args, nil
}

func (app *application) ParseParameter(key string, value interface{}) error {
	return fmt.Errorf("unrecognised parameter %v", key)
}

func (app *application) ParseTunnelParameter(tunnel *config.NamedTunnel, key string, value interface{}) error {
	return fmt.Errorf("unrecognised parameter %v", key)
}

func (app *application) ParseSessionParameter(tunnel *config.NamedTunnel, session *config.NamedSession, key string, value interface{}) error {
	switch key {
	case "pppd_args":
		path, ok := value.(string)
		if !ok {
			return fmt.Errorf("failed to parse pppd_args parameter for session %s as a string", session.Name)
		}
		args, err := readPPPdArgsFile(path)
		if err != nil {
			return err
		}
		if _, ok := app.sessionPPPdArgs[tunnel.Name]; !ok {
			app.sessionPPPdArgs[tunnel.Name] = make(map[string][]string)
		}
		app.sessionPPPdArgs[tunnel.Name][session.Name] = args
		return nil
	}
	return fmt.Errorf("unrecognised parameter %v", key)
}

func (app *application) getSessionPPPdArgs(tunnelName, sessionName string) (args []string) {
	_, ok := app.sessionPPPdArgs[tunnelName]
	if !ok {
		goto fail
	}
	args, ok = app.sessionPPPdArgs[tunnelName][sessionName]
	if !ok {
		goto fail
	}
	return args
fail:
	level.Info(app.logger).Log(
		"message", "no pppd args specified in session config",
		"tunnel_name", tunnelName,
		"session_name", sessionName)
	return []string{}
}

func (app *application) HandleEvent(event interface{}) {
	switch ev := event.(type) {
	case *l2tp.TunnelUpEvent:
		if _, ok := app.sessionPPPoL2TP[ev.TunnelName]; !ok {
			app.sessionPPPoL2TP[ev.TunnelName] = make(map[string]*pppol2tp)
		}

	case *l2tp.TunnelDownEvent:
		delete(app.sessionPPPoL2TP, ev.TunnelName)

	case *l2tp.SessionUpEvent:

		level.Info(app.logger).Log(
			"message", "session up",
			"tunnel_name", ev.TunnelName,
			"session_name", ev.SessionName,
			"tunnel_id", ev.TunnelConfig.TunnelID,
			"session_id", ev.SessionConfig.SessionID,
			"peer_tunnel_id", ev.TunnelConfig.PeerTunnelID,
			"peer_session_id", ev.SessionConfig.PeerSessionID)

		pppol2tp, err := newPPPoL2TP(ev.Session,
			ev.TunnelConfig.TunnelID,
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

		pppdArgs := app.getSessionPPPdArgs(ev.TunnelName, ev.SessionName)
		pppol2tp.pppd.Args = append(pppol2tp.pppd.Args, pppdArgs...)

		err = pppol2tp.pppd.Start()
		if err != nil {
			level.Error(app.logger).Log(
				"message", "pppd failed to start",
				"error", err,
				"error_message", pppdExitCodeString(err),
				"stderr", pppol2tp.stderrBuf.String())
			app.closeSession(ev.Session)
			break
		}

		app.sessionPPPoL2TP[ev.TunnelName][ev.SessionName] = pppol2tp

		app.wg.Add(1)
		go func() {
			defer app.wg.Done()
			err = pppol2tp.pppd.Wait()
			if err != nil {
				level.Error(app.logger).Log(
					"message", "pppd exited with an error code",
					"error", err,
					"error_message", pppdExitCodeString(err))
			}
			app.pppCompleteChan <- pppol2tp
		}()

	case *l2tp.SessionDownEvent:

		level.Info(app.logger).Log(
			"message", "session down",
			"result", ev.Result,
			"tunnel_name", ev.TunnelName,
			"session_name", ev.SessionName,
			"tunnel_id", ev.TunnelConfig.TunnelID,
			"session_id", ev.SessionConfig.SessionID,
			"peer_tunnel_id", ev.TunnelConfig.PeerTunnelID,
			"peer_session_id", ev.SessionConfig.PeerSessionID)

		level.Info(app.logger).Log("message", "killing pppd")
		app.sessionPPPoL2TP[ev.TunnelName][ev.SessionName].pppd.Process.Signal(os.Interrupt)
		delete(app.sessionPPPoL2TP[ev.TunnelName], ev.SessionName)
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

	var shutdown bool
	for {
		select {
		case <-app.sigChan:
			if !shutdown {
				level.Info(app.logger).Log("message", "received signal, shutting down")
				shutdown = true
				go func() {
					app.l2tpCtx.Close()
					app.wg.Wait()
					level.Info(app.logger).Log("message", "graceful shutdown complete")
					close(app.closeChan)
				}()
			} else {
				level.Info(app.logger).Log("message", "pending graceful shutdown")
			}
		case pppol2tp, ok := <-app.pppCompleteChan:
			if !ok {
				close(app.closeChan)
			}
			level.Info(app.logger).Log("message", "pppd terminated")
			if !shutdown {
				app.closeSession(pppol2tp.session)
			}
		case <-app.closeChan:
			return 0
		}
	}
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
