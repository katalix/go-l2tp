/*
The kl2tpd command is a daemon for creating dynamic L2TPv2 tunnels and sessions.

Package l2tp is used for the L2TPv2 control protocol and Linux kernel dataplane
operations.  For established sessions, kl2tpd spawns pppd(8) instances to run the
PPP protocol and bring up a network interface.

kl2tpd is driven by a configuration file which describes the tunnel and session
instances to create.  For more information on the configuration file format please
refer to package config's documentation.

In addition to the configuration options offered by package config, kl2tpd extends
the session configuration table to allow for the configuration of pppd:

	[tunnel.t1.session.s1]
	pppd_args = "/etc/pppd_args.txt"

The pppd_args parameter specifies a file to read for pppd arguments.  These should
either be whitespace or newline delimited, and should call out pppd command line arguments
as described in the pppd manpage.  kl2tpd augments the arguments from the command file
with arguments specific to the establishment of the PPPoL2TP session using the pppd
pppol2tp plugin.
*/
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

type sessionPPPArgs struct {
	pppdArgs []string
}

type kl2tpdConfig struct {
	config *config.Config
	// pppArgs[tunnel_name][session_name]
	pppArgs map[string]map[string]*sessionPPPArgs
}

type application struct {
	cfg     *kl2tpdConfig
	logger  log.Logger
	l2tpCtx *l2tp.Context
	// sessionPPPoL2TP[tunnel_name][session_name]
	sessionPPPoL2TP map[string]map[string]*pppol2tp
	sigChan         chan os.Signal
	pppCompleteChan chan *pppol2tp
	closeChan       chan interface{}
	wg              sync.WaitGroup
}

func newKl2tpdConfig() (cfg *kl2tpdConfig) {
	return &kl2tpdConfig{
		pppArgs: make(map[string]map[string]*sessionPPPArgs),
	}
}

func (cfg *kl2tpdConfig) readPPPdArgsFile(path string) ([]string, error) {
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

func (cfg *kl2tpdConfig) addSession(tunnelName, sessionName string) {
	if _, ok := cfg.pppArgs[tunnelName]; !ok {
		cfg.pppArgs[tunnelName] = make(map[string]*sessionPPPArgs)
	}
	if _, ok := cfg.pppArgs[tunnelName][sessionName]; !ok {
		cfg.pppArgs[tunnelName][sessionName] = &sessionPPPArgs{}
	}
}

func (cfg *kl2tpdConfig) setSessionPPPdArgs(tunnelName, sessionName string, args []string) {
	cfg.addSession(tunnelName, sessionName)
	cfg.pppArgs[tunnelName][sessionName].pppdArgs = args
}

func (cfg *kl2tpdConfig) ParseParameter(key string, value interface{}) error {
	return fmt.Errorf("unrecognised parameter %v", key)
}

func (cfg *kl2tpdConfig) ParseTunnelParameter(tunnel *config.NamedTunnel, key string, value interface{}) error {
	return fmt.Errorf("unrecognised parameter %v", key)
}

func (cfg *kl2tpdConfig) ParseSessionParameter(tunnel *config.NamedTunnel, session *config.NamedSession, key string, value interface{}) error {
	switch key {
	case "pppd_args":
		path, ok := value.(string)
		if !ok {
			return fmt.Errorf("failed to parse pppd_args parameter for session %s as a string", session.Name)
		}
		args, err := cfg.readPPPdArgsFile(path)
		if err != nil {
			return err
		}
		cfg.setSessionPPPdArgs(tunnel.Name, session.Name, args)
		return nil
	}
	return fmt.Errorf("unrecognised parameter %v", key)
}

func newApplication(cfg *kl2tpdConfig, verbose, nullDataplane bool) (app *application, err error) {

	app = &application{
		cfg:             cfg,
		sigChan:         make(chan os.Signal, 1),
		sessionPPPoL2TP: make(map[string]map[string]*pppol2tp),
		pppCompleteChan: make(chan *pppol2tp),
		closeChan:       make(chan interface{}),
	}

	signal.Notify(app.sigChan, unix.SIGINT, unix.SIGTERM)

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

func (app *application) getSessionPPPArgs(tunnelName, sessionName string) (args *sessionPPPArgs) {
	_, ok := app.cfg.pppArgs[tunnelName]
	if !ok {
		goto fail
	}
	args, ok = app.cfg.pppArgs[tunnelName][sessionName]
	if !ok {
		goto fail
	}
	return
fail:
	level.Info(app.logger).Log(
		"message", "no pppd args specified in session config",
		"tunnel_name", tunnelName,
		"session_name", sessionName)
	return &sessionPPPArgs{}
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

		if ev.SessionConfig.Pseudowire == l2tp.PseudowireTypePPPAC {
			level.Info(app.logger).Log("message", "session running as AC, don't bring up pppd")
			// cf. handling of l2tp.SessionDownEvent
			app.sessionPPPoL2TP[ev.TunnelName][ev.SessionName] = nil
			break
		}

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

		pppArgs := app.getSessionPPPArgs(ev.TunnelName, ev.SessionName)
		pppol2tp.pppd.Args = append(pppol2tp.pppd.Args, pppArgs.pppdArgs...)

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

		// if the session is running in AC mode, there won't be a local pppd
		if app.sessionPPPoL2TP[ev.TunnelName][ev.SessionName] != nil {
			level.Info(app.logger).Log("message", "killing pppd")
			app.sessionPPPoL2TP[ev.TunnelName][ev.SessionName].pppd.Process.Signal(os.Interrupt)
			delete(app.sessionPPPoL2TP[ev.TunnelName], ev.SessionName)
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

	// Listen for L2TP events
	app.l2tpCtx.RegisterEventHandler(app)

	// Instantiate tunnels and sessions from the config file
	for _, tcfg := range app.cfg.config.Tunnels {

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
	mycfg := newKl2tpdConfig()
	cfgPathPtr := flag.String("config", "/etc/kl2tpd/kl2tpd.toml", "specify configuration file path")
	verbosePtr := flag.Bool("verbose", false, "toggle verbose log output")
	nullDataPlanePtr := flag.Bool("null", false, "toggle null data plane")
	flag.Parse()

	config, err := config.LoadFileWithCustomParser(*cfgPathPtr, mycfg)
	if err != nil {
		stdlog.Fatalf("failed to load configuration: %v", err)
	}
	mycfg.config = config

	app, err := newApplication(mycfg, *verbosePtr, *nullDataPlanePtr)
	if err != nil {
		stdlog.Fatalf("failed to instantiate application: %v", err)
	}

	os.Exit(app.run())
}
