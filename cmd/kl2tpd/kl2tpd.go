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

// An interface for managing a pseudowire instance.
// The core l2tp code creates the L2TP session control plane
// and kernel l2tp subsystem data plane instance.
// kl2tpd may then need to e.g. instantiate pppd for a PPP
// pseudowire, or bridge pppox sockets for a PPPAC pseudowire.
// This interface abstracts that away from kl2tpd core.
type pseudowire interface {
	close()
	getSession() l2tp.Session
}

type application struct {
	cfg     *kl2tpdConfig
	logger  log.Logger
	l2tpCtx *l2tp.Context
	// sessionPW[tunnel_name][session_name]
	sessionPW      map[string]map[string]pseudowire
	sigChan        chan os.Signal
	pwCompleteChan chan pseudowire
	closeChan      chan interface{}
	wg             sync.WaitGroup
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
		cfg:            cfg,
		sigChan:        make(chan os.Signal, 1),
		sessionPW:      make(map[string]map[string]pseudowire),
		pwCompleteChan: make(chan pseudowire),
		closeChan:      make(chan interface{}),
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

func (app *application) instantiatePPPPseudowire(ev *l2tp.SessionUpEvent) (pw pseudowire) {
	pppd, err := newPPPDaemon(ev.Session,
		ev.TunnelConfig.TunnelID,
		ev.SessionConfig.SessionID,
		ev.TunnelConfig.PeerTunnelID,
		ev.SessionConfig.PeerSessionID)
	if err != nil {
		level.Error(app.logger).Log(
			"message", "failed to create pppol2tp instance",
			"error", err)
		return nil
	}

	pppArgs := app.getSessionPPPArgs(ev.TunnelName, ev.SessionName)
	pppd.cmd.Args = append(pppd.cmd.Args, pppArgs.pppdArgs...)

	err = pppd.cmd.Start()
	if err != nil {
		level.Error(app.logger).Log(
			"message", "pppd failed to start",
			"error", err,
			"error_message", pppdExitCodeString(err),
			"stderr", pppd.stderrBuf.String())
		return nil
	}

	app.sessionPW[ev.TunnelName][ev.SessionName] = pppd

	app.wg.Add(1)
	go func() {
		defer app.wg.Done()
		err = pppd.cmd.Wait()
		if err != nil {
			level.Error(app.logger).Log(
				"message", "pppd exited with an error code",
				"error", err,
				"error_message", pppdExitCodeString(err))
		}
		app.pwCompleteChan <- pppd
	}()
	return pppd
}

func (app *application) instantiatePPPACPseudowire(ev *l2tp.SessionUpEvent) (pw pseudowire) {
	pb, err := newPPPBridge(ev.Session,
		ev.TunnelConfig.TunnelID,
		ev.SessionConfig.SessionID,
		ev.TunnelConfig.PeerTunnelID,
		ev.SessionConfig.PeerSessionID,
		ev.SessionConfig.PPPoESessionId,
		ev.SessionConfig.PPPoEPeerMac,
		ev.SessionConfig.InterfaceName)
	if err != nil {
		level.Error(app.logger).Log(
			"message", "ppp/ac bridge failed to start",
			"error", err)
		return nil
	}
	return pb
}

func (app *application) instantiatePseudowire(ev *l2tp.SessionUpEvent) (pw pseudowire) {
	switch ev.SessionConfig.Pseudowire {
	case l2tp.PseudowireTypePPP:
		return app.instantiatePPPPseudowire(ev)
	case l2tp.PseudowireTypePPPAC:
		return app.instantiatePPPACPseudowire(ev)
	}
	level.Error(app.logger).Log(
		"message", "unsupported pseudowire type",
		"pseudowire_type", ev.SessionConfig.Pseudowire)
	return nil
}

func (app *application) HandleEvent(event interface{}) {
	switch ev := event.(type) {
	case *l2tp.TunnelUpEvent:
		if _, ok := app.sessionPW[ev.TunnelName]; !ok {
			app.sessionPW[ev.TunnelName] = make(map[string]pseudowire)
		}

	case *l2tp.TunnelDownEvent:
		delete(app.sessionPW, ev.TunnelName)

	case *l2tp.SessionUpEvent:

		level.Info(app.logger).Log(
			"message", "session up",
			"tunnel_name", ev.TunnelName,
			"session_name", ev.SessionName,
			"tunnel_id", ev.TunnelConfig.TunnelID,
			"session_id", ev.SessionConfig.SessionID,
			"peer_tunnel_id", ev.TunnelConfig.PeerTunnelID,
			"peer_session_id", ev.SessionConfig.PeerSessionID)

		app.sessionPW[ev.TunnelName][ev.SessionName] = app.instantiatePseudowire(ev)
		if app.sessionPW[ev.TunnelName][ev.SessionName] == nil {
			app.closeSession(ev.Session)
		}

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

		if app.sessionPW[ev.TunnelName][ev.SessionName] != nil {
			level.Info(app.logger).Log("message", "killing pseudowire")
			app.sessionPW[ev.TunnelName][ev.SessionName].close()
			delete(app.sessionPW[ev.TunnelName], ev.SessionName)
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
		case pw, ok := <-app.pwCompleteChan:
			if !ok {
				close(app.closeChan)
			}
			level.Info(app.logger).Log("message", "pseudowire terminated")
			if !shutdown {
				app.closeSession(pw.getSession())
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
