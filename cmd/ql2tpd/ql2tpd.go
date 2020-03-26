/*
The ql2tpd command is a daemon for instantiating quiescent L2TP tunnels and sessions.

Quiescent tunnels run a minimal control plane alongside the L2TP data plane.  The
control plane is limited to sending and acknowledging keep-alive (HELLO) messages
in order to detect tunnel failure.

Tunnels may also be configured with HELLO messages disabled, in which case they
behave as static instances.  When running in this mode ql2tpd provides a more convenient
way to create static tunnels and sessions than the iproute2 l2tp commands, and exposes
all the options the Linux data plane offers.

ql2tpd is driven by a configuration file which describes the tunnel and session
instances to create.  For more information on the configuration file format please
refer to package l2tp's documentation.

Run with the -help argument for documentation of the command line arguments.
*/
package main

import (
	"flag"
	stdlog "log"
	"os"
	"os/signal"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/katalix/l2tp/l2tp"
	"golang.org/x/sys/unix"
)

func main() {

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)

	cfgPathPtr := flag.String("config", "/etc/ql2tpd/ql2tpd.toml", "specify configuration file path")
	verbosePtr := flag.Bool("verbose", false, "toggle verbose log output")
	flag.Parse()

	config, err := l2tp.LoadConfigFile(*cfgPathPtr)
	if err != nil {
		stdlog.Fatalf("failed to load l2tp configuration: %v", err)
	}

	logger := log.NewLogfmtLogger(os.Stderr)
	if *verbosePtr {
		logger = level.NewFilter(logger, level.AllowInfo(), level.AllowDebug())
	} else {
		logger = level.NewFilter(logger, level.AllowInfo())
	}

	l2tpCtx, err := l2tp.NewContext(logger, nil)
	if err != nil {
		stdlog.Fatalf("failed to load l2tp configuration: %v", err)
	}
	defer l2tpCtx.Close()

	for tnam, tcfg := range config.GetTunnels() {
		tunl, err := l2tpCtx.NewQuiescentTunnel(tnam, tcfg)
		if err != nil {
			stdlog.Fatalf("failed to instantiate tunnel %v: %v", tnam, err)
		}
		for snam, scfg := range tcfg.Sessions {
			_, err := tunl.NewSession(snam, scfg)
			if err != nil {
				stdlog.Fatalf("failed to instantiate session %v in tunnel %v: %v", snam, tnam, err)
			}
		}
	}

	<-sigs
}
