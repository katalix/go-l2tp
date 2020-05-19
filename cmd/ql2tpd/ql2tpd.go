/*
The ql2tpd command is a daemon for creating static L2TPv3 tunnels and sessions.

ql2tpd is driven by a configuration file which describes the tunnel and session
instances to create.  For more information on the configuration file format please
refer to package config's documentation.

Run with the -help argument for documentation of the command line arguments.

Two tunnel modes are supported.

By default tunnels are created in static mode, which means that the kernel-space
L2TP data plane is created, but no control messages are sent.  When running in this
mode ql2tpd provides functionality equivalent to the iproute2 l2tp commands.

Alternatively, tunnels may be created with a hello_timeout configured, in which case
a minimal control plane transport is set up to send and acknowledge keep-alive
(HELLO) messages.  This mode of operation extends static mode by allowing tunnel
failure to be detected.  If a given tunnel is determined to have failed (HELLO message
transmission fails) then the sessions in that tunnel are automatically torn down.
*/
package main

import (
	"flag"
	stdlog "log"
	"os"
	"os/signal"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/katalix/go-l2tp/config"
	"github.com/katalix/go-l2tp/l2tp"
	"golang.org/x/sys/unix"
)

func main() {

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)

	cfgPathPtr := flag.String("config", "/etc/ql2tpd/ql2tpd.toml", "specify configuration file path")
	verbosePtr := flag.Bool("verbose", false, "toggle verbose log output")
	flag.Parse()

	config, err := config.LoadFile(*cfgPathPtr)
	if err != nil {
		stdlog.Fatalf("failed to load l2tp configuration: %v", err)
	}

	logger := log.NewLogfmtLogger(os.Stderr)
	if *verbosePtr {
		logger = level.NewFilter(logger, level.AllowInfo(), level.AllowDebug())
	} else {
		logger = level.NewFilter(logger, level.AllowInfo())
	}

	l2tpCtx, err := l2tp.NewContext(l2tp.LinuxNetlinkDataPlane, logger)
	if err != nil {
		stdlog.Fatalf("failed to load l2tp configuration: %v", err)
	}
	defer l2tpCtx.Close()

	for _, tcfg := range config.Tunnels {
		tunl, err := l2tpCtx.NewQuiescentTunnel(tcfg.Name, tcfg.Config)
		if err != nil {
			stdlog.Fatalf("failed to instantiate tunnel %v: %v", tcfg.Name, err)
		}
		for _, scfg := range tcfg.Sessions {
			_, err := tunl.NewSession(scfg.Name, scfg.Config)
			if err != nil {
				stdlog.Fatalf("failed to instantiate session %v in tunnel %v: %v", scfg.Name, tcfg.Name, err)
			}
		}
	}

	<-sigs
}
