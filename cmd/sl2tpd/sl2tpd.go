package main

import (
	"flag"
	stdlog "log"
	"os"
	"os/signal"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/katalix/sl2tpd/l2tp"
	"golang.org/x/sys/unix"
)

func main() {

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)

	cfgPathPtr := flag.String("config", "/etc/sl2tpd/sl2tpd.toml", "specify configuration file path")
	verbosePtr := flag.Bool("verbose", false, "toggle verbose log output")
	flag.Parse()

	config, err := l2tp.LoadFile(*cfgPathPtr)
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
