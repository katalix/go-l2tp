package main

import (
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/katalix/sl2tpd/l2tp"
	"golang.org/x/sys/unix"
)

func main() {

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)

	cfgPathPtr := flag.String("config", "/etc/sl2tpd/sl2tpd.toml", "specify configuration file path")
	//verbosePtr := flag.Bool("verbose", false, "toggle verbose log output")
	//_ = verbosePtr
	flag.Parse()

	config, err := l2tp.LoadFile(*cfgPathPtr)
	if err != nil {
		log.Fatalf("failed to load l2tp configuration: %v", err)
	}

	l2tpCtx, err := l2tp.NewContext(nil)
	if err != nil {
		log.Fatalf("failed to load l2tp configuration: %v", err)
	}
	defer l2tpCtx.Close()

	for tnam, tcfg := range config.GetTunnels() {
		tunl, err := l2tpCtx.NewQuiescentTunnel(tnam, tcfg)
		if err != nil {
			log.Fatalf("failed to instantiate tunnel %v: %v", tnam, err)
		}
		for snam, scfg := range tcfg.Sessions {
			_, err := tunl.NewSession(snam, scfg)
			if err != nil {
				log.Fatalf("failed to instantiate session %v in tunnel %v: %v", snam, tnam, err)
			}
		}
	}

	<-sigs
}
