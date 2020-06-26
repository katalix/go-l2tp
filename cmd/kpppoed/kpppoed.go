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
	"github.com/katalix/go-l2tp/pppoe"
	"golang.org/x/sys/unix"
)

type application struct {
	config    *config.Config
	logger    log.Logger
	conn      *pppoe.PPPoEConn
	sigChan   chan os.Signal
	rxChan    chan []byte
	closeChan chan interface{}
}

func newApplication(configPath string, verbose bool) (app *application, err error) {
	app = &application{
		sigChan:   make(chan os.Signal, 1),
		rxChan:    make(chan []byte),
		closeChan: make(chan interface{}),
	}

	signal.Notify(app.sigChan, unix.SIGINT, unix.SIGTERM)

	logger := log.NewLogfmtLogger(os.Stderr)
	if verbose {
		app.logger = level.NewFilter(logger, level.AllowDebug())
	} else {
		app.logger = level.NewFilter(logger, level.AllowInfo())
	}

	app.conn, err = pppoe.NewDiscoveryConnection("veth1")
	if err != nil {
		return nil, fmt.Errorf("failed to create PPPoE connection: %v", err)
	}

	return
}

func (app *application) handlePacket(pkt *pppoe.PPPoEPacket) (err error) {
	fmt.Printf("recv: %v\n", pkt)
	return fmt.Errorf("handlePacket not implemented")
}

func (app *application) run() int {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			buf := make([]byte, 1500)
			_, err := app.conn.Recv(buf)
			if err != nil {
				level.Error(app.logger).Log("message", "recv on PPPoE discovery connection failed", "error", err)
				close(app.rxChan)
				break
			}
			app.rxChan <- buf
		}
	}()

	for {
		select {
		case <-app.sigChan:
			level.Info(app.logger).Log("message", "received signal, shutting down")
			// TODO
			close(app.closeChan)
		case <-app.closeChan:
			app.conn.Close()
			wg.Wait()
			return 0
		case rx, ok := <-app.rxChan:
			if !ok {
				close(app.closeChan)
				break
			}

			pkts, err := pppoe.ParsePacketBuffer(rx)
			if err != nil {
				level.Error(app.logger).Log("message", "failed to parse received message(s)", "error", err)
				continue
			}

			for _, pkt := range pkts {
				err = app.handlePacket(pkt)
				if err != nil {
					level.Error(app.logger).Log("message", "failed to handle message",
						"type", pkt.Code,
						"error", err)
				}
			}

		}
	}
}

func main() {
	cfgPathPtr := flag.String("config", "/etc/kpppoed/kpppoed.toml", "specify configuration file path")
	verbosePtr := flag.Bool("verbose", false, "toggle verbose log output")
	flag.Parse()

	app, err := newApplication(*cfgPathPtr, *verbosePtr)
	if err != nil {
		stdlog.Fatalf("failed to instantiate application: %v", err)
	}

	os.Exit(app.run())
}
