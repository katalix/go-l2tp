package main

import (
	"flag"
	"fmt"
	stdlog "log"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/katalix/go-l2tp/config"
	"github.com/katalix/go-l2tp/pppoe"
	"golang.org/x/sys/unix"
)

type kpppoedConfig struct {
	acName   string
	ifName   string
	services []string
}

type pppoeSession struct {
	peerHWAddr [6]byte
}

type application struct {
	config    *kpppoedConfig
	logger    log.Logger
	conn      *pppoe.PPPoEConn
	sessions  map[pppoe.PPPoESessionID]*pppoeSession
	sigChan   chan os.Signal
	rxChan    chan []byte
	closeChan chan interface{}
}

func ifaceToString(key string, v interface{}) (s string, err error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("failed to parse %s as a string", key)
	}
	return
}

func ifaceToStringList(key string, v interface{}) (sl []string, err error) {
	l, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse %s as an array", key)
	}
	for _, vv := range l {
		s, err := ifaceToString(fmt.Sprintf("%v in %s", vv, key), vv)
		if err != nil {
			return nil, err
		}
		sl = append(sl, s)
	}
	return
}

func (cfg *kpppoedConfig) ParseParameter(key string, value interface{}) (err error) {
	var n string
	switch key {
	case "ac_name":
		n, err = ifaceToString(key, value)
		if err != nil {
			return
		}
		if cfg.acName != "" {
			return fmt.Errorf("cannot specify ac_name multiple times in configuration")
		}
		cfg.acName = n
	case "interface_name":
		n, err = ifaceToString(key, value)
		if err != nil {
			return
		}
		if cfg.ifName != "" {
			return fmt.Errorf("cannot specify interface_name multiple times in configuration")
		}
		cfg.ifName = n
	case "services":
		cfg.services, err = ifaceToStringList(key, value)
		if err != nil {
			return
		}
	default:
		return fmt.Errorf("unrecognised parameter %v", key)
	}
	return nil
}

func (cfg *kpppoedConfig) ParseTunnelParameter(tunnel *config.NamedTunnel, key string, value interface{}) error {
	return fmt.Errorf("unrecognised parameter %v", key)
}

func (cfg *kpppoedConfig) ParseSessionParameter(tunnel *config.NamedTunnel, session *config.NamedSession, key string, value interface{}) error {
	return fmt.Errorf("unrecognised parameter %v", key)
}

func newApplication(cfg *kpppoedConfig, verbose bool) (app *application, err error) {
	app = &application{
		config:    cfg,
		sessions:  make(map[pppoe.PPPoESessionID]*pppoeSession),
		sigChan:   make(chan os.Signal, 1),
		rxChan:    make(chan []byte),
		closeChan: make(chan interface{}),
	}

	signal.Notify(app.sigChan, unix.SIGINT, unix.SIGTERM)

	rand.Seed(time.Now().UnixNano())

	logger := log.NewLogfmtLogger(os.Stderr)
	if verbose {
		app.logger = level.NewFilter(logger, level.AllowDebug())
	} else {
		app.logger = level.NewFilter(logger, level.AllowInfo())
	}

	app.conn, err = pppoe.NewDiscoveryConnection(app.config.ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to create PPPoE connection: %v", err)
	}

	return
}

func (app *application) sendPacket(pkt *pppoe.PPPoEPacket) (err error) {
	err = pkt.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate %s: %v", pkt.Code, err)
	}

	b, err := pkt.ToBytes()
	if err != nil {
		return fmt.Errorf("unable to encode %s: %v", pkt.Code, err)
	}

	level.Debug(app.logger).Log("message", "send", "packet", pkt)

	_, err = app.conn.Send(b)
	return
}

func (app *application) mapServiceName(requested string) (got string, err error) {
	// empty service name is a wildcard, so anything will do
	if requested == "" {
		return requested, nil
	}
	for _, sn := range app.config.services {
		if sn == requested {
			return requested, nil
		}
	}
	return requested, fmt.Errorf("requested service \"%s\" not available", requested)
}

func (app *application) getPacketServiceName(pkt *pppoe.PPPoEPacket) (sn string, err error) {
	serviceNameTag, err := pkt.GetTag(pppoe.PPPoETagTypeServiceName)
	if err != nil {
		// Don't expect this to occur since service name is mandatory and
		// pppoe.Validate() is done as a part of parsing incoming messages.
		// TODO: panic?
		return
	}
	return app.mapServiceName(string(serviceNameTag.Data))
}

func (app *application) appendEchoedTags(in, out *pppoe.PPPoEPacket) (err error) {
	hostUniqTag, err := in.GetTag(pppoe.PPPoETagTypeHostUniq)
	if err == nil {
		err = out.AddHostUniqTag(hostUniqTag.Data)
		if err != nil {
			return fmt.Errorf("failed to add host uniq tag to %s: %v", out.Code, err)
		}
	}

	relaySessionIDTag, err := in.GetTag(pppoe.PPPoETagTypeRelaySessionID)
	if err == nil {
		err = out.AddTag(pppoe.PPPoETagTypeRelaySessionID, relaySessionIDTag.Data)
		if err != nil {
			return fmt.Errorf("failed to add relay session ID tag to %s: %v", out.Code, err)
		}
	}

	return nil
}

func (app *application) genSessionID() (sid pppoe.PPPoESessionID, err error) {
	for i := 0; i < 100; i++ {
		// session ID is a 16 bit number, but 0 is not a valid ID
		sid = pppoe.PPPoESessionID(1 + rand.Intn(65534))

		// don't duplicate an existing session ID
		if _, ok := app.sessions[sid]; !ok {
			return
		}
	}
	return pppoe.PPPoESessionID(0), fmt.Errorf("exhausted session ID space")
}

func (app *application) handlePADI(pkt *pppoe.PPPoEPacket) (err error) {

	serviceName, err := app.getPacketServiceName(pkt)
	if err != nil {
		// We don't like the service name, so just ignore the request.
		return
	}

	pado, err := pppoe.NewPADO(
		app.conn.HWAddr(),
		pkt.SrcHWAddr,
		serviceName,
		app.config.acName)
	if err != nil {
		return fmt.Errorf("failed to build PADO: %v", err)
	}

	err = app.appendEchoedTags(pkt, pado)
	if err != nil {
		return
	}

	/* TODO: AC cookie */

	return app.sendPacket(pado)
}

func (app *application) handlePADR(pkt *pppoe.PPPoEPacket) (err error) {
	sessionID := pppoe.PPPoESessionID(0)
	errorReason := ""

	// If we don't like the service name or fail to allocate resources,
	// we need to send a PADS indicating the error condition.
	serviceName, err := app.getPacketServiceName(pkt)
	if err != nil {
		errorReason = err.Error()
	}

	if errorReason == "" {
		sessionID, err = app.genSessionID()
		if err != nil {
			errorReason = fmt.Sprintf("failed to allocate session ID: %v", err)
		}
	}

	// If we fail to build the PADS or send it, there's not much we can
	// do to let the peer know, so just fail silently.
	pads, err := pppoe.NewPADS(
		app.conn.HWAddr(),
		pkt.SrcHWAddr,
		serviceName,
		sessionID)
	if err != nil {
		return
	}

	err = app.appendEchoedTags(pkt, pads)
	if err != nil {
		return
	}

	if errorReason != "" {
		err = pads.AddServiceNameErrorTag(errorReason)
		if err != nil {
			return
		}
	}

	err = app.sendPacket(pads)
	if err != nil {
		return
	}

	// Keep track of the session now
	app.sessions[sessionID] = &pppoeSession{
		peerHWAddr: pkt.SrcHWAddr,
	}

	return
}

func (app *application) handlePADT(pkt *pppoe.PPPoEPacket) (err error) {

	session, ok := app.sessions[pkt.SessionID]
	if !ok {
		return fmt.Errorf("unrecognised session ID %v", pkt.SessionID)
	}

	// TODO: tear down session instance
	_ = session

	delete(app.sessions, pkt.SessionID)

	return
}

func (app *application) handlePacket(pkt *pppoe.PPPoEPacket) (err error) {
	level.Debug(app.logger).Log("message", "recv", "packet", pkt)
	switch pkt.Code {
	case pppoe.PPPoECodePADI:
		return app.handlePADI(pkt)
	case pppoe.PPPoECodePADR:
		return app.handlePADR(pkt)
	case pppoe.PPPoECodePADT:
		return app.handlePADT(pkt)
	case pppoe.PPPoECodePADO,
		pppoe.PPPoECodePADS:
		return fmt.Errorf("unexpected PPPoE %v packet", pkt.Code)
	}
	return fmt.Errorf("unhandled PPPoE code %v", pkt.Code)
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
	cfg := kpppoedConfig{}

	cfgPathPtr := flag.String("config", "/etc/kpppoed/kpppoed.toml", "specify configuration file path")
	verbosePtr := flag.Bool("verbose", false, "toggle verbose log output")
	flag.Parse()

	_, err := config.LoadFileWithCustomParser(*cfgPathPtr, &cfg)
	if err != nil {
		stdlog.Fatalf("failed to load configuration: %v", err)
	}

	if len(cfg.services) == 0 {
		stdlog.Fatalf("no services called out in the configuration file")
	}

	if cfg.ifName == "" {
		stdlog.Fatalf("no interface name called out in the configuration file")
	}

	if cfg.acName == "" {
		cfg.acName = "kpppoed"
	}

	app, err := newApplication(&cfg, *verbosePtr)
	if err != nil {
		stdlog.Fatalf("failed to instantiate application: %v", err)
	}

	os.Exit(app.run())
}
