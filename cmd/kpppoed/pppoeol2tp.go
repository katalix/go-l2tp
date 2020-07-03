package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type kl2tpEvent int

const (
	kl2tpdTunnelCreated      kl2tpEvent = 0
	kl2tpdSessionCreated     kl2tpEvent = 1
	kl2tpdSessionEstablished kl2tpEvent = 2
	kl2tpdSessionDestroyed   kl2tpEvent = 3
	kl2tpdTunnelDestroyed    kl2tpEvent = 4
)

type pppoeoL2TPEventHandler interface {
	handleEvent(event interface{})
}

type sessionUpEvent struct {
	tunnelID  int
	sessionID int
}

type sessionDownEvent struct {
	tunnelID  int
	sessionID int
}

type pppoeoL2TP struct {
	logRegexp    map[kl2tpEvent]*regexp.Regexp
	wg           sync.WaitGroup
	kl2tpd       *exec.Cmd
	logger       log.Logger
	eventHandler pppoeoL2TPEventHandler
}

func genkl2tpdCfg(peerIPAddr string, out *os.File) (err error) {
	cfg := fmt.Sprintf(`[tunnel.t1]
		peer = "%s"
		version = "l2tpv2"
		encap = "udp"
		[tunnel.t1.session.s1]
		pseudowire = "ppp"
		ppp_ac = true`, peerIPAddr)
	_, err = out.WriteString(cfg)
	return
}

func newPPPoEoL2TP(peerIPAddr string, logger log.Logger, eventHandler pppoeoL2TPEventHandler) (pppoeol2tp *pppoeoL2TP, err error) {

	pppoeol2tp = &pppoeoL2TP{
		logRegexp:    make(map[kl2tpEvent]*regexp.Regexp),
		logger:       logger,
		eventHandler: eventHandler,
	}

	/* Regular expressions for kl2tpd logging to derive events.
	   To keep things simple we're relying on the fact that we
	   have just one tunnel and one session, with the well-known
	   names as per the autogenerated kl2tpd configuration file.

	   If kl2tpd logging changes, or the configuration file changes,
	   these expressions may need to be updated accordingly!
	*/
	pppoeol2tp.logRegexp[kl2tpdTunnelCreated] = regexp.MustCompile(
		"^.*new dynamic tunnel.* tunnel_id=([0-9]+)")
	pppoeol2tp.logRegexp[kl2tpdSessionCreated] = regexp.MustCompile(
		"^.*new dynamic session.* session_id=([0-9]+)")
	pppoeol2tp.logRegexp[kl2tpdSessionEstablished] = regexp.MustCompile(
		"^.*session_name=s1 message=\"data plane established\"")
	pppoeol2tp.logRegexp[kl2tpdSessionDestroyed] = regexp.MustCompile(
		"^.*session_name=s1 message=close")
	pppoeol2tp.logRegexp[kl2tpdTunnelDestroyed] = regexp.MustCompile(
		"^.*tunnel_name=t1 message=close")

	cfgFile, err := ioutil.TempFile(os.TempDir(), "kpppoed.kl2tpd.")
	if err != nil {
		return nil, fmt.Errorf("failed to generate kl2tpd configuration: %v", err)
	}
	defer cfgFile.Close()

	err = genkl2tpdCfg(peerIPAddr, cfgFile)
	if err != nil {
		return nil, fmt.Errorf("failed to generate kl2tpd configuration: %v", err)
	}

	pppoeol2tp.kl2tpd = exec.Command(
		"/usr/local/sbin/kl2tpd",
		"-config", cfgFile.Name(),
	)
	stderrPipe, err := pppoeol2tp.kl2tpd.StderrPipe()
	if err != nil {
		os.Remove(cfgFile.Name())
		return nil, fmt.Errorf("failed to create kl2tpd log stream pipe: %v", err)
	}

	// FIXME: who waits on this waitgroup?
	// Do we even need it given the main app waits on the process?
	pppoeol2tp.wg.Add(1)
	go func() {
		defer pppoeol2tp.wg.Done()
		pppoeol2tp.scanLog(stderrPipe)
	}()

	return
}

func (pppoeol2tp *pppoeoL2TP) scanLog(stderrPipe io.ReadCloser) {

	scanner := bufio.NewScanner(stderrPipe)
	var l2tpTunnelID, l2tpSessionID int
	var err error
	isUp := false

	for scanner.Scan() {
		line := scanner.Text()

		level.Debug(pppoeol2tp.logger).Log(
			"message", "kl2tpd log line received",
			"log", line)

		for et, re := range pppoeol2tp.logRegexp {
			if re == nil {
				continue
			}
			match := re.FindStringSubmatch(line)
			if match == nil {
				continue
			}
			switch et {
			case kl2tpdTunnelCreated:
				l2tpTunnelID, err = strconv.Atoi(match[1])
				if err != nil {
					level.Error(pppoeol2tp.logger).Log(
						"message", "failed to parse l2tp tunnel ID",
						"error", err)
					continue
				}
				level.Debug(pppoeol2tp.logger).Log(
					"message", "l2tp tunnel created",
					"tunnel_id", l2tpTunnelID)
			case kl2tpdSessionCreated:
				l2tpSessionID, err = strconv.Atoi(match[1])
				if err != nil {
					level.Error(pppoeol2tp.logger).Log(
						"message", "failed to parse l2tp session ID",
						"error", err)
					continue
				}
				level.Debug(pppoeol2tp.logger).Log(
					"message", "l2tp session created",
					"session_id", l2tpSessionID)
			case kl2tpdSessionEstablished:
				isUp = true
				if pppoeol2tp.eventHandler != nil {
					pppoeol2tp.eventHandler.handleEvent(
						&sessionUpEvent{
							tunnelID:  l2tpTunnelID,
							sessionID: l2tpSessionID,
						})
				}
			case kl2tpdSessionDestroyed, kl2tpdTunnelDestroyed:
				if !isUp {
					continue
				}
				isUp = false
				if pppoeol2tp.eventHandler != nil {
					pppoeol2tp.eventHandler.handleEvent(
						&sessionDownEvent{
							tunnelID:  l2tpTunnelID,
							sessionID: l2tpSessionID,
						})
				}
				pppoeol2tp.kl2tpd.Process.Signal(os.Interrupt)
			}
		}
	}
}
