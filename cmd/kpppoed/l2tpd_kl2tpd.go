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
	"github.com/katalix/go-l2tp/pppoe"
)

var _ l2tpdRunner = (*kl2tpdRunner)(nil)
var _ l2tpd = (*kl2tpd)(nil)

type kl2tpEvent int

const (
	kl2tpdTunnelCreated      kl2tpEvent = 0
	kl2tpdSessionCreated     kl2tpEvent = 1
	kl2tpdSessionEstablished kl2tpEvent = 2
	kl2tpdSessionDestroyed   kl2tpEvent = 3
	kl2tpdTunnelDestroyed    kl2tpEvent = 4
)

type kl2tpdRunner struct {
	execPath string
}

type kl2tpd struct {
	logRegexp    map[kl2tpEvent]*regexp.Regexp
	wg           sync.WaitGroup
	eventHandler l2tpEventHandler
	sid          pppoe.PPPoESessionID
	kl2tpd       *exec.Cmd
	logger       log.Logger
}

func newKl2tpdRunner() (runner *kl2tpdRunner, err error) {
	return &kl2tpdRunner{
		// TODO: could search likely candidates to find kl2tpd
		execPath: "/usr/sbin/kl2tpd",
	}, nil
}

func (runner *kl2tpdRunner) genCfg(peerIPAddr string, out *os.File) (err error) {
	cfg := []string{
		`[tunnel.t1]`,
		fmt.Sprintf(`peer = "%s"`, peerIPAddr),
		`version = "l2tpv2"`,
		`encap = "udp"`,
		`[tunnel.t1.session.s1]`,
		`pseudowire = "pppac"`,
	}
	for _, s := range cfg {
		_, err = out.WriteString(fmt.Sprintf("%s\n", s))
		if err != nil {
			break
		}
	}
	return
}
func (runner *kl2tpdRunner) spawn(sessionID pppoe.PPPoESessionID,
	ifName string,
	peerMAC [6]byte,
	lnsIPAddr string,
	logger log.Logger,
	eventHandler l2tpEventHandler) (daemon l2tpd, err error) {

	d := &kl2tpd{
		sid:          sessionID,
		logRegexp:    make(map[kl2tpEvent]*regexp.Regexp),
		logger:       logger,
		eventHandler: eventHandler,
	}
	daemon = d

	/* Regular expressions for kl2tpd logging to derive events.
	   To keep things simple we're relying on the fact that we
	   have just one tunnel and one session, with the well-known
	   names as per the autogenerated kl2tpd configuration file.

	   If kl2tpd logging changes, or the configuration file changes,
	   these expressions may need to be updated accordingly!
	*/
	d.logRegexp[kl2tpdTunnelCreated] = regexp.MustCompile(
		"^.*new dynamic tunnel.* tunnel_id=([0-9]+)")
	d.logRegexp[kl2tpdSessionCreated] = regexp.MustCompile(
		"^.*new dynamic session.* session_id=([0-9]+)")
	d.logRegexp[kl2tpdSessionEstablished] = regexp.MustCompile(
		"^.*session_name=s1 message=\"data plane established\"")
	d.logRegexp[kl2tpdSessionDestroyed] = regexp.MustCompile(
		"^.*session_name=s1 message=close")
	d.logRegexp[kl2tpdTunnelDestroyed] = regexp.MustCompile(
		"^.*tunnel_name=t1 message=close")

	cfgFile, err := ioutil.TempFile(os.TempDir(), "kpppoed.kl2tpd.")
	if err != nil {
		return nil, fmt.Errorf("failed to generate kl2tpd configuration: %v", err)
	}
	defer cfgFile.Close()

	err = runner.genCfg(lnsIPAddr, cfgFile)
	if err != nil {
		return nil, fmt.Errorf("failed to generate kl2tpd configuration: %v", err)
	}

	d.kl2tpd = exec.Command(
		runner.execPath,
		"-config", cfgFile.Name(),
	)
	stderrPipe, err := d.kl2tpd.StderrPipe()
	if err != nil {
		os.Remove(cfgFile.Name())
		return nil, fmt.Errorf("failed to create kl2tpd log stream pipe: %v", err)
	}

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer os.Remove(cfgFile.Name())
		d.scanLog(stderrPipe)
	}()

	err = d.kl2tpd.Start()
	if err != nil {
		// wait for the goroutine
		d.terminate()
		return nil, fmt.Errorf("failed to start kl2tpd: %v", err)
	}
	return
}

func (daemon *kl2tpd) wait() error {
	return daemon.kl2tpd.Wait()
}

func (daemon *kl2tpd) terminate() {
	daemon.kl2tpd.Process.Signal(os.Interrupt)
	daemon.wg.Wait()
}

func (daemon *kl2tpd) onEvent(ev interface{}) {
	if daemon.eventHandler != nil {
		daemon.eventHandler.handleEvent(ev)
	}
}

func (daemon *kl2tpd) scanLog(stderrPipe io.ReadCloser) {

	scanner := bufio.NewScanner(stderrPipe)
	var l2tpTunnelID, l2tpSessionID int
	var err error
	isUp := false

	for scanner.Scan() {
		line := scanner.Text()

		// This is a bit verbose for normal usage, but handy for debugging
		/*
			level.Debug(daemon.logger).Log(
				"message", "kl2tpd log line received",
				"log", line)
		*/

		for et, re := range daemon.logRegexp {
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
					level.Error(daemon.logger).Log(
						"message", "failed to parse l2tp tunnel ID",
						"error", err)
					continue
				}
				level.Debug(daemon.logger).Log(
					"message", "l2tp tunnel created",
					"tunnel_id", l2tpTunnelID)
			case kl2tpdSessionCreated:
				l2tpSessionID, err = strconv.Atoi(match[1])
				if err != nil {
					level.Error(daemon.logger).Log(
						"message", "failed to parse l2tp session ID",
						"error", err)
					continue
				}
				level.Debug(daemon.logger).Log(
					"message", "l2tp session created",
					"session_id", l2tpSessionID)
			case kl2tpdSessionEstablished:
				if isUp {
					continue
				}
				isUp = true
				daemon.onEvent(&l2tpSessionUp{
					pppoeSessionID: daemon.sid,
					l2tpTunnelID:   uint32(l2tpTunnelID),
					l2tpSessionID:  uint32(l2tpSessionID),
				})
			case kl2tpdSessionDestroyed, kl2tpdTunnelDestroyed:
				if !isUp {
					continue
				}
				isUp = false
				daemon.onEvent(&l2tpSessionDown{
					pppoeSessionID: daemon.sid,
					l2tpTunnelID:   uint32(l2tpTunnelID),
					l2tpSessionID:  uint32(l2tpSessionID),
				})
				daemon.kl2tpd.Process.Signal(os.Interrupt)
			}
		}
	}
}
