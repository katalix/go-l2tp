package l2tp

// More tunnel tests which require root permissions are implemented
// in l2tp_test.go in the TestRequiresRoot function.
//
// These tests are using the null dataplane and hence don't require root.

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"golang.org/x/sys/unix"
)

type eventCounters struct {
	tunnelUp, tunnelDown, sessionUp, sessionDown int
}

type testEventCounter struct {
	eventCounters
}

func (tec *testEventCounter) HandleEvent(event interface{}) {
	switch event.(type) {
	case *TunnelUpEvent:
		tec.tunnelUp++
	case *TunnelDownEvent:
		tec.tunnelDown++
	case *SessionUpEvent:
		tec.sessionUp++
	case *SessionDownEvent:
		tec.sessionDown++
	}
}

func (tec *testEventCounter) getEventCounts() eventCounters {
	return tec.eventCounters
}

type testTunnelEventCounterCloser struct {
	testEventCounter
	wg sync.WaitGroup
}

type eventCounterCloser interface {
	EventHandler
	getEventCounts() eventCounters
	wait()
}

func (tecc *testTunnelEventCounterCloser) HandleEvent(event interface{}) {
	tecc.testEventCounter.HandleEvent(event)
	if ev, ok := event.(*TunnelUpEvent); ok {
		t := ev.Tunnel
		tecc.wg.Add(1)
		go func() {
			t.Close()
			tecc.wg.Done()
		}()
	}
}

func (tecc *testTunnelEventCounterCloser) wait() {
	tecc.wg.Wait()
}

type testLNS struct {
	logger             log.Logger
	tcfg               *TunnelConfig
	scfg               *SessionConfig
	xport              *transport
	tunnelEstablished  bool
	sessionEstablished bool
	isShutdown         bool
}

func newTestLNS(logger log.Logger, tcfg *TunnelConfig, scfg *SessionConfig) (*testLNS, error) {
	myLogger := log.With(logger, "tunnel_name", "testLNS")

	sal, sap, err := newUDPAddressPair(tcfg.Local, tcfg.Peer)
	if err != nil {
		return nil, fmt.Errorf("newUDPAddressPair(%v, %v): %v", tcfg.Local, tcfg.Peer, err)
	}

	cp, err := newL2tpControlPlane(sal, sap)
	if err != nil {
		return nil, fmt.Errorf("newL2tpControlPlane(%v, %v): %v", sal, sap, err)
	}

	err = cp.bind()
	if err != nil {
		return nil, fmt.Errorf("cp.bind(): %v", err)
	}

	xcfg := defaulttransportConfig()
	xcfg.Version = tcfg.Version
	xport, err := newTransport(myLogger, cp, xcfg)
	if err != nil {
		return nil, fmt.Errorf("newTransport(): %v", err)
	}

	lns := &testLNS{
		logger: myLogger,
		tcfg:   tcfg,
		scfg:   scfg,
		xport:  xport,
	}

	return lns, nil
}

func (lns *testLNS) shutdown() {
	level.Debug(lns.logger).Log("message", "shutdown")
	lns.isShutdown = true
}

func (lns *testLNS) handleV2Msg(msg *v2ControlMessage, from unix.Sockaddr) error {
	level.Debug(lns.logger).Log(
		"message", "receive control message",
		"message_type", msg.getType())
	switch msg.getType() {
	// Tunnel messages
	case avpMsgTypeSccrq:
		ptid, err := findUint16Avp(msg.getAvps(), vendorIDIetf, avpTypeTunnelID)
		if err != nil {
			return fmt.Errorf("no Tunnel ID AVP in SCCRQ")
		}
		lns.xport.config.PeerControlConnID = ControlConnID(ptid)
		lns.tcfg.PeerTunnelID = ControlConnID(ptid)
		lns.xport.cp.connectTo(from)
		rsp, err := newV2Sccrp(lns.tcfg)
		if err != nil {
			return fmt.Errorf("failed to build SCCRP: %v", err)
		}
		return lns.xport.send(rsp)
	case avpMsgTypeScccn:
		lns.tunnelEstablished = true
		return nil
	case avpMsgTypeStopccn:
		// HACK: allow the transport to ack the stopccn.
		// By closing the transport the transport recvChan will be
		// closed, which will cause the run() function to return.
		time.Sleep(250 * time.Millisecond)
		lns.isShutdown = true
		return nil
	case avpMsgTypeHello:
		return nil

	// Session messages
	case avpMsgTypeIcrq:
		psid, err := findUint16Avp(msg.getAvps(), vendorIDIetf, avpTypeSessionID)
		if err != nil {
			return fmt.Errorf("no Session ID AVP in ICRQ")
		}
		lns.scfg.PeerSessionID = ControlConnID(psid)
		rsp, err := newV2Icrp(lns.tcfg.PeerTunnelID, lns.scfg)
		if err != nil {
			return fmt.Errorf("failed to build ICRP: %v", err)
		}
		return lns.xport.send(rsp)
	case avpMsgTypeIccn:
		lns.sessionEstablished = true
		return nil
	case avpMsgTypeCdn:
		return nil
	}
	return fmt.Errorf("message %v not handled", msg.getType())
}

func (lns *testLNS) run(timeout time.Duration) {
	deadline := time.NewTimer(timeout)
	for !lns.isShutdown {
		select {
		case <-deadline.C:
			lns.shutdown()
			return
		case m, ok := <-lns.xport.recvChan:
			if !ok {
				return
			}
			msg, ok := m.msg.(*v2ControlMessage)
			if !ok {
				panic("failed to cast received message as v2ControlMessage")
			}
			err := lns.handleV2Msg(msg, m.from)
			if err != nil {
				lns.shutdown()
				return
			}
		}
	}
	lns.xport.close()
}

func TestDynamicClient(t *testing.T) {
	cases := []struct {
		name                            string
		localTunnelCfg, peerTunnelCfg   *TunnelConfig
		localSessionCfg, peerSessionCfg *SessionConfig
	}{
		{
			name: "L2TPv2 UDP AF_INET",
			localTunnelCfg: &TunnelConfig{
				Local:          "127.0.0.1:6000",
				Peer:           "localhost:5000",
				Version:        ProtocolVersion2,
				TunnelID:       4567,
				Encap:          EncapTypeUDP,
				StopCCNTimeout: 250 * time.Millisecond,
			},
			peerTunnelCfg: &TunnelConfig{
				Local:          "localhost:5000",
				Peer:           "127.0.0.1:6000",
				Version:        ProtocolVersion2,
				TunnelID:       4567,
				Encap:          EncapTypeUDP,
				StopCCNTimeout: 250 * time.Millisecond,
			},
		},
		{
			name: "L2TPv2 UDP AF_INET (alloc TID)",
			localTunnelCfg: &TunnelConfig{
				Local:          "127.0.0.1:6000",
				Peer:           "localhost:5000",
				Version:        ProtocolVersion2,
				Encap:          EncapTypeUDP,
				StopCCNTimeout: 250 * time.Millisecond,
			},
			peerTunnelCfg: &TunnelConfig{
				Local:          "localhost:5000",
				Peer:           "127.0.0.1:6000",
				Version:        ProtocolVersion2,
				TunnelID:       4567,
				Encap:          EncapTypeUDP,
				StopCCNTimeout: 250 * time.Millisecond,
			},
		},
		{
			name: "L2TPv2 UDP AF_INET (alloc TID, with session)",
			localTunnelCfg: &TunnelConfig{
				Local:          "127.0.0.1:6000",
				Peer:           "localhost:5000",
				Version:        ProtocolVersion2,
				Encap:          EncapTypeUDP,
				StopCCNTimeout: 250 * time.Millisecond,
			},
			localSessionCfg: &SessionConfig{
				Pseudowire: PseudowireTypePPP,
			},
			peerTunnelCfg: &TunnelConfig{
				Local:          "localhost:5000",
				Peer:           "127.0.0.1:6000",
				Version:        ProtocolVersion2,
				TunnelID:       4567,
				Encap:          EncapTypeUDP,
				StopCCNTimeout: 250 * time.Millisecond,
			},
			peerSessionCfg: &SessionConfig{
				Pseudowire: PseudowireTypePPP,
				SessionID:  5566,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			logger := level.NewFilter(log.NewLogfmtLogger(os.Stderr), level.AllowDebug())

			// Create and run a test LNS instance
			lns, err := newTestLNS(logger, c.peerTunnelCfg, c.peerSessionCfg)
			if err != nil {
				t.Fatalf("newTestLNS: %v", err)
			}

			var lnsWg sync.WaitGroup
			lnsWg.Add(1)
			go func() {
				lns.run(3 * time.Second)
				lnsWg.Done()
			}()

			// Bring up the client tunnel.
			ctx, err := NewContext(nil, logger)
			if err != nil {
				t.Fatalf("NewContext(): %v", err)
			}

			var eventCounter eventCounterCloser
			eventCounter = &testTunnelEventCounterCloser{}
			ctx.RegisterEventHandler(eventCounter)

			tunl, err := ctx.NewDynamicTunnel("t1", c.localTunnelCfg)
			if err != nil {
				t.Fatalf("NewDynamicTunnel(%q, %v): %v", "t1", c.localTunnelCfg, err)
			}

			// And optionally the client session
			if c.localSessionCfg != nil {
				_, err = tunl.NewSession("s1", c.peerSessionCfg)
				if err != nil {
					t.Fatalf("NewSession(%q, %v): %v", "s1", c.peerSessionCfg, err)
				}
			}

			lnsWg.Wait()
			ctx.Close()
			eventCounter.wait()

			expectEvents := eventCounters{tunnelUp: 1, tunnelDown: 1, sessionUp: 0, sessionDown: 0}
			gotEvents := eventCounter.getEventCounts()
			if expectEvents != gotEvents {
				t.Errorf("event listener: expected %v event, got %v", expectEvents, gotEvents)
			}

			if lns.tunnelEstablished != true {
				t.Errorf("LNS didn't establish")
			}
		})
	}
}
