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

type testTunnelEventCounter struct {
	tunnelUp   int
	tunnelDown int
}

func (teh *testTunnelEventCounter) HandleEvent(event interface{}) {
	switch event.(type) {
	case *TunnelUpEvent:
		teh.tunnelUp++
	case *TunnelDownEvent:
		teh.tunnelDown++
	}
}

type testTunnelEventCounterCloser struct {
	testTunnelEventCounter
}

func (teh *testTunnelEventCounterCloser) HandleEvent(event interface{}) {
	teh.testTunnelEventCounter.HandleEvent(event)
	if ev, ok := event.(*TunnelUpEvent); ok {
		t := ev.Tunnel
		go func() {
			t.Close()
		}()
	}
}

type testLNS struct {
	logger             log.Logger
	tcfg               *TunnelConfig
	scfg               *SessionConfig
	xport              *transport
	tunnelEstablished  bool
	sessionEstablished bool
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
	msg, err := newV2Stopccn(&resultCode{avpStopCCNResultCodeClearConnection, 0, ""}, lns.tcfg)
	if err != nil {
		panic(fmt.Sprintf("failed to build STOPCCN: %v", err))
	}
	lns.xport.send(msg)
	lns.xport.close()
}

func (lns *testLNS) handleV2Msg(msg *v2ControlMessage, from unix.Sockaddr) error {
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
		lns.xport.close()
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
	for {
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
}

func TestDynamicClient(t *testing.T) {
	cases := []struct {
		name              string
		localCfg, peerCfg TunnelConfig
	}{
		{
			name: "L2TPv2 UDP AF_INET",
			localCfg: TunnelConfig{
				Local:          "127.0.0.1:6000",
				Peer:           "localhost:5000",
				Version:        ProtocolVersion2,
				TunnelID:       4567,
				Encap:          EncapTypeUDP,
				StopCCNTimeout: 250 * time.Millisecond,
			},
			peerCfg: TunnelConfig{
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
			localCfg: TunnelConfig{
				Local:          "127.0.0.1:6000",
				Peer:           "localhost:5000",
				Version:        ProtocolVersion2,
				Encap:          EncapTypeUDP,
				StopCCNTimeout: 250 * time.Millisecond,
			},
			peerCfg: TunnelConfig{
				Local:          "localhost:5000",
				Peer:           "127.0.0.1:6000",
				Version:        ProtocolVersion2,
				TunnelID:       4567,
				Encap:          EncapTypeUDP,
				StopCCNTimeout: 250 * time.Millisecond,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			logger := level.NewFilter(log.NewLogfmtLogger(os.Stderr), level.AllowDebug())

			// Create and run a test LNS instance
			lns, err := newTestLNS(logger, &c.peerCfg, nil)
			if err != nil {
				t.Fatalf("newTestLNS: %v", err)
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				lns.run(3 * time.Second)
				wg.Done()
			}()

			// Bring up the client tunnel.
			ctx, err := NewContext(nil, logger)
			if err != nil {
				t.Fatalf("NewContext(): %v", err)
			}

			teh := testTunnelEventCounterCloser{}
			ctx.RegisterEventHandler(&teh)

			_, err = ctx.NewDynamicTunnel("t1", &c.localCfg)
			if err != nil {
				t.Fatalf("NewDynamicTunnel(\"t1\", %v): %v", c.localCfg, err)
			}

			wg.Wait()
			ctx.Close()

			expect := testTunnelEventCounterCloser{testTunnelEventCounter: testTunnelEventCounter{1, 1}}
			if teh != expect {
				t.Errorf("event listener: expected %v event, got %v", expect, teh)
			}

			if lns.tunnelEstablished != true {
				t.Errorf("LNS didn't establish")
			}
		})
	}
}
