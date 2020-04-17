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
)

type testEventHandler struct {
	tunnelUp   int
	tunnelDown int
}

func (teh *testEventHandler) HandleEvent(event interface{}) {
	switch event.(type) {
	case *TunnelUpEvent:
		teh.tunnelUp++
	case *TunnelDownEvent:
		teh.tunnelDown++
	}
}

func dummyV2LNS(tcfg *TunnelConfig, xport *transport, wg *sync.WaitGroup, established *bool) {
	defer wg.Done()
	timeout := time.NewTimer(3 * time.Second)
	for {
		select {
		case <-timeout.C:
			rsp, err := newV2Stopccn(&resultCode{avpStopCCNResultCodeClearConnection, 0, ""}, tcfg)
			if err != nil {
				panic(fmt.Sprintf("failed to build STOPCCN: %v", err))
			}
			xport.send(rsp)
			xport.close()
			return
		case m, ok := <-xport.recvChan:
			if !ok {
				return
			}
			msg, ok := m.msg.(*v2ControlMessage)
			if !ok {
				panic("failed to cast received message as v2ControlMessage")
			}
			if msg.getType() == avpMsgTypeSccrq {
				ptid, err := findUint16Avp(msg.getAvps(), vendorIDIetf, avpTypeTunnelID)
				if err != nil {
					panic("no Tunnel ID AVP in SCCRQ")
				}
				xport.config.PeerControlConnID = ControlConnID(ptid)
				tcfg.PeerTunnelID = ControlConnID(ptid)
				xport.cp.connectTo(m.from)
				rsp, err := newV2Sccrp(tcfg)
				if err != nil {
					panic(fmt.Sprintf("failed to build SCCRP: %v", err))
				}
				xport.send(rsp)
			} else if msg.getType() == avpMsgTypeScccn {
				*established = true
				rsp, err := newV2Stopccn(&resultCode{avpStopCCNResultCodeClearConnection, 0, ""}, tcfg)
				if err != nil {
					panic(fmt.Sprintf("failed to build STOPCCN: %v", err))
				}
				xport.send(rsp)
				xport.close()
				return
			} else if msg.getType() == avpMsgTypeStopccn {
				// HACK: allow the transport to ack the stopccn
				time.Sleep(250 * time.Millisecond)
				xport.close()
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

			// Set up a transport to dummy the LNS
			sal, sap, err := newUDPAddressPair(c.peerCfg.Local, c.peerCfg.Peer)
			if err != nil {
				t.Fatalf("newUDPAddressPair(%v, %v): %v", c.peerCfg.Local, c.peerCfg.Peer, err)
			}

			cp, err := newL2tpControlPlane(sal, sap)
			if err != nil {
				t.Fatalf("newL2tpControlPlane(%v, %v): %v", sal, sap, err)
			}

			err = cp.bind()
			if err != nil {
				t.Fatalf("cp.bind(): %v", err)
			}

			xcfg := defaulttransportConfig()
			xcfg.Version = c.peerCfg.Version
			xport, err := newTransport(log.With(logger, "tunnel_name", "dummyV2LNS"), cp, xcfg)
			if err != nil {
				t.Fatalf("newTransport(): %v", err)
			}
			var wg sync.WaitGroup
			lnsEstablished := false
			wg.Add(1)
			go dummyV2LNS(&c.peerCfg, xport, &wg, &lnsEstablished)

			// Bring up the client tunnel.
			ctx, err := NewContext(nil, logger)
			if err != nil {
				t.Fatalf("NewContext(): %v", err)
			}

			teh := testEventHandler{}
			ctx.RegisterEventHandler(&teh)

			_, err = ctx.NewDynamicTunnel("t1", &c.localCfg)
			if err != nil {
				t.Fatalf("NewDynamicTunnel(\"t1\", %v): %v", c.localCfg, err)
			}

			wg.Wait()
			ctx.Close()

			expect := testEventHandler{1, 1}
			if teh != expect {
				t.Errorf("event listener: expected %v event, got %v", expect, teh)
			}

			if lnsEstablished != true {
				t.Errorf("LNS didn't establish")
			}
		})
	}
}
