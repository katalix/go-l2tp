package l2tp

// More tunnel tests which require root permissions are implemented
// in l2tp_test.go in the TestRequiresRoot function.
//
// These tests cover the dynamic tunnel control plane which doesn't
// require root permissions to run.  We expect tunnels to fail when
// trying to instantiate the data plane.

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

func dummyV2LNS(tcfg *TunnelConfig, xport *transport, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case m, ok := <-xport.recvChan:
			if !ok {
				return
			}
			msg, ok := m.msg.(*v2ControlMessage)
			if !ok {
				panic("failed to cast received message as v2ControlMessage")
			}
			fmt.Printf("dummyV2LNS: recv %v\n", msg.getType())
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
			} else if msg.getType() == avpMsgTypeStopccn {
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
				Local:    "127.0.0.1:6000",
				Peer:     "localhost:5000",
				Version:  ProtocolVersion2,
				TunnelID: 4567,
				Encap:    EncapTypeUDP,
			},
			peerCfg: TunnelConfig{
				Local:    "localhost:5000",
				Peer:     "127.0.0.1:6000",
				Version:  ProtocolVersion2,
				TunnelID: 4567,
				Encap:    EncapTypeUDP,
			},
		},
		{
			name: "L2TPv2 UDP AF_INET (alloc TID)",
			localCfg: TunnelConfig{
				Local:   "127.0.0.1:6000",
				Peer:    "localhost:5000",
				Version: ProtocolVersion2,
				Encap:   EncapTypeUDP,
			},
			peerCfg: TunnelConfig{
				Local:    "localhost:5000",
				Peer:     "127.0.0.1:6000",
				Version:  ProtocolVersion2,
				TunnelID: 4567,
				Encap:    EncapTypeUDP,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			testLog := level.NewFilter(log.NewLogfmtLogger(log.NewSyncWriter(&out)), level.AllowDebug(), level.AllowInfo())
			myLog := level.NewFilter(log.NewLogfmtLogger(os.Stderr), level.AllowDebug(), level.AllowInfo())

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
			xport, err := newTransport(myLog, cp, xcfg)
			var wg sync.WaitGroup
			wg.Add(1)
			go dummyV2LNS(&c.peerCfg, xport, &wg)

			// Bring up the client tunnel.
			// Note that we are relying on the tunnel failing to come up due to dataplane
			// permissions issues, and sending a stopccn to the dummy LNS which will cause its
			// goroutine to exit.
			// It would be better to be able to control this more directly.
			ctx, err := NewContext(LinuxNetlinkDataPlane, testLog)
			if err != nil {
				t.Fatalf("NewContext(): %v", err)
			}

			_, err = ctx.NewDynamicTunnel("t1", &c.localCfg)
			if err != nil {
				t.Fatalf("NewDynamicTunnel(\"t1\", %v): %v", c.localCfg, err)
			}

			wg.Wait()
			ctx.Close()
			want := "control plane established"
			if !strings.Contains(out.String(), want) {
				t.Fatalf("%q does not contain %q", out.String(), want)
			}
		})
	}
}
