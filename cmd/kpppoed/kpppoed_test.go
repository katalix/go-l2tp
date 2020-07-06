package main

import (
	"fmt"
	"os/exec"
	"os/user"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/katalix/go-l2tp/config"
	"github.com/katalix/go-l2tp/pppoe"
)

const (
	testVeth0 = "vetest0"
	testVeth1 = "vetest1"
)

func createTestVethPair() (err error) {
	cmd := exec.Command("sudo", "ip", "link", "add", "dev", testVeth0, "type", "veth", "peer", "name", testVeth1)
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("unable to create veth pair: %v", err)
	}

	cmd = exec.Command("sudo", "ip", "link", "set", testVeth0, "up")
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("unable to set %s up: %v", testVeth0, err)
	}

	cmd = exec.Command("sudo", "ip", "link", "set", testVeth1, "up")
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("unable to set %s up: %v", testVeth1, err)
	}
	return nil
}

func deleteTestVethPair() (err error) {
	cmd := exec.Command("sudo", "ip", "link", "delete", "dev", testVeth0)
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to delete veth interface %s: %v", testVeth0, err)
	}
	return nil
}

type kpppoedTestApp struct {
	app *application
	wg  sync.WaitGroup
}

func newKpppoedTestApp(cfg *kpppoedConfig) (testApp *kpppoedTestApp, err error) {
	testApp = &kpppoedTestApp{}
	testApp.app, err = newApplication(cfg, true)
	if err != nil {
		return nil, err
	}
	testApp.wg.Add(1)
	go func() {
		defer testApp.wg.Done()
		testApp.app.run()
	}()
	return
}

func (testApp *kpppoedTestApp) Close() {
	close(testApp.app.closeChan)
	testApp.wg.Wait()
}

type testClient struct {
	conn   *pppoe.PPPoEConn
	wg     sync.WaitGroup
	rxChan chan []byte
}

func newTestClient(ifName string) (tc *testClient, err error) {
	tc = &testClient{
		rxChan: make(chan []byte),
	}
	tc.conn, err = pppoe.NewDiscoveryConnection(ifName)
	if err != nil {
		return nil, err
	}
	tc.wg.Add(1)
	go func() {
		defer tc.wg.Done()
		for {
			buf := make([]byte, 1500)
			_, err := tc.conn.Recv(buf)
			if err != nil {
				close(tc.rxChan)
				break
			}
			tc.rxChan <- buf
		}
	}()
	return
}

func (tc *testClient) recvPacket(timeout time.Duration) (pkt *pppoe.PPPoEPacket, err error) {
	select {
	case buf, ok := <-tc.rxChan:
		if !ok {
			return nil, fmt.Errorf("connection recv channel closed")
		}
		parsed, err := pppoe.ParsePacketBuffer(buf)
		if err != nil {
			return nil, err
		}
		if len(parsed) != 1 {
			return nil, fmt.Errorf("expected 1 packet, got %d", len(parsed))
		}
		return parsed[0], nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("rx timed out after %v", timeout)
	}
}

func (tc *testClient) sendPacket(pkt *pppoe.PPPoEPacket) (err error) {
	b, err := pkt.ToBytes()
	if err != nil {
		return
	}
	_, err = tc.conn.Send(b)
	return
}

func (tc *testClient) Close() {
	tc.conn.Close()
	tc.wg.Wait()
}

type testTagIn struct {
	id   pppoe.PPPoETagType
	data []byte
}

func checkPktType(pkt *pppoe.PPPoEPacket, typ pppoe.PPPoECode, t *testing.T) {
	if pkt.Code != typ {
		t.Errorf("received %s, expected %s", pkt.Code, typ)
	}
}

func checkRspIsPADO(pkt *pppoe.PPPoEPacket, t *testing.T) {
	checkPktType(pkt, pppoe.PPPoECodePADO, t)
}

func checkRspIsPADS(pkt *pppoe.PPPoEPacket, t *testing.T) {
	checkPktType(pkt, pppoe.PPPoECodePADS, t)
}

func checkHasTag(pkt *pppoe.PPPoEPacket, t *testing.T, typ pppoe.PPPoETagType) (tag *pppoe.PPPoETag) {
	tag, err := pkt.GetTag(typ)
	if err != nil {
		t.Fatalf("no tag %s", typ)
	}
	return
}

func checkTagData(pkt *pppoe.PPPoEPacket, t *testing.T, typ pppoe.PPPoETagType, data []byte) {
	tag := checkHasTag(pkt, t, typ)
	if !reflect.DeepEqual(tag.Data, data) {
		t.Fatalf("expected %s to contain %q, got %q", typ, data, tag.Data)
	}
}

func checkAddTags(pkt *pppoe.PPPoEPacket, tags []testTagIn, t *testing.T) {
	for _, tag := range tags {
		err := pkt.AddTag(tag.id, tag.data)
		if err != nil {
			t.Fatalf("AddTag: %v", err)
		}
	}
}

func checkSendRecv(client *testClient,
	pkt *pppoe.PPPoEPacket,
	timeout time.Duration,
	expectSilence bool,
	checkRsp func(pkt *pppoe.PPPoEPacket, t *testing.T),
	t *testing.T) (rsp *pppoe.PPPoEPacket) {

	err := client.sendPacket(pkt)
	if err != nil {
		t.Fatalf("sendPacket: %v", err)
	}

	rsp, err = client.recvPacket(timeout)

	if expectSilence {
		if err == nil {
			t.Errorf("recvPacket: expect timeout error but didn't get one")
		}
		if rsp != nil {
			t.Errorf("recvPacket: expected no reply, but got packet: %v", rsp)
		}
	} else {
		if err != nil {
			t.Fatalf("recvPacket: %v", err)
		}
		if checkRsp != nil {
			checkRsp(rsp, t)
		}
	}
	return
}

func testPADI(t *testing.T) {
	service0 := "Super_Internet_03A"
	service1 := "MyMagicalService2001"
	service2 := "transx.world.com.gateway"

	hostUniq0 := []byte{0x42, 0x12, 0xee, 0xf4, 0x91, 0x00, 0x72}
	hostUniq1 := []byte{}

	relaySessionID0 := []byte{
		0x01, 0x02, 0x03, 0x04,
		0x11, 0x12, 0x13, 0x14,
		0xa1, 0xa2, 0xa3, 0xa4,
	}

	dfltCfg := &kpppoedConfig{
		acName:   "bobby",
		services: []string{service1, service2, service0},
		ifName:   testVeth0,
	}

	cases := []struct {
		name          string
		service       string
		tags          []testTagIn
		expectSilence bool
		checkRsp      func(pkt *pppoe.PPPoEPacket, t *testing.T)
	}{
		{
			name:     "service0",
			service:  service0,
			checkRsp: checkRspIsPADO,
		},
		{
			name:     "service1",
			service:  service1,
			checkRsp: checkRspIsPADO,
		},
		{
			name:     "service2",
			service:  service2,
			checkRsp: checkRspIsPADO,
		},
		{
			name:          "badservice",
			service:       "badservice",
			expectSilence: true,
		},
		{
			name:    "hostUniq0",
			service: service0,
			tags: []testTagIn{
				{
					id:   pppoe.PPPoETagTypeHostUniq,
					data: hostUniq0,
				},
			},
			checkRsp: func(pkt *pppoe.PPPoEPacket, t *testing.T) {
				checkRspIsPADO(pkt, t)
				checkTagData(pkt, t, pppoe.PPPoETagTypeHostUniq, hostUniq0)
			},
		},
		{
			name:    "hostUniq1",
			service: service0,
			tags: []testTagIn{
				{
					id:   pppoe.PPPoETagTypeHostUniq,
					data: hostUniq1,
				},
			},
			checkRsp: func(pkt *pppoe.PPPoEPacket, t *testing.T) {
				checkRspIsPADO(pkt, t)
				checkTagData(pkt, t, pppoe.PPPoETagTypeHostUniq, hostUniq1)
			},
		},
		{
			name:    "relaySessionID0",
			service: service0,
			tags: []testTagIn{
				{
					id:   pppoe.PPPoETagTypeRelaySessionID,
					data: relaySessionID0,
				},
			},
			checkRsp: func(pkt *pppoe.PPPoEPacket, t *testing.T) {
				checkRspIsPADO(pkt, t)
				checkTagData(pkt, t, pppoe.PPPoETagTypeRelaySessionID, relaySessionID0)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			app, err := newKpppoedTestApp(dfltCfg)
			if err != nil {
				t.Fatalf("newKpppoedTestApp: %v", err)
			}
			defer app.Close()

			client, err := newTestClient(testVeth1)
			if err != nil {
				t.Fatalf("newTestClient: %v", err)
			}
			defer client.Close()

			padi, err := pppoe.NewPADI(client.conn.HWAddr(), c.service)
			if err != nil {
				t.Fatalf("NewPADI: %v", err)
			}

			checkAddTags(padi, c.tags, t)

			_ = checkSendRecv(client, padi, 250*time.Millisecond, c.expectSilence, c.checkRsp, t)
		})
	}
}

type testPktIn struct {
	service       string
	tags          []testTagIn
	expectSilence bool
	checkRsp      func(pkt *pppoe.PPPoEPacket, t *testing.T)
}

func testPADR(t *testing.T) {

	service0 := "Super_Internet_03A"
	service1 := "MyMagicalService2001"
	service2 := "transx.world.com.gateway"

	hostUniq0 := []byte{0x42, 0x12, 0xee, 0xf4, 0x91, 0x00, 0x72}

	relaySessionID0 := []byte{
		0x01, 0x02, 0x03, 0x04,
		0x11, 0x12, 0x13, 0x14,
		0xa1, 0xa2, 0xa3, 0xa4,
	}

	dfltCfg := &kpppoedConfig{
		acName:   "bobby",
		services: []string{service1, service2, service0},
		ifName:   testVeth0,
	}

	cases := []struct {
		name string
		padi *testPktIn
		padr *testPktIn
	}{
		{
			name: "establish0",
			padi: &testPktIn{
				service: service2,
				tags: []testTagIn{
					{
						id:   pppoe.PPPoETagTypeHostUniq,
						data: hostUniq0,
					},
				},
				checkRsp: func(pkt *pppoe.PPPoEPacket, t *testing.T) {
					checkRspIsPADO(pkt, t)
					checkTagData(pkt, t, pppoe.PPPoETagTypeHostUniq, hostUniq0)
				},
			},
			padr: &testPktIn{
				service: service2,
				tags: []testTagIn{
					{
						id:   pppoe.PPPoETagTypeHostUniq,
						data: hostUniq0,
					},
				},
				checkRsp: func(pkt *pppoe.PPPoEPacket, t *testing.T) {
					checkRspIsPADS(pkt, t)
					checkTagData(pkt, t, pppoe.PPPoETagTypeHostUniq, hostUniq0)
					if pkt.SessionID == 0 {
						t.Errorf("expect non-zero session ID")
					}
				},
			},
		},
		{
			name: "establish1",
			padi: &testPktIn{
				service: service1,
				tags: []testTagIn{
					{
						id:   pppoe.PPPoETagTypeHostUniq,
						data: hostUniq0,
					},
					{
						id:   pppoe.PPPoETagTypeRelaySessionID,
						data: relaySessionID0,
					},
				},
				checkRsp: func(pkt *pppoe.PPPoEPacket, t *testing.T) {
					checkRspIsPADO(pkt, t)
					checkTagData(pkt, t, pppoe.PPPoETagTypeHostUniq, hostUniq0)
					checkTagData(pkt, t, pppoe.PPPoETagTypeRelaySessionID, relaySessionID0)
				},
			},
			padr: &testPktIn{
				service: service1,
				tags: []testTagIn{
					{
						id:   pppoe.PPPoETagTypeHostUniq,
						data: hostUniq0,
					},
					{
						id:   pppoe.PPPoETagTypeRelaySessionID,
						data: relaySessionID0,
					},
				},
				checkRsp: func(pkt *pppoe.PPPoEPacket, t *testing.T) {
					checkRspIsPADS(pkt, t)
					checkTagData(pkt, t, pppoe.PPPoETagTypeHostUniq, hostUniq0)
					checkTagData(pkt, t, pppoe.PPPoETagTypeRelaySessionID, relaySessionID0)
					if pkt.SessionID == 0 {
						t.Errorf("expect non-zero session ID")
					}
				},
			},
		},
		{
			name: "badservice",
			padi: &testPktIn{
				service:  service1,
				checkRsp: checkRspIsPADO,
			},
			padr: &testPktIn{
				service: "badservice",
				tags: []testTagIn{
					{
						id:   pppoe.PPPoETagTypeHostUniq,
						data: hostUniq0,
					},
					{
						id:   pppoe.PPPoETagTypeRelaySessionID,
						data: relaySessionID0,
					},
				},
				checkRsp: func(pkt *pppoe.PPPoEPacket, t *testing.T) {
					checkRspIsPADS(pkt, t)
					checkTagData(pkt, t, pppoe.PPPoETagTypeHostUniq, hostUniq0)
					checkTagData(pkt, t, pppoe.PPPoETagTypeRelaySessionID, relaySessionID0)
					if pkt.SessionID != 0 {
						t.Errorf("expect zero session ID")
					}
					checkHasTag(pkt, t, pppoe.PPPoETagTypeServiceNameError)
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {

			app, err := newKpppoedTestApp(dfltCfg)
			if err != nil {
				t.Fatalf("newKpppoedTestApp: %v", err)
			}
			defer app.Close()

			client, err := newTestClient(testVeth1)
			if err != nil {
				t.Fatalf("newTestClient: %v", err)
			}
			defer client.Close()

			padi, err := pppoe.NewPADI(client.conn.HWAddr(), c.padi.service)
			if err != nil {
				t.Fatalf("NewPADI: %v", err)
			}
			checkAddTags(padi, c.padi.tags, t)
			pado := checkSendRecv(client,
				padi,
				250*time.Millisecond,
				c.padi.expectSilence,
				c.padi.checkRsp,
				t)

			if c.padr != nil {
				padr, err := pppoe.NewPADR(client.conn.HWAddr(), pado.SrcHWAddr, c.padr.service)
				if err != nil {
					t.Fatalf("NewPADR: %v", err)
				}
				checkAddTags(padr, c.padr.tags, t)

				acCookieTag, err := pado.GetTag(pppoe.PPPoETagTypeACCookie)
				if err == nil {
					checkAddTags(padr, []testTagIn{{id: acCookieTag.Type, data: acCookieTag.Data}}, t)
				}
				checkSendRecv(client, padr, 250*time.Millisecond, c.padr.expectSilence, c.padr.checkRsp, t)
			}
		})
	}
}

func TestRequiresRoot(t *testing.T) {

	// These tests need root permissions, so verify we have those first of all
	user, err := user.Current()
	if err != nil {
		t.Errorf("Unable to obtain current user: %q", err)
	}
	if user.Uid != "0" {
		t.Skip("skipping test because we don't have root permissions")
	}

	// Set up veth pair to use for connection tests
	err = createTestVethPair()
	if err != nil {
		t.Fatalf("%v", err)
	}

	tests := []struct {
		name   string
		testFn func(t *testing.T)
	}{
		{
			name:   "PADI",
			testFn: testPADI,
		},
		{
			name:   "PADR",
			testFn: testPADR,
		},
	}

	for _, sub := range tests {
		t.Run(sub.name, sub.testFn)
	}

	// Tear down veth pair
	err = deleteTestVethPair()
	if err != nil {
		t.Errorf("%v", err)
	}
}

func TestConfigParser(t *testing.T) {
	cases := []struct {
		in         string
		expectFail bool
		out        *kpppoedConfig
	}{
		{
			in: `ac_name = "wombles"
			 interface_name = "eth0"
			 services = [ "DeathStar", "tatoonie" ]
			 lns_ipaddr = "192.168.21.12:1701"
			 `,
			out: &kpppoedConfig{
				acName:    "wombles",
				ifName:    "eth0",
				services:  []string{"DeathStar", "tatoonie"},
				lnsIPAddr: "192.168.21.12:1701",
			},
		},
	}
	for _, c := range cases {
		cfg := &kpppoedConfig{}
		_, err := config.LoadStringWithCustomParser(c.in, cfg)
		if err != nil {
			t.Fatalf("LoadStringWithCustomParser: %v", err)
		}
		if !reflect.DeepEqual(cfg, c.out) {
			t.Fatalf("expect %v, got %v", c.out, cfg)
		}
	}
}
