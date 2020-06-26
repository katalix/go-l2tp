package pppoe

import (
	"fmt"
	"os/exec"
	"os/user"
	"reflect"
	"sync"
	"testing"
)

const (
	testVeth0 = "vetest0"
	testVeth1 = "vetest1"
)

func TestTagRenderAndParse(t *testing.T) {
	cases := []struct {
		name string
		tags []*PPPoETag
	}{
		{
			name: "service name",
			tags: []*PPPoETag{
				&PPPoETag{
					Type: PPPoETagTypeServiceName,
					Data: []byte("myMagicService"),
				},
			},
		},
		{
			name: "ac name",
			tags: []*PPPoETag{
				&PPPoETag{
					Type: PPPoETagTypeACName,
					Data: []byte("ThisSpecialAC"),
				},
			},
		},
		{
			name: "host uniq",
			tags: []*PPPoETag{
				&PPPoETag{
					Type: PPPoETagTypeHostUniq,
					Data: []byte{0x42, 0x81, 0xba, 0x3b, 0xc6, 0x1e, 0x94, 0xb1},
				},
			},
		},
		{
			name: "cookie",
			tags: []*PPPoETag{
				&PPPoETag{
					Type: PPPoETagTypeACCookie,
					Data: []byte{0x37, 0xd0, 0xba, 0x3b, 0x94, 0x82, 0xc6, 0x1e, 0x01, 0xc3, 0x42, 0x81, 0xa5, 0x93, 0xf9, 0x13},
				},
			},
		},
		{
			name: "service name error",
			tags: []*PPPoETag{
				&PPPoETag{
					Type: PPPoETagTypeServiceNameError,
					Data: []byte{},
				},
			},
		},
		{
			name: "ac system error",
			tags: []*PPPoETag{
				&PPPoETag{
					Type: PPPoETagTypeACSystemError,
					Data: []byte("insufficient resources to create a virtual circuit"),
				},
			},
		},
		{
			name: "generic error",
			tags: []*PPPoETag{
				&PPPoETag{
					Type: PPPoETagTypeGenericError,
					Data: []byte("out of cheese error"),
				},
			},
		},
		{
			name: "multiple tags",
			tags: []*PPPoETag{
				&PPPoETag{
					Type: PPPoETagTypeHostUniq,
					Data: []byte{0x42, 0x81, 0xba, 0x3b, 0xc6, 0x1e, 0x94, 0xb1},
				},
				&PPPoETag{
					Type: PPPoETagTypeACCookie,
					Data: []byte{0x37, 0xd0, 0xba, 0x3b, 0x94, 0x82, 0xc6, 0x1e, 0x01, 0xc3, 0x42, 0x81, 0xa5, 0x93, 0xf9, 0x13},
				},
				&PPPoETag{
					Type: PPPoETagTypeServiceName,
					Data: []byte("myMagicService"),
				},
				&PPPoETag{
					Type: PPPoETagTypeACName,
					Data: []byte("ThisSpecialAC"),
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srcHWAddr := [6]byte{0x12, 0x42, 0xae, 0x10, 0xf9, 0x48}
			dstHWAddr := [6]byte{0x22, 0xa2, 0xa4, 0x19, 0xfb, 0xc8}
			sid := PPPoESessionID(15241)

			// use PADT because it doesn't contain any tags by default
			pkt, err := NewPADT(srcHWAddr, dstHWAddr, sid)
			if err != nil {
				t.Fatalf("NewPADT(%v, %v, %v): %v", srcHWAddr, dstHWAddr, sid, err)
			}
			for _, tag := range c.tags {
				err = pkt.AddTag(tag.Type, tag.Data)
				if err != nil {
					t.Fatalf("AddTag(%v): %v", tag, err)
				}
			}
			got, err := pkt.Tags()
			if err != nil {
				t.Fatalf("Tags(): %v", err)
			}
			if !reflect.DeepEqual(got, c.tags) {
				t.Errorf("Expect: %v, got: %v", c.tags, got)
			}
		})
	}
}

func TestPacketRenderAndParse(t *testing.T) {
	cases := []struct {
		name      string
		genPacket func(t *testing.T) *PPPoEPacket
	}{
		{
			name: "PADI",
			genPacket: func(t *testing.T) *PPPoEPacket {
				packet, err := NewPADI([6]byte{0x81, 0x82, 0x83, 0x84, 0x85, 0x86}, "MegaCorpAC")
				if err != nil {
					t.Fatalf("NewPADI: %v", err)
				}
				err = packet.AddHostUniqTag([]byte("wakw39485ryjn398"))
				if err != nil {
					t.Fatalf("AddHostUniqTag: %v", err)
				}
				return packet
			},
		},
		{
			name: "PADO",
			genPacket: func(t *testing.T) *PPPoEPacket {
				packet, err := NewPADO(
					[6]byte{0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6},
					[6]byte{0x81, 0x82, 0x83, 0x84, 0x85, 0x86},
					"MegaCorpAC",
					"WunderAC_2001")
				if err != nil {
					t.Fatalf("NewPADO: %v", err)
				}
				for _, sn := range []string{"WomblesFC", "BatmanLives", "CuriousEarthling", "WilliamWonka"} {
					err = packet.AddServiceNameTag(sn)
					if err != nil {
						t.Fatalf("AddServiceNameTag: %v", err)
					}
				}
				err = packet.AddHostUniqTag([]byte("wakw39485ryjn398"))
				if err != nil {
					t.Fatalf("AddHostUniqTag: %v", err)
				}
				err = packet.AddACCookieTag([]byte("0912340u9q23ejow3er09u235oih"))
				if err != nil {
					t.Fatalf("AddACCookieTag: %v", err)
				}
				return packet
			},
		},
		{
			name: "PADR",
			genPacket: func(t *testing.T) *PPPoEPacket {
				packet, err := NewPADR(
					[6]byte{0x81, 0x82, 0x83, 0x84, 0x85, 0x86},
					[6]byte{0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6},
					"MegaCorpAC")
				if err != nil {
					t.Fatalf("NewPADR: %v", err)
				}
				err = packet.AddHostUniqTag([]byte("wakw39485ryjn398"))
				if err != nil {
					t.Fatalf("AddHostUniqTag: %v", err)
				}
				err = packet.AddACCookieTag([]byte("0912340u9q23ejow3er09u235oih"))
				if err != nil {
					t.Fatalf("AddACCookieTag: %v", err)
				}
				return packet
			},
		},
		{
			name: "PADS",
			genPacket: func(t *testing.T) *PPPoEPacket {
				packet, err := NewPADS(
					[6]byte{0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6},
					[6]byte{0x81, 0x82, 0x83, 0x84, 0x85, 0x86},
					"MegaCorpAC",
					PPPoESessionID(12345))
				if err != nil {
					t.Fatalf("NewPADS: %v", err)
				}
				err = packet.AddHostUniqTag([]byte("wakw39485ryjn398"))
				if err != nil {
					t.Fatalf("AddHostUniqTag: %v", err)
				}
				return packet
			},
		},
		{
			name: "PADSError",
			genPacket: func(t *testing.T) *PPPoEPacket {
				packet, err := NewPADS(
					[6]byte{0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6},
					[6]byte{0x81, 0x82, 0x83, 0x84, 0x85, 0x86},
					"MegaCorpAC",
					PPPoESessionID(0))
				if err != nil {
					t.Fatalf("NewPADS: %v", err)
				}
				err = packet.AddHostUniqTag([]byte("wakw39485ryjn398"))
				if err != nil {
					t.Fatalf("AddHostUniqTag: %v", err)
				}
				err = packet.AddServiceNameErrorTag("I don't like this service name after all, sorry")
				if err != nil {
					t.Fatalf("AddServiceNameErrorTag: %v", err)
				}
				return packet
			},
		},
		{
			name: "PADT",
			genPacket: func(t *testing.T) *PPPoEPacket {
				packet, err := NewPADT(
					[6]byte{0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6},
					[6]byte{0x81, 0x82, 0x83, 0x84, 0x85, 0x86},
					PPPoESessionID(12345))
				if err != nil {
					t.Fatalf("NewPADT: %v", err)
				}
				err = packet.AddACSystemErrorTag("OUT OF CHEESE ERROR")
				if err != nil {
					t.Fatalf("AddACSystemErrorTag: %v", err)
				}
				return packet
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			packet := c.genPacket(t)
			fmt.Printf("%v\n", packet)
			encoded, err := packet.ToBytes()
			if err != nil {
				t.Fatalf("ToBytes: %v", err)
			}
			parsed, err := parsePacketBuffer(encoded)
			if err != nil {
				t.Fatalf("parsePacketBuffer(%x): %v", encoded, err)
			}
			if len(parsed) != 1 {
				t.Fatalf("expected 1 parsed packet, got %d", len(parsed))
			}
			if !reflect.DeepEqual(parsed[0], packet) {
				t.Errorf("Expect: %v, got: %v", packet, parsed[0])
			}
		})
	}
}

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

func testConnSendRecv(t *testing.T) {
	recvBuf := make([]byte, 1500)

	conn0, err := NewPPPoEConnection(testVeth0, ethTypePPPoEDiscovery)
	if err != nil {
		t.Fatalf("NewPPPoEConnection: %v", err)
	}
	defer conn0.Close()

	conn1, err := NewPPPoEConnection(testVeth1, ethTypePPPoEDiscovery)
	if err != nil {
		t.Fatalf("NewPPPoEConnection: %v", err)
	}
	defer conn1.Close()

	var startWg, endWg sync.WaitGroup
	startWg.Add(1)
	endWg.Add(1)
	go func() {
		startWg.Done()
		_, err = conn1.Recv(recvBuf)
		if err != nil {
			t.Errorf("Recv: %v", err)
		}
		endWg.Done()
	}()
	startWg.Wait()

	pkt, err := NewPADI(conn0.HWAddr(), "BobsService")
	if err != nil {
		t.Fatalf("NewPADI: %v", err)
	}

	b, err := pkt.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes: %v", err)
	}

	_, err = conn0.Send(b)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	endWg.Wait()

	parsed, err := parsePacketBuffer(recvBuf)
	if err != nil {
		t.Fatalf("parsePacketBuffer(%x): %v", recvBuf, err)
	}

	if len(parsed) != 1 {
		t.Fatalf("expected 1 parsed packet, got %d", len(parsed))
	}
	if !reflect.DeepEqual(parsed[0], pkt) {
		t.Errorf("Expect: %v, got: %v", pkt, parsed[0])
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
			name:   "conn send/recv",
			testFn: testConnSendRecv,
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
