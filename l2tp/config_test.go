package l2tp

import (
	"reflect"
	"testing"
	"time"
)

func TestGetTunnels(t *testing.T) {
	cases := []struct {
		in   string
		want map[string]*TunnelConfig
	}{
		{
			in: `[tunnel.t1]
				 encap = "ip"
				 version = "l2tpv3"
				 peer = "82.9.90.101:1701"
				 tid = 412
				 ptid = 8192

				 [tunnel.t2]
				 encap = "udp"
				 version = "l2tpv2"
				 peer = "[2001:0000:1234:0000:0000:C1C0:ABCD:0876]:6543"
				 `,
			want: map[string]*TunnelConfig{
				"t1": &TunnelConfig{
					Encap:        EncapTypeIP,
					Version:      ProtocolVersion3,
					Peer:         "82.9.90.101:1701",
					TunnelID:     412,
					PeerTunnelID: 8192,
					Sessions:     make(map[string]*SessionConfig),
				},
				"t2": &TunnelConfig{
					Encap:    EncapTypeUDP,
					Version:  ProtocolVersion2,
					Peer:     "[2001:0000:1234:0000:0000:C1C0:ABCD:0876]:6543",
					Sessions: make(map[string]*SessionConfig),
				},
			},
		},
		{
			in: `[tunnel.t1]
				 encap = "ip"
				 version = "l2tpv3"
				 peer = "127.0.0.1:5001"

				 [tunnel.t1.session.s1]
				 pseudowire = "eth"
				 cookie = [ 0x34, 0x04, 0xa9, 0xbe ]
				 peer_cookie = [ 0x80, 0x12, 0xff, 0x5b ]
				 seqnum = true
				 reorder_timeout = 1500
				 l2spec_type = "none"

				 [tunnel.t1.session.s2]
				 pseudowire = "ppp"
				 sid = 90210
				 psid = 1237812
				 interface_name = "becky"
				 l2spec_type = "default"
				`,
			want: map[string]*TunnelConfig{
				"t1": &TunnelConfig{
					Encap:   EncapTypeIP,
					Version: ProtocolVersion3,
					Peer:    "127.0.0.1:5001",
					Sessions: map[string]*SessionConfig{
						"s1": &SessionConfig{
							Pseudowire:     PseudowireTypeEth,
							Cookie:         []byte{0x34, 0x04, 0xa9, 0xbe},
							PeerCookie:     []byte{0x80, 0x12, 0xff, 0x5b},
							SeqNum:         true,
							ReorderTimeout: time.Millisecond * 1500,
						},
						"s2": &SessionConfig{
							Pseudowire:    PseudowireTypePPP,
							SessionID:     90210,
							PeerSessionID: 1237812,
							InterfaceName: "becky",
							L2SpecType:    L2SpecTypeDefault,
						},
					},
				},
			},
		},
	}
	for _, c := range cases {
		cfg, err := LoadString(c.in)
		if err != nil {
			t.Fatalf("LoadString(%v): %v", c.in, err)
		}
		tunnels := cfg.GetTunnels()
		if !reflect.DeepEqual(tunnels, c.want) {
			t.Fatalf("GetTunnels(): got %v, want %v", tunnels, c.want)
		}
	}
}
