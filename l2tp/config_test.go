package l2tp

import (
	"reflect"
	"testing"
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

				 [tunnel.t2]
				 encap = "udp"
				 version = "l2tpv2"
				 peer = "[2001:0000:1234:0000:0000:C1C0:ABCD:0876]:6543"
				 `,
			want: map[string]*TunnelConfig{
				"t1": &TunnelConfig{
					Encap:    EncapTypeIP,
					Version:  ProtocolVersion3,
					Peer:     "82.9.90.101:1701",
					Sessions: make(map[string]*SessionConfig),
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

				 [tunnel.t1.session.s2]
				 pseudowire = "ppp"
				`,
			want: map[string]*TunnelConfig{
				"t1": &TunnelConfig{
					Encap:   EncapTypeIP,
					Version: ProtocolVersion3,
					Peer:    "127.0.0.1:5001",
					Sessions: map[string]*SessionConfig{
						"s1": &SessionConfig{
							Pseudowire: "eth",
							Cookie:     []byte{0x34, 0x04, 0xa9, 0xbe},
						},
						"s2": &SessionConfig{
							Pseudowire: "ppp",
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
