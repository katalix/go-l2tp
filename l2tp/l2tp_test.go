package l2tp

import (
	"bytes"
	"fmt"
	"os/exec"
	"os/user"
	"strings"
	"testing"

	"github.com/katalix/sl2tpd/internal/nll2tp"
)

func TestRequiresRoot(t *testing.T) {

	// Test tests need root permissions, so verify we have those first of all
	user, err := user.Current()
	if err != nil {
		t.Errorf("Unable to obtain current user: %q", err)
	}
	if user.Uid != "0" {
		t.Skip("skipping test because we don't have root permissions")
	}

	nlconn, err := nll2tp.Dial()
	if err != nil {
		t.Errorf("Failed to establish netlink/L2TP connection: %q", err)
	}
	defer nlconn.Close()

	// subtests!
	t.Run("QuiescentInst", func(t *testing.T) {
		cases := []struct {
			cfg        QuiescentTunnelConfig
			expectFail bool
		}{
			{
				cfg: QuiescentTunnelConfig{
					LocalAddress:      "127.0.0.1:6000",
					RemoteAddress:     "localhost:5000",
					Version:           ProtocolVersion2,
					ControlConnID:     1,
					PeerControlConnID: 1001,
					Encap:             EncapTypeIP,
				},
				// L2TPv2 doesn't support IP encap
				expectFail: true,
			},
			{
				cfg: QuiescentTunnelConfig{
					LocalAddress:  "127.0.0.1:6000",
					RemoteAddress: "localhost:5000",
					Version:       ProtocolVersion2,
					Encap:         EncapTypeUDP,
				},
				// Must call out tunnel IDs
				expectFail: true,
			},
			{
				cfg: QuiescentTunnelConfig{
					LocalAddress:  "127.0.0.1:6000",
					RemoteAddress: "localhost:5000",
					Version:       ProtocolVersion3,
					Encap:         EncapTypeUDP,
				},
				// Must call out control connection IDs
				expectFail: true,
			},
			{
				cfg: QuiescentTunnelConfig{
					LocalAddress:      "127.0.0.1:6000",
					RemoteAddress:     "localhost:5000",
					Version:           ProtocolVersion2,
					ControlConnID:     1,
					PeerControlConnID: 1001,
					Encap:             EncapTypeUDP,
				},
			},
			{
				cfg: QuiescentTunnelConfig{
					LocalAddress:      "[::1]:6000",
					RemoteAddress:     "[::1]:5000",
					Version:           ProtocolVersion2,
					ControlConnID:     2,
					PeerControlConnID: 1002,
					Encap:             EncapTypeUDP,
				},
			},
			{
				cfg: QuiescentTunnelConfig{
					LocalAddress:      "127.0.0.1:6000",
					RemoteAddress:     "localhost:5000",
					Version:           ProtocolVersion3,
					ControlConnID:     3,
					PeerControlConnID: 1003,
					Encap:             EncapTypeUDP,
				},
			},
			{
				cfg: QuiescentTunnelConfig{
					LocalAddress:      "[::1]:6000",
					RemoteAddress:     "[::1]:5000",
					Version:           ProtocolVersion3,
					ControlConnID:     4,
					PeerControlConnID: 1004,
					Encap:             EncapTypeUDP,
				},
			},
			{
				cfg: QuiescentTunnelConfig{
					LocalAddress:      "127.0.0.1:6000",
					RemoteAddress:     "localhost:5000",
					Version:           ProtocolVersion3,
					ControlConnID:     5,
					PeerControlConnID: 1005,
					Encap:             EncapTypeIP,
				},
			},
			{
				cfg: QuiescentTunnelConfig{
					LocalAddress:      "[::1]:6000",
					RemoteAddress:     "[::1]:5000",
					Version:           ProtocolVersion3,
					ControlConnID:     6,
					PeerControlConnID: 1006,
					Encap:             EncapTypeIP,
				},
			},
		}
		for _, c := range cases {
			tunl, err := NewQuiescentTunnel(nlconn, &c.cfg)
			if c.expectFail {
				if err == nil {
					if tunl != nil {
						tunl.Close()
					}
					t.Fatalf("Expected NewQuiescentTunnel(%v) to fail", c.cfg)
				}
			} else {
				if err != nil {
					t.Fatalf("NewQuiescentTunnel(%v): %v", c.cfg, err)
				}

				err = checkQuiescentTunnel(&c.cfg)
				tunl.Close()

				if err != nil {
					t.Errorf("NewQuiescentTunnel(%v): failed to validate: %v", c.cfg, err)
				}
			}
		}
	})

	t.Run("StaticInst", func(t *testing.T) {
		cases := []struct {
			cfg        StaticTunnelConfig
			expectFail bool
		}{
			{
				cfg: StaticTunnelConfig{
					LocalAddress:  "127.0.0.1:6000",
					RemoteAddress: "localhost:5000",
					Encap:         EncapTypeUDP,
				},
				// Must call out control connection IDs
				expectFail: true,
			},
			{
				cfg: StaticTunnelConfig{
					LocalAddress:      "127.0.0.1:6000",
					RemoteAddress:     "localhost:5000",
					ControlConnID:     5001,
					PeerControlConnID: 6001,
					Encap:             EncapTypeUDP,
				},
			},
			{
				cfg: StaticTunnelConfig{
					LocalAddress:      "[::1]:6000",
					RemoteAddress:     "[::1]:5000",
					ControlConnID:     5002,
					PeerControlConnID: 6002,
					Encap:             EncapTypeUDP,
				},
			},
			{
				cfg: StaticTunnelConfig{
					LocalAddress:      "127.0.0.1:6000",
					RemoteAddress:     "localhost:5000",
					ControlConnID:     5003,
					PeerControlConnID: 6003,
					Encap:             EncapTypeIP,
				},
			},
			{
				cfg: StaticTunnelConfig{
					LocalAddress:      "[::1]:6000",
					RemoteAddress:     "[::1]:5000",
					ControlConnID:     5004,
					PeerControlConnID: 6004,
					Encap:             EncapTypeIP,
				},
			},
		}
		for _, c := range cases {
			tunl, err := NewStaticTunnel(nlconn, &c.cfg)
			if c.expectFail {
				if err == nil {
					if tunl != nil {
						tunl.Close()
					}
					t.Fatalf("Expected NewStaticTunnel(%v) to fail", c.cfg)
				}
			} else {
				if err != nil {
					t.Fatalf("NewStaticTunnel(%v): %v", c.cfg, err)
				}

				err = checkStaticTunnel(&c.cfg)
				tunl.Close()

				if err != nil {
					t.Errorf("NewStaticTunnel(%v): failed to validate: %v", c.cfg, err)
				}
			}
		}
	})
}

func ipL2tpShowTunnel(tid uint32) (out string, err error) {
	var tidStr string
	var tidArgStr string
	var sout bytes.Buffer

	if tid > 0 {
		tidArgStr = "tunnel_id"
		tidStr = fmt.Sprintf("%d", tid)
	}

	cmd := exec.Command("sudo", "ip", "l2tp", "show", "tunnel", tidArgStr, tidStr)
	cmd.Stdout = &sout

	err = cmd.Run()
	if err != nil {
		return "", err
	}

	fmt.Println(sout.String())

	return sout.String(), nil
}

func ipL2tpShowSession(tid, sid uint32) (out string, err error) {
	var tidStr string
	var tidArgStr string
	var sidStr string
	var sidArgStr string
	var sout bytes.Buffer

	if tid > 0 {
		tidArgStr = "tunnel_id"
		tidStr = fmt.Sprintf("%d", tid)
	}
	if sid > 0 {
		sidArgStr = "session_id"
		sidStr = fmt.Sprintf("%d", sid)
	}

	cmd := exec.Command("sudo", "ip", "l2tp", "show", "session", tidArgStr, tidStr, sidArgStr, sidStr)
	cmd.Stdout = &sout

	err = cmd.Run()
	if err != nil {
		return "", err
	}

	fmt.Println(sout.String())

	return sout.String(), nil
}

func validateIPL2tpTunnelOut(out string, tid, ptid uint32, encap EncapType) error {
	expect := []string{
		fmt.Sprintf("Tunnel %v,", tid),
		fmt.Sprintf("encap %v", encap),
		fmt.Sprintf("Peer tunnel %v", ptid),
	}
	for _, e := range expect {
		if !strings.Contains(out, e) {
			return fmt.Errorf("failed to locate expected substring %q in output %q", e, out)
		}
	}
	return nil
}

func validateIPL2tpSessionOut(out string, tid, sid, psid uint32) error {
	return nil // TODO
}

func checkQuiescentTunnel(cfg *QuiescentTunnelConfig) error {
	var tid, ptid uint32
	if cfg.Version == ProtocolVersion2 {
		tid = uint32(cfg.ControlConnID)
		ptid = uint32(cfg.PeerControlConnID)
	} else {
		tid = uint32(cfg.ControlConnID)
		ptid = uint32(cfg.PeerControlConnID)
	}
	out, err := ipL2tpShowTunnel(tid)
	if err != nil {
		return fmt.Errorf("ip l2tp couldn't show tunnel %v: %v", tid, err)
	}
	return validateIPL2tpTunnelOut(out, tid, ptid, cfg.Encap)
}

func checkStaticTunnel(cfg *StaticTunnelConfig) error {
	tid := uint32(cfg.ControlConnID)
	ptid := uint32(cfg.PeerControlConnID)
	out, err := ipL2tpShowTunnel(tid)
	if err != nil {
		return fmt.Errorf("ip l2tp couldn't show tunnel %v: %v", tid, err)
	}
	return validateIPL2tpTunnelOut(out, tid, ptid, cfg.Encap)
}
