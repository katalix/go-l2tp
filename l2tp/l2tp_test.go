package l2tp

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

// Must be called with root permissions
func testQuiescentTunnels(t *testing.T) {
	cases := []struct {
		name       string
		cfg        TunnelConfig
		expectFail bool
	}{
		{
			name: "reject L2TPv2 IP encap",
			cfg: TunnelConfig{
				Local:        "127.0.0.1:6000",
				Peer:         "localhost:5000",
				Version:      ProtocolVersion2,
				TunnelID:     1,
				PeerTunnelID: 1001,
				Encap:        EncapTypeIP,
			},
			// L2TPv2 doesn't support IP encap
			expectFail: true,
		},
		{
			name: "reject L2TPv2 config with no tunnel IDs",
			cfg: TunnelConfig{
				Local:   "127.0.0.1:6000",
				Peer:    "localhost:5000",
				Version: ProtocolVersion2,
				Encap:   EncapTypeUDP,
			},
			// Must call out tunnel IDs
			expectFail: true,
		},
		{
			name: "reject L2TPv3 config with no tunnel IDs",
			cfg: TunnelConfig{
				Local:   "127.0.0.1:6000",
				Peer:    "localhost:5000",
				Version: ProtocolVersion3,
				Encap:   EncapTypeUDP,
			},
			// Must call out control connection IDs
			expectFail: true,
		},
		{
			name: "L2TPv2 UDP AF_INET",
			cfg: TunnelConfig{
				Local:        "127.0.0.1:6000",
				Peer:         "localhost:5000",
				Version:      ProtocolVersion2,
				TunnelID:     1,
				PeerTunnelID: 1001,
				Encap:        EncapTypeUDP,
			},
		},
		{
			name: "L2TPv2 UDP AF_INET6",
			cfg: TunnelConfig{
				Local:        "[::1]:6000",
				Peer:         "[::1]:5000",
				Version:      ProtocolVersion2,
				TunnelID:     2,
				PeerTunnelID: 1002,
				Encap:        EncapTypeUDP,
			},
		},
		{
			name: "L2TPv3 UDP AF_INET",
			cfg: TunnelConfig{
				Local:        "127.0.0.1:6000",
				Peer:         "localhost:5000",
				Version:      ProtocolVersion3,
				TunnelID:     3,
				PeerTunnelID: 1003,
				Encap:        EncapTypeUDP,
			},
		},
		{
			name: "L2TPv3 UDP AF_INET6",
			cfg: TunnelConfig{
				Local:        "[::1]:6000",
				Peer:         "[::1]:5000",
				Version:      ProtocolVersion3,
				TunnelID:     4,
				PeerTunnelID: 1004,
				Encap:        EncapTypeUDP,
			},
		},
		{
			name: "L2TPv3 IP AF_INET",
			cfg: TunnelConfig{
				Local:        "127.0.0.1:6000",
				Peer:         "localhost:5000",
				Version:      ProtocolVersion3,
				TunnelID:     5,
				PeerTunnelID: 1005,
				Encap:        EncapTypeIP,
			},
		},
		{
			name: "L2TPv3 IP AF_INET6",
			cfg: TunnelConfig{
				Local:        "[::1]:6000",
				Peer:         "[::1]:5000",
				Version:      ProtocolVersion3,
				TunnelID:     6,
				PeerTunnelID: 1006,
				Encap:        EncapTypeIP,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, err := NewContext(
				level.NewFilter(log.NewLogfmtLogger(os.Stderr),
					level.AllowDebug(), level.AllowInfo()), nil)
			if err != nil {
				t.Fatalf("NewContext(): %v", err)
			}
			defer ctx.Close()

			_, err = ctx.NewQuiescentTunnel("t1", &c.cfg)
			if c.expectFail {
				if err == nil {
					t.Fatalf("Expected NewQuiescentTunnel(%v) to fail", c.cfg)
				}
			} else {
				if err != nil {
					t.Fatalf("NewQuiescentTunnel(%v): %v", c.cfg, err)
				}

				err = checkTunnel(&c.cfg)
				if err != nil {
					t.Errorf("NewQuiescentTunnel(%v): failed to validate: %v", c.cfg, err)
				}
			}
		})
	}
}

// Must be called with root permissions
func testQuiescentSessions(t *testing.T) {
	cases := []struct {
		name string
		tcfg TunnelConfig
		scfg SessionConfig
	}{
		{
			name: "L2TPv3 Eth Session",
			tcfg: TunnelConfig{
				Local:        "127.0.0.1:6000",
				Peer:         "localhost:5000",
				TunnelID:     5003,
				PeerTunnelID: 6003,
				Encap:        EncapTypeIP,
				Version:      ProtocolVersion3,
			},
			scfg: SessionConfig{
				SessionID:     500001,
				PeerSessionID: 500002,
				Pseudowire:    PseudowireTypeEth,
				// FIXME: currently causes nl create to fail with EINVAL
				//InterfaceName: "l2tpeth42",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, err := NewContext(
				level.NewFilter(log.NewLogfmtLogger(os.Stderr),
					level.AllowDebug(), level.AllowInfo()), nil)
			if err != nil {
				t.Fatalf("NewContext(): %v", err)
			}
			defer ctx.Close()

			tunl, err := ctx.NewQuiescentTunnel("t1", &c.tcfg)
			if err != nil {
				t.Fatalf("NewQuiescentTunnel(%v): %v", c.tcfg, err)
			}

			_, err = tunl.NewSession("s1", &c.scfg)
			if err != nil {
				t.Fatalf("NewSession(%v): %v", c.scfg, err)
			}

			err = checkSession(&c.tcfg, &c.scfg)
			if err != nil {
				t.Fatalf("NewSession(%v): failed to validate: %v", c.scfg, err)
			}
		})
	}
}

// Must be called with root permissions
func testStaticTunnels(t *testing.T) {
	cases := []struct {
		name       string
		cfg        TunnelConfig
		expectFail bool
	}{
		{
			name: "reject L2TPv3 config with no tunnel IDs",
			cfg: TunnelConfig{
				Local:   "127.0.0.1:6000",
				Peer:    "localhost:5000",
				Encap:   EncapTypeUDP,
				Version: ProtocolVersion3,
			},
			// Must call out control connection IDs
			expectFail: true,
		},
		{
			name: "L2TPv3 UDP AF_INET",
			cfg: TunnelConfig{
				Local:        "127.0.0.1:6000",
				Peer:         "localhost:5000",
				TunnelID:     5001,
				PeerTunnelID: 6001,
				Encap:        EncapTypeUDP,
				Version:      ProtocolVersion3,
			},
		},
		{
			name: "L2TPv3 UDP AF_INET6",
			cfg: TunnelConfig{
				Local:        "[::1]:6000",
				Peer:         "[::1]:5000",
				TunnelID:     5002,
				PeerTunnelID: 6002,
				Encap:        EncapTypeUDP,
				Version:      ProtocolVersion3,
			},
		},
		{
			name: "L2TPv3 IP AF_INET",
			cfg: TunnelConfig{
				Local:        "127.0.0.1:6000",
				Peer:         "localhost:5000",
				TunnelID:     5003,
				PeerTunnelID: 6003,
				Encap:        EncapTypeIP,
				Version:      ProtocolVersion3,
			},
		},
		{
			name: "L2TPv3 IP AF_INET6",
			cfg: TunnelConfig{
				Local:        "[::1]:6000",
				Peer:         "[::1]:5000",
				TunnelID:     5004,
				PeerTunnelID: 6004,
				Encap:        EncapTypeIP,
				Version:      ProtocolVersion3,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, err := NewContext(
				level.NewFilter(log.NewLogfmtLogger(os.Stderr),
					level.AllowDebug(), level.AllowInfo()), nil)
			if err != nil {
				t.Fatalf("NewContext(): %v", err)
			}
			defer ctx.Close()

			_, err = ctx.NewStaticTunnel("t1", &c.cfg)
			if c.expectFail {
				if err == nil {
					t.Fatalf("Expected NewStaticTunnel(%v) to fail", c.cfg)
				}
			} else {
				if err != nil {
					t.Fatalf("NewStaticTunnel(%v): %v", c.cfg, err)
				}

				err = checkTunnel(&c.cfg)
				if err != nil {
					t.Errorf("NewStaticTunnel(%v): failed to validate: %v", c.cfg, err)
				}
			}
		})
	}
}

// Must be called with root permissions
func testStaticSessions(t *testing.T) {
	cases := []struct {
		name string
		tcfg TunnelConfig
		scfg SessionConfig
	}{
		{
			name: "L2TPv3 Eth Session",
			tcfg: TunnelConfig{
				Local:        "127.0.0.1:6000",
				Peer:         "localhost:5000",
				TunnelID:     5003,
				PeerTunnelID: 6003,
				Encap:        EncapTypeIP,
				Version:      ProtocolVersion3,
			},
			scfg: SessionConfig{
				SessionID:     500001,
				PeerSessionID: 500002,
				Pseudowire:    PseudowireTypeEth,
				// FIXME: currently causes nl create to fail with EINVAL
				//InterfaceName: "l2tpeth42",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, err := NewContext(
				level.NewFilter(log.NewLogfmtLogger(os.Stderr),
					level.AllowDebug(), level.AllowInfo()), nil)
			if err != nil {
				t.Fatalf("NewContext(): %v", err)
			}
			defer ctx.Close()

			tunl, err := ctx.NewStaticTunnel("t1", &c.tcfg)
			if err != nil {
				t.Fatalf("NewStaticTunnel(%v): %v", c.tcfg, err)
			}

			_, err = tunl.NewSession("s1", &c.scfg)
			if err != nil {
				t.Fatalf("NewSession(%v): %v", c.scfg, err)
			}

			err = checkSession(&c.tcfg, &c.scfg)
			if err != nil {
				t.Fatalf("NewSession(%v): failed to validate: %v", c.scfg, err)
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

	tests := []struct {
		name   string
		testFn func(t *testing.T)
	}{
		{
			name:   "QuiescentTunnels",
			testFn: testQuiescentTunnels,
		},
		{
			name:   "QuiescentSessions",
			testFn: testQuiescentSessions,
		},
		{
			name:   "StaticTunnels",
			testFn: testStaticTunnels,
		},
		{
			name:   "StaticSessions",
			testFn: testStaticSessions,
		},
	}

	for _, sub := range tests {
		t.Run(sub.name, sub.testFn)
	}
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

func validateIPL2tpSessionOut(out string, tid, sid, ptid, psid uint32, ifnam string) error {
	expect := []string{
		fmt.Sprintf("Session %v in", sid),
		fmt.Sprintf("in tunnel %v", tid),
		fmt.Sprintf("Peer session %v,", psid),
		fmt.Sprintf(", tunnel %v", ptid),
	}

	if ifnam != "" {
		expect = append(expect, fmt.Sprintf("interface name: %v", ifnam))
	}

	for _, e := range expect {
		if !strings.Contains(out, e) {
			return fmt.Errorf("failed to locate expected substring %q in output %q", e, out)
		}
	}
	return nil
}

func checkSession(tcfg *TunnelConfig, scfg *SessionConfig) error {
	tid := uint32(tcfg.TunnelID)
	sid := uint32(scfg.SessionID)
	ptid := uint32(tcfg.PeerTunnelID)
	psid := uint32(scfg.PeerSessionID)
	out, err := ipL2tpShowSession(tid, sid)
	if err != nil {
		return fmt.Errorf("ip l2tp couldn't show session %v/%v: %v", tid, sid, err)
	}
	return validateIPL2tpSessionOut(out, tid, sid, ptid, psid, scfg.InterfaceName)
}

func checkTunnel(cfg *TunnelConfig) error {
	tid := uint32(cfg.TunnelID)
	ptid := uint32(cfg.PeerTunnelID)
	out, err := ipL2tpShowTunnel(tid)
	if err != nil {
		return fmt.Errorf("ip l2tp couldn't show tunnel %v: %v", tid, err)
	}
	return validateIPL2tpTunnelOut(out, tid, ptid, cfg.Encap)
}
