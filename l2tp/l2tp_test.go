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

func ipL2tpShowTunnel(tid TunnelID) (out string, err error) {
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

func validateIpL2tpOut(out string, tid, ptid TunnelID, encap EncapType) error {
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
			local, peer string
			version     ProtocolVersion
			encap       EncapType
			tid, ptid   TunnelID
		}{
			{"127.0.0.1:6000", "localhost:5000", ProtocolVersion2, EncapTypeUDP, 10, 20},
			{"[::1]:6000", "[::1]:5000", ProtocolVersion2, EncapTypeUDP, 10, 20},
			{"127.0.0.1:6000", "localhost:5000", ProtocolVersion3, EncapTypeUDP, 30, 40},
			{"[::1]:6000", "[::1]:5000", ProtocolVersion3, EncapTypeUDP, 30, 40},
			{"127.0.0.1:6000", "localhost:5000", ProtocolVersion3, EncapTypeIP, 50, 60},
			{"[::1]:6000", "[::1]:5000", ProtocolVersion3, EncapTypeUDP, 30, 40},
		}
		for _, c := range cases {
			tunl, err := NewQuiescentTunnel(nlconn, c.local, c.peer, c.tid, c.ptid, c.version, c.encap, 0)
			if err != nil {
				t.Fatalf("Failed to bring up quiescent tunnel: %q", err)
			}

			if tunl == nil {
				t.Fatalf("No error reported but NewQuiescentTunnel returned a nil tunnel instance")
			}

			// ip l2tp will report an error if the tunnel ID doesn't exist
			out, err := ipL2tpShowTunnel(c.tid)
			if err != nil {
				t.Errorf("Couldn't validate tunnel using ip l2tp: %q", err)
			}

			err = validateIpL2tpOut(out, c.tid, c.ptid, c.encap)
			if err != nil {
				t.Errorf("Failed to validate ip l2tp output: %v", err)
			}

			tunl.Close()
		}
	})

	t.Run("StaticInst", func(t *testing.T) {
		cases := []struct {
			local, peer string
			encap       EncapType
			tid, ptid   TunnelID
		}{
			{"127.0.0.1:6000", "localhost:5000", EncapTypeUDP, 11, 12},
			{"[::1]:6000", "[::1]:5000", EncapTypeUDP, 11, 12},
			{"127.0.0.1:6000", "localhost:5000", EncapTypeIP, 13, 14},
			{"[::1]:6000", "[::1]:5000", EncapTypeIP, 13, 14},
		}
		for _, c := range cases {
			tunl, err := NewStaticTunnel(nlconn, c.local, c.peer, c.tid, c.ptid, c.encap, 0)
			if err != nil {
				t.Fatalf("Failed to bring up static tunnel: %q", err)
			}

			if tunl == nil {
				t.Fatalf("No error reported but NewStaticTunnel returned a nil tunnel instance")
			}

			// ip l2tp will report an error if the tunnel ID doesn't exist
			out, err := ipL2tpShowTunnel(c.tid)
			if err != nil {
				t.Errorf("Couldn't validate tunnel using ip l2tp: %q", err)
			}

			err = validateIpL2tpOut(out, c.tid, c.ptid, c.encap)
			if err != nil {
				t.Errorf("Failed to validate ip l2tp output: %v", err)
			}
			tunl.Close()
		}
	})
}
