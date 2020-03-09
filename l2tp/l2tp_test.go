package l2tp

import (
	"bytes"
	"fmt"
	"os/exec"
	"os/user"
	"testing"

	"github.com/katalix/sl2tpd/internal/nll2tp"
)

func ipL2tpShowTunnel(tid nll2tp.L2tpTunnelID) (out string, err error) {
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

	return sout.String(), nil
}

func TestRequiresRoot(t *testing.T) {

	local := "127.0.0.1:6000"
	peer := "localhost:5000"

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
			version ProtocolVersion
			encap   nll2tp.L2tpEncapType
		}{
			{ProtocolVersion2, nll2tp.EncaptypeUdp},
			{ProtocolVersion3, nll2tp.EncaptypeUdp},
			// TODO: we need to support L2TPIP sockaddr before this will work
			//{nll2tp.ProtocolVersion3, nll2tp.EncaptypeIp},
		}
		for _, c := range cases {
			tunl, err := NewQuiescentTunnel(nlconn, local, peer, 42, 42, c.version, c.encap, 0)
			if err == nil {
				if tunl != nil {
					_, err = ipL2tpShowTunnel(42)
					tunl.Close()
					if err != nil {
						t.Errorf("Couldn't validate tunnel using ip l2tp: %q", err)
					}
				} else {
					t.Errorf("No error reported but NewQuiescentTunnel returned a nil tunnel instance")
				}
			} else {
				t.Errorf("Failed to bring up quiescent tunnel: %q", err)
			}
		}
	})

	t.Run("StaticInst", func(t *testing.T) {
		cases := []struct {
			encap nll2tp.L2tpEncapType
		}{
			{nll2tp.EncaptypeUdp},
			// TODO: we need to support L2TPIP sockaddr before this will work
			{nll2tp.EncaptypeIp},
		}
		for _, c := range cases {
			tunl, err := NewStaticTunnel(nlconn, local, peer, 42, 42, c.encap, 0)
			if err == nil {
				if tunl != nil {
					_, err = ipL2tpShowTunnel(42)
					tunl.Close()
					if err != nil {
						t.Errorf("Couldn't validate tunnel using ip l2tp: %q", err)
					}
				} else {
					t.Errorf("No error reported but NewStaticTunnel returned a nil tunnel instance")
				}
			} else {
				t.Errorf("Failed to bring up static tunnel: %q", err)
			}
		}
	})
}
