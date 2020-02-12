package main

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/katalix/sl2tpd/internal/nll2tp"
)

func ipL2tpShowTunnel(tid nll2tp.L2tpTunnelID) (out string, err error) {
	var tid_s string
	var arg string
	var sout bytes.Buffer

	if tid > 0 {
		arg = "tunnel_id"
		tid_s = fmt.Sprintf("%d", tid)
	}

	cmd := exec.Command("sudo", "ip", "l2tp", "show", "tunnel", arg, tid_s)
	cmd.Stdout = &sout

	err = cmd.Run()
	if err != nil {
		return "", err
	}

	return sout.String(), nil
}

func main() {

	local_addr := "127.0.0.1:5000"
	peer_addr := "localhost:5001"

	nlconn, err := nll2tp.Dial()
	if err != nil {
		panic(err)
	}
	defer nlconn.Close()

	t1, err := NewQuiescentL2tpTunnel(nlconn, local_addr, peer_addr, 42, 1, nll2tp.ProtocolVersion3, nll2tp.EncaptypeUdp, 0)
	if err != nil {
		panic(err)
	}
	out, err := ipL2tpShowTunnel(42)
	if err != nil {
		panic(err)
	}
	fmt.Println(out)

	for {
		buf := make([]byte, 1024)
		nb, err := t1.cp.Read(buf)
		if err != nil {
			panic(err)
		}
		fmt.Println(nb, buf)
	}

	t1.Close()
}
