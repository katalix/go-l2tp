package main

import (
	"bytes"
	"fmt"
	"os/exec"

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

func main() {

	b := []byte{
		0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, /* control message AVP */
	}

	b = []byte{
		0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, /* control message AVP */
		0x00, 0x08, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, /* protocol version AVP */
		0x80, 0x0a, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, /* framing cap AVP */
		0x80, 0x0a, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, /* bearer cap AVP */
		0x00, 0x08, 0x00, 0x00, 0x00, 0x06, 0x01, 0x73, /* firmware revision AVP */
		0x80, 0x09, 0x00, 0x00, 0x00, 0x07, 0x6c, 0x61, 0x63, /* hostname AVP */
		0x00, 0x34, 0x00, 0x00, 0x00, 0x08, 0x70, 0x72, 0x6f, 0x6c, 0x32, 0x74, 0x70, 0x20, 0x31, 0x2e,
		0x37, 0x2e, 0x33, 0x20, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x2d, 0x33, 0x2e, 0x31, 0x33, 0x2e, 0x30,
		0x2d, 0x37, 0x31, 0x2d, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x20, 0x28, 0x78, 0x38, 0x36,
		0x5f, 0x36, 0x34, 0x29, /* vendor-name AVP */
		0x80, 0x08, 0x00, 0x00, 0x00, 0x09, 0x5f, 0x2b, /* assigned tunnel-id AVP */
		0x80, 0x08, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a, /* receive window size */
	}

	avps, err := ParseAVPBuffer(b)
	if err != nil {
		panic(err)
	}

	for _, avp := range avps {
		fmt.Println(avp)
		if avp.Type() == AvpTypeFirmwareRevision {
			if rev, err := avp.DecodeUint16Data(); err == nil {
				fmt.Printf("  firmware rev %d\n", rev)
			} else {
				fmt.Println(err)
			}
		}
		if avp.Type() == AvpTypeVendorName {
			if name, err := avp.DecodeStringData(); err == nil {
				fmt.Printf("  vendor name %s\n", name)
			} else {
				fmt.Println(err)
			}
		}
	}

	localAddr := "127.0.0.1:6000"
	remoteAddr := "localhost:5000"

	nlconn, err := nll2tp.Dial()
	if err != nil {
		panic(err)
	}
	defer nlconn.Close()

	t1, err := NewQuiescentL2tpTunnel(nlconn, localAddr, remoteAddr, 42, 1, nll2tp.ProtocolVersion3, nll2tp.EncaptypeUdp, 0)
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
		fmt.Println(nb, buf[:nb])
	}

	t1.Close()
}
