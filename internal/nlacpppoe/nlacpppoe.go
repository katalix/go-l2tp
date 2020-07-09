package nlacpppoe

import (
	"fmt"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

type Conn struct {
	genlFamily genetlink.Family
	c          *genetlink.Conn
}

func Dial() (conn *Conn, err error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return
	}

	id, err := c.GetFamily(GenlName)
	if err != nil {
		c.Close()
		return
	}

	conn = &Conn{
		genlFamily: id,
		c:          c,
	}
	return
}

func (conn *Conn) Close() {
	conn.c.Close()
}

func (conn *Conn) addDelRoute(cmd uint8,
	l2tpTunnelId, l2tpSessionId, l2tpPeerSessionId uint32,
	pppoeSessionId uint16, ifname string) (err error) {

	if l2tpTunnelId == 0 {
		return fmt.Errorf("L2TP tunnel ID must be nonzero")
	} else if l2tpSessionId == 0 {
		return fmt.Errorf("L2TP session ID must be nonzero")
	} else if pppoeSessionId == 0 {
		return fmt.Errorf("PPPoE session ID must be nonzero")
	} else if ifname == "" {
		return fmt.Errorf("PPPoE interface name must be specified")
	}

	ae := netlink.NewAttributeEncoder()
	ae.Uint32(AttrL2TPTunnelId, l2tpTunnelId)
	ae.Uint32(AttrL2TPSessionId, l2tpSessionId)
	ae.Uint32(AttrL2TPPeerSessionId, l2tpPeerSessionId)
	ae.Uint16(AttrPPPoESessionId, pppoeSessionId)
	ae.String(AttrPPPoEIfname, ifname)

	b, err := ae.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode attributes: %v", err)
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: cmd,
			Version: conn.genlFamily.Version,
		},
		Data: b,
	}

	_, err = conn.c.Execute(req, conn.genlFamily.ID, netlink.Request|netlink.Acknowledge)
	return
}

func (conn *Conn) AddRoute(l2tpTunnelId, l2tpSessionId, l2tpPeerSessionId uint32,
	pppoeSessionId uint16, ifname string) (err error) {
	return conn.addDelRoute(CmdAdd, l2tpTunnelId, l2tpSessionId, l2tpPeerSessionId, pppoeSessionId, ifname)
}

func (conn *Conn) DelRoute(l2tpTunnelId, l2tpSessionId, l2tpPeerSessionId uint32,
	pppoeSessionId uint16, ifname string) (err error) {
	return conn.addDelRoute(CmdDel, l2tpTunnelId, l2tpSessionId, l2tpPeerSessionId, pppoeSessionId, ifname)
}
