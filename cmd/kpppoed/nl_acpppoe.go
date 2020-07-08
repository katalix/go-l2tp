package main

import (
	"github.com/katalix/go-l2tp/internal/nlacpppoe"
)

var _ acNetlink = (*acpppoeNL)(nil)
var _ acNetlinkConn = (*acpppoeNLConn)(nil)

type acpppoeNL struct {
}

type acpppoeNLConn struct {
	c *nlacpppoe.Conn
}

func (nl *acpppoeNL) Dial() (acNetlinkConn, error) {
	c, err := nlacpppoe.Dial()
	if err != nil {
		return nil, err
	}
	return &acpppoeNLConn{c: c}, nil
}

func (conn *acpppoeNLConn) addACRoute(l2tpTunnelID, l2tpSessionID uint32, pppoeSessionID uint16, interfaceName string) error {
	// Fun fact: the l2tp_ac_pppoe driver wants a value for peer session ID
	// sending in the netlink add route command, but doesn't actually do anything
	// with it.  Send zero to make it happy.
	return conn.c.AddRoute(l2tpTunnelID, l2tpSessionID, 0, pppoeSessionID, interfaceName)
}

func (conn *acpppoeNLConn) delACRoute(l2tpTunnelID, l2tpSessionID uint32, pppoeSessionID uint16, interfaceName string) error {
	// Fun fact: the l2tp_ac_pppoe driver wants a value for peer session ID
	// sending in the netlink del route command, but doesn't actually do anything
	// with it.  Send zero to make it happy.
	return conn.c.DelRoute(l2tpTunnelID, l2tpSessionID, 0, pppoeSessionID, interfaceName)
}
