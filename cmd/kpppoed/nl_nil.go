package main

var _ acNetlink = (*nilNL)(nil)
var _ acNetlinkConn = (*nilNLConn)(nil)

type nilNL struct {
}

type nilNLConn struct {
}

func (nl *nilNL) Dial() (acNetlinkConn, error) {
	return &nilNLConn{}, nil
}

func (conn *nilNLConn) addACRoute(l2tpTunnelID, l2tpSessionID uint32, pppoeSessionID uint16, interfaceName string) error {
	return nil
}

func (conn *nilNLConn) delACRoute(l2tpTunnelID, l2tpSessionID uint32, pppoeSessionID uint16, interfaceName string) error {
	return nil
}
