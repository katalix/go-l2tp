package main

type acNetlink interface {
	Dial() (acNetlinkConn, error)
}

type acNetlinkConn interface {
	addACRoute(l2tpTunnelID, l2tpSessionID uint32, pppoeSessionID uint16, interfaceName string) error
	delACRoute(l2tpTunnelID, l2tpSessionID uint32, pppoeSessionID uint16, interfaceName string) error
}
