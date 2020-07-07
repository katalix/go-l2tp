package nlacpppoe

const (
	GenlName    = "l2tp_ac_pppoe"
	GenlVersion = 0x1
)

const (
	CmdNoop = iota
	CmdAdd
	CmdDel
	CmdGet
)

const (
	AttrNone = iota
	AttrL2TPTunnelId
	AttrL2TPSessionId
	AttrL2TPPeerSessionId
	AttrPPPoESessionId
	AttrPPPoEIfname
)
