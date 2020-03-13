package nll2tp

import (
	"errors"
	"fmt"
	"sync"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
)

// L2tpProtocolVersion describes the RFC version of the tunnel:
// L2TPv2 is described by RFC2661, while L2TPv3 is described by
// RFC3931.
type L2tpProtocolVersion uint32

// L2tpTunnelID represents the numeric identifier of an L2TP tunnel.
// This ID is used in L2TP control and data packet headers and AVPs,
// and is unique to the host.
type L2tpTunnelID uint32

// L2tpSessionID represents the numeric identifier of an L2TP session.
// This ID is used in L2TP control and data packet headers and AVPs,
// and is unique to the tunnel for L2TPv2, or the host for L2TPv3.
type L2tpSessionID uint32

const (
	// ProtocolVersion2 specifies L2TPv2 RFC2661
	ProtocolVersion2 = 2
	// ProtocolVersion3 specifies L2TPv3 RFC3931
	ProtocolVersion3 = 3
)

// TunnelConfig encapsulates genetlink parameters for L2TP tunnel commands.
type TunnelConfig struct {
	// Tid is the host's L2TP ID for the tunnel.
	Tid L2tpTunnelID
	// Ptid is the peer's L2TP ID for the tunnel
	Ptid L2tpTunnelID
	// Version is the tunnel protocol version (L2TPv2 or L2TPv3)
	Version L2tpProtocolVersion
	// Encap specifies the tunnel encapsulation type.
	// For L2TPv3 this may be UDP or IP.
	// For L2TPv2 this may only be UDP.
	Encap L2tpEncapType
	// DebugFlags specifies the kernel debugging flags to use for the tunnel instance.
	DebugFlags L2tpDebugFlags
}

// SessionConfig encapsulates genetlink parameters for L2TP session commands.
type SessionConfig struct {
	// Tid is the host's L2TP ID for the tunnel containing the session.
	Tid L2tpTunnelID
	// Ptid is the peer's L2TP ID for the tunnel containing the session.
	Ptid L2tpTunnelID
	// Sid is the host's L2TP ID for the session.
	Sid L2tpSessionID
	// Psid is the peer's L2TP ID for the session.
	Psid L2tpSessionID
	// PseudowireType specifies the type of traffic carried by the session.
	// For L2TPv3 this may be PPP or Ethernet.
	// For L2TPv2 this may be PPP only.
	PseudowireType L2tpPwtype
	// SendSeq controls whether to send data packet sequence numbers per RFC2661 section 5.4.
	SendSeq bool
	// RecvSeq if set will cause data packets without sequence numbers to be dropped.
	RecvSeq bool
	// IsLNS if unset allows the LNS to enable data packet sequence numbers per RFC2661 section 5.4
	IsLNS bool
	// ReorderTimeout sets the maximum amount of time to hold a data packet in the reorder
	// queue when sequence numbers are enabled.  This number is defined in jiffies for the
	// running kernel (ref: man 7 time: sysconf(_SC_CLK_TCK))
	// TODO: make this use something a bit more sane...
	ReorderTimeout uint64
	// LocalCookie sets the RFC3931 cookie for the session.
	// Transmitted data packets will include the cookie.
	// The LocalCookie may be either 4 or 8 bytes in length if set.
	LocalCookie []byte
	// PeerCookie sets the RFC3931 peer cookie for the session as negotiated by the control protocol.
	// Received data packets with a cookie mismatch are discarded.
	// The PeerCookie may be either 4 or 8 bytes in length if set.
	PeerCookie []byte
	// IfName specifies the interface name to use for an RFC3931 Ethernet pseudowire.
	// By default the kernel generates a name "l2tpethX".
	IfName string
	// L2SpecType specifies the Layer 2 specific sublayer field to be used in data packets
	// as per RFC3931 section 3.2.2
	L2SpecType L2tpL2specType
	// DebugFlags specifies the kernel debugging flags to use for the session instance.
	DebugFlags L2tpDebugFlags
}

type msgRequest struct {
	msg    genetlink.Message
	family uint16
	flags  netlink.HeaderFlags
}

type msgResponse struct {
	msg []genetlink.Message
	err error
}

// Conn represents the genetlink L2TP connection to the kernel.
type Conn struct {
	genlFamily genetlink.Family
	c          *genetlink.Conn
	reqChan    chan *msgRequest
	rspChan    chan *msgResponse
	wg         sync.WaitGroup
}

// Dial creates a new genetlink L2TP connection to the kernel.
func Dial() (*Conn, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}

	id, err := c.GetFamily(GenlName)
	if err != nil {
		c.Close()
		return nil, err
	}

	conn := &Conn{
		genlFamily: id,
		c:          c,
		reqChan:    make(chan *msgRequest),
		rspChan:    make(chan *msgResponse),
	}

	conn.wg.Add(1)
	go runConn(conn, &conn.wg)

	return conn, nil
}

// Close connection, releasing associated resources
func (c *Conn) Close() {
	close(c.reqChan)
	c.wg.Wait()
	c.c.Close()
}

// CreateManagedTunnel creates a new managed tunnel instance in the kernel.
// A "managed" tunnel is one whose tunnel socket fd is created and managed
// by a userspace process.  A managed tunnel's lifetime is bound by the lifetime
// of the tunnel socket fd, and may optionally be destroyed using explicit
// netlink commands.
func (c *Conn) CreateManagedTunnel(fd int, config *TunnelConfig) (err error) {
	if fd < 0 {
		return errors.New("managed tunnel needs a valid socket file descriptor")
	}

	attr, err := tunnelCreateAttr(config)
	if err != nil {
		return err
	}

	return c.createTunnel(append(attr, netlink.Attribute{
		Type: AttrFd,
		Data: nlenc.Uint32Bytes(uint32(fd)),
	}))
}

// CreateStaticTunnel creates a new static tunnel instance in the kernel.
// A "static" tunnel is one whose tunnel socket fd is implicitly created
// by the kernel.  A static tunnel must be explicitly deleted using netlink
// commands.
func (c *Conn) CreateStaticTunnel(
	localAddr []byte, localPort uint16,
	peerAddr []byte, peerPort uint16,
	config *TunnelConfig) (err error) {

	if config == nil {
		return errors.New("invalid nil tunnel config pointer")
	}
	if len(localAddr) == 0 {
		return errors.New("unmanaged tunnel needs a valid local address")
	}
	if len(peerAddr) == 0 {
		return errors.New("unmanaged tunnel needs a valid peer address")
	}
	if len(localAddr) != len(peerAddr) {
		return errors.New("local and peer IP addresses must be of the same address family")
	}
	if config.Encap == EncaptypeUdp {
		if localPort == 0 {
			return errors.New("unmanaged tunnel needs a valid local port")
		}
		if peerPort == 0 {
			return errors.New("unmanaged tunnel needs a valid peer port")
		}
	}

	attr, err := tunnelCreateAttr(config)
	if err != nil {
		return err
	}

	switch len(localAddr) {
	case 4:
		attr = append(attr, netlink.Attribute{
			Type: AttrIpSaddr,
			Data: localAddr,
		}, netlink.Attribute{
			Type: AttrIpDaddr,
			Data: peerAddr,
		})
	case 16:
		attr = append(attr, netlink.Attribute{
			Type: AttrIp6Saddr,
			Data: localAddr,
		}, netlink.Attribute{
			Type: AttrIp6Daddr,
			Data: peerAddr,
		})
	default:
		panic("unexpected address length")
	}

	return c.createTunnel(append(attr, netlink.Attribute{
		Type: AttrUdpSport,
		Data: nlenc.Uint16Bytes(localPort),
	}, netlink.Attribute{
		Type: AttrUdpDport,
		Data: nlenc.Uint16Bytes(peerPort),
	}))
}

// DeleteTunnel deletes a tunnel instance from the kernel.
// Deleting a tunnel instance implicitly destroys any sessions
// running in that tunnel.
func (c *Conn) DeleteTunnel(config *TunnelConfig) error {
	if config == nil {
		return errors.New("invalid nil tunnel config")
	}

	b, err := netlink.MarshalAttributes([]netlink.Attribute{
		{
			Type: AttrConnId,
			Data: nlenc.Uint32Bytes(uint32(config.Tid)),
		},
	})
	if err != nil {
		return err
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdTunnelDelete,
			Version: c.genlFamily.Version,
		},
		Data: b,
	}

	_, err = c.execute(req, c.genlFamily.ID, netlink.Request|netlink.Acknowledge)
	return err
}

// CreateSession creates a session instance in the kernel.
// The parent tunnel instance referenced by the tunnel IDs in
// the session configuration must already exist in the kernel.
func (c *Conn) CreateSession(config *SessionConfig) error {
	attr, err := sessionCreateAttr(config)
	if err != nil {
		return err
	}

	b, err := netlink.MarshalAttributes(attr)
	if err != nil {
		return err
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdSessionCreate,
			Version: c.genlFamily.Version,
		},
		Data: b,
	}

	_, err = c.execute(req, c.genlFamily.ID, netlink.Request|netlink.Acknowledge)
	return err
}

// DeleteSession deletes a session instance from the kernel.
func (c *Conn) DeleteSession(config *SessionConfig) error {
	if config == nil {
		return errors.New("invalid nil session config")
	}

	b, err := netlink.MarshalAttributes([]netlink.Attribute{
		{
			Type: AttrConnId,
			Data: nlenc.Uint32Bytes(uint32(config.Tid)),
		},
		{
			Type: AttrSessionId,
			Data: nlenc.Uint32Bytes(uint32(config.Sid)),
		},
	})
	if err != nil {
		return err
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdSessionDelete,
			Version: c.genlFamily.Version,
		},
		Data: b,
	}

	_, err = c.execute(req, c.genlFamily.ID, netlink.Request|netlink.Acknowledge)
	return err
}

func (c *Conn) createTunnel(attr []netlink.Attribute) error {
	b, err := netlink.MarshalAttributes(attr)
	if err != nil {
		return err
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdTunnelCreate,
			Version: c.genlFamily.Version,
		},
		Data: b,
	}

	_, err = c.execute(req, c.genlFamily.ID, netlink.Request|netlink.Acknowledge)
	return err
}

func (c *Conn) execute(msg genetlink.Message, family uint16, flags netlink.HeaderFlags) ([]genetlink.Message, error) {
	c.reqChan <- &msgRequest{
		msg:    msg,
		family: family,
		flags:  flags,
	}

	rsp, ok := <-c.rspChan
	if !ok {
		return nil, errors.New("netlink connection closed")
	}

	return rsp.msg, rsp.err
}

func tunnelCreateAttr(config *TunnelConfig) ([]netlink.Attribute, error) {

	// Basic error checking
	if config == nil {
		return nil, errors.New("invalid nil tunnel config")
	}
	if config.Tid == 0 {
		return nil, errors.New("tunnel config must have a non-zero tunnel ID")
	}
	if config.Ptid == 0 {
		return nil, errors.New("tunnel config must have a non-zero peer tunnel ID")
	}
	if config.Version < ProtocolVersion2 || config.Version > ProtocolVersion3 {
		return nil, fmt.Errorf("invalid tunnel protocol version %d", config.Version)
	}
	if config.Encap != EncaptypeUdp && config.Encap != EncaptypeIp {
		return nil, errors.New("invalid tunnel encap (expect IP or UDP)")
	}

	// Version-specific checks
	if config.Version == ProtocolVersion2 {
		if config.Tid > 65535 {
			return nil, errors.New("L2TPv2 tunnel ID can't exceed 16-bit limit")
		}
		if config.Ptid > 65535 {
			return nil, errors.New("L2TPv2 peer tunnel ID can't exceed 16-bit limit")
		}
		if config.Encap != EncaptypeUdp {
			return nil, errors.New("L2TPv2 only supports UDP encapsuation")
		}
	}

	return []netlink.Attribute{
		{
			Type: AttrConnId,
			Data: nlenc.Uint32Bytes(uint32(config.Tid)),
		},
		{
			Type: AttrPeerConnId,
			Data: nlenc.Uint32Bytes(uint32(config.Ptid)),
		},
		{
			Type: AttrProtoVersion,
			Data: nlenc.Uint8Bytes(uint8(config.Version)),
		},
		{
			Type: AttrEncapType,
			Data: nlenc.Uint16Bytes(uint16(config.Encap)),
		},
		{
			Type: AttrDebug,
			Data: nlenc.Uint32Bytes(uint32(config.DebugFlags)),
		},
	}, nil
}

func sessionCreateAttr(config *SessionConfig) ([]netlink.Attribute, error) {

	// Sanity checks
	if config == nil {
		return nil, errors.New("invalid nil session config")
	}
	if config.Tid == 0 {
		return nil, errors.New("session config must have a non-zero parent tunnel ID")
	}
	if config.Ptid == 0 {
		return nil, errors.New("session config must have a non-zero parent peer tunnel ID")
	}
	if config.Sid == 0 {
		return nil, errors.New("session config must have a non-zero session ID")
	}
	if config.Psid == 0 {
		return nil, errors.New("session config must have a non-zero peer session ID")
	}
	if config.PseudowireType == PwtypeNone {
		return nil, errors.New("session config must have a valid pseudowire type")
	}
	if len(config.LocalCookie) > 0 {
		if len(config.LocalCookie) != 4 && len(config.LocalCookie) != 8 {
			return nil, fmt.Errorf("session config has peer cookie of %d bytes: valid lengths are 4 or 8 bytes",
				len(config.LocalCookie))
		}
	}
	if len(config.PeerCookie) > 0 {
		if len(config.PeerCookie) != 4 && len(config.PeerCookie) != 8 {
			return nil, fmt.Errorf("session config has peer cookie of %d bytes: valid lengths are 4 or 8 bytes",
				len(config.PeerCookie))
		}
	}

	attr := []netlink.Attribute{
		{
			Type: AttrConnId,
			Data: nlenc.Uint32Bytes(uint32(config.Tid)),
		},
		{
			Type: AttrPeerConnId,
			Data: nlenc.Uint32Bytes(uint32(config.Ptid)),
		},
		{
			Type: AttrSessionId,
			Data: nlenc.Uint32Bytes(uint32(config.Tid)),
		},
		{
			Type: AttrPeerSessionId,
			Data: nlenc.Uint32Bytes(uint32(config.Ptid)),
		},
	}

	// VLAN pseudowires use the kernel l2tp_eth driver
	if config.PseudowireType == PwtypeEthVlan {
		attr = append(attr, netlink.Attribute{
			Type: AttrPwType,
			Data: nlenc.Uint16Bytes(uint16(PwtypeEth)),
		})
	} else {
		attr = append(attr, netlink.Attribute{
			Type: AttrPwType,
			Data: nlenc.Uint16Bytes(uint16(config.PseudowireType)),
		})
	}

	if config.SendSeq {
		attr = append(attr, netlink.Attribute{
			Type: AttrSendSeq,
			Data: nlenc.Uint8Bytes(1),
		})
	}

	if config.RecvSeq {
		attr = append(attr, netlink.Attribute{
			Type: AttrRecvSeq,
			Data: nlenc.Uint8Bytes(1),
		})
	}

	if (config.SendSeq || config.RecvSeq) && config.IsLNS {
		attr = append(attr, netlink.Attribute{
			Type: AttrLnsMode,
			Data: nlenc.Uint8Bytes(1),
		})
	}

	if config.ReorderTimeout > 0 {
		attr = append(attr, netlink.Attribute{
			Type: AttrRecvTimeout,
			Data: nlenc.Uint64Bytes(config.ReorderTimeout),
		})
	}

	if len(config.LocalCookie) > 0 {
		attr = append(attr, netlink.Attribute{
			Type: AttrCookie,
			Data: config.LocalCookie,
		})
	}

	if len(config.PeerCookie) > 0 {
		attr = append(attr, netlink.Attribute{
			Type: AttrCookie,
			Data: config.PeerCookie,
		})
	}

	if config.IfName != "" {
		attr = append(attr, netlink.Attribute{
			Type: AttrIfname,
			Data: []byte(config.IfName),
		})
	}

	attr = append(attr, netlink.Attribute{
		Type: AttrL2specType,
		Data: nlenc.Uint8Bytes(uint8(config.L2SpecType)),
	})

	switch config.L2SpecType {
	case L2spectypeNone:
		attr = append(attr, netlink.Attribute{
			Type: AttrL2specLen,
			Data: nlenc.Uint8Bytes(0),
		})
	case L2spectypeDefault:
		attr = append(attr, netlink.Attribute{
			Type: AttrL2specLen,
			Data: nlenc.Uint8Bytes(4),
		})
	default:
		return nil, fmt.Errorf("unhandled L2 Spec Type %v", config.L2SpecType)
	}

	return attr, nil
}

func runConn(c *Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	for req := range c.reqChan {
		m, err := c.c.Execute(req.msg, req.family, req.flags)
		c.rspChan <- &msgResponse{
			msg: m,
			err: err,
		}
	}
}
