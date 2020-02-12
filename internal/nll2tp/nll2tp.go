package nll2tp

import (
	"errors"
	"fmt"
	"net"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
)

type L2tpProtocolVersion uint32
type L2tpTunnelID uint32
type L2tpSessionID uint32

const (
	ProtocolVersion2 = 2
	ProtocolVersion3 = 3
)

type TunnelConfig struct {
	Tid         L2tpTunnelID
	Ptid        L2tpTunnelID
	Version     L2tpProtocolVersion
	Encap       L2tpEncapType
	Debug_flags L2tpDebugFlags
}

type SessionConfig struct {
	Tid             L2tpTunnelID
	Ptid            L2tpTunnelID
	Sid             L2tpSessionID
	Psid            L2tpSessionID
	Pseudowire_type L2tpPwtype
	Debug_flags     L2tpDebugFlags
}

type Conn struct {
	genl_family genetlink.Family
	c           *genetlink.Conn
}

// Create a new genetlink L2TP connection to the kernel
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

	return &Conn{
		genl_family: id,
		c:           c,
	}, nil
}

// Close connection, releasing associated resources
func (c *Conn) Close() {
	c.c.Close()
}

// Create a new managed tunnel instance in the kernel
func (c *Conn) CreateManagedTunnel(fd int, config *TunnelConfig) (err error) {
	if fd < 0 {
		return errors.New("Managed tunnel needs a valid socket file descriptor")
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

// Create a new static tunnel instance in the kernel
func (c *Conn) CreateStaticTunnel(local_addr *net.IP, local_port uint16,
	peer_addr *net.IP, peer_port uint16,
	config *TunnelConfig) (err error) {

	if local_addr == nil {
		return errors.New("Unmanaged tunnel needs a valid local address")
	}
	if local_port == 0 {
		return errors.New("Unmanaged tunnel needs a valid local port")
	}
	if peer_addr == nil {
		return errors.New("Unmanaged tunnel needs a valid peer address")
	}
	if peer_port == 0 {
		return errors.New("Unmanaged tunnel needs a valid peer port")
	}
	if ipAddrLen(local_addr) != ipAddrLen(peer_addr) {
		return errors.New("Local and peer IP addresses must be of the same address family")
	}

	attr, err := tunnelCreateAttr(config)
	if err != nil {
		return err
	}

	return c.createTunnel(append(attr, netlink.Attribute{
		Type: AttrIpSaddr,
		Data: ipAddrBytes(local_addr),
	}, netlink.Attribute{
		Type: AttrUdpSport,
		Data: nlenc.Uint16Bytes(local_port),
	}, netlink.Attribute{
		Type: AttrIpDaddr,
		Data: ipAddrBytes(peer_addr),
	}, netlink.Attribute{
		Type: AttrUdpDport,
		Data: nlenc.Uint16Bytes(peer_port),
	}))
}

// Delete a tunnel instance in the kernel
func (c *Conn) DeleteTunnel(config *TunnelConfig) error {
	if config == nil {
		return errors.New("Invalid nil tunnel config")
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

	_, err = c.c.Execute(genetlink.Message{
		Header: genetlink.Header{
			Command: CmdTunnelDelete,
			Version: c.genl_family.Version,
		},
		Data: b,
	},
		c.genl_family.ID,
		netlink.Request|netlink.Acknowledge)
	return err
}

// Create a session instance in the kernel
func (c *Conn) CreateSession(config *SessionConfig) error {
	if config == nil {
		return errors.New("Invalid nil session config")
	}
	return nil
}

// Delete a session instance in the kernel
func (c *Conn) DeleteSession(config *SessionConfig) error {
	if config == nil {
		return errors.New("Invalid nil session config")
	}
	return nil
}

func (c *Conn) createTunnel(attr []netlink.Attribute) error {
	b, err := netlink.MarshalAttributes(attr)
	if err != nil {
		return err
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdTunnelCreate,
			Version: c.genl_family.Version,
		},
		Data: b,
	}

	_, err = c.c.Execute(req, c.genl_family.ID, netlink.Request|netlink.Acknowledge)
	return err
}

func tunnelCreateAttr(config *TunnelConfig) ([]netlink.Attribute, error) {

	// Basic error checking
	if config == nil {
		return nil, errors.New("Invalid nil tunnel config")
	}
	if config.Tid == 0 {
		return nil, errors.New("Tunnel config must have a non-zero tunnel ID")
	}
	if config.Ptid == 0 {
		return nil, errors.New("Tunnel config must have a non-zero peer tunnel ID")
	}
	if config.Version < ProtocolVersion2 || config.Version > ProtocolVersion3 {
		return nil, fmt.Errorf("Invalid tunnel protocol version %d", config.Version)
	}
	if config.Encap != EncaptypeUdp && config.Encap != EncaptypeIp {
		return nil, errors.New("Invalid tunnel encap (expect IP or UDP)")
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
			Data: nlenc.Uint32Bytes(uint32(config.Debug_flags)),
		},
	}, nil
}

func ipAddrLen(addr *net.IP) uint {
	switch {
	case addr == nil:
		return 0
	case addr.To4() != nil:
		return 4
	case addr.To16() != nil:
		return 16
	default:
		panic("Unexpected IP address length")
	}
}

func ipAddrBytes(addr *net.IP) []byte {
	if addr != nil {
		b := addr.To4()
		if b != nil {
			return b
		}
		b = addr.To16()
		if b != nil {
			return b
		}
	}
	return nil
}
