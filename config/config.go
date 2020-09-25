/*
Package config implements a parser for L2TP configuration represented in
the TOML format: https://github.com/toml-lang/toml.

Please refer to the TOML repos for an in-depth description of the syntax.

Tunnel and session instances are called out in the configuration file
using named TOML tables.  Each tunnel or session instance table contains
configuration parameters for that instance as key:value pairs.

	# This is a tunnel instance named "t1"
	[tunnel.t1]

	# local specifies the local address that the tunnel should
	# bind its socket to
	local = "127.0.0.1:5000"

	# peer specifies the address of the peer that the tunnel should
	# connect its socket to
	peer = "127.0.0.1:5001"

	# version specifies the version of the L2TP specification the
	# tunnel should use.
	# Currently supported values are "l2tpv2" and "l2tpv3"
	version = "l2tpv3"

	# encap specifies the encapsulation to be used for the tunnel.
	# Currently supported values are "udp" and "ip".
	# L2TPv2 tunnels are UDP only.
	encap = "udp"

	# tid specifies the local tunnel ID of the tunnel.
	# Tunnel IDs must be unique for the host.
	# L2TPv2 tunnel IDs are 16 bit, and may be in the range 1 - 65535.
	# L2TPv3 tunnel IDs are 32 bit, and may be in the range 1 - 4294967295.
	tid = 62719

	# ptid specifies the peer's tunnel ID for the tunnel.
	# The peer's tunnel ID must be unique for the peer, and are unrelated
	# to the local tunnel ID.
	# The rules for tunnel ID range apply to the peer tunnel ID too.
	ptid = 72819

	# window_size specifies the initial window size to use for the L2TP
	# reliable transport algorithm which is used for control protocol
	# messages.  The window size dictates how many control messages the
	# tunnel may have "in flight" (i.e. pending an ACK from the peer) at
	# any one time.  Tuning the window size can allow high-volume L2TP servers
	# to improve performance.  Generally it won't be necessary to change
	# this from the default value of 4.
	window_size = 10 # control messages

	# hello_timeout if set enables L2TP keep-alive (HELLO) messages.
	# A hello message is sent N milliseconds after the last control
	# message was sent or received.  It allows for early detection of
	# tunnel failure on quiet connections.
	# By default no keep-alive messages are sent.
	hello_timeout = 7500 # milliseconds

	# retry_timeout if set tweaks the starting retry timeout for the
	# reliable transport algorithm used for L2TP control messages.
	# The algorithm uses an exponential backoff when retrying messages.
	# By default a starting retry timeout of 1000ms is used.
	retry_timeout = 1500 # milliseconds

	# max_retries sets how many times a given control message may be
	# retried before the transport considers the message transmission to
	# have failed.
	# It may be useful to tune this value on unreliable network connections
	# to avoid suprious tunnel failure, or conversely to allow for quicker
	# tunnel failure detection on reliable links.
	# The default is 3 retries.
	max_retries 5

	# host_name sets the host name the tunnel will advertise in the
	# Host Name AVP per RFC2661.
	# If unset the host's name will be queried and the returned value used.
	host_name "basilbrush.local"

	# framing_caps sets the framing capabilites the tunnel will advertise
	# in the Framing Capabilites AVP per RFC2661.
	# The default is to advertise both sync and async framing.
	framing_caps = ["sync","async"]

	# This is a session instance called "s1" within parent tunnel "t1".
	# Session instances are always created inside a parent tunnel.
	[tunnel.t1.session.s1]

	# sid specifies the local session ID of the session.
	# Session IDs must be unique to the tunnel for L2TPv2, or unique to
	# the peer for L2TPv3.
	# L2TPv2 session IDs are 16 bit, and may be in the range 1 - 65535.
	# L2TPv3 session IDs are 32 bit, and may be in the range 1 - 4294967295.
	sid = 12389

	# psid specifies the peer's session ID for the session.
	# The peer's session ID is unrelated to the local session ID.
	# The rules for the session ID range apply to the peer session ID too.
	psid = 1234

	# pseudowire specifies the type of layer 2 frames carried by the session.
	# Currently supported values are "ppp", "eth", and "pppac".
	# L2TPv2 tunnels support PPP and PPPAC pseudowires only.
	pseudowire = "eth"

	# seqnum, if set, enables the transmission of sequence numbers with
	# L2TP data messages.  Use of sequence numbers enables the data plane
	# to reorder data packets to ensure they are delivered in sequence.
	# By default sequence numbers are not used.
	seqnum = false

	# cookie, if set, specifies the local L2TPv3 cookie for the session.
	# Cookies are a data verification mechanism intended to allow misdirected
	# data packets to be detected and rejected.
	# Transmitted data packets will include the local cookie in their header.
	# Cookies may be either 4 or 8 bytes long, and contain aribrary data.
	# By default no local cookie is set.
	cookie = [ 0x12, 0xe9, 0x54, 0x0f, 0xe2, 0x68, 0x72, 0xbc ]

	# peer_cookie, if set, specifies the L2TPv3 cookie the peer will send in
	# the header of its data messages.
	# Messages received without the peer's cookie (or with the wrong cookie)
	# will be rejected.
	# By default no peer cookie is set.
	peer_cookie = [ 0x74, 0x2e, 0x28, 0xa8 ]

	# interface_name, if set, specifies the network interface name to be
	# used for the session instance.
	# By default the Linux kernel autogenerates an interface name specific to
	# the pseudowire type, e.g. "l2tpeth0", "ppp0".
	# Setting the interface name can be useful when you need to be certain
	# of the interface name a given session will use.
	# By default the kernel autogenerates an interface name.
	interface_name = "l2tpeth42"

	# l2spec_type specifies the L2TPv3 Layer 2 specific sublayer field to
	# be used in data packet headers as per RFC3931 section 3.2.2.
	# Currently supported values are "none" and "default".
	# By default no Layer 2 specific sublayer is used.
	l2spec_type = "default"

	# pppoe_session_id specifies the assigned PPPoE session ID for the session.
	# Per RFC2516, the PPPoE session ID is in the range 1 - 65535
	# This parameter only applies to pppac pseudowires.
	pppoe_session_id = 1234

	# pppoe_peer_mac specifies the MAC address of the PPPoE peer for the session.
	# This parameter only applies to pppac pseudowires.
	pppoe_peer_mac = [ 0x02, 0x42, 0x94, 0xd1, 0x4e, 0x9a ]
*/
package config

import (
	"fmt"
	"time"

	"github.com/katalix/go-l2tp/l2tp"
	"github.com/pelletier/go-toml"
)

// Config contains L2TP configuration for tunnel and session instances.
type Config struct {
	// The entire tree as a map as parsed from the TOML representation.
	// Apps may access this tree to handle their own config tables.
	Map map[string]interface{}
	// All the tunnels defined in the configuration.
	Tunnels []NamedTunnel
	// Custom parser interface for caller to handle unrecognised key/value pairs.
	customParser ConfigParser
}

// NamedTunnel contains L2TP configuration for a tunnel instance,
// and the sessions that tunnel contains.
type NamedTunnel struct {
	// The tunnel's name as specified in the config file.
	Name string
	// The tunnel L2TP configuration.
	Config *l2tp.TunnelConfig
	// The sessions defined within this tunnel in the config file.
	Sessions []NamedSession
}

// NamedSession contains L2TP configuration for a session instance.
type NamedSession struct {
	// The session's name as specified in the config file.
	Name string
	// The session L2TP configuration.
	Config *l2tp.SessionConfig
}

// ConfigParser allows for parsing of custom config file fields which
// are not directly implemented by package config.
//
// This is useful to allow an application to embed custom configuration
// into the configuration file.
type ConfigParser interface {
	// ParseParameter is called for any unrecognised key/value pair not
	// within either a tunnel or session block.
	ParseParameter(key string, value interface{}) error
	// ParseTunnelParameter is called for an unrecognised key/value pair
	// within a tunnel block.
	ParseTunnelParameter(tunnel *NamedTunnel, key string, value interface{}) error
	// ParseSessionParameter is called for an unrecognised key/value pair
	// within a session block.
	ParseSessionParameter(tunnel *NamedTunnel, session *NamedSession, key string, value interface{}) error
}

type nilCustomParser struct {
}

func (np *nilCustomParser) ParseParameter(key string, value interface{}) error {
	return fmt.Errorf("unrecognised parameter %v", key)
}

func (np *nilCustomParser) ParseTunnelParameter(tunnel *NamedTunnel, key string, value interface{}) error {
	return fmt.Errorf("unrecognised parameter %v", key)
}

func (np *nilCustomParser) ParseSessionParameter(tunnel *NamedTunnel, session *NamedSession, key string, value interface{}) error {
	return fmt.Errorf("unrecognised parameter %v", key)
}

func toBool(v interface{}) (bool, error) {
	if b, ok := v.(bool); ok {
		return b, nil
	}
	return false, fmt.Errorf("supplied value could not be parsed as a bool")
}

// go-toml's ToMap function represents numbers as either uint64 or int64.
// So when we are converting numbers, we need to figure out which one it
// has picked and range check to ensure that the number from the config
// fits within the range of the destination type.
func toByte(v interface{}) (byte, error) {
	if b, ok := v.(int64); ok {
		if b < 0x0 || b > 0xff {
			return 0, fmt.Errorf("value %x out of range", b)
		}
		return byte(b), nil
	} else if b, ok := v.(uint64); ok {
		if b > 0xff {
			return 0, fmt.Errorf("value %x out of range", b)
		}
		return byte(b), nil
	}
	return 0, fmt.Errorf("unexpected %T value %v", v, v)
}

func toUint16(v interface{}) (uint16, error) {
	if b, ok := v.(int64); ok {
		if b < 0x0 || b > 0xffff {
			return 0, fmt.Errorf("value %x out of range", b)
		}
		return uint16(b), nil
	} else if b, ok := v.(uint64); ok {
		if b > 0xffff {
			return 0, fmt.Errorf("value %x out of range", b)
		}
		return uint16(b), nil
	}
	return 0, fmt.Errorf("unexpected %T value %v", v, v)
}

func toUint32(v interface{}) (uint32, error) {
	if b, ok := v.(int64); ok {
		if b < 0x0 || b > 0xffffffff {
			return 0, fmt.Errorf("value %x out of range", b)
		}
		return uint32(b), nil
	} else if b, ok := v.(uint64); ok {
		if b > 0xffffffff {
			return 0, fmt.Errorf("value %x out of range", b)
		}
		return uint32(b), nil
	}
	return 0, fmt.Errorf("unexpected %T value %v", v, v)
}

func toString(v interface{}) (string, error) {
	if s, ok := v.(string); ok {
		return s, nil
	}
	return "", fmt.Errorf("supplied value could not be parsed as a string")
}

func toDurationMs(v interface{}) (time.Duration, error) {
	u, err := toUint32(v)
	return time.Duration(u) * time.Millisecond, err
}

func toVersion(v interface{}) (l2tp.ProtocolVersion, error) {
	s, err := toString(v)
	if err == nil {
		switch s {
		case "l2tpv2":
			return l2tp.ProtocolVersion2, nil
		case "l2tpv3":
			return l2tp.ProtocolVersion3, nil
		}
		return 0, fmt.Errorf("expect 'l2tpv2' or 'l2tpv3'")
	}
	return 0, err
}

func toFramingCaps(v interface{}) (l2tp.FramingCapability, error) {
	var fc l2tp.FramingCapability

	// First ensure that the supplied value is actually an array
	caps, ok := v.([]interface{})
	if !ok {
		return 0, fmt.Errorf("expected array value")
	}

	// TOML arrays can be mixed type, so we have to check on a value-by-value
	// basis that the value in the array can be represented as a string.
	for _, c := range caps {
		cs, err := toString(c)
		if err != nil {
			return 0, err
		}
		switch cs {
		case "sync":
			fc |= l2tp.FramingCapSync
		case "async":
			fc |= l2tp.FramingCapAsync
		default:
			return 0, fmt.Errorf("expect 'sync' or 'async'")
		}
	}
	return fc, nil
}

func toEncapType(v interface{}) (l2tp.EncapType, error) {
	s, err := toString(v)
	if err == nil {
		switch s {
		case "udp":
			return l2tp.EncapTypeUDP, nil
		case "ip":
			return l2tp.EncapTypeIP, nil
		}
		return 0, fmt.Errorf("expect 'udp' or 'ip'")
	}
	return 0, err
}

func toPseudowireType(v interface{}) (l2tp.PseudowireType, error) {
	s, err := toString(v)
	if err == nil {
		switch s {
		case "ppp":
			return l2tp.PseudowireTypePPP, nil
		case "eth":
			return l2tp.PseudowireTypeEth, nil
		case "pppac":
			return l2tp.PseudowireTypePPPAC, nil
		}
		return 0, fmt.Errorf("expect 'ppp', 'eth', or 'pppac'")
	}
	return 0, err
}

func toL2SpecType(v interface{}) (l2tp.L2SpecType, error) {
	s, err := toString(v)
	if err == nil {
		switch s {
		case "none":
			return l2tp.L2SpecTypeNone, nil
		case "default":
			return l2tp.L2SpecTypeDefault, nil
		}
		return 0, fmt.Errorf("expect 'none' or 'default'")
	}
	return l2tp.L2SpecTypeNone, err
}

func toCCID(v interface{}) (l2tp.ControlConnID, error) {
	u, err := toUint32(v)
	return l2tp.ControlConnID(u), err
}

func toBytes(v interface{}) ([]byte, error) {
	out := []byte{}

	// First ensure that the supplied value is actually an array
	numbers, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("expected array value")
	}

	// TOML arrays can be mixed type, so we have to check on a value-by-value
	// basis that the value in the array can be represented as a byte.
	for _, number := range numbers {
		b, err := toByte(number)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func (cfg *Config) newSessionConfig(tunnel *NamedTunnel, name string, scfg map[string]interface{}) (*NamedSession, error) {
	ns := &NamedSession{
		Name:   name,
		Config: &l2tp.SessionConfig{},
	}
	for k, v := range scfg {
		var err error
		switch k {
		case "sid":
			ns.Config.SessionID, err = toCCID(v)
		case "psid":
			ns.Config.PeerSessionID, err = toCCID(v)
		case "pseudowire":
			ns.Config.Pseudowire, err = toPseudowireType(v)
		case "seqnum":
			ns.Config.SeqNum, err = toBool(v)
		case "reorder_timeout":
			ns.Config.ReorderTimeout, err = toDurationMs(v)
		case "cookie":
			ns.Config.Cookie, err = toBytes(v)
		case "peer_cookie":
			ns.Config.PeerCookie, err = toBytes(v)
		case "interface_name":
			ns.Config.InterfaceName, err = toString(v)
		case "l2spec_type":
			ns.Config.L2SpecType, err = toL2SpecType(v)
		case "pppoe_session_id":
			ns.Config.PPPoESessionId, err = toUint16(v)
		case "pppoe_peer_mac":
			ns.Config.PPPoEPeerMac, err = toBytes(v)
		default:
			err = cfg.customParser.ParseSessionParameter(tunnel, ns, k, v)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to process %v: %v", k, err)
		}
	}
	return ns, nil
}

func (cfg *Config) loadSessions(tunnel *NamedTunnel, v interface{}) ([]NamedSession, error) {
	var out []NamedSession
	sessions, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("session instances must be named, e.g. '[tunnel.mytunnel.session.mysession]'")
	}
	for name, got := range sessions {
		smap, ok := got.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("session instances must be named, e.g. '[tunnel.mytunnel.session.mysession]'")
		}
		scfg, err := cfg.newSessionConfig(tunnel, name, smap)
		if err != nil {
			return nil, fmt.Errorf("session %v: %v", name, err)
		}
		out = append(out, *scfg)
	}
	return out, nil
}

func (cfg *Config) newTunnelConfig(name string, tcfg map[string]interface{}) (*NamedTunnel, error) {
	nt := &NamedTunnel{
		Name: name,
		Config: &l2tp.TunnelConfig{
			FramingCaps: l2tp.FramingCapSync | l2tp.FramingCapAsync,
		},
	}
	for k, v := range tcfg {
		var err error
		switch k {
		case "local":
			nt.Config.Local, err = toString(v)
		case "peer":
			nt.Config.Peer, err = toString(v)
		case "encap":
			nt.Config.Encap, err = toEncapType(v)
		case "version":
			nt.Config.Version, err = toVersion(v)
		case "tid":
			nt.Config.TunnelID, err = toCCID(v)
		case "ptid":
			nt.Config.PeerTunnelID, err = toCCID(v)
		case "window_size":
			nt.Config.WindowSize, err = toUint16(v)
		case "hello_timeout":
			nt.Config.HelloTimeout, err = toDurationMs(v)
		case "retry_timeout":
			nt.Config.RetryTimeout, err = toDurationMs(v)
		case "max_retries":
			if u, err := toUint16(v); err == nil {
				nt.Config.MaxRetries = uint(u)
			}
		case "host_name":
			nt.Config.HostName, err = toString(v)
		case "framing_caps":
			nt.Config.FramingCaps, err = toFramingCaps(v)
		case "session":
			nt.Sessions, err = cfg.loadSessions(nt, v)
		default:
			err = cfg.customParser.ParseTunnelParameter(nt, k, v)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to process %v: %v", k, err)
		}
	}
	return nt, nil
}

func (cfg *Config) loadTunnels(tunnels map[string]interface{}) ([]NamedTunnel, error) {
	var out []NamedTunnel

	for name, got := range tunnels {
		tmap, ok := got.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("tunnel instances must be named, e.g. '[tunnel.mytunnel]'")
		}
		tcfg, err := cfg.newTunnelConfig(name, tmap)
		if err != nil {
			return nil, fmt.Errorf("tunnel %v: %v", name, err)
		}
		out = append(out, *tcfg)
	}
	return out, nil
}

func newConfig(tree *toml.Tree, customParser ConfigParser) (*Config, error) {
	cfg := &Config{
		Map:          tree.ToMap(),
		customParser: customParser,
	}

	// Walk the parameters, directly parse tunnel tables, defer everything else the custom parser
	for k, v := range cfg.Map {
		if k == "tunnel" {
			tunnels, ok := v.(map[string]interface{})
			if !ok || len(tunnels) == 0 {
				return nil, fmt.Errorf("tunnel instances must be named, e.g. '[tunnel.mytunnel]'")
			}
			parsedTunnels, err := cfg.loadTunnels(tunnels)
			if err != nil {
				return nil, fmt.Errorf("failed to parse tunnels: %v", err)
			}
			cfg.Tunnels = append(cfg.Tunnels, parsedTunnels...)
		} else {
			err := cfg.customParser.ParseParameter(k, v)
			if err != nil {
				return nil, err
			}
		}
	}

	return cfg, nil
}

func newConfigFromFile(path string, customParser ConfigParser) (*Config, error) {
	tree, err := toml.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config file: %v", err)
	}
	return newConfig(tree, customParser)
}

func newConfigFromString(content string, customParser ConfigParser) (*Config, error) {
	tree, err := toml.Load(content)
	if err != nil {
		return nil, fmt.Errorf("failed to load config string: %v", err)
	}
	return newConfig(tree, customParser)
}

// LoadFile loads configuration from the specified file.
func LoadFile(path string) (*Config, error) {
	return newConfigFromFile(path, &nilCustomParser{})
}

// LoadString loads configuration from the specified string.
func LoadString(content string) (*Config, error) {
	return newConfigFromString(content, &nilCustomParser{})
}

// LoadFileWithCustomParser loads configuration from the specified file,
// calling the ConfigParser interface for unrecognised key/value pairs.
func LoadFileWithCustomParser(path string, customParser ConfigParser) (*Config, error) {
	return newConfigFromFile(path, customParser)
}

// LoadStringWithCustomParser loads configuration from the specified file,
// calling the ConfigParser interface for unrecognised key/value pairs.
func LoadStringWithCustomParser(content string, customParser ConfigParser) (*Config, error) {
	return newConfigFromString(content, customParser)
}
