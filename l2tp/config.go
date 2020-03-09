package l2tp

import (
	"fmt"

	"github.com/pelletier/go-toml"
)

// Config represents L2TP configuration described by a TOML file.
// Ref: https://github.com/toml-lang/toml
type Config struct {
	// entire tree as a map
	cm map[string]interface{}
	// map of tunnels mapping tunnel name to config
	tunnels map[string]*TunnelConfig
}

// TunnelConfig encapsulates tunnel configuration for a single
// connection between two L2TP hosts.  Each tunnel may contain
// multiple sessions.
type TunnelConfig struct {
	Local   string
	Peer    string
	Encap   EncapType
	Version ProtocolVersion
	// map of sessions within the tunnel
	Sessions map[string]*SessionConfig
}

// SessionConfig encapsulates session configuration for a pseudowire
// connection within a tunnel between two L2TP hosts.
type SessionConfig struct {
	Pseudowire PseudowireType
	Cookie     []byte
}

func toString(v interface{}) (string, error) {
	if s, ok := v.(string); ok {
		return s, nil
	}
	return "", fmt.Errorf("supplied value could not be parsed as a string")
}

func toVersion(v interface{}) (ProtocolVersion, error) {
	s, err := toString(v)
	if err == nil {
		switch s {
		case "l2tpv2":
			return ProtocolVersion2, nil
		case "l2tpv3":
			return ProtocolVersion3, nil
		}
		return 0, fmt.Errorf("expect 'l2tpv2' or 'l2tpv3'")
	}
	return 0, err
}

func toEncapType(v interface{}) (EncapType, error) {
	s, err := toString(v)
	if err == nil {
		switch s {
		case "udp":
			return EncapTypeUDP, nil
		case "ip":
			return EncapTypeIP, nil
		}
		return 0, fmt.Errorf("expect 'udp' or 'ip'")
	}
	return 0, err
}

func toPseudowireType(v interface{}) (PseudowireType, error) {
	s, err := toString(v)
	if err == nil {
		switch s {
		case "ppp":
			return PseudowireTypePPP, nil
		case "eth":
			return PseudowireTypeEth, nil
		}
		return 0, fmt.Errorf("expect 'ppp' or 'eth'")
	}
	return 0, err
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
		// go-toml's ToMap function represents numbers as either uint64 or int64.
		// Figure out which one it has picked and range check to ensure that each
		// array member fits in the bounds of a byte.
		if b, ok := number.(int64); ok {
			if b < 0x0 || b > 0xff {
				return nil, fmt.Errorf("value %x out of range in byte array", b)
			}
			out = append(out, byte(b))
		} else if b, ok := number.(uint64); ok {
			if b < 0x0 || b > 0xff {
				return nil, fmt.Errorf("value %x out of range in byte array", b)
			}
			out = append(out, byte(b))
		} else {
			return nil, fmt.Errorf("unexpected %T value %v in byte array", number, number)
		}
	}
	return out, nil
}

func newSessionConfig(scfg map[string]interface{}) (*SessionConfig, error) {
	sc := SessionConfig{}
	for k, v := range scfg {
		var err error
		switch k {
		case "pseudowire":
			sc.Pseudowire, err = toPseudowireType(v)
		case "cookie":
			sc.Cookie, err = toBytes(v)
		default:
			return nil, fmt.Errorf("unrecognised parameter '%v'", k)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to process %v: %v", k, err)
		}
	}
	return &sc, nil
}

func (t *TunnelConfig) loadSessions(v interface{}) error {
	sessions, ok := v.(map[string]interface{})
	if !ok {
		return fmt.Errorf("session instances must be named, e.g. '[tunnel.mytunnel.session.mysession]'")
	}
	for name, got := range sessions {
		smap, ok := got.(map[string]interface{})
		if !ok {
			// Unlikely, so the slightly opaque error is probably OK
			return fmt.Errorf("config for session %v isn't a map", name)
		}
		scfg, err := newSessionConfig(smap)
		if err != nil {
			return fmt.Errorf("session %v: %v", name, err)
		}
		t.Sessions[name] = scfg
	}
	return nil
}

func newTunnelConfig(tcfg map[string]interface{}) (*TunnelConfig, error) {
	tc := TunnelConfig{
		Sessions: make(map[string]*SessionConfig),
	}
	for k, v := range tcfg {
		var err error
		switch k {
		case "local":
			tc.Local, err = toString(v)
		case "peer":
			tc.Peer, err = toString(v)
		case "encap":
			tc.Encap, err = toEncapType(v)
		case "version":
			tc.Version, err = toVersion(v)
		case "session":
			err = tc.loadSessions(v)
		default:
			return nil, fmt.Errorf("unrecognised parameter '%v'", k)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to process %v: %v", k, err)
		}
	}
	return &tc, nil
}

func (cfg *Config) loadTunnels() error {
	var tunnels map[string]interface{}

	// Extract the tunnel map from the configuration tree
	if got, ok := cfg.cm["tunnel"]; ok {
		tunnels, ok = got.(map[string]interface{})
		if !ok {
			return fmt.Errorf("tunnel instances must be named, e.g. '[tunnel.mytunnel]'")
		}
	} else {
		return fmt.Errorf("no tunnel table present")
	}

	// Iterate through the map and build tunnel config instances
	for name, got := range tunnels {
		tmap, ok := got.(map[string]interface{})
		if !ok {
			// Unlikely, so the slightly opaque error is probably OK
			return fmt.Errorf("config for tunnel %v isn't a map", name)
		}
		tcfg, err := newTunnelConfig(tmap)
		if err != nil {
			return fmt.Errorf("tunnel %v: %v", name, err)
		}
		cfg.tunnels[name] = tcfg
	}
	return nil
}

func newConfig(tree *toml.Tree) (*Config, error) {
	cfg := &Config{
		cm:      tree.ToMap(),
		tunnels: make(map[string]*TunnelConfig),
	}
	err := cfg.loadTunnels()
	if err != nil {
		return nil, fmt.Errorf("failed to parse tunnels: %v", err)
	}
	return cfg, nil
}

// LoadFile loads configuration from the specified file.
func LoadFile(path string) (*Config, error) {
	tree, err := toml.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config file: %v", err)
	}
	return newConfig(tree)
}

// LoadString loads configuration from the specified string.
func LoadString(content string) (*Config, error) {
	tree, err := toml.Load(content)
	if err != nil {
		return nil, fmt.Errorf("failed to load config string: %v", err)
	}
	return newConfig(tree)
}

// GetTunnels returns a map of tunnel name to tunnel config for
// all the tunnels described by the configuration.
func (cfg *Config) GetTunnels() map[string]*TunnelConfig {
	return cfg.tunnels
}

// ToMap provides access to the configuration for application-specific
// information to be handled.
func (cfg *Config) ToMap() map[string]interface{} {
	return cfg.cm
}
