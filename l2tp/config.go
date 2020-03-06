package l2tp

import (
	"fmt"

	"github.com/pelletier/go-toml"
)

type Config struct {
	// entire tree as a map
	cm map[string]interface{}
	// map of tunnels mapping tunnel name to config
	tunnels map[string]TunnelConfig
}

type TunnelConfig struct {
	Local   string
	Peer    string
	Encap   string
	Version ProtocolVersion
	// map of sessions within the tunnel
	Sessions map[string]SessionConfig
}

type SessionConfig struct {
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

func newTunnelConfig(tcfg map[string]interface{}) (*TunnelConfig, error) {
	tc := TunnelConfig{
		Sessions: make(map[string]SessionConfig),
	}
	for k, v := range tcfg {
		var err error
		switch k {
		case "local":
			tc.Local, err = toString(v)
		case "peer":
			tc.Peer, err = toString(v)
		case "encap":
			// for the time being just handle as string
			tc.Encap, err = toString(v)
		case "version":
			tc.Version, err = toVersion(v)
		default:
			err = fmt.Errorf("unrecognised tunnel config key '%v'", k)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to load key %v: %v", k, err)
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
			return fmt.Errorf("failed to load config for tunnel %v: %v", name, err)
		}
		cfg.tunnels[name] = *tcfg
	}
	return nil
}

func newConfig(tree *toml.Tree) (*Config, error) {
	cfg := &Config{
		cm:      tree.ToMap(),
		tunnels: make(map[string]TunnelConfig),
	}
	err := cfg.loadTunnels()
	if err != nil {
		return nil, fmt.Errorf("failed to parse tunnels: %v", err)
	}
	return cfg, nil
}

func LoadFile(path string) (*Config, error) {
	tree, err := toml.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config file: %v", err)
	}
	return newConfig(tree)
}

func LoadString(content string) (*Config, error) {
	tree, err := toml.Load(content)
	if err != nil {
		return nil, fmt.Errorf("failed to load config string: %v", err)
	}
	return newConfig(tree)
}

func (cfg *Config) GetTunnels() map[string]TunnelConfig {
	return cfg.tunnels
}

func (cfg *Config) ToMap() map[string]interface{} {
	return cfg.cm
}
