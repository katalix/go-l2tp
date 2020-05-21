/*
Package l2tp is a library for Layer 2 Tunneling Protocol applications
running on Linux systems.

L2TP is specified by RFC2661 (L2TPv2) and RFC3931 (L2TPv3).

L2TPv2 applies only to PPP tunneling, and is widely used in home
broadband installations to convey consumer PPPoE frames to the ISP
network.  It is also used in conjunction with IPSec in VPN
implementations.

L2TPv3 extends the protocol in a backward-compatible manner, and
allows for the tunneling of various additional Layer 2 frames including
Ethernet and VLAN.

On Linux systems, the kernel natively supports the L2TPv2 and L2TPv3
data plane.  Tunneled frames are handled entirely by the kernel
for maximum efficiency.  The more complex control plane for instantiating
and managing tunnel and session instances is implemented in user space.

Currently package l2tp implements:

 * support for controlling the Linux L2TP data plane for L2TPv2 and
   L2TPv3 tunnels and sessions,
 * the L2TPv2 control plane for client/LAC mode.

In the future we plan to add support for the L2TPv3 control plane, and
server/LNS mode.

Usage

	import (
		"github.com/katalix/go-l2tp/l2tp"
		"github.com/katalix/go-l2tp/config"
	)

	# Note we're ignoring errors for brevity.

	# Read configuration using the config package.
	# This is optional: you can build your own configuration
	# structures if you prefer.
	config, _ := config.LoadFile("./my-l2tp-config.toml")

	# Creation of L2TP instances requires an L2TP context.
	# We're disabling logging and using the default Linux data plane.
	l2tpctx, _ := l2tp.NewContext(l2tp.LinuxNetlinkDataPlane, nil)

	# Create tunnel and session instances based on the config
	for _, tcfg := range config.Tunnels {
		tunl, _ := l2tpctx.NewStaticTunnel(tcfg.Name, tcfg.Config)
		for _, scfg := range tcfg.Sessions {
			_, _, := tunl.NewSession(scfg.Name, scfg.Config)
		}
	}

Tunnel types

Package l2tp has a concept of "tunnel types" which are used to describe
how much of the L2TP control protocol the tunnel instance runs.

The most basic type is the static tunnel (sometimes described as an
"unmanaged" tunnel).  The static tunnel runs no control protocol at all,
and just instantiates the L2TP data plane in the Linux kernel.  Consequently
all configuration parameters relating to the tunnel and the sessions within
that tunnel must be agreed ahead of time by the peers terminating the tunnel.

A slight variation on the theme of the static tunnel is the quiescent tunnel.
The quiescent tunnel extends the static tunnel slightly by running just enough
of the L2TP control protocol to allow keep-alive (HELLO) messages to be sent and
acknowledged using the L2TP reliable transport algorithm.  This slight extension
allows for detection of tunnel failure in an otherwise static setup.

The final tunnel type is the dynamic tunnel.  This runs the full L2TP control protocol.

Configuration

Each tunnel and session instance can be configured using the TunnelConfig
and SessionConfig types respectively.

These types can be generated as required for your use-case.  This partner
package config in this repository implements a TOML parser for expressing
L2TP configuration using a configuration file.

Logging

Package l2tp uses structured logging.  The logger of choice is the go-kit
logger: https://godoc.org/github.com/go-kit/kit/log, and uses go-kit levels
in order to separate verbose debugging logs from normal informational output:
https://godoc.org/github.com/go-kit/kit/log/level.

Logging emitted at level.Info should be enabled for normal useful runtime
information about the lifetime of tunnels and sessions.

Logging emitted at level.Debug should be enabled for more verbose output
allowing development debugging of the code or troubleshooting misbehaving L2TP
instances.

To disable all logging from package l2tp, pass in a nil logger.

*/
package l2tp
