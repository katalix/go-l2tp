/*
Package l2tp implements the Layer 2 Tunneling Protocol as per
RFC2661 (L2TPv2) and RFC3931 (L2TPv3).

L2TPv2 applies only to PPP tunneling, and is widely used in home
broadband installations to convey consumer PPPoE frames to the ISP
network.  It is also used in conjunction with IPSec in VPN
implementations.

L2TPv3 extends the protocol in a backward-compatible manner, and
allows for the tunneling of multiple Layer 2 frames including Ethernet
and VLAN.

On Linux systems, the kernel natively supports the L2TPv2 and L2TPv3
data plane.  Tunneled frames are handled entirely by the kernel
for maximum efficiency.  The more complex control plane for instantiating
and managing tunnel and session instances is implemented in user space.

Usage

	# Read configuration.
	# Ignore errors for the purposes of demonstration!
	config, _ := l2tp.LoadConfigFile("./my-l2tp-config.toml")

	# Creation of L2TP instances requires an L2TP context
	# We're disabling logging and using default context config
	# for brevity here.
	l2tpctx, _ := l2tp.NewContext(nil, nil)

	# Create tunnel and session instances based on the config
	for tname, tcfg := range config.GetTunnels() {
		tunl, _ := l2tpctx.NewStaticTunnel(tname, tcfg)
		for sname, scfg := range tcfg.Sessions {
			_, _, := tunl.NewSession(sname, scfg)
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

The final tunnel type, which is currently unimplemented(!), is the dynamic
tunnel.  This runs the full L2TP control protocol.

Configuration

Package l2tp uses the TOML format for configuration files:
https://github.com/toml-lang/toml.

Please refer to the TOML repos for an in-depth description of the syntax,
we'll concentrate on the l2tp-specific configuration parameters here.

The l2tp configuration file specifies configuration parameters for tunnel
and session instances.  It may also contain command-specific parameters
which are handled by the commands making use of package l2tp: these are
out of scope here.

Tunnel and session instances are called out in the configuration file
using named TOML tables.  Each tunnel or session instance table contains
configuration parameters for that instance as key:value pairs.

	# This is a tunnel instance named "t1"
	# Note that not all configuration parameters apply to all tunnel types.
	# Refer to the documentation for the specific tunnel creation
	# functions for more information.
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
	# Currently supported values are "ppp" and "eth".
	# L2TPv2 tunnels support PPP pseudowires only.
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

Limitations

	* Dynamic tunnels are not currently supported.
	* Only Linux systems are supported for the data plane.
*/
package l2tp
