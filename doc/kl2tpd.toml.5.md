% kl2tpd.toml(5) go-l2tp _VERSION_ | go-l2tp
% Katalix Systems, Ltd
% _DATE_

# NAME

**kl2tpd.toml** - configuration file for **kl2tpd**

# DESCRIPTION

The **kl2tpd.toml** file configures **kl2tpd**.  It calls out the L2TP tunnels and sessions to establish.

**kl2tpd.toml** is written in the TOML markup language (https://toml.io/en/).

Tunnel and session instances are called out in the configuration file using named TOML tables.

Each tunnel or session instance table contains configuration parameters for that instance as key:value pairs.

Each tunnel and session has a minimal set of configuration which ***must*** be specified.

In addition, each tunnel or session entry may call out various optional key:value pairs which will control **kl2tpd**'s runtime behaviour.

These options are generally not required, and **kl2tpd** will use sensible defaults for them if they are not included in the configuration.

## TUNNEL CONFIGURATION

Tunnels are described using named entries in the 'tunnel' table.

Each tunnel entry describes a single tunnel instance, and must call out at least:

* the peer's IP address,
* the tunnel L2TP version (currently only L2TPv2 is supported),
* the tunnels encapsulation protocol (currently only UDP is supported).

Here is the full list of tunnel configuration options:

	# This is a tunnel instance named "t1"
	[tunnel.t1]

	# peer specifies the address of the peer that the tunnel should
	# connect its socket to
	peer = "127.0.0.1:5001"

	# version specifies the version of the L2TP specification the
	# tunnel should use.
	# Currently supported values are "l2tpv2".
	version = "l2tpv2"

	# encap specifies the encapsulation to be used for the tunnel.
	# L2TPv2 tunnels are UDP only.
	encap = "udp"

	# local specifies the local address that the tunnel should
	# bind its socket to
	local = "127.0.0.1:5000"

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

## SESSION CONFIGURATION

Sessions are described using named entries in the 'session' table inside the parent tunnel table.

Each session entry describes a single session instance within the parent tunnel, and must call out at least:

* the pseudowire type to be used (for L2TPv2 this must be ppp or pppac).

Here is the full list of session configuration options:

	# This is a session instance called "s1" within parent tunnel "t1".
	# Session instances are always created inside a parent tunnel.
	[tunnel.t1.session.s1]

	# pseudowire specifies the type of layer 2 frames carried by the session.
	# Currently supported values are "ppp", "eth", and "pppac".
	# L2TPv2 tunnels support PPP and PPPAC pseudowires only.
	pseudowire = "eth"

    # pppd_args specifes a file to be read for pppd arguments.  These should
    # be either whitespace or newline delimited, and should call out pppd command
    # line arguments as described in the pppd manpage.
    pppd_args = "/etc/kl2tpd/t1s1_pppd_args.txt"

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

	# seqnum, if set, enables the transmission of sequence numbers with
	# L2TP data messages.  Use of sequence numbers enables the data plane
	# to reorder data packets to ensure they are delivered in sequence.
	# By default sequence numbers are not used.
	seqnum = false

	# pppoe_session_id specifies the assigned PPPoE session ID for the session.
	# Per RFC2516, the PPPoE session ID is in the range 1 - 65535
	# This parameter only applies to pppac pseudowires.
	pppoe_session_id = 1234

	# pppoe_peer_mac specifies the MAC address of the PPPoE peer for the session.
	# This parameter only applies to pppac pseudowires.
	pppoe_peer_mac = [ 0x02, 0x42, 0x94, 0xd1, 0x4e, 0x9a ]

# SEE ALSO

**kl2tpd**(1), **pppd**(8)
