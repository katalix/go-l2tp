% kpppoed(8) go-l2tp _VERSION_ | go-l2tp
% Katalix Systems, Ltd
% _DATE_

# NAME

kpppoed - a PPPoE daemon for creating L2TPv2 Access Concentrator sessions in response to PPPoE requests

# SYNOPSIS

**kpppoed** [ arguments ]

# DESCRIPTION

**kpppoed** is a PPPoE (RFC 2516) server daemon for creating L2TPv2 Access Concentrator sessions.  It spawns **kl2tpd** for L2TP protocol support.


**kpppoed** and is driven by a configuration file which describes the PPPoE service to offer.

# OPTIONS

-config string

:   specify configuration file path (default "/etc/kpppoed/kpppoed.toml")

-verbose

:   toggle verbose log output

# CONFIGURATION

The **kpppoed** file, **kpppoed.toml** is written in the TOML markup language (https://toml.io/en/).

It uses a small set of key:value pairs to configure the PPPoE server:

	# ac_name is the name that kpppoed will use in the PPPoE AC Name tag sent
	# in PADO packets.  If not specified it will default to "kpppoed".
	ac_name = "MyAccessConcentrator.2000"

	# interface_name is the name of the network interface that kpppoed will listen
	# on for PPPoE discovery packets.  It must be specified.
	interface_name = "eth0"

	# services is a list of service names that kpppoed will advertise in PADO packets
	# At least one service must be specified.
	services = [ "serviceA", "serviceB", "serviceC" ]

	# lns_ipaddr is the IP address and port of the L2TP server to tunnel
	# pppoe sessions to.  The LNS address must be specified.
	lns_ipaddr = "3.22.1.9:1701"

# SEE ALSO

**kpppoed.toml**(5), **kl2tpd**(8)
