% ql2tpd(1) go-l2tp _VERSION_ | go-l2tp
% Katalix Systems, Ltd
% _DATE_

# NAME

ql2tpd - a daemon for creating static (or quiescent) L2TPv3 tunnels and sessions

# SYNOPSIS

**ql2tpd** [ arguments ]

# DESCRIPTION

**ql2tpd** is a daemon for creating static L2TPv3 (RFC 3931) tunnels and sessions.

Static (or quiescent) tunnels and sessions implement ***only*** the data plane transport: the L2TP control protocol is not used.  This can be useful for setting up static L2TPv3 links where host configuration is known in advance.

When configured to bring up static tunnel and session instances, **ql2tpd** represents a more convenient way to bring up static sessions than **ip l2tp** commands.

Additionally, **ql2tpd** supports the use of a periodic keep-alive packet for tunnels it is managing (controlled by the configuration file ***hello_timeout*** parameter).

This allows for the detection of tunnel failure, which will then tear down the sessions running in that tunnel.  This mode of operation must only be enabled if the peer is also running **ql2tpd**.

**ql2tpd** requires root permissions to run, and is driven by a configuration file
which details the tunnel and session instances to create.

For further details of the configuration format, please refer to **ql2tpd.toml**(5).

# OPTIONS

-config string

:   specify configuration file path (default "/etc/ql2tpd/ql2tpd.toml")

-verbose

:   toggle verbose log output

# SEE ALSO

**ql2tpd.toml**(5), **ip-l2tp**(8)
