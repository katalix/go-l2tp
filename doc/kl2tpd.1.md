% kl2tpd(1) go-l2tp _VERSION_ | go-l2tp
% Katalix Systems, Ltd
% _DATE_

# NAME

kl2tpd - a minimal L2TPv2 client daemon

# SYNOPSIS

**kl2tpd** [ arguments ]

# DESCRIPTION

**kl2tpd** is a client/LAC-mode daemon for creating L2TPv2 (RFC 2661) tunnels and sessions.

**kl2tpd** requires root permissions to run, and is driven by a configuration file
which details the tunnel and session instances to create.

For further details of the configuration format, please refer to **kl2tpd.toml**(5).

By default, **kl2tpd** spawns the standard Linux **pppd** for PPP protocol support.

# OPTIONS

-config string

:   specify configuration file path (default "/etc/kl2tpd/kl2tpd.toml")

-null

:   toggle null data plane (establish L2TP tunnel and session but do not spawn **pppd**)

-verbose

:   toggle verbose log output

# SEE ALSO

**kl2tpd.toml**(5), **pppd**(8)
