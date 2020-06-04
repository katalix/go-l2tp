# go-l2tp

**go-l2tp** is a Go library for building
[L2TP](https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol) applications
on Linux systems.

## Features

* [L2TPv2 (RFC2661)](https://tools.ietf.org/html/rfc2661) and [L2TPv3 (RFC3931)](https://tools.ietf.org/html/rfc3931) data plane via. Linux L2TP subsystem
* AF_INET and AF_INET6 tunnel addresses
* UDP and L2TPIP tunnel encapsulation
* L2TPv2 control plane in client/LAC mode

## Installation

If you're familiar with Go, you can skip this section.

Prior to installing go-l2tp, install the [Go language distribution](https://golang.org/dl/)
which includes the compiler and other tooling required to install Go programs.
Please follow the instructions from the Go project to get your installation up and running.

You can now install go-l2tp as follows:

    go get github.com/katalix/go-l2tp

Read on for instructions on coding using the library.

## Import

    import (
        "github.com/katalix/go-l2tp/l2tp"
        "github.com/katalix/go-l2tp/config"
    )

## Usage

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

## Tools

go-l2tp includes two tools, **ql2tpd** and **kl2tpd**, which build on the library.

**ql2tpd** is a minimal daemon for creating static L2TPv3 sessions.

This tool requires root permissions to run, and is driven by a configuration file which
details the tunnel and session instances to create.

Each tunnel may run as a purely static instance.  In this mode **ql2tpd** represents
a more convenient way to bring up static sessions than **ip l2tp** commands.

If a tunnel has a ***hello_timeout*** set, the tunnel will send a periodic keep-alive
packet over a minimal implementation of the RFC3931 reliable control message transport.
This allows for the detection of tunnel failure, which will then tear down the sessions
running in that tunnel.  ***hello_timeout*** should only be enabled if the peer is also
running **ql2tpd**.

**kl2tpd** is a client/LAC-mode daemon for creating L2TPv2 sessions.  It spawns the standard
Linux **pppd** for PPP protocol support.

Similar to **ql2tpd**, **kl2tpd** requires root permissions to run, and is driven by a
configuration file which details the tunnel and session instances to create.

In addition to the configuration parameters documented by package config, **kl2tpd**
supports an extra session parameter, ***pppd_args*** which calls out an argument file
for extra **pppd** command line arguments.  Here is an example configuration for establishing
a single tunnel containing a single session:

    [tunnel.t1]
    peer = "42.102.77.204:1701"
    version = "l2tpv2"
    encap = "udp"

    [tunnel.t1.session.s1]
    pseudowire = "ppp"
    pppd_args = "/home/bob/pppd.args"

## Documentation

The go-l2tp library and tools are documented using Go's documentation tool.  A top-level
description of the library can be viewed as follows:

    go doc l2tp

This top level document includes details of the configuration file format used by the
library, as well as the main APIs the library exposes.

You can view documentation of a particular API or type like this:

    go doc l2tp.Context

Finally, documentation of the **ql2tpd** command can be viewed like this:

    go doc cmd/ql2tpd

and the documentation of the **kl2tpd** command can be viewed like this:

    go doc cmd/kl2tpd

## Testing

go-l2tp has unit tests which can be run using go test:

    go test ./...

Some tests instantiate tunnels and sessions in the Linux kernel's L2TP subsystem,
and hence require root permissions to run.  By default these tests are skipped if
run as a normal user.

The tests requiring root can be run as follows:

    go test -exec sudo -run TestRequiresRoot ./...

The tests are run using ***sudo***, which will need to be set up for your user,
and require the Linux kernel L2TP modules to be loaded:

    modprobe l2tp_core l2tp_netlink l2tp_eth l2tp_ip l2tp_ip6

Depending on your Linux distribution it may be necessary to install an extra package to
get the L2TP subsystem modules.  For example on Ubuntu:

    sudo apt-get install linux-modules-extra-$(uname -r)

A convenience wrapper script ***l2tp/runtests.sh*** runs all the l2tp tests and
produces a coverage html report:

    ( cd l2tp && ./runtests.sh )
    firefox l2tp/coverage.html
