# go-l2tp

**go-l2tp** is a Go library for building
[L2TP](https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol) applications
on Linux systems.

Currently static (or unmanaged) tunnels and sessions are supported, which implement
the L2TPv3 data plane only.  In the future we plan to add support for the control plane.

## Features

* [L2TPv3 (RFC3931)](https://tools.ietf.org/html/rfc3931) data plane
* AF_INET and AF_INET6 tunnel addresses
* UDP and L2TPIP tunnel encapsulation

## Installation

If you're familiar with Go, you can skip this section.

Prior to installing go-l2tp, install the [Go language distribution](https://golang.org/dl/)
which includes the compiler and other tooling required to install Go programs.
Please follow the instructions from the Go project to get your installation up and running.

You can now install go-l2tp as follows:

    go get github.com/katalix/go-l2tp

Read on for instructions on coding using the library.

## Import

    import "github.com/katalix/go-l2tp/l2tp"

## Usage

	# Read configuration.
    # Refer to the Documentation section below for references
    # on the syntax of this configuration file.
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

## Tools

go-l2tp includes a tool, **ql2tpd**, which builds on the library to implement a minimal
daemon for creating static L2TPv3 sessions.

This tool requires root permissions to run, and is driven by a configuration file which
details the tunnel and session instances to create.

Each tunnel may run as a purely static instance.  In this mode **ql2tpd** represents
a more convenient way to bring up static sessions than **ip l2tp** commands.

If a tunnel has a ***hello_timeout*** set, the tunnel will send a periodic keep-alive
packet over a minimal implementation of the RFC3931 reliable control message transport.
This allows for the detection of tunnel failure, which will then tear down the sessions
running in that tunnel.  ***hello_timeout*** should only be enabled if the peer is also
running **ql2tpd**.

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
