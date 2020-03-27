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
a more convenient way to bring up static sessions than **ip l2tp** commands, and exposes
more session data plane configuration options than **ip l2tp** supports (e.g. the setting
of local and peer cookies).

If a tunnel has a ***hello_timeout*** set, the tunnel will send a periodic keep-alive
packet over a minimal implementation of the RFC3931 reliable control message transport.
This allows for the detection of tunnel failure, which will then tear down the sessions
running in that tunnel.

## Documentation

The go-l2tp library and tools are documented using Go's documentation tool.  A top-level
description of the library can be viewed as follows:

    go doc github.com/katalix/go-l2tp/l2tp

This top level document includes details of the configuration file format used by the
library, as well as the main APIs the library exposes.

You can view documentation of a particular API or type like this:

    go doc github.com/katalix/go-l2tp/l2tp.Context

Finally, documentation of the **ql2tpd** command can be viewed like this:

    go doc github.com/katalix/go-l2tp/cmd/ql2tpd

If you have installed the library you can access the documentation more efficiently
by removing ***github.com/katalix*** from the full module path: 

    go doc go-l2tp/l2tp
    go doc go-l2tp/l2tp.Context
    go doc go-l2tp/cmd/ql2tpd
