/*
Package pppoe is a library for PPP over Ethernet applications running
on Linux systems.

PPPoE is specified by RFC2516, and is widely used in home broadband
links when connecting the client's router into the Internet Service
Provider network.

Currently package pppoe implements:

 * Connection and protocol support for the PPPoE Active Discovery
   protocol.  This is a simple sequence of messages which is used
   to instantiate and tear down a PPPoE connection.  Protocol support
   for both client and server applications is provided.

 * Integration with the Linux kernel's L2TP access concentrator
   subsystem used to control the switching of PPPoE session data
   packets into an L2TP session for transmission to the LNS.  This
   is of use when building PPPoE servers.

Actual session data packets are managed using a PPP daemon and are
outside the scope of package pppoe.

Usage

	# Note we're ignoring errors for brevity

	import (
		"fmt"
		"github.com/katalix/go-l2tp/pppoe"
	)

	// Create a new PPPoE discovery connection on interface eth0
	conn, _ := pppoe.NewDiscoveryConnection("eth0")

	// Build a PADI packet to kick off the discovery process.
	// Add two service name tags indicating the services we're interested in.
	padi, _ := pppoe.NewPADI(conn.HWAddr(), "SuperBroadbandServiceName")
	padi.AddServiceNameTag("MegaBroadbandServiceName")

	// Encode the packet ready to send on the connection.
	b, _ := padi.ToBytes()

	// Send the packet.  Hopefully a server responds!
	conn.Send(b)

	// Receive any replies to our PADI packet.
	rcv, _ := conn.Recv()

	// Parse the received frames into PPPoE packets.
	parsed, _ := pppoe.ParsePacketBuffer(rcv)
	fmt.Printf("received: %v\n", parsed[0])
*/
package pppoe
