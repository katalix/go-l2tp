package l2tp

import (
	"fmt"
	"net"
	"time"

	"github.com/katalix/sl2tpd/internal/nll2tp"
	"golang.org/x/sys/unix"
)

// ProtocolVersion is the version of the L2TP protocol to use
type ProtocolVersion int

const (
	// ProtocolVersion3Fallback is used for RFC3931 fallback mode
	ProtocolVersion3Fallback = 1
	// ProtocolVersion2 is used for RFC2661
	ProtocolVersion2 = nll2tp.ProtocolVersion2
	// ProtocolVersion3 is used for RFC3931
	ProtocolVersion3 = nll2tp.ProtocolVersion3
)

// ControlConnID is a generic identifier used for RFC2661 tunnel
// and session IDs as well as RFC3931 control connection IDs.
type ControlConnID uint32

const (
	v2TidSidMax = ControlConnID(^uint16(0))
)

// EncapType is the lower-level encapsulation to use for a tunnel
type EncapType int

const (
	// EncapTypeUDP is used for RFC2661 and RFC3931 tunnels using UDP encapsulation
	EncapTypeUDP = nll2tp.EncaptypeUdp
	// EncapTypeIP is used for RFC3931 tunnels using IP encapsulation
	EncapTypeIP = nll2tp.EncaptypeIp
)

// PseudowireType is the session type for a given session.
// RFC2661 is PPP-only; whereas RFC3931 supports multiple types.
type PseudowireType int

const (
	// PseudowireTypePPP specifies a PPP pseudowire
	PseudowireTypePPP = nll2tp.PwtypePpp
	// PseudowireTypeEth specifies an Ethernet pseudowire
	PseudowireTypeEth = nll2tp.PwtypeEth
)

// DebugFlags is used for kernel-space tunnel and session logging control.
// Logging is emitted using the kernel's printk facility, and may be viewed
// using dmesg, syslog, or the systemd journal depending on distro configuration.
// Multiple flags may be combined to enable different log messages.
type DebugFlags uint32

const (
	// DebugFlagsControl enables logging of userspace/kernelspace API interactions
	DebugFlagsControl = nll2tp.MsgControl
	// DebugFlagsSeq enables logging of data sequence numbers if enabled for a given session
	DebugFlagsSeq = nll2tp.MsgSeq
	// DebugFlagsData enables logging of session data messages
	DebugFlagsData = nll2tp.MsgData
)

// L2SpecType defines the Layer 2 specific sublayer for data packets as per RFC3931 section 3.2.2.
type L2SpecType int32

const (
	// L2SpecTypeNone defines no sublayer is to be used
	L2SpecTypeNone = nll2tp.L2spectypeNone
	// L2SpecTypeDefault defines use of the default sublayer
	L2SpecTypeDefault = nll2tp.L2spectypeDefault
)

// quiescentTunnel creates a user space socket for the
// L2TP control plane, but does not run the control protocol
// beyond acknowledging messages and optionally sending HELLO
// messages.
// The data plane is established on creation of the tunnel instance.
type quiescentTunnel struct {
	nl       *nll2tp.Conn
	cfg      *TunnelConfig
	cp       *l2tpControlPlane
	xport    *transport
	dp       dataPlane
	sessions map[string]Session
}

// staticTunnel does not run any control protocol
// and instead merely instantiates the data plane in the
// kernel.  This is equivalent to the Linux 'ip l2tp'
// command(s).
// Static L2TPv2 tunnels are not practically useful,
// so NewStaticTunnel only supports creation of L2TPv3
// unmanaged tunnel instances.
type staticTunnel struct {
	nl       *nll2tp.Conn
	cfg      *TunnelConfig
	dp       dataPlane
	sessions map[string]Session
}

// staticSession does not run any control protocol
// and instead merely instantiates the data plane in the
// kernel.  This is equivalent to the Linux 'ip l2tp'
// commands(s).
type staticSession struct {
	parent Tunnel
	cfg    *SessionConfig
	dp     dataPlane
}

// Session is an interface representing an L2TP session.
type Session interface {
	Close()
}

// Tunnel is an interface representing an L2TP tunnel.
type Tunnel interface {
	NewSession(name string, cfg *SessionConfig) (Session, error)
	//FindSessionByName(name string) (Session, error)
	Close()
	getCfg() *TunnelConfig
	getNLConn() *nll2tp.Conn
}

func (e EncapType) String() string {
	switch e {
	case EncapTypeIP:
		return "IP"
	case EncapTypeUDP:
		return "UDP"
	}
	panic("unhandled encap type")
}

// NewQuiescentTunnel creates a new "quiescent" L2TP tunnel.
func NewQuiescentTunnel(nl *nll2tp.Conn, cfg *TunnelConfig) (tunl Tunnel, err error) {

	var sal, sap unix.Sockaddr

	if nl == nil || cfg == nil {
		return nil, fmt.Errorf("invalid nil argument(s) to NewQuiescentTunnel")
	}

	// Sanity check the configuration
	if cfg.Version != ProtocolVersion3 && cfg.Encap == EncapTypeIP {
		return nil, fmt.Errorf("IP encapsulation only supported for L2TPv3 tunnels")
	}
	if cfg.Version == ProtocolVersion2 {
		if cfg.TunnelID == 0 || cfg.TunnelID > 65535 {
			return nil, fmt.Errorf("L2TPv2 connection ID %v out of range", cfg.TunnelID)
		} else if cfg.PeerTunnelID == 0 || cfg.PeerTunnelID > 65535 {
			return nil, fmt.Errorf("L2TPv2 peer connection ID %v out of range", cfg.PeerTunnelID)
		}
	} else {
		if cfg.TunnelID == 0 || cfg.PeerTunnelID == 0 {
			return nil, fmt.Errorf("L2TPv3 tunnel IDs %v and %v must both be > 0",
				cfg.TunnelID, cfg.PeerTunnelID)
		}
	}

	// Initialise tunnel address structures
	switch cfg.Encap {
	case EncapTypeUDP:
		sal, sap, err = newUDPAddressPair(cfg.Local, cfg.Peer)
	case EncapTypeIP:
		sal, sap, err = newIPAddressPair(cfg.Local, cfg.TunnelID,
			cfg.Peer, cfg.PeerTunnelID)
	default:
		err = fmt.Errorf("unrecognised encapsulation type %v", cfg.Encap)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to initialise tunnel addresses: %v", err)
	}

	return newQuiescentTunnel(nl, sal, sap, cfg)
}

// NewSession adds a session to the tunnel
func (qt *quiescentTunnel) NewSession(name string, cfg *SessionConfig) (Session, error) {

	if _, ok := qt.sessions[name]; ok {
		return nil, fmt.Errorf("already have session %q", name)
	}

	s, err := newStaticSession(qt, cfg)
	if err != nil {
		return nil, err
	}

	qt.sessions[name] = s

	return s, nil
}

// Close closes the tunnel, releasing allocated resources.
func (qt *quiescentTunnel) Close() {
	if qt != nil {
		if qt.xport != nil {
			qt.xport.close()
		}
		if qt.cp != nil {
			qt.cp.close()
		}
		if qt.dp != nil {
			qt.dp.close(qt.nl)
		}
	}
}

func (qt *quiescentTunnel) getCfg() *TunnelConfig {
	return qt.cfg
}

func (qt *quiescentTunnel) getNLConn() *nll2tp.Conn {
	return qt.nl
}

func newQuiescentTunnel(nl *nll2tp.Conn, sal, sap unix.Sockaddr, cfg *TunnelConfig) (qt *quiescentTunnel, err error) {
	qt = &quiescentTunnel{
		nl:       nl,
		cfg:      cfg,
		sessions: make(map[string]Session),
	}

	// Initialise the control plane.
	// We bind/connect immediately since we're not runnning most of the control protocol.
	qt.cp, err = newL2tpControlPlane(sal, sap)
	if err != nil {
		qt.Close()
		return nil, err
	}

	err = qt.cp.bind()
	if err != nil {
		qt.Close()
		return nil, err
	}

	err = qt.cp.connect()
	if err != nil {
		qt.Close()
		return nil, err
	}

	qt.dp, err = newManagedTunnelDataPlane(nl, qt.cp.fd, cfg)
	if err != nil {
		qt.Close()
		return nil, err
	}

	qt.xport, err = newTransport(qt.cp, transportConfig{
		HelloTimeout:      cfg.HelloTimeout,
		TxWindowSize:      cfg.WindowSize,
		MaxRetries:        cfg.MaxRetries,
		RetryTimeout:      cfg.RetryTimeout,
		AckTimeout:        time.Millisecond * 100,
		Version:           cfg.Version,
		PeerControlConnID: cfg.PeerTunnelID,
	})
	if err != nil {
		qt.Close()
		return nil, err
	}

	return
}

// NewStaticTunnel creates a new unmanaged L2TP tunnel.
func NewStaticTunnel(nl *nll2tp.Conn, cfg *TunnelConfig) (tunl Tunnel, err error) {

	var sal, sap unix.Sockaddr

	if nl == nil || cfg == nil {
		return nil, fmt.Errorf("invalid nil argument(s) to NewStaticTunnel")
	}

	// Sanity check  the configuration
	if cfg.Version != ProtocolVersion3 {
		return nil, fmt.Errorf("Static tunnels can be L2TPv3 only")
	}
	if cfg.TunnelID == 0 || cfg.PeerTunnelID == 0 {
		return nil, fmt.Errorf("L2TPv3 tunnel IDs %v and %v must both be > 0",
			cfg.TunnelID, cfg.PeerTunnelID)
	}

	// Initialise tunnel address structures
	switch cfg.Encap {
	case EncapTypeUDP:
		sal, sap, err = newUDPAddressPair(cfg.Local, cfg.Peer)
	case EncapTypeIP:
		sal, sap, err = newIPAddressPair(cfg.Local, cfg.TunnelID,
			cfg.Peer, cfg.PeerTunnelID)
	default:
		err = fmt.Errorf("unrecognised encapsulation type %v", cfg.Encap)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to initialise tunnel addresses: %v", err)
	}

	return newStaticTunnel(nl, sal, sap, cfg)
}

// NewSession adds a session to the tunnel
func (st *staticTunnel) NewSession(name string, cfg *SessionConfig) (Session, error) {

	if _, ok := st.sessions[name]; ok {
		return nil, fmt.Errorf("already have session %q", name)
	}

	s, err := newStaticSession(st, cfg)

	if err != nil {
		return nil, err
	}

	st.sessions[name] = s

	return s, nil
}

// Close closes the tunnel, releasing allocated resources.
func (st *staticTunnel) Close() {
	if st != nil {
		if st.dp != nil {
			st.dp.close(st.nl)
		}
	}
}

func (st *staticTunnel) getCfg() *TunnelConfig {
	return st.cfg
}

func (st *staticTunnel) getNLConn() *nll2tp.Conn {
	return st.nl
}

func newStaticTunnel(nl *nll2tp.Conn, sal, sap unix.Sockaddr, cfg *TunnelConfig) (st *staticTunnel, err error) {
	st = &staticTunnel{
		nl:       nl,
		cfg:      cfg,
		sessions: make(map[string]Session),
	}

	st.dp, err = newStaticTunnelDataPlane(nl, sal, sap, cfg)
	if err != nil {
		st.Close()
		return nil, err
	}

	return
}

func newStaticSession(parent Tunnel, cfg *SessionConfig) (ss *staticSession, err error) {
	// Since we're static we instantiate the session in the
	// dataplane at the point of creation.
	dp, err := newSessionDataPlane(parent.getNLConn(), parent.getCfg().TunnelID, parent.getCfg().PeerTunnelID, cfg)
	if err != nil {
		return
	}

	ss = &staticSession{
		parent: parent,
		cfg:    cfg,
		dp:     dp,
	}

	return
}

func (ss *staticSession) Close() {
	ss.dp.close(ss.parent.getNLConn())
}

func newUDPTunnelAddress(address string) (unix.Sockaddr, error) {

	u, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve %v: %v", address, err)
	}

	if b := u.IP.To4(); b != nil {
		return &unix.SockaddrInet4{
			Port: u.Port,
			Addr: [4]byte{b[0], b[1], b[2], b[3]},
		}, nil
	} else if b := u.IP.To16(); b != nil {
		// TODO: SockaddrInet6 has a uint32 ZoneId, while UDPAddr
		// has a Zone string.  How to convert between the two?
		return &unix.SockaddrInet6{
			Port: u.Port,
			Addr: [16]byte{
				b[0], b[1], b[2], b[3],
				b[4], b[5], b[6], b[7],
				b[8], b[9], b[10], b[11],
				b[12], b[13], b[14], b[15],
			},
			// ZoneId
		}, nil
	}

	return nil, fmt.Errorf("unhandled address family")
}

func newUDPAddressPair(local, remote string) (sal, sap unix.Sockaddr, err error) {
	sal, err = newUDPTunnelAddress(local)
	if err != nil {
		return nil, nil, err
	}
	sap, err = newUDPTunnelAddress(remote)
	if err != nil {
		return nil, nil, err
	}
	return sal, sap, nil
}

func newIPTunnelAddress(address string, ccid ControlConnID) (unix.Sockaddr, error) {

	u, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve %v: %v", address, err)
	}

	if b := u.IP.To4(); b != nil {
		return &unix.SockaddrL2TPIP{
			Addr:   [4]byte{b[0], b[1], b[2], b[3]},
			ConnId: uint32(ccid),
		}, nil
	} else if b := u.IP.To16(); b != nil {
		// TODO: SockaddrInet6 has a uint32 ZoneId, while UDPAddr
		// has a Zone string.  How to convert between the two?
		return &unix.SockaddrL2TPIP6{
			Addr: [16]byte{
				b[0], b[1], b[2], b[3],
				b[4], b[5], b[6], b[7],
				b[8], b[9], b[10], b[11],
				b[12], b[13], b[14], b[15],
			},
			// ZoneId
			ConnId: uint32(ccid),
		}, nil
	}

	return nil, fmt.Errorf("unhandled address family")
}

func newIPAddressPair(local string, ccid ControlConnID, remote string, pccid ControlConnID) (sal, sap unix.Sockaddr, err error) {
	sal, err = newIPTunnelAddress(local, ccid)
	if err != nil {
		return nil, nil, err
	}
	sap, err = newIPTunnelAddress(remote, pccid)
	if err != nil {
		return nil, nil, err
	}
	return sal, sap, nil
}
