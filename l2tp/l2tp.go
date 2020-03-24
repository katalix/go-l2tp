package l2tp

import (
	"fmt"
	"net"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/katalix/sl2tpd/internal/nll2tp"
	"golang.org/x/sys/unix"
)

// Context is a container for a collection of L2TP tunnels and
// their sessions, and associated configuration.
type Context struct {
	logger  log.Logger
	nlconn  *nll2tp.Conn
	tunnels map[string]Tunnel
}

// ContextConfig encodes top-level configuration for an L2TP
// context.
type ContextConfig struct {
	// TODO
}

// Tunnel is an interface representing an L2TP tunnel.
type Tunnel interface {
	NewSession(name string, cfg *SessionConfig) (Session, error)
	Close()
	getCfg() *TunnelConfig
	getNLConn() *nll2tp.Conn
	getLogger() log.Logger
	unlinkSession(name string)
}

// Session is an interface representing an L2TP session.
type Session interface {
	Close()
}

type quiescentTunnel struct {
	logger   log.Logger
	name     string
	parent   *Context
	cfg      *TunnelConfig
	cp       *l2tpControlPlane
	xport    *transport
	dp       dataPlane
	sessions map[string]Session
}

type staticTunnel struct {
	logger   log.Logger
	name     string
	parent   *Context
	cfg      *TunnelConfig
	dp       dataPlane
	sessions map[string]Session
}

// staticSession does not run any control protocol
// and instead merely instantiates the data plane in the
// kernel.  This is equivalent to the Linux 'ip l2tp'
// commands(s).
type staticSession struct {
	logger log.Logger
	name   string
	parent Tunnel
	cfg    *SessionConfig
	dp     dataPlane
}

// NewContext creates a new L2TP context, which can then be used
// to instantiate tunnel and session instances.
// If a nil configuration is passed, default configuration will
// be used.
func NewContext(logger log.Logger, cfg *ContextConfig) (*Context, error) {

	if cfg == nil {
		// TODO: default configuration.
		// Eventually we might set things like host name, router ID,
		// etc, etc.
	}

	nlconn, err := nll2tp.Dial()
	if err != nil {
		return nil, fmt.Errorf("failed to establish a netlink/L2TP connection: %v", err)
	}

	return &Context{
		logger:  logger,
		nlconn:  nlconn,
		tunnels: make(map[string]Tunnel),
	}, nil
}

// NewQuiescentTunnel creates a new "quiescent" L2TP tunnel.
// A quiescent tunnel creates a user space socket for the
// L2TP control plane, but does not run the control protocol
// beyond acknowledging messages and optionally sending HELLO
// messages.
// The data plane is established on creation of the tunnel instance.
// The name provided must be unique in the Context.
func (ctx *Context) NewQuiescentTunnel(name string, cfg *TunnelConfig) (tunl Tunnel, err error) {

	var sal, sap unix.Sockaddr

	// Must have configuration
	if cfg == nil {
		return nil, fmt.Errorf("invalid nil config")
	}

	// Must not have name clashes
	if _, ok := ctx.tunnels[name]; ok {
		return nil, fmt.Errorf("already have tunnel %q", name)
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

	tunl, err = newQuiescentTunnel(name, ctx, sal, sap, cfg)
	if err != nil {
		return nil, err
	}

	ctx.tunnels[name] = tunl

	return tunl, nil
}

// NewStaticTunnel creates a new unmanaged L2TP tunnel.
// A static tunnel does not run any control protocol
// and instead merely instantiates the data plane in the
// kernel.  This is equivalent to the Linux 'ip l2tp'
// command(s).
// Static L2TPv2 tunnels are not practically useful,
// so NewStaticTunnel only supports creation of L2TPv3
// unmanaged tunnel instances.
// The name provided must be unique in the Context.
func (ctx *Context) NewStaticTunnel(name string, cfg *TunnelConfig) (tunl Tunnel, err error) {

	var sal, sap unix.Sockaddr

	// Must have configuration
	if cfg == nil {
		return nil, fmt.Errorf("invalid nil config")
	}

	// Must not have name clashes
	if _, ok := ctx.tunnels[name]; ok {
		return nil, fmt.Errorf("already have tunnel %q", name)
	}

	// Sanity check  the configuration
	if cfg.Version != ProtocolVersion3 {
		return nil, fmt.Errorf("static tunnels can be L2TPv3 only")
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

	tunl, err = newStaticTunnel(name, ctx, sal, sap, cfg)
	if err != nil {
		return nil, err
	}

	ctx.tunnels[name] = tunl

	return tunl, nil
}

// Close tears down the context, including all the L2TP tunnels and sessions
// running inside it.
func (ctx *Context) Close() {
	for name, tunl := range ctx.tunnels {
		tunl.Close()
		ctx.unlinkTunnel(name)
	}
	ctx.nlconn.Close()
}

func (ctx *Context) unlinkTunnel(name string) {
	delete(ctx.tunnels, name)
}

// NewSession adds a session to a quiescent tunnel.
// Since the tunnel is running a limited control protocol
// the session data plane is instantiated on creation of
// the session.  All configuration parameters must be provided
// at point of instantiation, and must match up with the
// peer's configuartion.
func (qt *quiescentTunnel) NewSession(name string, cfg *SessionConfig) (Session, error) {

	if _, ok := qt.sessions[name]; ok {
		return nil, fmt.Errorf("already have session %q", name)
	}

	s, err := newStaticSession(name, qt, cfg)
	if err != nil {
		return nil, err
	}

	qt.sessions[name] = s

	return s, nil
}

// Close closes the tunnel, releasing allocated resources.
// The control plane socket is closed, and the data plane is
// torn down.
// Any sessions instantiated inside the tunnel are removed.
func (qt *quiescentTunnel) Close() {
	if qt != nil {
		for name, session := range qt.sessions {
			session.Close()
			qt.unlinkSession(name)
		}

		if qt.xport != nil {
			qt.xport.close()
		}
		if qt.cp != nil {
			qt.cp.close()
		}
		if qt.dp != nil {
			qt.dp.close(qt.getNLConn())
		}

		level.Info(qt.logger).Log("message", "close")
	}
}

func (qt *quiescentTunnel) getCfg() *TunnelConfig {
	return qt.cfg
}

func (qt *quiescentTunnel) getNLConn() *nll2tp.Conn {
	return qt.parent.nlconn
}

func (qt *quiescentTunnel) getLogger() log.Logger {
	return qt.logger
}

func (qt *quiescentTunnel) unlinkSession(name string) {
	delete(qt.sessions, name)
}

func (qt *quiescentTunnel) xportReader() {
	// Although we're not running the control protocol we do need
	// to drain messages from the transport to avoid the receive
	// path blocking.  Do so here, treating any error as a signal
	// to exit.
	for {
		_, err := qt.xport.recv()
		if err != nil {
			return
		}
	}
}

func newQuiescentTunnel(name string, parent *Context, sal, sap unix.Sockaddr, cfg *TunnelConfig) (qt *quiescentTunnel, err error) {
	qt = &quiescentTunnel{
		logger:   log.With(parent.logger, "tunnel_name", name),
		name:     name,
		parent:   parent,
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

	qt.dp, err = newManagedTunnelDataPlane(parent.nlconn, qt.cp.fd, cfg)
	if err != nil {
		qt.Close()
		return nil, err
	}

	qt.xport, err = newTransport(qt.logger, qt.cp, transportConfig{
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

	go qt.xportReader()

	level.Info(qt.logger).Log(
		"message", "new quiescent tunnel",
		"version", cfg.Version,
		"encap", cfg.Encap,
		"local", cfg.Local,
		"peer", cfg.Peer,
		"tunnel_id", cfg.TunnelID,
		"peer_tunnel_id", cfg.PeerTunnelID)

	return
}

// NewSession adds a session to a static tunnel.
// Since the tunnel is running no control protocol
// the session data plane is instantiated on the creation
// of the session.  All configuration parameters must be
// provided at the point of instantiation, and must match
// up with the peer's configuration.
func (st *staticTunnel) NewSession(name string, cfg *SessionConfig) (Session, error) {

	if _, ok := st.sessions[name]; ok {
		return nil, fmt.Errorf("already have session %q", name)
	}

	s, err := newStaticSession(name, st, cfg)

	if err != nil {
		return nil, err
	}

	st.sessions[name] = s

	return s, nil
}

// Close closes the tunnel, releasing allocated resources.
// The control plane socket is closed, and the data plane is
// torn down.
// Any sessions instantiated inside the tunnel are removed.
func (st *staticTunnel) Close() {
	if st != nil {

		for name, session := range st.sessions {
			session.Close()
			st.unlinkSession(name)
		}

		if st.dp != nil {
			st.dp.close(st.getNLConn())
		}

		level.Info(st.logger).Log("message", "close")
	}
}

func (st *staticTunnel) getCfg() *TunnelConfig {
	return st.cfg
}

func (st *staticTunnel) getNLConn() *nll2tp.Conn {
	return st.parent.nlconn
}

func (st *staticTunnel) getLogger() log.Logger {
	return st.logger
}

func (st *staticTunnel) unlinkSession(name string) {
	delete(st.sessions, name)
}

func newStaticTunnel(name string, parent *Context, sal, sap unix.Sockaddr, cfg *TunnelConfig) (st *staticTunnel, err error) {
	st = &staticTunnel{
		logger:   log.With(parent.logger, "tunnel_name", name),
		name:     name,
		parent:   parent,
		cfg:      cfg,
		sessions: make(map[string]Session),
	}

	st.dp, err = newStaticTunnelDataPlane(parent.nlconn, sal, sap, cfg)
	if err != nil {
		st.Close()
		return nil, err
	}

	level.Info(st.logger).Log(
		"message", "new static tunnel",
		"version", cfg.Version,
		"encap", cfg.Encap,
		"local", cfg.Local,
		"peer", cfg.Peer,
		"tunnel_id", cfg.TunnelID,
		"peer_tunnel_id", cfg.PeerTunnelID)

	return
}

func newStaticSession(name string, parent Tunnel, cfg *SessionConfig) (ss *staticSession, err error) {
	// Since we're static we instantiate the session in the
	// dataplane at the point of creation.
	dp, err := newSessionDataPlane(parent.getNLConn(), parent.getCfg().TunnelID, parent.getCfg().PeerTunnelID, cfg)
	if err != nil {
		return
	}

	ss = &staticSession{
		logger: log.With(parent.getLogger(), "session_name", name),
		name:   name,
		parent: parent,
		cfg:    cfg,
		dp:     dp,
	}

	level.Info(ss.logger).Log(
		"message", "new static session",
		"session_id", cfg.SessionID,
		"peer_session_id", cfg.PeerSessionID,
		"pseudowire", cfg.Pseudowire)

	return
}

// Close closes the static session, tearing down the data plane.
func (ss *staticSession) Close() {
	ss.dp.close(ss.parent.getNLConn())
	ss.parent.unlinkSession(ss.name)
	level.Info(ss.logger).Log("message", "close")
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
