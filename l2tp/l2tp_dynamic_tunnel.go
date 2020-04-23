package l2tp

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"golang.org/x/sys/unix"
)

type sendMsg struct {
	msg          controlMessage
	completeChan chan error
}

type eventArgs struct {
	event string
	args  []interface{}
}

type dynamicTunnel struct {
	*baseTunnel
	isClosing   bool
	established bool
	sal, sap    unix.Sockaddr
	cp          *controlPlane
	xport       *transport
	dp          TunnelDataPlane
	closeChan   chan bool
	sendChan    chan *sendMsg
	eventChan   chan *eventArgs
	wg          sync.WaitGroup
	fsm         fsm
}

func (dt *dynamicTunnel) NewSession(name string, cfg *SessionConfig) (sess Session, err error) {

	// Must have configuration
	if cfg == nil {
		return nil, fmt.Errorf("invalid nil config")
	}

	// Name clashes are not allowed
	if _, ok := dt.findSessionByName(name); ok {
		return nil, fmt.Errorf("already have session %q", name)
	}

	// Duplicate the configuration so we don't modify the user's copy
	myCfg := *cfg

	// If the session ID in the config is unset, we must generate one.
	// If the session ID is set, we must check for collisions.
	// TODO: there is a potential race here if sessions are concurrently
	// added -- an ID assigned here isn't actually reserved until the linkSession
	// call.
	if myCfg.SessionID != 0 {
		// Must not have session ID clashes
		if _, ok := dt.findSessionByID(myCfg.SessionID); ok {
			return nil, fmt.Errorf("already have session with SID %q", myCfg.SessionID)
		}
	} else {
		myCfg.SessionID, err = dt.allocSid()
		if err != nil {
			return nil, fmt.Errorf("failed to allocate a SID: %q", err)
		}
	}

	s, err := newDynamicSession(dt.parent.allocCallSerial(), name, dt, &myCfg)
	if err != nil {
		return nil, err
	}

	dt.injectEvent("newsession", s)
	sess = s

	return
}

func (dt *dynamicTunnel) Close() {
	if dt != nil {
		dt.parent.unlinkTunnel(dt)
		close(dt.closeChan)
		dt.wg.Wait()
	}
}

func (dt *dynamicTunnel) sendMessage(msg controlMessage) error {
	sm := &sendMsg{
		msg:          msg,
		completeChan: make(chan error),
	}
	dt.sendChan <- sm
	return <-sm.completeChan
}

func (dt *dynamicTunnel) runTunnel() {
	defer dt.wg.Done()

	level.Info(dt.logger).Log(
		"message", "new dynamic tunnel",
		"version", dt.cfg.Version,
		"encap", dt.cfg.Encap,
		"local", dt.cfg.Local,
		"peer", dt.cfg.Peer,
		"tunnel_id", dt.cfg.TunnelID,
		"peer_tunnel_id", dt.cfg.PeerTunnelID)

	dt.handleEvent("open")
	for {
		select {
		case <-dt.closeChan:
			dt.handleEvent("close", avpStopCCNResultCodeClearConnection)
			return
		case m, ok := <-dt.xport.recvChan:
			if !ok {
				dt.fsmActClose(nil)
				return
			}
			dt.handleMsg(m)
		case ea, ok := <-dt.eventChan:
			if !ok {
				dt.fsmActClose(nil)
				return
			}
			dt.handleEvent(ea.event, ea.args...)
		case sm, ok := <-dt.sendChan:
			if !ok {
				dt.fsmActClose(nil)
				return
			}
			go func() {
				err := dt.xport.send(sm.msg)
				sm.completeChan <- err
			}()
		}
	}
}

func (dt *dynamicTunnel) handleEvent(ev string, args ...interface{}) {
	if ev != "" {
		level.Debug(dt.logger).Log(
			"message", "fsm event",
			"event", ev)
		err := dt.fsm.handleEvent(ev, args...)
		if err != nil {
			level.Error(dt.logger).Log(
				"message", "failed to handle fsm event",
				"error", err)
			// TODO: this may be extreme
			dt.fsmActClose(nil)
		}
	}
}

func (dt *dynamicTunnel) injectEvent(ev string, args ...interface{}) {
	ea := eventArgs{event: ev}
	for i := 0; i < len(args); i++ {
		ea.args = append(ea.args, args[i])
	}
	dt.eventChan <- &ea
}

// panics if expected arguments are not passed
func fsmArgsToV2MsgFrom(args []interface{}) (msg *v2ControlMessage, from unix.Sockaddr) {
	if len(args) != 2 {
		panic(fmt.Sprintf("unexpected argument count (wanted 2, got %v)", len(args)))
	}
	msg, ok := args[0].(*v2ControlMessage)
	if !ok {
		panic(fmt.Sprintf("first argument %T not *v2ControlMessage", args[0]))
	}
	from, ok = args[1].(unix.Sockaddr)
	if !ok {
		panic(fmt.Sprintf("second argument %T not unix.Sockaddr", args[0]))
	}
	return
}

// panics if expected arguments are not passed
func fsmArgsToSession(args []interface{}) (ds *dynamicSession) {
	if len(args) != 1 {
		panic(fmt.Sprintf("unexpected argument count (wanted 1, got %v)", len(args)))
	}
	ds, ok := args[0].(*dynamicSession)
	if !ok {
		panic(fmt.Sprintf("first argument %T not *dynamicSession", args[0]))
	}
	return
}

// stopccn args are optional, we set defaults here
func fsmArgsToStopccnResult(args []interface{}) *resultCode {
	rc := resultCode{
		result:  avpStopCCNResultCodeClearConnection,
		errCode: avpErrorCodeNoError,
	}

	for i := 0; i < len(args); i++ {
		switch v := args[i].(type) {
		case avpResultCode:
			rc.result = v
		case avpErrorCode:
			rc.errCode = v
		case string:
			rc.errMsg = v
		}
	}

	return &rc
}

func (dt *dynamicTunnel) handleMsg(m *recvMsg) {

	// Initial validation: ignore a message with the wrong protocol version
	if m.msg.protocolVersion() != dt.cfg.Version {
		level.Error(dt.logger).Log(
			"message", "received control message with wrong protocol version",
			"expected", dt.cfg.Version,
			"got", m.msg.protocolVersion())
		return
	}

	switch m.msg.protocolVersion() {
	case ProtocolVersion2:
		msg, ok := m.msg.(*v2ControlMessage)
		if !ok {
			// This shouldn't occur, since the header protocol version
			// dictates the message type during parsing.  Bail out if
			// it does since it indicates some dire coding error.
			level.Error(dt.logger).Log(
				"message", "couldn't cast L2TPv2 message as v2ControlMessage")
			dt.fsmActClose(nil)
			return
		}
		dt.handleV2Msg(msg, m.from)
		return
	}

	level.Error(dt.logger).Log(
		"message", "unhandled protocol version",
		"version", m.msg.protocolVersion())

	dt.handleEvent("close",
		avpStopCCNResultCodeChannelProtocolVersionUnsupported,
		avpErrorCode(ProtocolVersion2),
		fmt.Sprintf("unhandled protocol version %v", m.msg.protocolVersion()))
}

func (dt *dynamicTunnel) handleV2Msg(msg *v2ControlMessage, from unix.Sockaddr) {

	// It's possible to have a message mis-delivered on our control
	// socket.  Ignore these messages: ideally we'd redirect them
	// but dropping them is a good compromise for now.
	if msg.Tid() != uint16(dt.cfg.TunnelID) {
		level.Error(dt.logger).Log(
			"message", "received control message with the wrong TID",
			"expected", dt.cfg.TunnelID,
			"got", msg.Tid())
		return
	}

	// Validate the message.  If validation fails drive shutdown via.
	// the FSM to allow the error to be communicated to the peer.
	err := msg.validate()
	if err != nil {
		level.Error(dt.logger).Log(
			"message", "bad control message",
			"message_type", msg.getType(),
			"error", err)
		dt.handleEvent("close",
			avpStopCCNResultCodeGeneralError,
			avpErrorCodeBadValue,
			fmt.Sprintf("bad %v message: %v", msg.getType(), err))
	}

	// Map the message to the appropriate event type.  If we haven't got
	// an event appropriate to the incoming message close the tunnel.
	eventMap := []struct {
		m avpMsgType
		e string
	}{
		{avpMsgTypeSccrq, "sccrq"},
		{avpMsgTypeSccrp, "sccrp"},
		{avpMsgTypeScccn, "scccn"},
		{avpMsgTypeStopccn, "stopccn"},
		{avpMsgTypeHello, ""}, // fsm ignores empty events
		{avpMsgTypeIcrq, "sessionmsg"},
		{avpMsgTypeIcrp, "sessionmsg"},
		{avpMsgTypeIccn, "sessionmsg"},
		{avpMsgTypeCdn, "sessionmsg"},
	}

	for _, em := range eventMap {
		if msg.getType() == em.m {
			dt.handleEvent(em.e, msg, from)
			return
		}
	}

	level.Error(dt.logger).Log(
		"message", "unhandled v2 control message",
		"message_type", msg.getType())

	dt.handleEvent("close",
		avpStopCCNResultCodeGeneralError,
		avpErrorCodeBadValue,
		fmt.Sprintf("unhandled v2 control message %v", msg.getType()))
}

func (dt *dynamicTunnel) fsmActSendSccrq(args []interface{}) {
	err := dt.sendSccrq()
	if err != nil {
		level.Error(dt.logger).Log(
			"message", "failed to send SCCRQ message",
			"error", err)
		dt.fsmActClose(nil)
	}
}

func (dt *dynamicTunnel) sendSccrq() error {
	msg, err := newV2Sccrq(dt.cfg)
	if err != nil {
		return err
	}
	return dt.xport.send(msg)
}

func (dt *dynamicTunnel) fsmActOnSccrp(args []interface{}) {

	msg, from := fsmArgsToV2MsgFrom(args)

	ptid, err := findUint16Avp(msg.getAvps(), vendorIDIetf, avpTypeTunnelID)
	if err != nil {
		// Shouldn't occur since tunnel ID is mandatory
		level.Error(dt.logger).Log(
			"message", "failed to parse peer tunnel ID from SCCRP",
			"error", err)
		dt.handleEvent("close")
		return
	}

	// Reconfigure transport and socket now we know the peer TID
	// and the address being used for this tunnel
	dt.xport.config.PeerControlConnID = ControlConnID(ptid)
	dt.cfg.PeerTunnelID = ControlConnID(ptid)
	dt.cp.connectTo(from)

	err = dt.sendScccn()
	if err != nil {
		level.Error(dt.logger).Log(
			"message", "failed to send SCCCN",
			"error", err)
		dt.fsmActClose(nil)
		return
	}

	level.Info(dt.logger).Log("message", "control plane established")

	// establish the data plane
	dt.dp, err = dt.parent.dp.NewTunnel(dt.cfg, dt.sal, dt.sap, dt.cp.fd)
	if err != nil {
		level.Error(dt.logger).Log(
			"message", "failed to establish data plane",
			"error", err)
		dt.handleEvent("close",
			avpStopCCNResultCodeGeneralError,
			avpErrorCodeVendorSpecificError,
			fmt.Sprintf("failed to instantiate tunnel data plane: %v", err))
		return
	}

	level.Info(dt.logger).Log("message", "data plane established")

	// inform sessions that we're up
	for _, s := range dt.allSessions() {
		if ds, ok := s.(*dynamicSession); ok {
			ds.onTunnelUp()
		}
	}

	dt.established = true
	dt.parent.handleUserEvent(&TunnelUpEvent{
		Tunnel:       dt,
		Config:       dt.cfg,
		LocalAddress: dt.sal,
		PeerAddress:  dt.sap,
	})
}

func (dt *dynamicTunnel) sendScccn() error {
	msg, err := newV2Scccn(dt.cfg)
	if err != nil {
		return err
	}
	return dt.xport.send(msg)
}

func (dt *dynamicTunnel) fsmActSendStopccn(args []interface{}) {

	rc := fsmArgsToStopccnResult(args)
	// Ignore tx error since we're going to close in any case
	_ = dt.sendStopccn(rc)
	dt.fsmActClose(args)
}

func (dt *dynamicTunnel) sendStopccn(rc *resultCode) error {
	msg, err := newV2Stopccn(rc, dt.cfg)
	if err != nil {
		return err
	}
	return dt.xport.send(msg)
}

// Implementes stopccn pend timeout as per RFC2661 section 5.7.
//
// While pending the timeout we ignore further messages, but
// continue to drain the transport in order to allow messages to
// be ACKed.
func (dt *dynamicTunnel) fsmActOnStopccn(args []interface{}) {
	level.Debug(dt.logger).Log(
		"message", "pending for stopccn retransmit period",
		"timeout", dt.cfg.StopCCNTimeout)
	timeout := time.NewTimer(dt.cfg.StopCCNTimeout)
	for {
		select {
		case <-timeout.C:
			dt.fsmActClose(args)
			return
		case <-dt.xport.recvChan:
		}
	}
}

func (dt *dynamicTunnel) fsmActLinkSession(args []interface{}) {
	ds := fsmArgsToSession(args)
	dt.linkSession(ds)
}

func (dt *dynamicTunnel) fsmActStartSession(args []interface{}) {
	ds := fsmArgsToSession(args)
	dt.linkSession(ds)
	ds.onTunnelUp()
}

func (dt *dynamicTunnel) fsmActForwardSessionMsg(args []interface{}) {

	msg, _ := fsmArgsToV2MsgFrom(args)

	if s, ok := dt.findSessionByID(ControlConnID(msg.Sid())); ok {
		if ds, ok := s.(*dynamicSession); ok {
			ds.handleCtlMsg(msg)
		}
	} else {
		// TODO: on receipt of ICRQ we'll end up here; to handle this
		// we'd need to be able to create an LNS-mode session instance
		level.Error(dt.logger).Log(
			"message", "received session message for unknown session",
			"message_type", msg.getType(),
			"session ID", msg.Sid())
	}
}

// Closes all tunnel resources and unlinks child sessions.
// The tunnel goroutine will terminate after this call completes
// because the transport recv channel will have been closed.
func (dt *dynamicTunnel) fsmActClose(args []interface{}) {
	if dt != nil {

		if dt.isClosing {
			return
		}

		dt.isClosing = true

		dt.baseTunnel.closeAllSessions()

		if dt.dp != nil {
			err := dt.dp.Down()
			if err != nil {
				level.Error(dt.logger).Log("message", "dataplane down failed", "error", err)
			}
		}
		if dt.xport != nil {
			dt.xport.close()
		}
		if dt.cp != nil {
			dt.cp.close()
		}

		if dt.established {
			dt.established = false
			dt.parent.handleUserEvent(&TunnelDownEvent{
				Tunnel:       dt,
				Config:       dt.cfg,
				LocalAddress: dt.sal,
				PeerAddress:  dt.sap,
			})
		}

		dt.parent.unlinkTunnel(dt)
		level.Info(dt.logger).Log("message", "close")
	}
}

// Create a new client/LAC mode tunnel instance running the full control protocol
func newDynamicTunnel(name string, parent *Context, sal, sap unix.Sockaddr, cfg *TunnelConfig) (dt *dynamicTunnel, err error) {

	// Currently only handle L2TPv2
	if cfg.Version != ProtocolVersion2 {
		return nil, fmt.Errorf("L2TPv3 dynamic tunnels are not (yet) supported")
	}

	dt = &dynamicTunnel{
		baseTunnel: newBaseTunnel(
			log.With(parent.logger, "tunnel_name", name),
			name,
			parent,
			cfg),
		sal:       sal,
		sap:       sap,
		closeChan: make(chan bool),
		sendChan:  make(chan *sendMsg),
		eventChan: make(chan *eventArgs),
	}

	// Ref: RFC2661 section 7.2.1
	dt.fsm = fsm{
		current: "idle",
		table: []eventDesc{
			// No other events possible in the idle state since we handle open to
			// kick off the FSM
			{from: "idle", events: []string{"open"}, cb: dt.fsmActSendSccrq, to: "waitctlreply"},

			// waitctlreply is for when we've sent an sccrq to the peer and are waiting on the reply
			{from: "waitctlreply", events: []string{"sccrp"}, cb: dt.fsmActOnSccrp, to: "established"},
			{from: "waitctlreply", events: []string{"stopccn"}, cb: dt.fsmActOnStopccn, to: "dead"},
			{from: "waitctlreply", events: []string{"newsession"}, cb: dt.fsmActLinkSession, to: "waitctlreply"},
			// TODO: don't really expect session messages: OK to ignore?
			{from: "waitctlreply", events: []string{"sessionmsg"}, cb: nil, to: "waitctlreply"},
			{
				from: "waitctlreply",
				events: []string{
					"sccrq",
					"scccn",
					"close",
				},
				cb: dt.fsmActSendStopccn,
				to: "dead",
			},

			// established is for once the tunnel three-way handshake is complete
			{from: "established", events: []string{"stopccn"}, cb: dt.fsmActOnStopccn, to: "dead"},
			{from: "established", events: []string{"newsession"}, cb: dt.fsmActStartSession, to: "established"},
			{from: "established", events: []string{"sessionmsg"}, cb: dt.fsmActForwardSessionMsg, to: "established"},
			{
				from: "established",
				events: []string{
					"sccrq",
					"sccrp",
					"scccn",
					"close",
				},
				cb: dt.fsmActSendStopccn,
				to: "dead",
			},
		},
	}

	dt.cp, err = newL2tpControlPlane(sal, sap)
	if err != nil {
		dt.Close()
		return nil, err
	}

	err = dt.cp.bind()
	if err != nil {
		dt.Close()
		return nil, err
	}

	dt.xport, err = newTransport(dt.logger, dt.cp, transportConfig{
		HelloTimeout:      dt.cfg.HelloTimeout,
		TxWindowSize:      dt.cfg.WindowSize,
		MaxRetries:        dt.cfg.MaxRetries,
		RetryTimeout:      dt.cfg.RetryTimeout,
		AckTimeout:        time.Millisecond * 100,
		Version:           dt.cfg.Version,
		PeerControlConnID: dt.cfg.PeerTunnelID,
	})
	if err != nil {
		dt.Close()
		return nil, err
	}

	dt.wg.Add(1)
	go dt.runTunnel()

	return
}
