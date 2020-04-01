package l2tp

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"golang.org/x/sys/unix"
)

// slowStartState represents state for the transport sequence numbers
// and slow start/congestion avoidance algorithm.
type slowStartState struct {
	ns, nr, cwnd, thresh, nacks, ntx uint16
}

// xmitMsg encapsulates state for control message transmission,
// wrapping the basic controlMessage with transport-specific
// metadata.
type xmitMsg struct {
	xport *transport
	// The message for transmission
	msg controlMessage
	// The current retry count for the message.  This is bound by
	// the transport config MaxRetries parameter.
	nretries uint
	// When transmission is complete (either: the message has been
	// transmitted and acked by the peer, transmission itself has
	// failed, or retransmission has timed out) the resulting error
	// is sent on this channel.
	completeChan chan error
	// Completion state flag used internally by the transport.
	isComplete bool
	// Timer for retransmission if the peer doesn't ack the message.
	retryTimer *time.Timer
	onComplete func(m *xmitMsg, err error)
}

// rawMsg represents a raw frame read from the transport socket.
type rawMsg struct {
	b  []byte
	sa unix.Sockaddr
}

// recvMsg represents a received control message.
type recvMsg struct {
	msg  controlMessage
	from unix.Sockaddr
}

// transportConfig represents the tunable parameters governing
// the behaviour of the reliable transport algorithm.
type transportConfig struct {
	// Duration to wait after last message receipt before
	// sending a HELLO keepalive message.  If set to 0, no HELLO messages
	// are transmitted.
	HelloTimeout time.Duration
	// Maximum number of messages we will send to the peer without having
	// received an acknowledgement.
	TxWindowSize uint16
	// Maximum number of retransmits of an unacknowledged control packet.
	MaxRetries uint
	// Duration to wait before first packet retransmit.
	// Subsequent retransmits up to the limit set by maxRetries occur at
	// exponentially increasing intervals as per RFC3931.  If set to 0,
	// a default value of 1 second is used.
	RetryTimeout time.Duration
	// Duration to wait before explicitly acking a control message.
	// Most control messages will be implicitly acked by control protocol
	// responses.
	AckTimeout time.Duration
	// Version of the L2TP protocol to use for transport-generated messages.
	Version ProtocolVersion
	// Peer control connection ID to use for transport-generated messages
	PeerControlConnID ControlConnID
}

// transport represents the RFC2661/RFC3931
// reliable transport algorithm state.
type transport struct {
	logger               log.Logger
	slowStart            slowStartState
	config               transportConfig
	cp                   *controlPlane
	helloTimer, ackTimer *time.Timer
	helloInFlight        bool
	sendChan             chan *xmitMsg
	retryChan            chan *xmitMsg
	recvChan             chan *recvMsg
	cpChan               chan *rawMsg
	rxQueue              []*recvMsg
	txQueue, ackQueue    []*xmitMsg
	wg                   sync.WaitGroup
}

// Increment transport sequence number by one avoiding overflow
// as per RFC2661/RFC3931
func seqIncrement(seqNum uint16) uint16 {
	next := uint32(seqNum)
	next = (next + 1) % 0x10000
	return uint16(next)
}

// Sequence number comparision as per RFC2661/RFC3931
func seqCompare(seq1, seq2 uint16) int {
	var delta uint16
	if seq2 <= seq1 {
		delta = seq1 - seq2
	} else {
		delta = (0xffff - seq2 + 1) + seq1
	}
	if delta == 0 {
		return 0
	} else if delta < 0x8000 {
		return 1
	}
	return -1
}

func (s *slowStartState) reset(txWindow uint16) {
	s.cwnd = 1
	s.thresh = txWindow
	s.nacks = 0
	s.ntx = 0
}

func (s *slowStartState) canSend() bool {
	return s.ntx < s.cwnd
}

func (s *slowStartState) onSend() {
	if !s.canSend() {
		panic("slowStartState onSend() called when tx window is closed")
	}
	s.ntx++
}

func (s *slowStartState) onAck(maxTxWindow uint16) {
	if s.ntx > 0 {
		if s.cwnd < maxTxWindow {
			if s.cwnd < s.thresh {
				// slow start
				s.cwnd++
			} else {
				// congestion avoidance
				s.nacks++
				if s.nacks >= s.cwnd {
					s.nacks = 0
					s.cwnd++
				}
			}
		}
		s.ntx--
	}
}

func (s *slowStartState) onRetransmit() {
	s.thresh = s.cwnd / 2
	s.cwnd = 1
}

func (s *slowStartState) incrementNr() {
	s.nr = seqIncrement(s.nr)
}

func (s *slowStartState) incrementNs() {
	s.ns = seqIncrement(s.ns)
}

// A message with ns value equal to our nr is the next packet in sequence.
func (s *slowStartState) msgIsInSequence(msg controlMessage) bool {
	return seqCompare(s.nr, msg.ns()) == 0
}

// A message with ns value < our nr is stale/duplicated.
func (s *slowStartState) msgIsStale(msg controlMessage) bool {
	return seqCompare(msg.ns(), s.nr) == -1
}

func (m *xmitMsg) txComplete(err error) {
	if !m.isComplete {

		level.Debug(m.xport.logger).Log(
			"message", "send complete",
			"message_type", m.msg.getType(),
			"error", err)

		m.isComplete = true
		if m.retryTimer != nil {
			m.retryTimer.Stop()
		}
		m.onComplete(m, err)
	}
}

func newTimer(duration time.Duration) *time.Timer {
	if duration == 0 {
		duration = 1 * time.Hour
	}
	t := time.NewTimer(duration)
	t.Stop()
	return t
}

func sanitiseConfig(cfg *transportConfig) {
	if cfg.TxWindowSize == 0 || cfg.TxWindowSize > 65535 {
		cfg.TxWindowSize = defaulttransportConfig().TxWindowSize
	}
	if cfg.RetryTimeout == 0 {
		cfg.RetryTimeout = defaulttransportConfig().RetryTimeout
	}
	if cfg.AckTimeout == 0 {
		cfg.AckTimeout = defaulttransportConfig().AckTimeout
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = defaulttransportConfig().MaxRetries
	}
}

func cpRead(xport *transport, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		b := make([]byte, 4096)
		n, sa, err := xport.cp.recvFrom(b)
		if err != nil {
			close(xport.cpChan)
			level.Error(xport.logger).Log(
				"message", "socket read failed",
				"error", err)
			return
		}
		xport.cpChan <- &rawMsg{b: b[:n], sa: sa}
	}
}

func runTransport(xport *transport, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		// Transmission request from user code
		case xmitMsg, ok := <-xport.sendChan:
			if !ok {
				xport.down(errors.New("transport shut down by user"))
				return
			}

			level.Debug(xport.logger).Log(
				"message", "send",
				"message_type", xmitMsg.msg.getType())

			xport.txQueue = append(xport.txQueue, xmitMsg)
			err := xport.processTxQueue()
			if err != nil {
				xport.down(err)
				return
			}

		// Socket receive from the transport socket
		case rawMsg, ok := <-xport.cpChan:

			if !ok {
				xport.down(errors.New("control plane socket read error"))
				return
			}

			level.Debug(xport.logger).Log(
				"message", "socket recv",
				"length", len(rawMsg.b))

			messages, err := xport.recvFrame(rawMsg)
			if err != nil {
				// Early packet handling can fail for a variety of reasons.
				// The most important of these is if a peer sends a mandatory
				// AVP that we don't recognise: this MUST cause the tunnel to fail
				// per the RFCs.  Anything else we just log for information.
				level.Error(xport.logger).Log(
					"message", "frame receive failed",
					"error", err)
				if strings.Contains("failed to parse mandatory AVP", err.Error()) {
					xport.down(err)
					return
				}
			}

			for _, msg := range messages {
				xport.rxQueue = append(xport.rxQueue, &recvMsg{msg: msg, from: rawMsg.sa})

				// Process the ack queue using sequence numbers from the newly received
				// message.  If we manage to dequeue a message it may result in opening
				// the window for further transmits.
				if xport.processAckQueue(msg) {
					err = xport.processTxQueue()
					if err != nil {
						xport.down(err)
						return
					}
				}
			}

			// TODO: connect socket here if required

			// Having added messages to the receive queue, process the queue
			// to attempt to handle any messages that are in sequence.
			xport.processRxQueue()

		// Message retry request due to timeout waiting for an ack
		case xmitMsg, ok := <-xport.retryChan:
			if !ok {
				return
			}

			level.Info(xport.logger).Log(
				"message", "retransmit",
				"message_type", xmitMsg.msg.getType())

			// It's possible that a message ack could race with the retry timer.
			// Hence we track completion state in the message struct to avoid
			// a bogus retransmit.
			if !xmitMsg.isComplete {
				err := xport.retransmitMessage(xmitMsg)
				if err != nil {
					xmitMsg.txComplete(err)
					xport.down(err)
					return
				}
			}

		// Timer fired for sending a hello message
		case <-xport.helloTimer.C:
			if !xport.helloInFlight {
				err := xport.sendHelloMessage()
				if err != nil {
					xport.down(err)
					return
				}
				xport.helloInFlight = true
			}

		// Timer fired for sending an explicit ack
		case <-xport.ackTimer.C:
			err := xport.sendExplicitAck()
			if err != nil {
				xport.down(err)
				return
			}
		}
	}
}

func (xport *transport) recvFrame(rawMsg *rawMsg) (messages []controlMessage, err error) {
	messages, err = parseMessageBuffer(rawMsg.b)
	if err != nil {
		return nil, err
	}

	for _, msg := range messages {
		// Sanity check the packet sequence number: enqueue the packet for rx if it's OK
		if seqCompare(msg.nr(), seqIncrement(xport.slowStart.ns)) > 0 {
			return nil, fmt.Errorf("dropping invalid packet %s ns %d nr %d (transport ns %d nr %d)",
				msg.getType(), msg.ns(), msg.nr(), xport.slowStart.ns, xport.slowStart.nr)
		}
	}

	return messages, nil
}

func (xport *transport) recvMessage(m *recvMsg) {
	if xport.slowStart.msgIsInSequence(m.msg) {

		level.Debug(xport.logger).Log(
			"message", "recv",
			"message_type", m.msg.getType())

		xport.toggleAckTimer(true)
		xport.resetHelloTimer()
		xport.slowStart.incrementNr()
		xport.recvChan <- m
	} else if xport.slowStart.msgIsStale(m.msg) {
		_ = xport.sendExplicitAck()
	}
}

func (xport *transport) dequeueRxMessage() bool {
	for i, m := range xport.rxQueue {
		if xport.slowStart.msgIsInSequence(m.msg) || xport.slowStart.msgIsStale(m.msg) {
			// Remove the message from the rx queue, and bubble it up for
			// processing.
			// In general we don't need to do anything more with an ack message
			// since they're just for the transport's purposes, so just drop them
			xport.rxQueue = append(xport.rxQueue[:i], xport.rxQueue[i+1:]...)
			if m.msg.getType() != avpMsgTypeAck {
				xport.recvMessage(m)
			}
			return true
		}
	}
	return false
}

func (xport *transport) processRxQueue() {
	// Loop the receive queue looking for messages in sequence.
	// We give up once we've been through the queue without finding
	// an in-sequence message.
	for {
		if !xport.dequeueRxMessage() {
			return
		}
	}
}

func (xport *transport) sendMessage1(msg controlMessage, isRetransmit bool) error {
	// Set message sequence numbers.
	// A retransmitted message should have ns set already.
	if isRetransmit {
		msg.setTransportSeqNum(msg.ns(), xport.slowStart.nr)
	} else {
		msg.setTransportSeqNum(xport.slowStart.ns, xport.slowStart.nr)
	}

	level.Debug(xport.logger).Log(
		"message", "send",
		"message_type", msg.getType(),
		"ns", msg.ns(),
		"nr", msg.nr(),
		"isRetransmit", isRetransmit)

	// Render as a byte slice and send.
	b, err := msg.toBytes()
	if err == nil {
		_, err = xport.cp.write(b)
	}
	return err
}

// Exponential retry timeout scaling as per RFC2661/RFC3931
func (xport *transport) scaleRetryTimeout(msg *xmitMsg) time.Duration {
	return xport.config.RetryTimeout * (1 << msg.nretries)
}

func (xport *transport) sendMessage(msg *xmitMsg) error {

	err := xport.sendMessage1(msg.msg, msg.nretries > 0)
	if err == nil {
		xport.toggleAckTimer(false) // we have just sent an implicit ack
		xport.resetHelloTimer()
		if msg.msg.getType() != avpMsgTypeAck && msg.nretries == 0 {
			xport.slowStart.incrementNs()
		}
		msg.retryTimer = time.AfterFunc(xport.scaleRetryTimeout(msg), func() {
			xport.retryChan <- msg
		})
	}
	return err
}

func (xport *transport) retransmitMessage(msg *xmitMsg) error {
	msg.nretries++
	if msg.nretries >= xport.config.MaxRetries {
		return fmt.Errorf("transmit of %s failed after %d retry attempts",
			msg.msg.getType(), xport.config.MaxRetries)
	}
	err := xport.sendMessage(msg)
	if err == nil {
		xport.slowStart.onRetransmit()
	}
	return err
}

func (xport *transport) processTxQueue() error {
	// Loop the transmit queue sending messages in order while
	// the transmit window is open.
	for i, msg := range xport.txQueue {
		if !xport.slowStart.canSend() {
			// We've sent all we can for the time being.  This is not
			// an error condition, so return successfully.
			return nil
		}

		// Remove from the tx queue, send, add to the ack queue
		xport.txQueue = append(xport.txQueue[:i], xport.txQueue[i+1:]...)
		err := xport.sendMessage(msg)
		if err == nil {
			xport.ackQueue = append(xport.ackQueue, msg)
			xport.slowStart.onSend()
		} else {
			msg.txComplete(err)
			return err
		}
	}
	return nil
}

func (xport *transport) processAckQueue(recvd controlMessage) bool {
	found := false
	for i, msg := range xport.ackQueue {
		if seqCompare(recvd.nr(), msg.msg.ns()) > 0 {
			xport.slowStart.onAck(xport.config.TxWindowSize)
			xport.ackQueue = append(xport.ackQueue[:i], xport.ackQueue[i+1:]...)
			msg.txComplete(nil)
			found = true
		}
	}
	return found
}

func (xport *transport) down(err error) {

	// Flush rx queue
	for i := range xport.rxQueue {
		xport.rxQueue = append(xport.rxQueue[:i], xport.rxQueue[i+1:]...)
	}

	// Flush tx and ack queues: complete these messages to unblock
	// callers pending on their completion.
	for i, msg := range xport.txQueue {
		xport.txQueue = append(xport.txQueue[:i], xport.txQueue[i+1:]...)
		msg.txComplete(err)
	}

	for i, msg := range xport.ackQueue {
		xport.ackQueue = append(xport.ackQueue[:i], xport.ackQueue[i+1:]...)
		msg.txComplete(err)
	}

	// Stop timers: we don't care about the return value since
	// the transport goroutine will return after calling this function
	// and hence won't be able to process racing timer messages
	xport.toggleAckTimer(false)
	_ = xport.helloTimer.Stop()

	level.Error(xport.logger).Log(
		"message", "transport down",
		"error", err)

	// Unblock recv path
	close(xport.recvChan)

	// Unblock control plane read goroutine
	xport.cp.close()
}

func (xport *transport) toggleAckTimer(enable bool) {
	if enable {
		xport.ackTimer.Reset(xport.config.AckTimeout)
	} else {
		// TODO: is this bad?
		_ = xport.ackTimer.Stop()
	}
}

func (xport *transport) resetHelloTimer() {
	if xport.config.HelloTimeout > 0 {
		xport.helloTimer.Reset(xport.config.HelloTimeout)
	}
}

func (xport *transport) sendHelloMessage() error {
	var msg controlMessage

	a, err := newAvp(vendorIDIetf, avpTypeMessage, avpMsgTypeHello)
	if err != nil {
		return fmt.Errorf("failed to build hello message type AVP: %v", err)
	}

	if xport.config.Version == ProtocolVersion3Fallback || xport.config.Version == ProtocolVersion3 {
		msg, err = newV3ControlMessage(xport.config.PeerControlConnID, []avp{*a})
	} else {
		msg, err = newV2ControlMessage(xport.config.PeerControlConnID, 0, []avp{*a})
	}

	if err != nil {
		return fmt.Errorf("failed to build hello message: %v", err)
	}

	return xport.sendMessage(&xmitMsg{
		xport:      xport,
		msg:        msg,
		onComplete: helloSendComplete,
	})
}

func helloSendComplete(m *xmitMsg, err error) {
	m.xport.helloInFlight = false
}

func (xport *transport) sendExplicitAck() (err error) {
	var msg controlMessage

	if xport.config.Version == ProtocolVersion3Fallback || xport.config.Version == ProtocolVersion3 {
		a, err := newAvp(vendorIDIetf, avpTypeMessage, avpMsgTypeAck)
		if err != nil {
			return fmt.Errorf("failed to build v3 explicit ack message type AVP: %v", err)
		}
		msg, err = newV3ControlMessage(xport.config.PeerControlConnID, []avp{*a})
		if err != nil {
			return fmt.Errorf("failed to build v3 explicit ack message: %v", err)
		}
	} else {
		msg, err = newV2ControlMessage(xport.config.PeerControlConnID, 0, []avp{})
		if err != nil {
			return fmt.Errorf("failed to build v2 ZLB message: %v", err)
		}
	}
	return xport.sendMessage1(msg, false)
}

// defaulttransportConfig returns a default configuration for the transport.
func defaulttransportConfig() transportConfig {
	return transportConfig{
		HelloTimeout: 0 * time.Second,
		TxWindowSize: 4,
		MaxRetries:   3,
		RetryTimeout: 1 * time.Second,
		AckTimeout:   100 * time.Millisecond,
		Version:      ProtocolVersion3,
	}
}

// newTransport creates a new RFC2661/RFC3931 reliable transport.
// The control plane passed in is owned by the transport and will
// be closed by the transport when the transport is closed.
func newTransport(logger log.Logger, cp *controlPlane, cfg transportConfig) (xport *transport, err error) {

	if cp == nil {
		return nil, errors.New("illegal nil control plane argument")
	}

	// Make sure the config is sane
	sanitiseConfig(&cfg)

	slowStart := slowStartState{}
	slowStart.reset(cfg.TxWindowSize)

	// We always create timer instances even if they're not going to be used.
	// This makes the logic for the transport go routine select easier to manage.
	helloTimer := newTimer(cfg.HelloTimeout)
	ackTimer := newTimer(cfg.AckTimeout)

	xport = &transport{
		logger:     log.With(logger, "function", "transport"),
		slowStart:  slowStart,
		config:     cfg,
		cp:         cp,
		helloTimer: helloTimer,
		ackTimer:   ackTimer,
		sendChan:   make(chan *xmitMsg),
		retryChan:  make(chan *xmitMsg),
		recvChan:   make(chan *recvMsg),
		cpChan:     make(chan *rawMsg),
		rxQueue:    []*recvMsg{},
		txQueue:    []*xmitMsg{},
		ackQueue:   []*xmitMsg{},
	}

	xport.wg.Add(2)
	xport.resetHelloTimer()
	go runTransport(xport, &xport.wg)
	go cpRead(xport, &xport.wg)

	return xport, nil
}

// getConfig allows transport parameters to be queried.
func (xport *transport) getConfig() transportConfig {
	return xport.config
}

// send sends a control message using the reliable transport.
// The caller will block until the message has been acked by the peer.
// Failure indicates that the transport has failed and the parent tunnel
// should be torn down.
func (xport *transport) send(msg controlMessage) error {
	cm := xmitMsg{
		xport:        xport,
		msg:          msg,
		completeChan: make(chan error),
		onComplete:   sendComplete,
	}
	xport.sendChan <- &cm
	err := <-cm.completeChan
	return err
}

func sendComplete(m *xmitMsg, err error) {
	m.completeChan <- err
}

// recv receives a control message using the reliable transport.
// The caller will block until a message has been received from the peer.
// Failure indicates that the transport has failed and the parent tunnel
// should be torn down.
func (xport *transport) recv() (msg controlMessage, from unix.Sockaddr, err error) {
	m, ok := <-xport.recvChan
	if !ok {
		return nil, nil, errors.New("transport is down")
	}
	return m.msg, m.from, nil
}

// close closes the transport.
func (xport *transport) close() {
	close(xport.sendChan)
	xport.wg.Wait()
}
