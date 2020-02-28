package l2tp

import (
	"errors"
	"net"
	"time"
)

type slowStartState struct {
	ns, nr, cwnd, thresh, nacks, ntx uint16
}

type ctlMsg struct {
	msg          ControlMessage
	completeChan chan error
}

type rawMsg struct {
	b    []byte
	addr net.Addr
}

// TransportConfig represents the tunable parameters governing
// the behaviour of the reliable transport algorithm.
type TransportConfig struct {
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
}

// Transport represents the RFC2661/RFC3931
// reliable transport algorithm state.
type Transport struct {
	slowStart                        slowStartState
	config                           TransportConfig
	cp                               *l2tpControlPlane
	helloTimer, ackTimer, retryTimer *time.Timer
	sendChan                         chan ctlMsg
	recvChan                         chan ControlMessage
	cpChan                           chan rawMsg
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
	s.ntx++
}

func (s *slowStartState) onAck() {
	if s.ntx > 0 {
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
		s.ntx--
	}
}

func (s *slowStartState) onRetransmit() {
	s.thresh = s.cwnd / 2
	s.cwnd = 1
}

func newTimer(duration time.Duration) *time.Timer {
	if duration == 0 {
		duration = 1 * time.Hour
	}
	t := time.NewTimer(duration)
	t.Stop()
	return t
}

func sanitiseConfig(cfg *TransportConfig) {
	if cfg.TxWindowSize == 0 || cfg.TxWindowSize > 65535 {
		cfg.TxWindowSize = DefaultTransportConfig().TxWindowSize
	}
	if cfg.RetryTimeout == 0 {
		cfg.RetryTimeout = DefaultTransportConfig().RetryTimeout
	}
}

func cpRead(xport *Transport) {
	for {
		b := make([]byte, 4096)
		n, addr, err := xport.cp.ReadFrom(b)
		if err != nil {
			close(xport.cpChan)
			return
		}
		xport.cpChan <- rawMsg{b: b[:n], addr: addr}
	}
}

func runTransport(xport *Transport) {
	for {
		select {
		case ctlMsg, ok := <-xport.sendChan:
			if !ok {
				return
			}
			// TODO: submit to the tx queue, and attempt to send
			ctlMsg.completeChan <- errors.New("transport send not yet implemented")
		case rawMsg, ok := <-xport.cpChan:
			if !ok {
				return
			}

			messages, err := ParseMessageBuffer(rawMsg.b)
			if err != nil {
				// discard buffer we can't parse as a control message
				// TODO: log the error here
				break
			}

			// TODO: submit to the rx queue and attempt to receive
			_ = messages
		case _ = <-xport.helloTimer.C:
			// TODO: send a hello message to the peer
		case _ = <-xport.ackTimer.C:
			// TODO: send an ack message to the peer
		case _ = <-xport.retryTimer.C:
			// TODO: resend a pending message to the peer
		}
	}
}

// DefaultTransportConfig returns a default configuration for the transport.
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		HelloTimeout: 0 * time.Second,
		TxWindowSize: 4,
		MaxRetries:   3,
		RetryTimeout: 1 * time.Second,
	}
}

// NewTransport creates a new RFC2661/RFC3931 reliable transport.
func NewTransport(cp *l2tpControlPlane, cfg TransportConfig) (xport *Transport, err error) {

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
	ackTimer := newTimer(100 * time.Millisecond)
	retryTimer := newTimer(cfg.RetryTimeout)

	xport = &Transport{
		slowStart:  slowStart,
		config:     cfg,
		cp:         cp,
		helloTimer: helloTimer,
		ackTimer:   ackTimer,
		retryTimer: retryTimer,
		sendChan:   make(chan ctlMsg),
		recvChan:   make(chan ControlMessage),
		cpChan:     make(chan rawMsg),
	}

	go runTransport(xport)
	go cpRead(xport)

	return xport, nil
}

// Reconfigure allows transport parameters to be tweaked.
// Out of range values are automatically reset to sane default values.
func (xport *Transport) Reconfigure(cfg TransportConfig) {
	sanitiseConfig(&cfg)
	xport.config = cfg
}

// Send sends a control message using the reliable transport.
// The caller will block until the message has been acked by the peer.
// Failure indicates that the transport has failed and the parent tunnel
// should be torn down.
func (xport *Transport) Send(msg ControlMessage) error {
	onComplete := make(chan error)
	xport.sendChan <- ctlMsg{msg: msg, completeChan: onComplete}
	err := <-onComplete
	return err
}

// Recv receives a control message using the reliable transport.
// The caller will block until a message has been received from the peer.
// Failure indicates that the transport has failed and the parent tunnel
// should be torn down.
func (xport *Transport) Recv() (msg ControlMessage, err error) {
	msg, ok := <-xport.recvChan
	if !ok {
		return nil, errors.New("transport is down")
	}
	return msg, nil
}

// Close closes the transport.
func (xport *Transport) Close() {
	close(xport.sendChan)
}
