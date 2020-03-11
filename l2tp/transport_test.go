package l2tp

import (
	"fmt"
	"testing"
	"time"
)

func TestOpenClose(t *testing.T) {
	xport, err := NewTransport(nil, DefaultTransportConfig())
	if xport != nil {
		t.Fatalf("NewTransport() with nil controlplane succeeded")
	} else if err == nil {
		t.Fatalf("NewTransport() with nil controlplane didn't report error")
	}

	cp, err := newL2tpControlPlane("127.0.0.1:5000", "127.0.0.1:6000", EncapTypeUDP)
	if err != nil {
		t.Fatalf("newL2tpControlPlane() failed: %v", err)
	}

	xport, err = NewTransport(cp, DefaultTransportConfig())
	if xport == nil {
		t.Fatalf("NewTransport() returned nil controlplane")
	} else if err != nil {
		t.Fatalf("NewTransport() error")
	}

	// Sleep briefly to allow the go routines to get scheduled:
	// we want to at least run the code there to give us a chance
	// to trip over e.g. uninitialised fields
	time.Sleep(1 * time.Millisecond)

	xport.Close()
}

func TestSeqNumIncrement(t *testing.T) {
	cases := []struct {
		in, want uint16
	}{
		{uint16(0), uint16(1)},
		{uint16(65534), uint16(65535)},
		{uint16(65535), uint16(0)},
	}
	for _, c := range cases {
		got := seqIncrement(c.in)
		if got != c.want {
			t.Errorf("seqIncrement(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSeqNumCompare(t *testing.T) {
	cases := []struct {
		seq1, seq2 uint16
		want       int
	}{
		{uint16(15), uint16(15), 0},
		{uint16(15), uint16(0), 1},
		{uint16(15), uint16(65535), 1},
		{uint16(15), uint16(32784), 1},
		{uint16(15), uint16(16), -1},
		{uint16(15), uint16(15000), -1},
		{uint16(15), uint16(32783), -1},
	}
	for _, c := range cases {
		got := seqCompare(c.seq1, c.seq2)
		if got != c.want {
			t.Errorf("seqCompare(%d, %d) = %d, want %d", c.seq1, c.seq2, got, c.want)
		}
	}
}

func checkWindowOpen(ss *slowStartState, t *testing.T) {
	if !ss.canSend() {
		t.Fatalf("transport window is closed when we expect it to be open")
	}
}

func checkWindowClosed(ss *slowStartState, t *testing.T) {
	if ss.canSend() {
		t.Fatalf("transport window is open when we expect it to be closed")
	}
}

func checkCwndThresh(ss *slowStartState, cwnd, thresh uint16, t *testing.T) {
	if ss.cwnd != cwnd {
		t.Fatalf("transport window didn't correctly reset on retransmission: expected %d, got %d", cwnd, ss.cwnd)
	}
	if ss.thresh != thresh {
		t.Fatalf("transport threshold didn't correctly reset on retransmission: expected %d, got %d", thresh, ss.thresh)
	}
}

func TestSlowStart(t *testing.T) {
	txWindow := uint16(4)

	// initialise state and validate window is open
	ss := slowStartState{}
	ss.reset(txWindow)
	checkWindowOpen(&ss, t)

	// send a packet, validate window is now closed
	ss.onSend()
	checkWindowClosed(&ss, t)

	// ack the packet: should now be able to send two packets before window closes
	ss.onAck(txWindow)
	for i := 0; i < 2; i++ {
		checkWindowOpen(&ss, t)
		ss.onSend()
	}
	checkWindowClosed(&ss, t)

	// ack the two packets in flight: should now be able to send four packets
	for i := 0; i < 2; i++ {
		ss.onAck(txWindow)
	}
	for i := 0; i < 4; i++ {
		checkWindowOpen(&ss, t)
		ss.onSend()
	}
	checkWindowClosed(&ss, t)

	// ack the four packets in flight, validate the state hasn't exceeded the max window
	for i := 0; i < 4; i++ {
		ss.onAck(txWindow)
		checkWindowOpen(&ss, t)
		if ss.cwnd > txWindow {
			t.Fatalf("transport window %d exceeded max %d", ss.cwnd, txWindow)
		}
	}

	// retransmit: validate threshold is reduced and cwnd is reset
	checkWindowOpen(&ss, t)
	ss.onSend()
	ss.onRetransmit()
	checkWindowClosed(&ss, t)
	checkCwndThresh(&ss, 1, 2, t)

	// ack the retransmit, validate we're in slow-start still
	ss.onAck(txWindow)
	checkWindowOpen(&ss, t)
	checkCwndThresh(&ss, 2, 2, t)

	// send packets, recv acks, validate congestion avoidance is applied
	checkWindowOpen(&ss, t)
	ss.onSend()
	ss.onAck(txWindow)
	checkCwndThresh(&ss, 2, 2, t)
	for i := 0; i < 3; i++ {
		checkWindowOpen(&ss, t)
		ss.onSend()
		ss.onAck(txWindow)
		checkCwndThresh(&ss, 3, 2, t)
	}
	checkWindowOpen(&ss, t)
	ss.onSend()
	ss.onAck(txWindow)
	checkCwndThresh(&ss, 4, 2, t)

	// lots more transmission, validate we don't exceed max tx window in congestion avoidance
	for i := 0; i < 100; i++ {
		checkWindowOpen(&ss, t)
		ss.onSend()
		ss.onAck(txWindow)
		checkCwndThresh(&ss, 4, 2, t)
	}
}

type transportSendRecvTestInfo struct {
	local, peer      string
	config           TransportConfig
	sender, receiver func(xport *Transport) error
}

func transportTestNewTransport(local, peer string, cfg TransportConfig) (*Transport, error) {
	cp, err := newL2tpControlPlane(local, peer, EncapTypeUDP)
	if err != nil {
		return nil, fmt.Errorf("failed to create control plane: %v", err)
	}
	err = cp.Bind()
	if err != nil {
		return nil, fmt.Errorf("failed to bind control plane socket: %v", err)
	}
	err = cp.Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect control plane socket: %v", err)
	}
	return NewTransport(cp, cfg)
}

func testBasicSendRecvSenderNewHelloMsg(version ProtocolVersion) (msg ControlMessage, err error) {
	if version == ProtocolVersion2 {
		msg, err = NewV2ControlMessage(42, 0, []AVP{})
		if err != nil {
			return nil, err
		}
	} else if version == ProtocolVersion3 {
		msg, err = NewV3ControlMessage(42, []AVP{})
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("testBasicSendRecvSenderNewMsg: unhandled protocol version")
	}

	avp, err := NewAvp(VendorIDIetf, AvpTypeMessage, AvpMsgTypeHello)
	if err != nil {
		return nil, err
	}
	msg.Append(avp)

	return msg, nil
}

func testBasicSendRecvHelloSender(xport *Transport) error {
	// Send sufficient HELLO messages to exercise slowstart a bit
	for i := uint16(0); i < 3*xport.GetConfig().TxWindowSize; i++ {
		msg, err := testBasicSendRecvSenderNewHelloMsg(xport.GetConfig().Version)
		if err != nil {
			return fmt.Errorf("failed to build Hello message: %v", err)
		}
		err = xport.Send(msg)
		if err != nil {
			return fmt.Errorf("failed to send Hello message: %v", err)
		}
	}
	return nil
}

func testBasicSendRecvHelloReceiver(xport *Transport) error {
	for i := uint16(0); i < 3*xport.GetConfig().TxWindowSize; i++ {
		msg, err := xport.Recv()
		if err != nil {
			return fmt.Errorf("failed to receive message: %v", err)
		}
		if msg.Type() != AvpMsgTypeHello {
			return fmt.Errorf("expected message %v, got %v", AvpMsgTypeHello, msg.Type())
		}
	}
	return nil
}

func TestBasicSendReceive(t *testing.T) {
	cases := []transportSendRecvTestInfo{
		{
			local: "127.0.0.1:9000",
			peer:  "127.0.0.1:9001",
			config: TransportConfig{
				Version:    ProtocolVersion2,
				AckTimeout: 5 * time.Millisecond,
			},
			sender:   testBasicSendRecvHelloSender,
			receiver: testBasicSendRecvHelloReceiver,
		},
		{
			local: "[::1]:9000",
			peer:  "[::1]:9001",
			config: TransportConfig{
				Version:    ProtocolVersion2,
				AckTimeout: 5 * time.Millisecond,
			},
			sender:   testBasicSendRecvHelloSender,
			receiver: testBasicSendRecvHelloReceiver,
		},
		{
			local: "127.0.0.1:9000",
			peer:  "127.0.0.1:9001",
			config: TransportConfig{
				Version:    ProtocolVersion3,
				AckTimeout: 5 * time.Millisecond,
			},
			sender:   testBasicSendRecvHelloSender,
			receiver: testBasicSendRecvHelloReceiver,
		},
		{
			local: "[::1]:9000",
			peer:  "[::1]:9001",
			config: TransportConfig{
				Version:    ProtocolVersion3,
				AckTimeout: 5 * time.Millisecond,
			},
			sender:   testBasicSendRecvHelloSender,
			receiver: testBasicSendRecvHelloReceiver,
		},
	}
	for i, c := range cases {
		t.Run(
			fmt.Sprintf("%d: send/recv %s %s L2TPv%v", i, c.local, c.peer, c.config.Version),
			func(t *testing.T) {
				tx, err := transportTestNewTransport(c.local, c.peer, c.config)
				if err != nil {
					t.Fatalf("transportTestNewTransport(%v, %v, %v) said: %v",
						c.local,
						c.peer,
						c.config,
						err)
				}
				defer tx.Close()

				rx, err := transportTestNewTransport(c.peer, c.local, c.config)
				if err != nil {
					t.Fatalf("transportTestNewTransport(%v, %v, %v) said: %v",
						c.peer,
						c.local,
						c.config,
						err)
				}
				defer rx.Close()

				txCompletion := make(chan error)
				rxCompletion := make(chan error)

				go func() {
					txCompletion <- c.sender(tx)
				}()

				go func() {
					rxCompletion <- c.receiver(rx)
				}()

				err = <-txCompletion
				if err != nil {
					t.Errorf("test sender function reported an error: %v", err)
				}
				err = <-rxCompletion
				if err != nil {
					t.Errorf("test receiver function reported an error: %v", err)
				}
			})
	}
}
