package l2tp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/katalix/l2tp/internal/nll2tp"
)

// L2TPv2 and L2TPv3 headers have these fields in common
type l2tpCommonHeader struct {
	FlagsVer uint16
	Len      uint16
}

// L2TPv2 control message header per RFC2661
type l2tpV2Header struct {
	Common l2tpCommonHeader
	Tid    uint16
	Sid    uint16
	Ns     uint16
	Nr     uint16
}

// L2TPv3 control message header per RFC3931
type l2tpV3Header struct {
	Common l2tpCommonHeader
	Ccid   uint32
	Ns     uint16
	Nr     uint16
}

const (
	controlMessageMinLen = 12
	controlMessageMaxLen = ^uint16(0)
	commonHeaderLen      = 4
	v2HeaderLen          = 12
	v3HeaderLen          = 12
)

func (h *l2tpCommonHeader) protocolVersion() (version nll2tp.L2tpProtocolVersion, err error) {
	switch h.FlagsVer & 0xf {
	case 2:
		return nll2tp.ProtocolVersion2, nil
	case 3:
		return nll2tp.ProtocolVersion3, nil
	}
	return 0, errors.New("illegal protocol version")
}

func newL2tpV2MessageHeader(tid, sid, ns, nr uint16, payloadBytes int) *l2tpV2Header {
	return &l2tpV2Header{
		Common: l2tpCommonHeader{
			FlagsVer: 0xc802,
			Len:      uint16(v2HeaderLen + payloadBytes),
		},
		Tid: tid,
		Sid: sid,
		Ns:  ns,
		Nr:  nr,
	}
}

func newL2tpV3MessageHeader(ccid uint32, ns, nr uint16, payloadBytes int) *l2tpV3Header {
	return &l2tpV3Header{
		Common: l2tpCommonHeader{
			FlagsVer: 0xc803,
			Len:      uint16(v3HeaderLen + payloadBytes),
		},
		Ccid: ccid,
		Ns:   ns,
		Nr:   nr,
	}
}

func bytesToV2CtlMsg(b []byte) (msg *v2ControlMessage, err error) {
	var hdr l2tpV2Header
	var avps []avp

	r := bytes.NewReader(b)
	if err = binary.Read(r, binary.BigEndian, &hdr); err != nil {
		return nil, err
	}

	// Messages with no AVP payload are treated as ZLB (zero-length-body) ack messages,
	// so they're valid L2TPv2 messages.  Don't try to parse the AVP payload in this case.
	if hdr.Common.Len > v2HeaderLen {
		if avps, err = parseAVPBuffer(b[v2HeaderLen:hdr.Common.Len]); err != nil {
			return nil, err
		}
		// RFC2661 says the first AVP in the message MUST be the Message Type AVP,
		// so let's validate that now
		// TODO: we need to do real actual validation
		if avps[0].getType() != avpTypeMessage {
			return nil, errors.New("invalid L2TPv2 message: first AVP is not Message Type AVP")
		}
	}

	return &v2ControlMessage{
		header: hdr,
		avps:   avps,
	}, nil
}

func bytesToV3CtlMsg(b []byte) (msg *v3ControlMessage, err error) {
	var hdr l2tpV3Header
	var avps []avp

	r := bytes.NewReader(b)
	if err = binary.Read(r, binary.BigEndian, &hdr); err != nil {
		return nil, err
	}

	if avps, err = parseAVPBuffer(b[v3HeaderLen:hdr.Common.Len]); err != nil {
		return nil, err
	}

	// RFC3931 says the first AVP in the message MUST be the Message Type AVP,
	// so let's validate that now
	if avps[0].getType() != avpTypeMessage {
		return nil, errors.New("invalid L2TPv3 message: first AVP is not Message Type AVP")
	}

	return &v3ControlMessage{
		header: hdr,
		avps:   avps,
	}, nil
}

// controlMessage is an interface representing a generic L2TP
// control message, providing access to the fields that are common
// to both v2 and v3 versions of the protocol.
type controlMessage interface {
	protocolVersion() nll2tp.L2tpProtocolVersion
	getLen() int
	ns() uint16
	nr() uint16
	getAvps() []avp
	getType() avpMsgType
	appendAvp(avp *avp)
	setTransportSeqNum(ns, nr uint16)
	toBytes() ([]byte, error)
}

// v2ControlMessage represents an RFC2661 control message
type v2ControlMessage struct {
	header l2tpV2Header
	avps   []avp
}

// v3ControlMessage represents an RFC3931 control message
type v3ControlMessage struct {
	header l2tpV3Header
	avps   []avp
}

// protocolVersion returns the protocol version for the control message.
// Implements the ControlMessage interface.
func (m *v2ControlMessage) protocolVersion() nll2tp.L2tpProtocolVersion {
	return nll2tp.ProtocolVersion2
}

// getLen returns the total control message length, including the header, in octets.
// Implements the ControlMessage interface.
func (m *v2ControlMessage) getLen() int {
	return int(m.header.Common.Len)
}

// ns returns the L2TP transport Ns value for the message.
// Implements the ControlMessage interface.
func (m *v2ControlMessage) ns() uint16 {
	return m.header.Ns
}

// nr returns the L2TP transport NR value for the message.
// Implements the ControlMessage interface.
func (m *v2ControlMessage) nr() uint16 {
	return m.header.Nr
}

// getAvps returns the slice of Attribute Value Pair (AVP) values held by the control message.
// Implements the ControlMessage interface.
func (m *v2ControlMessage) getAvps() []avp {
	return m.avps
}

// getType returns the value of the Message Type AVP.
// Implements the ControlMessage interface.
func (m v2ControlMessage) getType() avpMsgType {
	// Messages with no AVP payload are treated as ZLB (zero-length-body)
	// ack messages in RFC2661.  Strictly speaking ZLBs have no message type,
	// so we (ab)use the L2TPv3 AvpMsgTypeAck for that scenario.
	if len(m.getAvps()) == 0 {
		return avpMsgTypeAck
	}

	avp := m.getAvps()[0]

	// c.f. newv2ControlMessage: we've validated this condition at message
	// creation time, so this is just a belt/braces assertation to catch
	// programming errors during development
	if avp.getType() != avpTypeMessage {
		panic("Invalid L2TPv2 message")
	}

	mt, err := avp.decodeMsgType()
	if err != nil {
		panic(fmt.Sprintf("Failed to decode AVP message type: %v", err))
	}
	return mt
}

// Tid returns the L2TPv2 tunnel ID held by the control message header.
func (m *v2ControlMessage) Tid() uint16 {
	return m.header.Tid
}

// Sid returns the L2TPv2 session ID held by the control message header.
func (m *v2ControlMessage) Sid() uint16 {
	return m.header.Sid
}

// appendAvp appends an AVP to the message.
func (m *v2ControlMessage) appendAvp(avp *avp) {
	m.avps = append(m.avps, *avp)
	m.header.Common.Len += uint16(avp.totalLen())
}

// setTransportSeqNum sets the header sequence numbers.
func (m *v2ControlMessage) setTransportSeqNum(ns, nr uint16) {
	m.header.Ns = ns
	m.header.Nr = nr
}

// toBytes encodes the message as bytes for transmission
func (m *v2ControlMessage) toBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, m.header); err != nil {
		return nil, err
	}

	for _, avp := range m.avps {
		if err := binary.Write(buf, binary.BigEndian, avp.header); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, avp.payload.data); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// protocolVersion returns the protocol version for the control message.
// Implements the ControlMessage interface.
func (m *v3ControlMessage) protocolVersion() nll2tp.L2tpProtocolVersion {
	return nll2tp.ProtocolVersion3
}

// getLen returns the total control message length, including the header, in octets.
// Implements the ControlMessage interface.
func (m *v3ControlMessage) getLen() int {
	return int(m.header.Common.Len)
}

// ns returns the L2TP transport Ns value for the message.
// Implements the ControlMessage interface.
func (m *v3ControlMessage) ns() uint16 {
	return m.header.Ns
}

// nr returns the L2TP transport Nr value for the message.
// Implements the ControlMessage interface.
func (m *v3ControlMessage) nr() uint16 {
	return m.header.Nr
}

// getAvps returns the slice of Attribute Value Pair (AVP) values held by the control message.
// Implements the ControlMessage interface.
func (m *v3ControlMessage) getAvps() []avp {
	return m.avps
}

// getType returns the value of the Message Type AVP.
// Implements the ControlMessage interface.
func (m v3ControlMessage) getType() avpMsgType {
	avp := m.getAvps()[0]

	// c.f. bytesToV2CtlMsg: we've validated this condition at message
	// creation time, so this is just a belt/braces assertation to catch
	// programming errors during development
	if avp.getType() != avpTypeMessage {
		panic("Invalid L2TPv3 message")
	}

	mt, err := avp.decodeMsgType()
	if err != nil {
		panic(fmt.Sprintf("Failed to decode AVP message type: %v", err))
	}
	return mt
}

// ControlConnectionID returns the control connection ID held by the control message header.
func (m *v3ControlMessage) ControlConnectionID() uint32 {
	return m.header.Ccid
}

// appendAvp appends an AVP to the message.
func (m *v3ControlMessage) appendAvp(avp *avp) {
	m.avps = append(m.avps, *avp)
	m.header.Common.Len += uint16(avp.totalLen())
}

// setTransportSeqNum sets the header sequence numbers.
func (m *v3ControlMessage) setTransportSeqNum(ns, nr uint16) {
	m.header.Ns = ns
	m.header.Nr = nr
}

// toBytes encodes the message as bytes for transmission
func (m *v3ControlMessage) toBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, m.header); err != nil {
		return nil, err
	}

	for _, avp := range m.avps {
		if err := binary.Write(buf, binary.BigEndian, avp.header); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, avp.payload.data); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// parseMessageBuffer takes a byte slice of L2TP control message data and
// parses it into an array of controlMessage instances.
func parseMessageBuffer(b []byte) (messages []controlMessage, err error) {
	r := bytes.NewReader(b)
	for r.Len() >= controlMessageMinLen {
		var ver nll2tp.L2tpProtocolVersion
		var h l2tpCommonHeader
		var cursor int64

		if cursor, err = r.Seek(0, io.SeekCurrent); err != nil {
			return nil, errors.New("malformed message buffer: unable to determine current offset")
		}

		// Read the common part of the header: this will tell us the
		// protocol version and the length of the complete frame
		if err := binary.Read(r, binary.BigEndian, &h); err != nil {
			return nil, err
		}

		// Throw out malformed packets
		if int(h.Len-commonHeaderLen) > r.Len() {
			return nil, fmt.Errorf("malformed header: length %d exceeds buffer bounds of %d", h.Len, r.Len())
		}

		// Figure out the protocol version, and read the message
		if ver, err = h.protocolVersion(); err != nil {
			return nil, err
		}

		if ver == nll2tp.ProtocolVersion2 {
			var msg *v2ControlMessage
			if msg, err = bytesToV2CtlMsg(b[cursor : cursor+int64(h.Len)]); err != nil {
				return nil, err
			}
			messages = append(messages, msg)
		} else if ver == nll2tp.ProtocolVersion3 {
			var msg *v3ControlMessage
			if msg, err = bytesToV3CtlMsg(b[cursor : cursor+int64(+h.Len)]); err != nil {
				return nil, err
			}
			messages = append(messages, msg)
		} else {
			panic("Unhandled protocol version")
		}

		// Step on to the next message in the buffer, if any
		if _, err := r.Seek(int64(h.Len), io.SeekCurrent); err != nil {
			return nil, errors.New("malformed message buffer: invalid length for current message")
		}
	}
	return messages, nil
}

// newV2ControlMessage builds a new control message
func newV2ControlMessage(tid ControlConnID, sid ControlConnID, avps []avp) (msg *v2ControlMessage, err error) {
	if tid > v2TidSidMax {
		return nil, fmt.Errorf("v2 tunnel ID %v out of range", tid)
	}
	if sid > v2TidSidMax {
		return nil, fmt.Errorf("v2 session ID %v out of range", sid)
	}
	// TODO: validate AVPs
	return &v2ControlMessage{
		header: *newL2tpV2MessageHeader(uint16(tid), uint16(sid), 0, 0, avpsLengthBytes(avps)),
		avps:   avps,
	}, nil
}

// newV3ControlMessage builds a new control message
func newV3ControlMessage(ccid ControlConnID, avps []avp) (msg *v3ControlMessage, err error) {
	// TODO: validate AVPs
	return &v3ControlMessage{
		header: *newL2tpV3MessageHeader(uint32(ccid), 0, 0, avpsLengthBytes(avps)),
		avps:   avps,
	}, nil
}
