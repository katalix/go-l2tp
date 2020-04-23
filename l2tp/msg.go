package l2tp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

// Message AVP specification as per RFCx
type avpSpec int
type msgSpec struct {
	m map[avpType]avpSpec
}

const (
	mustExist avpSpec = 1
	mayExist  avpSpec = 2
)

func (spec *msgSpec) hasAvp(t avpType) (avpSpec, bool) {
	as, ok := spec.m[t]
	return as, ok
}

func v2SccrqMsgSpec() *msgSpec {
	/* Ref: RFC2661 section 6.1 */
	spec := msgSpec{make(map[avpType]avpSpec)}

	spec.m[avpTypeMessage] = mustExist
	spec.m[avpTypeProtocolVersion] = mustExist
	spec.m[avpTypeHostName] = mustExist
	spec.m[avpTypeFramingCap] = mustExist
	spec.m[avpTypeTunnelID] = mustExist

	spec.m[avpTypeBearerCap] = mayExist
	spec.m[avpTypeRxWindowSize] = mayExist
	spec.m[avpTypeChallenge] = mayExist
	spec.m[avpTypeTiebreaker] = mayExist
	spec.m[avpTypeFirmwareRevision] = mayExist
	spec.m[avpTypeVendorName] = mayExist
	return &spec
}

func v2SccrpMsgSpec() *msgSpec {
	/* Ref: RFC2661 section 6.2 */
	spec := msgSpec{make(map[avpType]avpSpec)}

	spec.m[avpTypeMessage] = mustExist
	spec.m[avpTypeProtocolVersion] = mustExist
	spec.m[avpTypeFramingCap] = mustExist
	spec.m[avpTypeHostName] = mustExist
	spec.m[avpTypeTunnelID] = mustExist

	spec.m[avpTypeBearerCap] = mayExist
	spec.m[avpTypeRxWindowSize] = mayExist
	spec.m[avpTypeChallenge] = mayExist
	spec.m[avpTypeChallengeResponse] = mayExist
	spec.m[avpTypeTiebreaker] = mayExist
	spec.m[avpTypeFirmwareRevision] = mayExist
	spec.m[avpTypeVendorName] = mayExist
	return &spec
}

func v2ScccnMsgSpec() *msgSpec {
	/* Ref: RFC2661 section 6.3 */
	spec := msgSpec{make(map[avpType]avpSpec)}
	spec.m[avpTypeMessage] = mustExist
	spec.m[avpTypeChallengeResponse] = mayExist
	return &spec
}

func v2StopccnMsgSpec() *msgSpec {
	/* Ref: RFC2661 section 6.4 */
	spec := msgSpec{make(map[avpType]avpSpec)}
	spec.m[avpTypeMessage] = mustExist
	spec.m[avpTypeTunnelID] = mustExist
	spec.m[avpTypeResultCode] = mustExist
	return &spec
}

func v2HelloMsgSpec() *msgSpec {
	/* Ref: RFC2661 section 6.5 */
	spec := msgSpec{make(map[avpType]avpSpec)}
	spec.m[avpTypeMessage] = mustExist
	return &spec
}

func v2IcrqMsgSpec() *msgSpec {
	/* Ref: RFC2661 section 6.6 */
	spec := msgSpec{make(map[avpType]avpSpec)}
	spec.m[avpTypeMessage] = mustExist
	spec.m[avpTypeSessionID] = mustExist
	spec.m[avpTypeCallSerialNumber] = mustExist
	spec.m[avpTypeBearerType] = mayExist
	spec.m[avpTypePhysicalChannelID] = mayExist
	spec.m[avpTypeCallingNumber] = mayExist
	spec.m[avpTypeCalledNumber] = mayExist
	spec.m[avpTypeSubAddress] = mayExist
	return &spec
}

func v2IcrpMsgSpec() *msgSpec {
	/* Ref: RFC2661 section 6.7 */
	spec := msgSpec{make(map[avpType]avpSpec)}
	spec.m[avpTypeMessage] = mustExist
	spec.m[avpTypeSessionID] = mustExist
	return &spec
}

func v2IccnMsgSpec() *msgSpec {
	/* Ref: RFC2661 section 6.8 */
	spec := msgSpec{make(map[avpType]avpSpec)}
	spec.m[avpTypeMessage] = mustExist
	spec.m[avpTypeConnectSpeed] = mustExist
	spec.m[avpTypeFramingType] = mustExist
	spec.m[avpTypeInitialRcvdLcpConfreq] = mayExist
	spec.m[avpTypeLastSentLcpConfreq] = mayExist
	spec.m[avpTypeLastRcvdLcpConfreq] = mayExist
	spec.m[avpTypeProxyAuthType] = mayExist
	spec.m[avpTypeProxyAuthName] = mayExist
	spec.m[avpTypeProxyAuthChallenge] = mayExist
	spec.m[avpTypeProxyAuthID] = mayExist
	spec.m[avpTypeProxyAuthResponse] = mayExist
	spec.m[avpTypePrivGroupID] = mayExist
	spec.m[avpTypeRxConnectSpeed] = mayExist
	spec.m[avpTypeSequencingRequired] = mayExist
	return &spec
}

func v2CdnMsgSpec() *msgSpec {
	/* Ref: RFC2661 section 6.12 */
	spec := msgSpec{make(map[avpType]avpSpec)}
	spec.m[avpTypeMessage] = mustExist
	spec.m[avpTypeResultCode] = mustExist
	spec.m[avpTypeSessionID] = mustExist
	spec.m[avpTypeQ931CauseCode] = mayExist
	return &spec
}

func getV2MsgSpec(t avpMsgType) (*msgSpec, error) {
	switch t {
	case avpMsgTypeSccrq:
		return v2SccrqMsgSpec(), nil
	case avpMsgTypeSccrp:
		return v2SccrpMsgSpec(), nil
	case avpMsgTypeScccn:
		return v2ScccnMsgSpec(), nil
	case avpMsgTypeStopccn:
		return v2StopccnMsgSpec(), nil
	case avpMsgTypeHello:
		return v2HelloMsgSpec(), nil
	case avpMsgTypeIcrq:
		return v2IcrqMsgSpec(), nil
	case avpMsgTypeIcrp:
		return v2IcrpMsgSpec(), nil
	case avpMsgTypeIccn:
		return v2IccnMsgSpec(), nil
	case avpMsgTypeCdn:
		return v2CdnMsgSpec(), nil
	}
	return nil, fmt.Errorf("no specification for v2 message %v", t)
}

func v3HelloMsgSpec() *msgSpec {
	/* Ref: RFC3931 section 6.5 */
	spec := msgSpec{make(map[avpType]avpSpec)}
	spec.m[avpTypeMessage] = mustExist
	spec.m[avpTypeRandomVector] = mayExist
	spec.m[avpTypeMessageDigest] = mayExist
	return &spec
}

func getV3MsgSpec(t avpMsgType) (*msgSpec, error) {
	switch t {
	case avpMsgTypeHello:
		return v3HelloMsgSpec(), nil
	}
	return nil, fmt.Errorf("no specification for v3 message %v", t)
}

func (h *l2tpCommonHeader) protocolVersion() (version ProtocolVersion, err error) {
	switch h.FlagsVer & 0xf {
	case 2:
		return ProtocolVersion2, nil
	case 3:
		return ProtocolVersion3, nil
	}
	return 0, errors.New("illegal protocol version")
}

func validateAvps(avps []avp, spec *msgSpec) error {
	seen := make(map[avpType]bool)

	for at, as := range spec.m {
		if as == mustExist {
			seen[at] = false
		}
	}

	for _, avp := range avps {
		as, ok := spec.hasAvp(avp.getType())
		if !ok {
			// RFC2661 section 4.1 says we MUST tear down the tunnel on receipt of
			// an unrecognised AVP with the M bit set.
			// And we MUST ignore an unrecognised AVP with the M bit unset.
			if avp.isMandatory() {
				return fmt.Errorf("unexpected AVP %v", avp.getType())
			}
			continue
		}
		if as == mustExist {
			seen[avp.getType()] = true
		}
		_, err := avp.decode()
		if err != nil {
			return fmt.Errorf("failed to decode AVP %v: %v", avp.getType(), err)
		}
	}

	// ensure we saw all the AVPs we must have
	for at, ok := range seen {
		if !ok {
			return fmt.Errorf("missing mandatory AVP %v", at)
		}
	}

	return nil
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
		// so let's validate that now.
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
	// protocolVersion returns the protocol version for the control message.
	protocolVersion() ProtocolVersion
	// getLen returns the total control message length, including the header, in octets.
	getLen() int
	// ns returns the L2TP transport Ns value for the message.
	ns() uint16
	// nr returns the L2TP transport NR value for the message.
	nr() uint16
	// getAvps returns the slice of Attribute Value Pair (AVP) values held by the control message.
	getAvps() []avp
	// getType returns the value of the Message Type AVP.
	getType() avpMsgType
	// appendAvp appends an AVP to the message.
	appendAvp(avp *avp)
	// setTransportSeqNum sets the header sequence numbers.
	setTransportSeqNum(ns, nr uint16)
	// toBytes encodes the message as bytes for transmission.
	toBytes() ([]byte, error)
	// validate the message AVPs, checking that the mandatory AVPs are
	// present and contain the expected data.
	validate() error
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

func (m *v2ControlMessage) protocolVersion() ProtocolVersion {
	return ProtocolVersion2
}

func (m *v2ControlMessage) getLen() int {
	return int(m.header.Common.Len)
}

func (m *v2ControlMessage) ns() uint16 {
	return m.header.Ns
}

func (m *v2ControlMessage) nr() uint16 {
	return m.header.Nr
}

func (m *v2ControlMessage) getAvps() []avp {
	return m.avps
}

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

func (m *v2ControlMessage) Tid() uint16 {
	return m.header.Tid
}

func (m *v2ControlMessage) Sid() uint16 {
	return m.header.Sid
}

func (m *v2ControlMessage) appendAvp(avp *avp) {
	m.avps = append(m.avps, *avp)
	m.header.Common.Len += uint16(avp.totalLen())
}

func (m *v2ControlMessage) setTransportSeqNum(ns, nr uint16) {
	m.header.Ns = ns
	m.header.Nr = nr
}

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

func (m *v2ControlMessage) validate() error {
	spec, err := getV2MsgSpec(m.getType())
	if err != nil {
		return err
	}
	return validateAvps(m.avps, spec)
}

func (m *v3ControlMessage) protocolVersion() ProtocolVersion {
	return ProtocolVersion3
}

func (m *v3ControlMessage) getLen() int {
	return int(m.header.Common.Len)
}

func (m *v3ControlMessage) ns() uint16 {
	return m.header.Ns
}

func (m *v3ControlMessage) nr() uint16 {
	return m.header.Nr
}

func (m *v3ControlMessage) getAvps() []avp {
	return m.avps
}

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

func (m *v3ControlMessage) ControlConnectionID() uint32 {
	return m.header.Ccid
}

func (m *v3ControlMessage) appendAvp(avp *avp) {
	m.avps = append(m.avps, *avp)
	m.header.Common.Len += uint16(avp.totalLen())
}

func (m *v3ControlMessage) setTransportSeqNum(ns, nr uint16) {
	m.header.Ns = ns
	m.header.Nr = nr
}

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

func (m *v3ControlMessage) validate() error {
	spec, err := getV3MsgSpec(m.getType())
	if err != nil {
		return err
	}
	return validateAvps(m.avps, spec)
}

// parseMessageBuffer takes a byte slice of L2TP control message data and
// parses it into an array of controlMessage instances.
func parseMessageBuffer(b []byte) (messages []controlMessage, err error) {
	r := bytes.NewReader(b)
	for r.Len() >= controlMessageMinLen {
		var ver ProtocolVersion
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

		if ver == ProtocolVersion2 {
			var msg *v2ControlMessage
			if msg, err = bytesToV2CtlMsg(b[cursor : cursor+int64(h.Len)]); err != nil {
				return nil, err
			}
			messages = append(messages, msg)
		} else if ver == ProtocolVersion3 {
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
	return &v2ControlMessage{
		header: *newL2tpV2MessageHeader(uint16(tid), uint16(sid), 0, 0, avpsLengthBytes(avps)),
		avps:   avps,
	}, nil
}

type avpIn struct {
	typ  avpType
	data interface{}
}

func buildV2Msg(ptid ControlConnID, psid ControlConnID, in []avpIn) (msg *v2ControlMessage, err error) {
	msg, err = newV2ControlMessage(ptid, psid, []avp{})
	if err != nil {
		return
	}
	for _, i := range in {
		avp, err := newAvp(vendorIDIetf, i.typ, i.data)
		if err != nil {
			return nil, fmt.Errorf("failed to create AVP %v: %v", i.typ, err)
		}
		msg.appendAvp(avp)
	}
	return
}

// newV2Sccrq builds a new SCCRQ message
func newV2Sccrq(cfg *TunnelConfig) (msg *v2ControlMessage, err error) {
	/* RFC2661 says we MUST include:

	- Message Type
	- Protocol Version
	- Host Name
	- Framing Capabilities
	- Assigned Tunnel ID

	and we MAY include:

	- Bearer Capabilities
	- Receive Window Size
	- Challenge
	- Tie Breaker
	- Firmware Revision
	- Vendor Name
	*/
	in := []avpIn{
		{avpTypeMessage, avpMsgTypeSccrq},
		{avpTypeProtocolVersion, []byte{1, 0}},
		{avpTypeHostName, cfg.HostName},
		{avpTypeFramingCap, uint32(cfg.FramingCaps)},
		{avpTypeTunnelID, uint16(cfg.TunnelID)},
	}
	return buildV2Msg(0, 0, in)
}

// newV2Sccrp builds a new SCCRP message
func newV2Sccrp(cfg *TunnelConfig) (msg *v2ControlMessage, err error) {
	/* RFC2661 says we MUST include:

	- Message Type
	- Protocol Version
	- Framing Capabilities
	- Host Name
	- Assigned Tunnel ID

	and we MAY include:

	- Bearer Capabilities
	- Firmware Revision
	- Vendor Name
	- Receive Window Size
	- Challenge
	- Challenge Response
	*/
	in := []avpIn{
		{avpTypeMessage, avpMsgTypeSccrp},
		{avpTypeProtocolVersion, []byte{1, 0}},
		{avpTypeFramingCap, uint32(cfg.FramingCaps)},
		{avpTypeHostName, cfg.HostName},
		{avpTypeTunnelID, uint16(cfg.TunnelID)},
	}
	return buildV2Msg(cfg.PeerTunnelID, 0, in)
}

// newV2Scccn builds a new SCCCN message
func newV2Scccn(cfg *TunnelConfig) (msg *v2ControlMessage, err error) {
	/* RFC2661 says we MUST include:

	- Message Type

	and we MAY include:

	- Challenge response

	*/
	in := []avpIn{
		{avpTypeMessage, avpMsgTypeScccn},
	}
	return buildV2Msg(cfg.PeerTunnelID, 0, in)
}

// newV2Stopccn builds a new StopCCN message
func newV2Stopccn(rc *resultCode, cfg *TunnelConfig) (msg *v2ControlMessage, err error) {
	/* RFC2661 says we MUST include:

	- Message Type
	- Assigned Tunnel ID
	- Result Code

	*/
	in := []avpIn{
		{avpTypeMessage, avpMsgTypeStopccn},
		{avpTypeTunnelID, uint16(cfg.TunnelID)},
		{avpTypeResultCode, rc},
	}
	return buildV2Msg(cfg.PeerTunnelID, 0, in)
}

// newV2Hello builds a new HELLO message
func newV2Hello(cfg *TunnelConfig) (msg *v2ControlMessage, err error) {
	/* RFC2661 says we MUST include:

	- Message Type

	*/
	in := []avpIn{
		{avpTypeMessage, avpMsgTypeHello},
	}
	return buildV2Msg(cfg.PeerTunnelID, 0, in)
}

// newV2Icrq builds a new ICRQ message
func newV2Icrq(callSerial uint32, ptid ControlConnID, scfg *SessionConfig) (msg *v2ControlMessage, err error) {
	/* RFC2661 says we MUST include:

	- Message Type
	- Assigned Session ID
	- Call Serial Number

	and we MAY include:

	- Bearer Type
	- Physical Channel ID
	- Calling Number
	- Called Number
	- Sub-Address

	*/
	in := []avpIn{
		{avpTypeMessage, avpMsgTypeIcrq},
		{avpTypeSessionID, uint16(scfg.SessionID)},
		{avpTypeCallSerialNumber, callSerial},
	}
	return buildV2Msg(ptid, 0, in)
}

// newV2Iccn builds a new ICCN message
func newV2Iccn(ptid ControlConnID, scfg *SessionConfig) (msg *v2ControlMessage, err error) {
	/* RFC2661 says we MUST include:

		- Message Type
		- (Tx) Connect Speed
		- Framing Type

		and we MAY include:

	    - Initial Received LCP CONFREQ
	    - Last Sent LCP CONFREQ
	    - Last Received LCP CONFREQ
	    - Proxy Authen Type
	    - Proxy Authen Name
	    - Proxy Authen Challenge
	    - Proxy Authen ID
	    - Proxy Authen Response
	    - Private Group ID
	    - Rx Connect Speed
	    - Sequencing Required
	*/
	in := []avpIn{
		{avpTypeMessage, avpMsgTypeIccn},
		{avpTypeConnectSpeed, uint32(0)},                               // TODO: config field?
		{avpTypeFramingType, uint32(FramingCapSync | FramingCapAsync)}, // TODO: config field?
	}
	return buildV2Msg(ptid, scfg.PeerSessionID, in)
}

// newV2Cdn builds a new CDN message
func newV2Cdn(ptid ControlConnID, rc *resultCode, scfg *SessionConfig) (msg *v2ControlMessage, err error) {
	/* RFC2661 says we MUST include:

	- Message Type
	- Result Code
	- Assigned Session ID

	and we MAY include:

	- Q.931 Cause Code
	*/
	in := []avpIn{
		{avpTypeMessage, avpMsgTypeCdn},
		{avpTypeResultCode, rc},
		{avpTypeSessionID, uint16(scfg.SessionID)},
	}
	return buildV2Msg(ptid, scfg.PeerSessionID, in)
}

// newV3ControlMessage builds a new control message
func newV3ControlMessage(ccid ControlConnID, avps []avp) (msg *v3ControlMessage, err error) {
	return &v3ControlMessage{
		header: *newL2tpV3MessageHeader(uint32(ccid), 0, 0, avpsLengthBytes(avps)),
		avps:   avps,
	}, nil
}
