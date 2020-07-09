package pppoe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// PPPoETag represents the TLV data structures which make up
// the data payload of PPPoE discovery packets.
type PPPoETag struct {
	Type PPPoETagType
	Data []byte
}

// PPPoEPacket represents a PPPoE discovery packet.
type PPPoEPacket struct {
	// SrcHWAddr is the Ethernet address of the sender of the packet.
	SrcHWAddr [6]byte
	// DstHWAddr is the Ethernet address of the receiver of the packet.
	DstHWAddr [6]byte
	// Code is the code per RFC2516 which identifes the packet.
	Code PPPoECode
	// SessionID is the allocated session ID, once it has been set.
	// Up until that point in the discovery sequence the ID is zero.
	SessionID PPPoESessionID
	// Tags is the data payload of the packet.
	Tags []*PPPoETag
}

// String provides a human-readable representation of PPPoECode.
func (code PPPoECode) String() string {
	switch code {
	case PPPoECodePADI:
		return "PADI"
	case PPPoECodePADO:
		return "PADO"
	case PPPoECodePADR:
		return "PADR"
	case PPPoECodePADS:
		return "PADS"
	case PPPoECodePADT:
		return "PADT"
	}
	return "???"
}

// String provides a human-readable representation of PPPoETagType.
func (typ PPPoETagType) String() string {
	switch typ {
	case PPPoETagTypeEOL:
		return "EOL"
	case PPPoETagTypeServiceName:
		return "Service Name"
	case PPPoETagTypeACName:
		return "AC Name"
	case PPPoETagTypeHostUniq:
		return "Host Uniq"
	case PPPoETagTypeACCookie:
		return "AC Cookie"
	case PPPoETagTypeVendorSpecific:
		return "Vendor Specific"
	case PPPoETagTypeRelaySessionID:
		return "Relay Session ID"
	case PPPoETagTypeServiceNameError:
		return "Service Name Error"
	case PPPoETagTypeACSystemError:
		return "AC System Error"
	case PPPoETagTypeGenericError:
		return "Generic Error"
	default:
		return "Unknown"
	}
}

// String provides a human-readable representation of PPPoETag.
//
// For tags specified by the RFC to contain strings, a string representation
// of the tag data is rendered.  For all other tags a dump of the raw hex bytes
// is provided.
func (tag *PPPoETag) String() string {
	// Render string tag payloads as strings
	switch tag.Type {
	case PPPoETagTypeServiceName,
		PPPoETagTypeACName,
		PPPoETagTypeServiceNameError,
		PPPoETagTypeACSystemError,
		PPPoETagTypeGenericError:
		return fmt.Sprintf("%v: '%s'", tag.Type, string(tag.Data))
	}
	return fmt.Sprintf("%v: %#v", tag.Type, tag.Data)
}

// String provides a human-readable representation of PPPoEPacket.
func (packet *PPPoEPacket) String() string {
	s := fmt.Sprintf("%s: src %s, dst %s, session %v, tags:",
		packet.Code,
		fmt.Sprintf("0x%02x:%02x:%02x:%02x:%02x:%02x",
			packet.SrcHWAddr[0],
			packet.SrcHWAddr[1],
			packet.SrcHWAddr[2],
			packet.SrcHWAddr[3],
			packet.SrcHWAddr[4],
			packet.SrcHWAddr[5]),
		fmt.Sprintf("0x%02x:%02x:%02x:%02x:%02x:%02x",
			packet.DstHWAddr[0],
			packet.DstHWAddr[1],
			packet.DstHWAddr[2],
			packet.DstHWAddr[3],
			packet.DstHWAddr[4],
			packet.DstHWAddr[5]),
		packet.SessionID)
	for _, tag := range packet.Tags {
		s += fmt.Sprintf(" %s,", tag)
	}
	return s
}

// ethTypeDiscovery returns the Ethernet type for PPPoE
// discovery packets in host byte order.
func ethTypeDiscovery() uint16 {
	return 0x8863
}

// ethTypeDiscoveryNetBytes returns the Ethernet type for
// PPPoE discovery packets as a network byte order byte slice.
func ethTypeDiscoveryNetBytes() []byte {
	ethType := make([]byte, 2)
	binary.BigEndian.PutUint16(ethType, ethTypeDiscovery())
	return ethType
}

// ethTypeDiscoveryNetUint16 returns the Ethernet type for
// PPPoE discovery packets in network byte order.
func ethTypeDiscoveryNetUint16() uint16 {
	b := ethTypeDiscoveryNetBytes()
	return uint16(b[1])<<8 + uint16(b[0])
}

// NewPADI returns a PADI packet with the RFC-mandated service name
// tag included.
//
// PADI packets are used by the client to initiate the PPPoE discovery
// sequence.
//
// Clients which wish to use any service available should pass an empty
// string.
//
// PADI packets are sent to the Ethernet broadcast address, so only the
// source address must be specified.
func NewPADI(sourceHWAddr [6]byte, serviceName string) (packet *PPPoEPacket, err error) {
	packet = &PPPoEPacket{
		SrcHWAddr: sourceHWAddr,
		DstHWAddr: [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Code:      PPPoECodePADI,
		SessionID: 0,
	}
	err = packet.AddServiceNameTag(serviceName)
	if err != nil {
		return nil, err
	}
	return
}

// NewPADO returns a PADO packet with the RFC-mandated service name and
// AC name tags included.
//
// PADO packets are used by the server respond to a client's PADI.
func NewPADO(sourceHWAddr [6]byte, destHWAddr [6]byte, serviceName string, acName string) (packet *PPPoEPacket, err error) {
	packet = &PPPoEPacket{
		SrcHWAddr: sourceHWAddr,
		DstHWAddr: destHWAddr,
		Code:      PPPoECodePADO,
		SessionID: 0,
	}
	err = packet.AddServiceNameTag(serviceName)
	if err != nil {
		return nil, err
	}
	err = packet.AddACNameTag(acName)
	if err != nil {
		return nil, err
	}
	return
}

// NewPADR returns a PADR packet with the RFC-mandated service name
// tag included.
//
// PADR packets are used by the client to request a specific service from
// a server, based on a server's PADO.
//
// The service name tag should be derived from the PADO packet received
// from the server.
func NewPADR(sourceHWAddr [6]byte, destHWAddr [6]byte, serviceName string) (packet *PPPoEPacket, err error) {
	packet = &PPPoEPacket{
		SrcHWAddr: sourceHWAddr,
		DstHWAddr: destHWAddr,
		Code:      PPPoECodePADR,
		SessionID: 0,
	}
	err = packet.AddServiceNameTag(serviceName)
	if err != nil {
		return nil, err
	}
	return
}

// NewPADS returns a PADS packet including an allocated session ID and the
// RFC-mandated service name tag.
//
// PADS packets are used by the server to respond to a client's PADR.  They
// represent the completion of the PPPoE discovery sequence, and may indicate
// either success or failure to establish the connection.
//
// If the PADS packet indicates success, the session ID should be a non-zero
// value which is unique for the PPPoE peers.
//
// If the PADS packet indicates failure, the session ID should be zero, and
// the packet should have the PPPoETagTypeServiceNameError tag appended.
func NewPADS(sourceHWAddr [6]byte, destHWAddr [6]byte, serviceName string, sid PPPoESessionID) (packet *PPPoEPacket, err error) {
	packet = &PPPoEPacket{
		SrcHWAddr: sourceHWAddr,
		DstHWAddr: destHWAddr,
		Code:      PPPoECodePADS,
		SessionID: sid,
	}
	err = packet.AddServiceNameTag(serviceName)
	if err != nil {
		return nil, err
	}
	return
}

// NewPADT returns a PADT packet for the specified session ID.
//
// PADT packets are used by either client or server to terminate the PPPoE
// connection once established.
func NewPADT(sourceHWAddr [6]byte, destHWAddr [6]byte, sid PPPoESessionID) (packet *PPPoEPacket, err error) {
	return &PPPoEPacket{
		SrcHWAddr: sourceHWAddr,
		DstHWAddr: destHWAddr,
		Code:      PPPoECodePADT,
		SessionID: sid,
	}, nil
}

// pppoeHeader is the on-the-wire structure which we use for parsing
// raw data buffers received on a connection.
type pppoeHeader struct {
	// Ethernet header
	DstHWAddr [6]byte
	SrcHWAddr [6]byte
	EtherType uint16
	// PPPoE header
	VerType   uint8
	Code      uint8
	SessionID uint16
	Length    uint16
}

func findTag(typ PPPoETagType, tags []*PPPoETag) (tag *PPPoETag, err error) {
	for _, tag = range tags {
		if tag.Type == typ {
			return tag, nil
		}
	}
	return nil, fmt.Errorf("no tag %v found", typ)
}

// packetSpec is used to define the requirements of each PPPoE packet
// as per RFC2516, allowing packets to be validated on receipt and prior
// to transmission.
type packetSpec struct {
	zeroSessionID bool
	mandatoryTags []PPPoETagType
}

// Validate validates a packet meets the requirements of RFC2516, checking
// the mandatory tags are included and the session ID is set correctly.
func (packet *PPPoEPacket) Validate() (err error) {
	specMap := map[PPPoECode]*packetSpec{
		PPPoECodePADI: &packetSpec{
			zeroSessionID: true,
			mandatoryTags: []PPPoETagType{PPPoETagTypeServiceName},
		},
		PPPoECodePADO: &packetSpec{
			zeroSessionID: true,
			mandatoryTags: []PPPoETagType{PPPoETagTypeServiceName, PPPoETagTypeACName},
		},
		PPPoECodePADR: &packetSpec{
			zeroSessionID: true,
			mandatoryTags: []PPPoETagType{PPPoETagTypeServiceName},
		},
		// PPPoECodePADS is a special case :-|
		PPPoECodePADT: &packetSpec{
			zeroSessionID: false,
		},
	}
	var spec *packetSpec
	var tags []*PPPoETag
	var ok bool

	if spec, ok = specMap[packet.Code]; !ok {
		// PADS is a special case: its mandatory tag list varies depending on whether
		// the access concentrator likes the service name in the PADR or not.  The session
		// ID is used to determine whether it's the happy or sad path: session ID of zero
		// is used in the sad path.
		if packet.Code == PPPoECodePADS {
			if packet.SessionID == 0 {
				spec = &packetSpec{
					zeroSessionID: true,
					mandatoryTags: []PPPoETagType{PPPoETagTypeServiceNameError},
				}
			} else {
				spec = &packetSpec{
					zeroSessionID: false,
					mandatoryTags: []PPPoETagType{PPPoETagTypeServiceName},
				}
			}
		} else {
			return fmt.Errorf("unrecognised packet code %v", packet.Code)
		}
	}

	if spec.zeroSessionID {
		if packet.SessionID != 0 {
			return fmt.Errorf("nonzero session ID in %v; must have zero", packet.Code)
		}
	} else {
		if packet.SessionID == 0 {
			return fmt.Errorf("zero session ID in %v; must have nonzero", packet.Code)
		}
	}

	if len(packet.Tags) < len(spec.mandatoryTags) {
		return fmt.Errorf("expect minimum of %d tags in %v; only got %d",
			len(spec.mandatoryTags), packet.Code, len(tags))
	}

	for _, tagType := range spec.mandatoryTags {
		_, err := findTag(tagType, packet.Tags)
		if err != nil {
			return fmt.Errorf("missing mandatory tag %v in %v", tagType, packet.Code)
		}
	}
	return nil
}

func newTagListFromBuffer(buf []byte) (tags []*PPPoETag, err error) {
	r := bytes.NewReader(buf)
	for r.Len() >= pppoeTagMinLength {
		var cursor int64
		var hdr pppoeTagHeader

		if cursor, err = r.Seek(0, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("failed to determine tag buffer offset: %v", err)
		}

		if err = binary.Read(r, binary.BigEndian, &hdr); err != nil {
			return nil, err
		}

		if int(hdr.Length) > r.Len() {
			return nil, fmt.Errorf("malformed tag: length %d exceeds buffer bounds of %d", hdr.Length, r.Len())
		}

		tags = append(tags, &PPPoETag{
			Type: hdr.Type,
			Data: buf[cursor+pppoeTagMinLength : cursor+pppoeTagMinLength+int64(hdr.Length)],
		})

		if _, err := r.Seek(int64(hdr.Length), io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("malformed tag buffer: invalid length for current tag")
		}
	}
	return
}

func newPacketFromBuffer(hdr *pppoeHeader, payload []byte) (packet *PPPoEPacket, err error) {

	// make sure we recognise the packet type
	switch PPPoECode(hdr.Code) {
	case PPPoECodePADI:
	case PPPoECodePADO:
	case PPPoECodePADR:
	case PPPoECodePADS:
	case PPPoECodePADT:
	default:
		return nil, fmt.Errorf("unrecognised packet code %x", hdr.Code)
	}

	tags, err := newTagListFromBuffer(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse packet tags: %v", err)
	}

	packet = &PPPoEPacket{
		SrcHWAddr: hdr.SrcHWAddr,
		DstHWAddr: hdr.DstHWAddr,
		Code:      PPPoECode(hdr.Code),
		SessionID: PPPoESessionID(hdr.SessionID),
		Tags:      tags,
	}

	err = packet.Validate()
	if err != nil {
		return nil, fmt.Errorf("failed to validate packet: %v", err)
	}

	return
}

// ParsePacketBuffer parses a raw received frame into one or more PPPoE
// packets.
func ParsePacketBuffer(b []byte) (packets []*PPPoEPacket, err error) {
	r := bytes.NewReader(b)
	for r.Len() >= pppoePacketMinLength {
		var cursor int64
		var hdr pppoeHeader

		if cursor, err = r.Seek(0, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("failed to determine packet buffer offset: %v", err)
		}

		if err = binary.Read(r, binary.BigEndian, &hdr); err != nil {
			return nil, err
		}

		if int(hdr.Length) > r.Len() {
			return nil, fmt.Errorf("malformed packet: length %d exceeds buffer bounds of %d", hdr.Length, r.Len())
		}

		// Silently ignore packets which are not PPPoE discovery packets
		if hdr.EtherType == ethTypeDiscovery() {
			packet, err := newPacketFromBuffer(&hdr, b[cursor+pppoePacketMinLength:cursor+pppoePacketMinLength+int64(hdr.Length)])
			if err != nil {
				return nil, fmt.Errorf("failed to parse packet: %v", err)
			}
			packets = append(packets, packet)
		}

		if _, err := r.Seek(int64(hdr.Length), io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("malformed packet buffer: invalid length for current tag")
		}
	}
	return
}

func newTag(typ PPPoETagType, length int, data []byte) *PPPoETag {
	return &PPPoETag{
		Type: typ,
		Data: data,
	}
}

func (tag *PPPoETag) toBytes() (encoded []byte, err error) {
	encBuf := new(bytes.Buffer)

	err = binary.Write(encBuf, binary.BigEndian, tag.Type)
	if err != nil {
		return nil, fmt.Errorf("unable to write tag type: %v", err)
	}

	err = binary.Write(encBuf, binary.BigEndian, uint16(len(tag.Data)))
	if err != nil {
		return nil, fmt.Errorf("unable to write tag length: %v", err)
	}

	_, _ = encBuf.Write(tag.Data)

	return encBuf.Bytes(), nil
}

func (packet *PPPoEPacket) appendTag(tag *PPPoETag) (err error) {
	packet.Tags = append(packet.Tags, tag)
	return
}

// GetTag searches a packet's tags to find one of the specified type.
//
// The first tag matching the specified type is returned on success.
func (packet *PPPoEPacket) GetTag(typ PPPoETagType) (tag *PPPoETag, err error) {
	return findTag(typ, packet.Tags)
}

// AddServiceNameTag adds a service name tag to the packet.
// The service name is an arbitrary string.
func (packet *PPPoEPacket) AddServiceNameTag(name string) (err error) {
	return packet.appendTag(newTag(PPPoETagTypeServiceName, len(name), []byte(name)))
}

// AddACNameTag adds an access concentrator name tag to the packet.
// The AC name is an arbitrary string.
func (packet *PPPoEPacket) AddACNameTag(name string) (err error) {
	return packet.appendTag(newTag(PPPoETagTypeACName, len(name), []byte(name)))
}

// AddHostUniqTag adds a host unique tag to the packet.
// The host unique value is an arbitrary byte slice which is used by
// the client to associate a given response (PADO or PADS) to a particular
// request (PADI or PADR).
func (packet *PPPoEPacket) AddHostUniqTag(hostUniq []byte) (err error) {
	return packet.appendTag(newTag(PPPoETagTypeHostUniq, len(hostUniq), hostUniq))
}

// AddACCookieTag adds an access concentrator cookie tag to the packet.
// The AC cookie value is an arbitrary byte slice which is used by the
// access concentrator to aid in protecting against DoS attacks.
// Refer to RFC2516 for details.
func (packet *PPPoEPacket) AddACCookieTag(cookie []byte) (err error) {
	return packet.appendTag(newTag(PPPoETagTypeACCookie, len(cookie), cookie))
}

// AddServiceNameErrorTag adds a service name error tag to the packet.
// The value may be an empty string, but should preferably be a human-readable
// string explaining why the request was denied.
func (packet *PPPoEPacket) AddServiceNameErrorTag(reason string) (err error) {
	return packet.appendTag(newTag(PPPoETagTypeServiceNameError, len(reason), []byte(reason)))
}

// AddACSystemErrorTag adds an access concentrator system error tag to the packet.
// The value may be an empty string, but should preferably be a human-readable
// string explaining the nature of the error.
func (packet *PPPoEPacket) AddACSystemErrorTag(reason string) (err error) {
	return packet.appendTag(newTag(PPPoETagTypeACSystemError, len(reason), []byte(reason)))
}

// AddGenericErrorTag adds an generic error tag to the packet.
// The value may be an empty string, but should preferably be a human-readable
// string explaining the nature of the error.
func (packet *PPPoEPacket) AddGenericErrorTag(reason string) (err error) {
	return packet.appendTag(newTag(PPPoETagTypeGenericError, len(reason), []byte(reason)))
}

// AddTag adds a generic tag to the packet.
// The caller is responsible for ensuring that the data type matches the tag type.
func (packet *PPPoEPacket) AddTag(typ PPPoETagType, data []byte) (err error) {
	return packet.appendTag(newTag(typ, len(data), data))
}

func (packet *PPPoEPacket) tagListBytes() (encoded []byte, err error) {
	encBuf := new(bytes.Buffer)
	for _, tag := range packet.Tags {
		encodedTag, err := tag.toBytes()
		if err != nil {
			return nil, fmt.Errorf("failed to encode tag %v: %v", tag, err)
		}
		_, _ = encBuf.Write(encodedTag)
	}
	return encBuf.Bytes(), nil
}

// ToBytes renders the PPPoE packet to a byte slice ready for transmission
// over a PPPoEConn connection.
//
// Prior to calling ToBytes a packet should ideally be validated using Validate
// to ensure it adheres to the RFC requirements.
func (packet *PPPoEPacket) ToBytes() (encoded []byte, err error) {
	encBuf := new(bytes.Buffer)

	encodedTags, err := packet.tagListBytes()
	if err != nil {
		return nil, err
	}

	// bytes.Buffer.Write always returns a nil error

	// Ethernet header: dst, src, type
	_, _ = encBuf.Write(packet.DstHWAddr[:])
	_, _ = encBuf.Write(packet.SrcHWAddr[:])
	_, _ = encBuf.Write(ethTypeDiscoveryNetBytes())

	// PPPoE header: VerType, code, session ID, length, payload
	_, _ = encBuf.Write([]byte{0x11})
	_, _ = encBuf.Write([]byte{byte(packet.Code)})
	err = binary.Write(encBuf, binary.BigEndian, packet.SessionID)
	if err != nil {
		return nil, fmt.Errorf("unable to write session ID: %v", err)
	}
	err = binary.Write(encBuf, binary.BigEndian, uint16(len(encodedTags)))
	if err != nil {
		return nil, fmt.Errorf("unable to write data length: %v", err)
	}
	_, _ = encBuf.Write(encodedTags)

	return encBuf.Bytes(), nil
}

type pppoeTagHeader struct {
	Type   PPPoETagType
	Length uint16
}
