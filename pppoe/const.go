package pppoe

// PPPoECode indicates the PPPoE packet type.
type PPPoECode uint8

// PPPoESessionID, in combination with the peer's Ethernet addresses,
// uniquely identifies a given PPPoE session.
type PPPoESessionID uint16

// PPPoETagType identifies the tags contained in the data payload of
// PPPoE discovery packets.
type PPPoETagType uint16

// PPPoE packet codes.
const (
	// PPPoE Active Discovery Initiation packet
	PPPoECodePADI PPPoECode = 0x09
	// PPPoE Active Discovery Offer packet
	PPPoECodePADO PPPoECode = 0x07
	// PPPoE Active Discovery Request packet
	PPPoECodePADR PPPoECode = 0x19
	// PPPoE Active Discovery Session-confirmation packet
	PPPoECodePADS PPPoECode = 0x65
	// PPPoE Active Discovery Terminate packet
	PPPoECodePADT PPPoECode = 0xa7
)

// PPPoE Tag types.
//
// PPPoE packets may contain zero or more tags, which are
// TLV constructs.
const (
	PPPoETagTypeEOL              PPPoETagType = 0x0000
	PPPoETagTypeServiceName      PPPoETagType = 0x0101
	PPPoETagTypeACName           PPPoETagType = 0x0102
	PPPoETagTypeHostUniq         PPPoETagType = 0x0103
	PPPoETagTypeACCookie         PPPoETagType = 0x0104
	PPPoETagTypeVendorSpecific   PPPoETagType = 0x0105
	PPPoETagTypeRelaySessionID   PPPoETagType = 0x0110
	PPPoETagTypeServiceNameError PPPoETagType = 0x0201
	PPPoETagTypeACSystemError    PPPoETagType = 0x0202
	PPPoETagTypeGenericError     PPPoETagType = 0x0203
)

// internal constants
const (
	pppoePacketMinLength = 20 // raw packet: 14 bytes Ethernet header, 6 bytes PPPoE header
	pppoeTagMinLength    = 4  // bytes: 2 for type, 2 for length
)
