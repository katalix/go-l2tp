package pppoe

type PPPoECode uint8
type PPPoESessionID uint16
type PPPoETagType uint16

const EthTypePPPoEDiscovery = 0x8863

// discovery packet types
const (
	PPPoECodePADI PPPoECode = 0x09
	PPPoECodePADO PPPoECode = 0x07
	PPPoECodePADR PPPoECode = 0x19
	PPPoECodePADS PPPoECode = 0x65
	PPPoECodePADT PPPoECode = 0xa7
)

// tag types
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
