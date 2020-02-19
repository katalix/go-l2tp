package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

type avpFlagLen uint16

// AVPVendorID is the Vendor ID from the AVP header as per RFC2661 section 4.1
type AVPVendorID uint16

// AVPType is the attribute type from the AVP header as per RFC2661 section 4.1
type AVPType uint16

// AVPMsgType stores the value of the Message Type AVP
type AVPMsgType uint16

// AVPDataType indicates the type of the data value carried by the AVP
type AVPDataType int

type avpInfo struct {
	avpType     AVPType
	VendorID    AVPVendorID
	isMandatory bool
	dataType    AVPDataType
}

// Don't be tempted to try to make the fields in this structure private:
// doing so breaks the reflection properties which binary.Read depends upon
// for extracting the header from the bytearray.
type avpHeader struct {
	FlagLen  avpFlagLen
	VendorID AVPVendorID
	AvpType  AVPType
}

type avpPayload struct {
	dataType AVPDataType
	data     []byte
}

// AVP represents a single AVP in an L2TP control message
type AVP struct {
	header  avpHeader
	payload avpPayload
}

const (
	avpHeaderLen = 6
	// VendorIDIetf is the namespace used for standard AVPS described
	// by RFC2661 and RFC3931.
	VendorIDIetf = 0
)

const (
	// AvpDataTypeEmpty represents an AVP with no value
	AvpDataTypeEmpty = iota
	// AvpDataTypeUint8 represents an AVP carrying a single uint8 value
	AvpDataTypeUint8
	// AvpDataTypeUint16 represents an AVP carrying a single uint16 value
	AvpDataTypeUint16
	// AvpDataTypeUint32 represents an AVP carrying a single uint32 value
	AvpDataTypeUint32
	// AvpDataTypeUint64 represents an AVP carrying a single uint64 value
	AvpDataTypeUint64
	// AvpDataTypeString represents an AVP carrying an ASCII string
	AvpDataTypeString
	// AvpDataTypeBytes represents an AVP carrying a raw byte array
	AvpDataTypeBytes
	// AvpDataTypeUnimplemented represents an AVP carrying a currently unimplemented data type
	AvpDataTypeUnimplemented
	// AvpDataTypeIllegal represents an AVP carrying an illegal data type.
	// AVPs falling into this category are typically those with currently
	// reserved IDs as per the RFCs.
	AvpDataTypeIllegal
)

var avpInfoTable = [...]avpInfo{
	{avpType: AvpTypeMessage, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUint16},
	{avpType: AvpTypeResultCode, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUnimplemented}, // TODO
	{avpType: AvpTypeProtocolVersion, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeBytes},
	{avpType: AvpTypeFramingCap, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUint32},
	{avpType: AvpTypeBearerCap, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUint32},
	{avpType: AvpTypeTiebreaker, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUnimplemented}, // TODO
	{avpType: AvpTypeFirmwareRevision, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUint16},
	{avpType: AvpTypeHostName, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeString},
	{avpType: AvpTypeVendorName, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeString},
	{avpType: AvpTypeTunnelID, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUint16},
	{avpType: AvpTypeRxWindowSize, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUint16},
	{avpType: AvpTypeChallenge, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeBytes},
	{avpType: AvpTypeQ931CauseCode, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUnimplemented}, // TODO
	{avpType: AvpTypeChallengeResponse, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeBytes},
	{avpType: AvpTypeSessionID, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUint16},
	{avpType: AvpTypeCallSerialNumber, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUint32},
	{avpType: AvpTypeMinimumBps, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUint32},
	{avpType: AvpTypeMaximumBps, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUint32},
	{avpType: AvpTypeBearerType, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUint32},
	{avpType: AvpTypeFramingType, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUint32},
	{avpType: AvpTypePacketProcDelay, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUnimplemented}, // TODO
	{avpType: AvpTypeCalledNumber, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeString},
	{avpType: AvpTypeCallingNumber, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeString},
	{avpType: AvpTypeSubAddress, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeString},
	{avpType: AvpTypeConnectSpeed, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUint32},
	{avpType: AvpTypePhysicalChannelID, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUint32},
	{avpType: AvpTypeInitialRcvdLcpConfreq, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeBytes},
	{avpType: AvpTypeLastSentLcpConfreq, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeBytes},
	{avpType: AvpTypeLastRcvdLcpConfreq, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeBytes},
	{avpType: AvpTypeProxyAuthType, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUint16},
	{avpType: AvpTypeProxyAuthName, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeString},
	{avpType: AvpTypeProxyAuthChallenge, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeBytes},
	{avpType: AvpTypeProxyAuthID, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeBytes},
	{avpType: AvpTypeProxyAuthResponse, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeBytes},
	{avpType: AvpTypeCallErrors, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUnimplemented}, // TODO
	{avpType: AvpTypeAccm, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeUnimplemented},       // TODO
	{avpType: AvpTypeRandomVector, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeBytes},
	{avpType: AvpTypePrivGroupID, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeString},
	{avpType: AvpTypeRxConnectSpeed, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUint32},
	{avpType: AvpTypeSequencingRequired, VendorID: VendorIDIetf, isMandatory: true, dataType: AvpDataTypeEmpty},
	{avpType: AvpTypeUnused40, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused41, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused42, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused43, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused44, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused45, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused46, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused47, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused48, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused49, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused50, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused51, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused52, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused53, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused54, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused55, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused56, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeUnused57, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeExtended, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypeMessageDigest, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeBytes},
	{avpType: AvpTypeRouterID, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUint32},
	{avpType: AvpTypeAssignedConnID, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUint32},
	{avpType: AvpTypePseudowireCaps, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUnimplemented},
	{avpType: AvpTypeLocalSessionID, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUint32},
	{avpType: AvpTypeRemoteSessionID, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUint32},
	{avpType: AvpTypeAssignedCookie, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeBytes},
	{avpType: AvpTypeRemoteEndID, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeBytes},
	{avpType: AvpTypeUnused67, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeIllegal},
	{avpType: AvpTypePseudowireType, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUint16},
	{avpType: AvpTypeL2specificSublayer, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUint16},
	{avpType: AvpTypeDataSequencing, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUint16},
	{avpType: AvpTypeCircuitStatus, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUint16},
	{avpType: AvpTypePreferredLanguage, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeBytes},
	{avpType: AvpTypeControlAuthNonce, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeBytes},
	{avpType: AvpTypeTxConnectSpeedBps, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUint64},
	{avpType: AvpTypeRxConnectSpeedBps, VendorID: VendorIDIetf, isMandatory: false, dataType: AvpDataTypeUint64},
}

// AVP type identifiers as per RFC2661 and RFC3931, representing the
// value held by a given AVP.
const (
	AvpTypeMessage               AVPType = 0
	AvpTypeResultCode            AVPType = 1
	AvpTypeProtocolVersion       AVPType = 2
	AvpTypeFramingCap            AVPType = 3
	AvpTypeBearerCap             AVPType = 4
	AvpTypeTiebreaker            AVPType = 5
	AvpTypeFirmwareRevision      AVPType = 6
	AvpTypeHostName              AVPType = 7
	AvpTypeVendorName            AVPType = 8
	AvpTypeTunnelID              AVPType = 9
	AvpTypeRxWindowSize          AVPType = 10
	AvpTypeChallenge             AVPType = 11
	AvpTypeQ931CauseCode         AVPType = 12
	AvpTypeChallengeResponse     AVPType = 13
	AvpTypeSessionID             AVPType = 14
	AvpTypeCallSerialNumber      AVPType = 15
	AvpTypeMinimumBps            AVPType = 16
	AvpTypeMaximumBps            AVPType = 17
	AvpTypeBearerType            AVPType = 18
	AvpTypeFramingType           AVPType = 19
	AvpTypePacketProcDelay       AVPType = 20 /* Draft only (ignored) */
	AvpTypeCalledNumber          AVPType = 21
	AvpTypeCallingNumber         AVPType = 22
	AvpTypeSubAddress            AVPType = 23
	AvpTypeConnectSpeed          AVPType = 24
	AvpTypePhysicalChannelID     AVPType = 25
	AvpTypeInitialRcvdLcpConfreq AVPType = 26
	AvpTypeLastSentLcpConfreq    AVPType = 27
	AvpTypeLastRcvdLcpConfreq    AVPType = 28
	AvpTypeProxyAuthType         AVPType = 29
	AvpTypeProxyAuthName         AVPType = 30
	AvpTypeProxyAuthChallenge    AVPType = 31
	AvpTypeProxyAuthID           AVPType = 32
	AvpTypeProxyAuthResponse     AVPType = 33
	AvpTypeCallErrors            AVPType = 34
	AvpTypeAccm                  AVPType = 35
	AvpTypeRandomVector          AVPType = 36
	AvpTypePrivGroupID           AVPType = 37
	AvpTypeRxConnectSpeed        AVPType = 38
	AvpTypeSequencingRequired    AVPType = 39
	AvpTypeUnused40              AVPType = 40
	AvpTypeUnused41              AVPType = 41
	AvpTypeUnused42              AVPType = 42
	AvpTypeUnused43              AVPType = 43
	AvpTypeUnused44              AVPType = 44
	AvpTypeUnused45              AVPType = 45
	AvpTypeUnused46              AVPType = 46
	AvpTypeUnused47              AVPType = 47
	AvpTypeUnused48              AVPType = 48
	AvpTypeUnused49              AVPType = 49
	AvpTypeUnused50              AVPType = 50
	AvpTypeUnused51              AVPType = 51
	AvpTypeUnused52              AVPType = 52
	AvpTypeUnused53              AVPType = 53
	AvpTypeUnused54              AVPType = 54
	AvpTypeUnused55              AVPType = 55
	AvpTypeUnused56              AVPType = 56
	AvpTypeUnused57              AVPType = 57
	AvpTypeExtended              AVPType = 58
	AvpTypeMessageDigest         AVPType = 59
	AvpTypeRouterID              AVPType = 60
	AvpTypeAssignedConnID        AVPType = 61
	AvpTypePseudowireCaps        AVPType = 62
	AvpTypeLocalSessionID        AVPType = 63
	AvpTypeRemoteSessionID       AVPType = 64
	AvpTypeAssignedCookie        AVPType = 65
	AvpTypeRemoteEndID           AVPType = 66
	AvpTypeUnused67              AVPType = 67
	AvpTypePseudowireType        AVPType = 68
	AvpTypeL2specificSublayer    AVPType = 69
	AvpTypeDataSequencing        AVPType = 70
	AvpTypeCircuitStatus         AVPType = 71
	AvpTypePreferredLanguage     AVPType = 72
	AvpTypeControlAuthNonce      AVPType = 73
	AvpTypeTxConnectSpeedBps     AVPType = 74
	AvpTypeRxConnectSpeedBps     AVPType = 75
	AvpTypeNumAvps               AVPType = 76
)

// AVP message types as per RFC2661 and RFC3931, representing the various
// control protocol messages used in the L2TPv2 and L2TPv3 protocols.
const (
	AvpMsgTypeIllegal    AVPMsgType = 0
	AvpMsgTypeSccrq      AVPMsgType = 1
	AvpMsgTypeSccrp      AVPMsgType = 2
	AvpMsgTypeScccn      AVPMsgType = 3
	AvpMsgTypeStopccn    AVPMsgType = 4
	AvpMsgTypeReserved5  AVPMsgType = 5
	AvpMsgTypeHello      AVPMsgType = 6
	AvpMsgTypeOcrq       AVPMsgType = 7
	AvpMsgTypeOcrp       AVPMsgType = 8
	AvpMsgTypeOccn       AVPMsgType = 9
	AvpMsgTypeIcrq       AVPMsgType = 10
	AvpMsgTypeIcrp       AVPMsgType = 11
	AvpMsgTypeIccn       AVPMsgType = 12
	AvpMsgTypeReserved13 AVPMsgType = 13
	AvpMsgTypeCdn        AVPMsgType = 14
	AvpMsgTypeWen        AVPMsgType = 15
	AvpMsgTypeSli        AVPMsgType = 16
	AvpMsgTypeMdmst      AVPMsgType = 17
	AvpMsgTypeSrrq       AVPMsgType = 18
	AvpMsgTypeSrrp       AVPMsgType = 19
	AvpMsgTypeAck        AVPMsgType = 20
	AvpMsgTypeFsq        AVPMsgType = 21
	AvpMsgTypeFsr        AVPMsgType = 22
	AvpMsgTypeMsrq       AVPMsgType = 23
	AvpMsgTypeMsrp       AVPMsgType = 24
	AvpMsgTypeMse        AVPMsgType = 25
	AvpMsgTypeMsi        AVPMsgType = 26
	AvpMsgTypeMsen       AVPMsgType = 27
	AvpMsgTypeCsun       AVPMsgType = 28
	AvpMsgTypeCsurq      AVPMsgType = 29
	AvpMsgTypeCount      AVPMsgType = 30
)

// String converts an AVPType identifier into a human-readable string.
// Implements the fmt.Stringer() interface.
func (t AVPType) String() string {
	switch t {
	case AvpTypeMessage:
		return "AvpTypeMessage"
	case AvpTypeResultCode:
		return "AvpTypeResultCode"
	case AvpTypeProtocolVersion:
		return "AvpTypeProtocolVersion"
	case AvpTypeFramingCap:
		return "AvpTypeFramingCap"
	case AvpTypeBearerCap:
		return "AvpTypeBearerCap"
	case AvpTypeTiebreaker:
		return "AvpTypeTiebreaker"
	case AvpTypeFirmwareRevision:
		return "AvpTypeFirmwareRevision"
	case AvpTypeHostName:
		return "AvpTypeHostName"
	case AvpTypeVendorName:
		return "AvpTypeVendorName"
	case AvpTypeTunnelID:
		return "AvpTypeTunnelID"
	case AvpTypeRxWindowSize:
		return "AvpTypeRxWindowSize"
	case AvpTypeChallenge:
		return "AvpTypeChallenge"
	case AvpTypeQ931CauseCode:
		return "AvpTypeQ931CauseCode"
	case AvpTypeChallengeResponse:
		return "AvpTypeChallengeResponse"
	case AvpTypeSessionID:
		return "AvpTypeSessionID"
	case AvpTypeCallSerialNumber:
		return "AvpTypeCallSerialNumber"
	case AvpTypeMinimumBps:
		return "AvpTypeMinimumBps"
	case AvpTypeMaximumBps:
		return "AvpTypeMaximumBps"
	case AvpTypeBearerType:
		return "AvpTypeBearerType"
	case AvpTypeFramingType:
		return "AvpTypeFramingType"
	case AvpTypePacketProcDelay:
		return "AvpTypePacketProcDelay"
	case AvpTypeCalledNumber:
		return "AvpTypeCalledNumber"
	case AvpTypeCallingNumber:
		return "AvpTypeCallingNumber"
	case AvpTypeSubAddress:
		return "AvpTypeSubAddress"
	case AvpTypeConnectSpeed:
		return "AvpTypeConnectSpeed"
	case AvpTypePhysicalChannelID:
		return "AvpTypePhysicalChannelID"
	case AvpTypeInitialRcvdLcpConfreq:
		return "AvpTypeInitialRcvdLcpConfreq"
	case AvpTypeLastSentLcpConfreq:
		return "AvpTypeLastSentLcpConfreq"
	case AvpTypeLastRcvdLcpConfreq:
		return "AvpTypeLastRcvdLcpConfreq"
	case AvpTypeProxyAuthType:
		return "AvpTypeProxyAuthType"
	case AvpTypeProxyAuthName:
		return "AvpTypeProxyAuthName"
	case AvpTypeProxyAuthChallenge:
		return "AvpTypeProxyAuthChallenge"
	case AvpTypeProxyAuthID:
		return "AvpTypeProxyAuthID"
	case AvpTypeProxyAuthResponse:
		return "AvpTypeProxyAuthResponse"
	case AvpTypeCallErrors:
		return "AvpTypeCallErrors"
	case AvpTypeAccm:
		return "AvpTypeAccm"
	case AvpTypeRandomVector:
		return "AvpTypeRandomVector"
	case AvpTypePrivGroupID:
		return "AvpTypePrivGroupID"
	case AvpTypeRxConnectSpeed:
		return "AvpTypeRxConnectSpeed"
	case AvpTypeSequencingRequired:
		return "AvpTypeSequencingRequired"
	case AvpTypeUnused40:
		return "AvpTypeUnused40"
	case AvpTypeUnused41:
		return "AvpTypeUnused41"
	case AvpTypeUnused42:
		return "AvpTypeUnused42"
	case AvpTypeUnused43:
		return "AvpTypeUnused43"
	case AvpTypeUnused44:
		return "AvpTypeUnused44"
	case AvpTypeUnused45:
		return "AvpTypeUnused45"
	case AvpTypeUnused46:
		return "AvpTypeUnused46"
	case AvpTypeUnused47:
		return "AvpTypeUnused47"
	case AvpTypeUnused48:
		return "AvpTypeUnused48"
	case AvpTypeUnused49:
		return "AvpTypeUnused49"
	case AvpTypeUnused50:
		return "AvpTypeUnused50"
	case AvpTypeUnused51:
		return "AvpTypeUnused51"
	case AvpTypeUnused52:
		return "AvpTypeUnused52"
	case AvpTypeUnused53:
		return "AvpTypeUnused53"
	case AvpTypeUnused54:
		return "AvpTypeUnused54"
	case AvpTypeUnused55:
		return "AvpTypeUnused55"
	case AvpTypeUnused56:
		return "AvpTypeUnused56"
	case AvpTypeUnused57:
		return "AvpTypeUnused57"
	case AvpTypeExtended:
		return "AvpTypeExtended"
	case AvpTypeMessageDigest:
		return "AvpTypeMessageDigest"
	case AvpTypeRouterID:
		return "AvpTypeRouterID"
	case AvpTypeAssignedConnID:
		return "AvpTypeAssignedConnID"
	case AvpTypePseudowireCaps:
		return "AvpTypePseudowireCaps"
	case AvpTypeLocalSessionID:
		return "AvpTypeLocalSessionID"
	case AvpTypeRemoteSessionID:
		return "AvpTypeRemoteSessionID"
	case AvpTypeAssignedCookie:
		return "AvpTypeAssignedCookie"
	case AvpTypeRemoteEndID:
		return "AvpTypeRemoteEndID"
	case AvpTypeUnused67:
		return "AvpTypeUnused67"
	case AvpTypePseudowireType:
		return "AvpTypePseudowireType"
	case AvpTypeL2specificSublayer:
		return "AvpTypeL2specificSublayer"
	case AvpTypeDataSequencing:
		return "AvpTypeDataSequencing"
	case AvpTypeCircuitStatus:
		return "AvpTypeCircuitStatus"
	case AvpTypePreferredLanguage:
		return "AvpTypePreferredLanguage"
	case AvpTypeControlAuthNonce:
		return "AvpTypeControlAuthNonce"
	case AvpTypeTxConnectSpeedBps:
		return "AvpTypeTxConnectSpeedBps"
	case AvpTypeRxConnectSpeedBps:
		return "AvpTypeRxConnectSpeedBps"
	}
	return ""
}

// String converts an AVPMsgType identifier into a human-readable string.
// Implements the fmt.Stringer() interface.
func (t AVPMsgType) String() string {
	switch t {
	case AvpMsgTypeIllegal:
		return "AvpMsgTypeIllegal"
	case AvpMsgTypeSccrq:
		return "AvpMsgTypeSccrq"
	case AvpMsgTypeSccrp:
		return "AvpMsgTypeSccrp"
	case AvpMsgTypeScccn:
		return "AvpMsgTypeScccn"
	case AvpMsgTypeStopccn:
		return "AvpMsgTypeStopccn"
	case AvpMsgTypeReserved5:
		return "AvpMsgTypeReserved5"
	case AvpMsgTypeHello:
		return "AvpMsgTypeHello"
	case AvpMsgTypeOcrq:
		return "AvpMsgTypeOcrq"
	case AvpMsgTypeOcrp:
		return "AvpMsgTypeOcrp"
	case AvpMsgTypeOccn:
		return "AvpMsgTypeOccn"
	case AvpMsgTypeIcrq:
		return "AvpMsgTypeIcrq"
	case AvpMsgTypeIcrp:
		return "AvpMsgTypeIcrp"
	case AvpMsgTypeIccn:
		return "AvpMsgTypeIccn"
	case AvpMsgTypeReserved13:
		return "AvpMsgTypeReserved13"
	case AvpMsgTypeCdn:
		return "AvpMsgTypeCdn"
	case AvpMsgTypeWen:
		return "AvpMsgTypeWen"
	case AvpMsgTypeSli:
		return "AvpMsgTypeSli"
	case AvpMsgTypeMdmst:
		return "AvpMsgTypeMdmst"
	case AvpMsgTypeSrrq:
		return "AvpMsgTypeSrrq"
	case AvpMsgTypeSrrp:
		return "AvpMsgTypeSrrp"
	case AvpMsgTypeAck:
		return "AvpMsgTypeAck"
	case AvpMsgTypeFsq:
		return "AvpMsgTypeFsq"
	case AvpMsgTypeFsr:
		return "AvpMsgTypeFsr"
	case AvpMsgTypeMsrq:
		return "AvpMsgTypeMsrq"
	case AvpMsgTypeMsrp:
		return "AvpMsgTypeMsrp"
	case AvpMsgTypeMse:
		return "AvpMsgTypeMse"
	case AvpMsgTypeMsi:
		return "AvpMsgTypeMsi"
	case AvpMsgTypeMsen:
		return "AvpMsgTypeMsen"
	case AvpMsgTypeCsun:
		return "AvpMsgTypeCsun"
	case AvpMsgTypeCsurq:
		return "AvpMsgTypeCsurq"
	case AvpMsgTypeCount:
		return "AvpMsgTypeCount"
	}
	return ""
}

// String represents the AVP as a human-readable string.
// Implements the fmt.Stringer() interface.
func (avp AVP) String() string {
	return fmt.Sprintf("%s %s", avp.header, avp.payload)
}

// String represents the AVP data type as a human-readable string.
// Implements the fmt.Stringer() interface.
func (t AVPDataType) String() string {
	switch t {
	case AvpDataTypeEmpty:
		return "no data"
	case AvpDataTypeUint8:
		return "uint8"
	case AvpDataTypeUint16:
		return "uint16"
	case AvpDataTypeUint32:
		return "uint32"
	case AvpDataTypeUint64:
		return "uint64"
	case AvpDataTypeString:
		return "string"
	case AvpDataTypeBytes:
		return "byte array"
	case AvpDataTypeUnimplemented:
		return "unimplemented AVP data type"
	case AvpDataTypeIllegal:
		return "illegal AVP"
	}
	return "Unrecognised AVP data type"
}

func (hdr avpHeader) String() string {
	m := "-"
	h := "-"
	var t string
	if hdr.VendorID == VendorIDIetf {
		t = fmt.Sprintf("%s", hdr.AvpType)
	} else {
		t = fmt.Sprintf("Vendor %d AVP %d", hdr.VendorID, uint16(hdr.AvpType))
	}
	if hdr.isMandatory() {
		m = "M"
	}
	if hdr.isHidden() {
		h = "H"
	}
	return fmt.Sprintf("%s [%s%s]", t, m, h)
}

func (p avpPayload) String() string {
	var str strings.Builder

	str.WriteString(fmt.Sprintf("(%s) ", p.dataType))

	switch p.dataType {
	case AvpDataTypeUint8:
		v, _ := p.toUint8()
		str.WriteString(fmt.Sprintf("%d", v))
	case AvpDataTypeUint16:
		v, _ := p.toUint16()
		str.WriteString(fmt.Sprintf("%d", v))
	case AvpDataTypeUint32:
		v, _ := p.toUint32()
		str.WriteString(fmt.Sprintf("%d", v))
	case AvpDataTypeUint64:
		v, _ := p.toUint64()
		str.WriteString(fmt.Sprintf("%d", v))
	case AvpDataTypeString:
		s, _ := p.toString()
		str.WriteString(s)
	case AvpDataTypeBytes:
		str.WriteString(fmt.Sprintf("%s", p.data))
	case AvpDataTypeEmpty, AvpDataTypeUnimplemented, AvpDataTypeIllegal:
		str.WriteString("")
	}

	return str.String()
}

func (h *avpHeader) isMandatory() bool {
	return (0x8000 & h.FlagLen) == 0x8000
}

func (h *avpHeader) isHidden() bool {
	return (0x4000 & h.FlagLen) == 0x4000
}

func (h *avpHeader) dataLen() int {
	return int(0x3ff&h.FlagLen) - avpHeaderLen
}

// IsMandatory returns true if a given AVP is flagged as being mandatory.
// The RFCs state that if an unrecognised AVP with the mandatory flag set
// is received by an implementation, the implementation MUST terminate the
// associated tunnel or session instance.
func (avp *AVP) IsMandatory() bool {
	return avp.header.isMandatory()
}

// IsHidden returns true if a given AVP has been obscured using the hiding
// algorithm described by RFC2661 Section 4.3.
func (avp *AVP) IsHidden() bool {
	return avp.header.isHidden()
}

// Type returns the type identifier for the AVP.
func (avp *AVP) Type() AVPType {
	return avp.header.AvpType
}

// VendorID returns the vendor ID for the AVP.
// Standard AVPs per RFC2661 and RFC3931 will use the IETF namespace.
// Vendor-specific AVPs will use a per-vendor ID.
func (avp *AVP) VendorID() AVPVendorID {
	return avp.header.VendorID
}

func getAVPInfo(avpType AVPType, VendorID AVPVendorID) (*avpInfo, error) {
	for _, info := range avpInfoTable {
		if info.avpType == avpType && info.VendorID == VendorID {
			return &info, nil
		}
	}
	return nil, errors.New("Unrecognised AVP type")
}

// ParseAVPBuffer takes a byte slice of encoded AVP data and parses it
// into an array of AVP instances.
func ParseAVPBuffer(b []byte) (avps []AVP, err error) {
	r := bytes.NewReader(b)
	fmt.Println(r.Len(), r.Size(), len(b))
	for r.Len() >= avpHeaderLen {
		var h avpHeader
		var info *avpInfo
		var cursor int64

		// Read the AVP header in
		if err := binary.Read(r, binary.BigEndian, &h); err != nil {
			return nil, err
		}

		// Look up the AVP
		info, err := getAVPInfo(h.AvpType, h.VendorID)
		if err != nil {
			if h.isMandatory() {
				return nil, err
			}
			// RFC2661 section 4.1 says unrecognised AVPs without the
			// mandatory bit set MUST be ignored
			continue
		}

		if cursor, err = r.Seek(0, io.SeekCurrent); err != nil {
			return nil, errors.New("Malformed AVP buffer: unable to determine offset of current AVP")
		}

		avps = append(avps, AVP{
			header: h,
			payload: avpPayload{
				dataType: info.dataType,
				data:     b[cursor : cursor+int64(h.dataLen())],
			},
		})

		// Step on to the next AVP in the buffer
		if _, err := r.Seek(int64(h.dataLen()), io.SeekCurrent); err != nil {
			return nil, errors.New("Malformed AVP buffer: invalid length for current AVP")
		}
	}
	return avps, nil
}

// RawData returns the data type for the AVP, along with the raw byte
// slice for the data carried by the AVP.
func (avp *AVP) RawData() (dataType AVPDataType, buffer []byte) {
	return avp.payload.dataType, avp.payload.data
}

// IsDataType returns true if the AVP holds the specified data type.
func (avp *AVP) IsDataType(dt AVPDataType) bool {
	return avp.payload.dataType == dt
}

func (p *avpPayload) toUint8() (out uint8, err error) {
	return p.data[0], nil
}

func (p *avpPayload) toUint16() (out uint16, err error) {
	r := bytes.NewReader(p.data)
	if err = binary.Read(r, binary.BigEndian, &out); err != nil {
		return 0, err
	}
	return out, err
}

func (p *avpPayload) toUint32() (out uint32, err error) {
	r := bytes.NewReader(p.data)
	if err = binary.Read(r, binary.BigEndian, &out); err != nil {
		return 0, err
	}
	return out, err
}

func (p *avpPayload) toUint64() (out uint64, err error) {
	r := bytes.NewReader(p.data)
	if err = binary.Read(r, binary.BigEndian, &out); err != nil {
		return 0, err
	}
	return out, err
}

func (p *avpPayload) toString() (out string, err error) {
	return string(p.data), nil
}

// DecodeUint16Data decodes an AVP holding a uint16 value.
// It is an error to call this function on an AVP which doesn't
// contain a uint16 payload.
func (avp *AVP) DecodeUint16Data() (value uint16, err error) {
	if !avp.IsDataType(AvpDataTypeUint16) {
		return 0, errors.New("AVP data is not of type uint16, cannot decode")
	}
	return avp.payload.toUint16()
}

// DecodeUint32Data decodes an AVP holding a uint32 value.
// It is an error to call this function on an AVP which doesn't
// contain a uint32 payload.
func (avp *AVP) DecodeUint32Data() (value uint32, err error) {
	if !avp.IsDataType(AvpDataTypeUint32) {
		return 0, errors.New("AVP data is not of type uint32, cannot decode")
	}
	return avp.payload.toUint32()
}

// DecodeStringData decodes an AVP holding a string value.
// It is an error to call this function on an AVP which doesn't
// contain a string payload.
func (avp *AVP) DecodeStringData() (value string, err error) {
	if !avp.IsDataType(AvpDataTypeString) {
		return "", errors.New("AVP data is not of type string, cannot decode")
	}
	return avp.payload.toString()
}
