package l2tp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

type avpFlagLen uint16

// avpVendorID is the Vendor ID from the AVP header as per RFC2661 section 4.1
type avpVendorID uint16

// avpType is the attribute type from the AVP header as per RFC2661 section 4.1
type avpType uint16

// avpMsgType stores the value of the Message Type AVP
type avpMsgType uint16

// avpDataType indicates the type of the data value carried by the AVP
type avpDataType int

type avpInfo struct {
	avpType     avpType
	VendorID    avpVendorID
	isMandatory bool
	dataType    avpDataType
}

// Don't be tempted to try to make the fields in this structure private:
// doing so breaks the reflection properties which binary.Read depends upon
// for extracting the header from the bytearray.
type avpHeader struct {
	FlagLen  avpFlagLen
	VendorID avpVendorID
	AvpType  avpType
}

type avpPayload struct {
	dataType avpDataType
	data     []byte
}

// avp represents a single AVP in an L2TP control message
type avp struct {
	header  avpHeader
	payload avpPayload
}

// avpResultCode represents an RFC2661/RFC3931 result code
type avpResultCode uint16

// avpErrorCode represents an RFC2661/RFC3931 error code
type avpErrorCode uint16

// resultCode represents an RFC2661/RFC3931 result code AVP
type resultCode struct {
	result  avpResultCode
	errCode avpErrorCode
	errMsg  string
}

const (
	avpHeaderLen = 6
	// vendorIDIetf is the namespace used for standard AVPS described
	// by RFC2661 and RFC3931.
	vendorIDIetf = 0
)

const (
	// avpDataTypeEmpty represents an AVP with no value
	avpDataTypeEmpty avpDataType = iota
	// avpDataTypeUint16 represents an AVP carrying a single uint16 value
	avpDataTypeUint16 avpDataType = iota
	// avpDataTypeUint32 represents an AVP carrying a single uint32 value
	avpDataTypeUint32 avpDataType = iota
	// avpDataTypeUint64 represents an AVP carrying a single uint64 value
	avpDataTypeUint64 avpDataType = iota
	// avpDataTypeString represents an AVP carrying an ASCII string
	avpDataTypeString avpDataType = iota
	// avpDataTypeBytes represents an AVP carrying a raw byte array
	avpDataTypeBytes avpDataType = iota
	// avpDataTypeResultCode represents an AVP carrying an RFC2661 result code
	avpDataTypeResultCode avpDataType = iota
	// avpDataTypeMsgID represents an AVP carrying the message type identifier
	avpDataTypeMsgID avpDataType = iota
	// avpDataTypeUnimplemented represents an AVP carrying a currently unimplemented data type
	avpDataTypeUnimplemented avpDataType = iota
	// avpDataTypeIllegal represents an AVP carrying an illegal data type.
	// AVPs falling into this category are typically those with currently
	// reserved IDs as per the RFCs.
	avpDataTypeIllegal avpDataType = iota
	// avpDataTypeMax is a sentinel value for test purposes
	avpDataTypeMax avpDataType = iota
)

var avpInfoTable = [...]avpInfo{
	{avpType: avpTypeMessage, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeMsgID},
	{avpType: avpTypeResultCode, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeResultCode},
	{avpType: avpTypeProtocolVersion, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeBytes},
	{avpType: avpTypeFramingCap, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeUint32},
	{avpType: avpTypeBearerCap, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeUint32},
	{avpType: avpTypeTiebreaker, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeBytes},
	{avpType: avpTypeFirmwareRevision, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUint16},
	{avpType: avpTypeHostName, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeString},
	{avpType: avpTypeVendorName, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeString},
	{avpType: avpTypeTunnelID, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeUint16},
	{avpType: avpTypeRxWindowSize, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeUint16},
	{avpType: avpTypeChallenge, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeBytes},
	{avpType: avpTypeQ931CauseCode, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeUnimplemented}, // TODO
	{avpType: avpTypeChallengeResponse, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeBytes},
	{avpType: avpTypeSessionID, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeUint16},
	{avpType: avpTypeCallSerialNumber, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeUint32},
	{avpType: avpTypeMinimumBps, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeUint32},
	{avpType: avpTypeMaximumBps, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeUint32},
	{avpType: avpTypeBearerType, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeUint32},
	{avpType: avpTypeFramingType, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeUint32},
	{avpType: avpTypePacketProcDelay, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUnimplemented}, // TODO
	{avpType: avpTypeCalledNumber, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeString},
	{avpType: avpTypeCallingNumber, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeString},
	{avpType: avpTypeSubAddress, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeString},
	{avpType: avpTypeConnectSpeed, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeUint32},
	{avpType: avpTypePhysicalChannelID, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUint32},
	{avpType: avpTypeInitialRcvdLcpConfreq, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeBytes},
	{avpType: avpTypeLastSentLcpConfreq, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeBytes},
	{avpType: avpTypeLastRcvdLcpConfreq, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeBytes},
	{avpType: avpTypeProxyAuthType, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUint16},
	{avpType: avpTypeProxyAuthName, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeString},
	{avpType: avpTypeProxyAuthChallenge, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeBytes},
	{avpType: avpTypeProxyAuthID, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeBytes},
	{avpType: avpTypeProxyAuthResponse, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeBytes},
	{avpType: avpTypeCallErrors, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeUnimplemented}, // TODO
	{avpType: avpTypeAccm, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeUnimplemented},       // TODO
	{avpType: avpTypeRandomVector, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeBytes},
	{avpType: avpTypePrivGroupID, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeString},
	{avpType: avpTypeRxConnectSpeed, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUint32},
	{avpType: avpTypeSequencingRequired, VendorID: vendorIDIetf, isMandatory: true, dataType: avpDataTypeEmpty},
	{avpType: avpTypeUnused40, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused41, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused42, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused43, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused44, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused45, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused46, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused47, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused48, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused49, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused50, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused51, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused52, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused53, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused54, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused55, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused56, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeUnused57, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeExtended, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypeMessageDigest, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeBytes},
	{avpType: avpTypeRouterID, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUint32},
	{avpType: avpTypeAssignedConnID, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUint32},
	{avpType: avpTypePseudowireCaps, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUnimplemented},
	{avpType: avpTypeLocalSessionID, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUint32},
	{avpType: avpTypeRemoteSessionID, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUint32},
	{avpType: avpTypeAssignedCookie, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeBytes},
	{avpType: avpTypeRemoteEndID, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeBytes},
	{avpType: avpTypeUnused67, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeIllegal},
	{avpType: avpTypePseudowireType, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUint16},
	{avpType: avpTypeL2specificSublayer, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUint16},
	{avpType: avpTypeDataSequencing, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUint16},
	{avpType: avpTypeCircuitStatus, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUint16},
	{avpType: avpTypePreferredLanguage, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeBytes},
	{avpType: avpTypeControlAuthNonce, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeBytes},
	{avpType: avpTypeTxConnectSpeedBps, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUint64},
	{avpType: avpTypeRxConnectSpeedBps, VendorID: vendorIDIetf, isMandatory: false, dataType: avpDataTypeUint64},
}

// AVP type identifiers as per RFC2661 and RFC3931, representing the
// value held by a given AVP.
const (
	avpTypeMessage               avpType = 0
	avpTypeResultCode            avpType = 1
	avpTypeProtocolVersion       avpType = 2
	avpTypeFramingCap            avpType = 3
	avpTypeBearerCap             avpType = 4
	avpTypeTiebreaker            avpType = 5
	avpTypeFirmwareRevision      avpType = 6
	avpTypeHostName              avpType = 7
	avpTypeVendorName            avpType = 8
	avpTypeTunnelID              avpType = 9
	avpTypeRxWindowSize          avpType = 10
	avpTypeChallenge             avpType = 11
	avpTypeQ931CauseCode         avpType = 12
	avpTypeChallengeResponse     avpType = 13
	avpTypeSessionID             avpType = 14
	avpTypeCallSerialNumber      avpType = 15
	avpTypeMinimumBps            avpType = 16
	avpTypeMaximumBps            avpType = 17
	avpTypeBearerType            avpType = 18
	avpTypeFramingType           avpType = 19
	avpTypePacketProcDelay       avpType = 20 /* Draft only (ignored) */
	avpTypeCalledNumber          avpType = 21
	avpTypeCallingNumber         avpType = 22
	avpTypeSubAddress            avpType = 23
	avpTypeConnectSpeed          avpType = 24
	avpTypePhysicalChannelID     avpType = 25
	avpTypeInitialRcvdLcpConfreq avpType = 26
	avpTypeLastSentLcpConfreq    avpType = 27
	avpTypeLastRcvdLcpConfreq    avpType = 28
	avpTypeProxyAuthType         avpType = 29
	avpTypeProxyAuthName         avpType = 30
	avpTypeProxyAuthChallenge    avpType = 31
	avpTypeProxyAuthID           avpType = 32
	avpTypeProxyAuthResponse     avpType = 33
	avpTypeCallErrors            avpType = 34
	avpTypeAccm                  avpType = 35
	avpTypeRandomVector          avpType = 36
	avpTypePrivGroupID           avpType = 37
	avpTypeRxConnectSpeed        avpType = 38
	avpTypeSequencingRequired    avpType = 39
	avpTypeUnused40              avpType = 40
	avpTypeUnused41              avpType = 41
	avpTypeUnused42              avpType = 42
	avpTypeUnused43              avpType = 43
	avpTypeUnused44              avpType = 44
	avpTypeUnused45              avpType = 45
	avpTypeUnused46              avpType = 46
	avpTypeUnused47              avpType = 47
	avpTypeUnused48              avpType = 48
	avpTypeUnused49              avpType = 49
	avpTypeUnused50              avpType = 50
	avpTypeUnused51              avpType = 51
	avpTypeUnused52              avpType = 52
	avpTypeUnused53              avpType = 53
	avpTypeUnused54              avpType = 54
	avpTypeUnused55              avpType = 55
	avpTypeUnused56              avpType = 56
	avpTypeUnused57              avpType = 57
	avpTypeExtended              avpType = 58
	avpTypeMessageDigest         avpType = 59
	avpTypeRouterID              avpType = 60
	avpTypeAssignedConnID        avpType = 61
	avpTypePseudowireCaps        avpType = 62
	avpTypeLocalSessionID        avpType = 63
	avpTypeRemoteSessionID       avpType = 64
	avpTypeAssignedCookie        avpType = 65
	avpTypeRemoteEndID           avpType = 66
	avpTypeUnused67              avpType = 67
	avpTypePseudowireType        avpType = 68
	avpTypeL2specificSublayer    avpType = 69
	avpTypeDataSequencing        avpType = 70
	avpTypeCircuitStatus         avpType = 71
	avpTypePreferredLanguage     avpType = 72
	avpTypeControlAuthNonce      avpType = 73
	avpTypeTxConnectSpeedBps     avpType = 74
	avpTypeRxConnectSpeedBps     avpType = 75
	avpTypeMax                   avpType = 76
)

// AVP message types as per RFC2661 and RFC3931, representing the various
// control protocol messages used in the L2TPv2 and L2TPv3 protocols.
const (
	avpMsgTypeIllegal    avpMsgType = 0
	avpMsgTypeSccrq      avpMsgType = 1
	avpMsgTypeSccrp      avpMsgType = 2
	avpMsgTypeScccn      avpMsgType = 3
	avpMsgTypeStopccn    avpMsgType = 4
	avpMsgTypeReserved5  avpMsgType = 5
	avpMsgTypeHello      avpMsgType = 6
	avpMsgTypeOcrq       avpMsgType = 7
	avpMsgTypeOcrp       avpMsgType = 8
	avpMsgTypeOccn       avpMsgType = 9
	avpMsgTypeIcrq       avpMsgType = 10
	avpMsgTypeIcrp       avpMsgType = 11
	avpMsgTypeIccn       avpMsgType = 12
	avpMsgTypeReserved13 avpMsgType = 13
	avpMsgTypeCdn        avpMsgType = 14
	avpMsgTypeWen        avpMsgType = 15
	avpMsgTypeSli        avpMsgType = 16
	avpMsgTypeMdmst      avpMsgType = 17
	avpMsgTypeSrrq       avpMsgType = 18
	avpMsgTypeSrrp       avpMsgType = 19
	avpMsgTypeAck        avpMsgType = 20
	avpMsgTypeFsq        avpMsgType = 21
	avpMsgTypeFsr        avpMsgType = 22
	avpMsgTypeMsrq       avpMsgType = 23
	avpMsgTypeMsrp       avpMsgType = 24
	avpMsgTypeMse        avpMsgType = 25
	avpMsgTypeMsi        avpMsgType = 26
	avpMsgTypeMsen       avpMsgType = 27
	avpMsgTypeCsun       avpMsgType = 28
	avpMsgTypeCsurq      avpMsgType = 29
	avpMsgTypeMax        avpMsgType = 30
)

// AVP result codes as per RFC2661 and RFC3931.
// StopCCN messages and CDN messages have seperate result codes.
const (
	avpStopCCNResultCodeReserved                          avpResultCode = 0
	avpStopCCNResultCodeClearConnection                   avpResultCode = 1
	avpStopCCNResultCodeGeneralError                      avpResultCode = 2
	avpStopCCNResultCodeChannelExists                     avpResultCode = 3
	avpStopCCNResultCodeChannelNotAuthorized              avpResultCode = 4
	avpStopCCNResultCodeChannelProtocolVersionUnsupported avpResultCode = 5
	avpStopCCNResultCodeChannelShuttingDown               avpResultCode = 6
	avpStopCCNResultCodeChannelFSMError                   avpResultCode = 7
	avpCDNResultCodeReserved                              avpResultCode = 0
	avpCDNResultCodeLostCarrier                           avpResultCode = 1
	avpCDNResultCodeGeneralError                          avpResultCode = 2
	avpCDNResultCodeAdminDisconnect                       avpResultCode = 3
	avpCDNResultCodeNoResources                           avpResultCode = 4
	avpCDNResultCodeNotAvailable                          avpResultCode = 5
	avpCDNResultCodeInvalidDestination                    avpResultCode = 6
	avpCDNResultCodeNoAnswer                              avpResultCode = 7
	avpCDNResultCodeBusy                                  avpResultCode = 8
	avpCDNResultCodeNoDialTone                            avpResultCode = 9
	avpCDNResultCodeTimeout                               avpResultCode = 10
	avpCDNResultCodeBadTransport                          avpResultCode = 11
)

// AVP error codes as per RFC2661 and RFC3931
const (
	avpErrorCodeNoError             avpErrorCode = 0
	avpErrorCodeNoControlConnection avpErrorCode = 1
	avpErrorCodeBadLength           avpErrorCode = 2
	avpErrorCodeBadValue            avpErrorCode = 3
	avpErrorCodeNoResource          avpErrorCode = 4
	avpErrorCodeInvalidSessionID    avpErrorCode = 5
	avpErrorCodeVendorSpecificError avpErrorCode = 6
	avpErrorCodeTryAnother          avpErrorCode = 7
	avpErrorCodeMBitShutdown        avpErrorCode = 8
)

// String converts an avpType identifier into a human-readable string.
// Implements the fmt.Stringer() interface.
var _ fmt.Stringer = (*avpType)(nil)

func (t avpType) String() string {
	switch t {
	case avpTypeMessage:
		return "avpTypeMessage"
	case avpTypeResultCode:
		return "avpTypeResultCode"
	case avpTypeProtocolVersion:
		return "avpTypeProtocolVersion"
	case avpTypeFramingCap:
		return "avpTypeFramingCap"
	case avpTypeBearerCap:
		return "avpTypeBearerCap"
	case avpTypeTiebreaker:
		return "avpTypeTiebreaker"
	case avpTypeFirmwareRevision:
		return "avpTypeFirmwareRevision"
	case avpTypeHostName:
		return "avpTypeHostName"
	case avpTypeVendorName:
		return "avpTypeVendorName"
	case avpTypeTunnelID:
		return "avpTypeTunnelID"
	case avpTypeRxWindowSize:
		return "avpTypeRxWindowSize"
	case avpTypeChallenge:
		return "avpTypeChallenge"
	case avpTypeQ931CauseCode:
		return "avpTypeQ931CauseCode"
	case avpTypeChallengeResponse:
		return "avpTypeChallengeResponse"
	case avpTypeSessionID:
		return "avpTypeSessionID"
	case avpTypeCallSerialNumber:
		return "avpTypeCallSerialNumber"
	case avpTypeMinimumBps:
		return "avpTypeMinimumBps"
	case avpTypeMaximumBps:
		return "avpTypeMaximumBps"
	case avpTypeBearerType:
		return "avpTypeBearerType"
	case avpTypeFramingType:
		return "avpTypeFramingType"
	case avpTypePacketProcDelay:
		return "avpTypePacketProcDelay"
	case avpTypeCalledNumber:
		return "avpTypeCalledNumber"
	case avpTypeCallingNumber:
		return "avpTypeCallingNumber"
	case avpTypeSubAddress:
		return "avpTypeSubAddress"
	case avpTypeConnectSpeed:
		return "avpTypeConnectSpeed"
	case avpTypePhysicalChannelID:
		return "avpTypePhysicalChannelID"
	case avpTypeInitialRcvdLcpConfreq:
		return "avpTypeInitialRcvdLcpConfreq"
	case avpTypeLastSentLcpConfreq:
		return "avpTypeLastSentLcpConfreq"
	case avpTypeLastRcvdLcpConfreq:
		return "avpTypeLastRcvdLcpConfreq"
	case avpTypeProxyAuthType:
		return "avpTypeProxyAuthType"
	case avpTypeProxyAuthName:
		return "avpTypeProxyAuthName"
	case avpTypeProxyAuthChallenge:
		return "avpTypeProxyAuthChallenge"
	case avpTypeProxyAuthID:
		return "avpTypeProxyAuthID"
	case avpTypeProxyAuthResponse:
		return "avpTypeProxyAuthResponse"
	case avpTypeCallErrors:
		return "avpTypeCallErrors"
	case avpTypeAccm:
		return "avpTypeAccm"
	case avpTypeRandomVector:
		return "avpTypeRandomVector"
	case avpTypePrivGroupID:
		return "avpTypePrivGroupID"
	case avpTypeRxConnectSpeed:
		return "avpTypeRxConnectSpeed"
	case avpTypeSequencingRequired:
		return "avpTypeSequencingRequired"
	case avpTypeUnused40:
		return "avpTypeUnused40"
	case avpTypeUnused41:
		return "avpTypeUnused41"
	case avpTypeUnused42:
		return "avpTypeUnused42"
	case avpTypeUnused43:
		return "avpTypeUnused43"
	case avpTypeUnused44:
		return "avpTypeUnused44"
	case avpTypeUnused45:
		return "avpTypeUnused45"
	case avpTypeUnused46:
		return "avpTypeUnused46"
	case avpTypeUnused47:
		return "avpTypeUnused47"
	case avpTypeUnused48:
		return "avpTypeUnused48"
	case avpTypeUnused49:
		return "avpTypeUnused49"
	case avpTypeUnused50:
		return "avpTypeUnused50"
	case avpTypeUnused51:
		return "avpTypeUnused51"
	case avpTypeUnused52:
		return "avpTypeUnused52"
	case avpTypeUnused53:
		return "avpTypeUnused53"
	case avpTypeUnused54:
		return "avpTypeUnused54"
	case avpTypeUnused55:
		return "avpTypeUnused55"
	case avpTypeUnused56:
		return "avpTypeUnused56"
	case avpTypeUnused57:
		return "avpTypeUnused57"
	case avpTypeExtended:
		return "avpTypeExtended"
	case avpTypeMessageDigest:
		return "avpTypeMessageDigest"
	case avpTypeRouterID:
		return "avpTypeRouterID"
	case avpTypeAssignedConnID:
		return "avpTypeAssignedConnID"
	case avpTypePseudowireCaps:
		return "avpTypePseudowireCaps"
	case avpTypeLocalSessionID:
		return "avpTypeLocalSessionID"
	case avpTypeRemoteSessionID:
		return "avpTypeRemoteSessionID"
	case avpTypeAssignedCookie:
		return "avpTypeAssignedCookie"
	case avpTypeRemoteEndID:
		return "avpTypeRemoteEndID"
	case avpTypeUnused67:
		return "avpTypeUnused67"
	case avpTypePseudowireType:
		return "avpTypePseudowireType"
	case avpTypeL2specificSublayer:
		return "avpTypeL2specificSublayer"
	case avpTypeDataSequencing:
		return "avpTypeDataSequencing"
	case avpTypeCircuitStatus:
		return "avpTypeCircuitStatus"
	case avpTypePreferredLanguage:
		return "avpTypePreferredLanguage"
	case avpTypeControlAuthNonce:
		return "avpTypeControlAuthNonce"
	case avpTypeTxConnectSpeedBps:
		return "avpTypeTxConnectSpeedBps"
	case avpTypeRxConnectSpeedBps:
		return "avpTypeRxConnectSpeedBps"
	}
	return ""
}

// String converts an avpMsgType identifier into a human-readable string.
// Implements the fmt.Stringer() interface.
var _ fmt.Stringer = (*avpMsgType)(nil)

func (t avpMsgType) String() string {
	switch t {
	case avpMsgTypeIllegal:
		return "avpMsgTypeIllegal"
	case avpMsgTypeSccrq:
		return "avpMsgTypeSccrq"
	case avpMsgTypeSccrp:
		return "avpMsgTypeSccrp"
	case avpMsgTypeScccn:
		return "avpMsgTypeScccn"
	case avpMsgTypeStopccn:
		return "avpMsgTypeStopccn"
	case avpMsgTypeReserved5:
		return "avpMsgTypeReserved5"
	case avpMsgTypeHello:
		return "avpMsgTypeHello"
	case avpMsgTypeOcrq:
		return "avpMsgTypeOcrq"
	case avpMsgTypeOcrp:
		return "avpMsgTypeOcrp"
	case avpMsgTypeOccn:
		return "avpMsgTypeOccn"
	case avpMsgTypeIcrq:
		return "avpMsgTypeIcrq"
	case avpMsgTypeIcrp:
		return "avpMsgTypeIcrp"
	case avpMsgTypeIccn:
		return "avpMsgTypeIccn"
	case avpMsgTypeReserved13:
		return "avpMsgTypeReserved13"
	case avpMsgTypeCdn:
		return "avpMsgTypeCdn"
	case avpMsgTypeWen:
		return "avpMsgTypeWen"
	case avpMsgTypeSli:
		return "avpMsgTypeSli"
	case avpMsgTypeMdmst:
		return "avpMsgTypeMdmst"
	case avpMsgTypeSrrq:
		return "avpMsgTypeSrrq"
	case avpMsgTypeSrrp:
		return "avpMsgTypeSrrp"
	case avpMsgTypeAck:
		return "avpMsgTypeAck"
	case avpMsgTypeFsq:
		return "avpMsgTypeFsq"
	case avpMsgTypeFsr:
		return "avpMsgTypeFsr"
	case avpMsgTypeMsrq:
		return "avpMsgTypeMsrq"
	case avpMsgTypeMsrp:
		return "avpMsgTypeMsrp"
	case avpMsgTypeMse:
		return "avpMsgTypeMse"
	case avpMsgTypeMsi:
		return "avpMsgTypeMsi"
	case avpMsgTypeMsen:
		return "avpMsgTypeMsen"
	case avpMsgTypeCsun:
		return "avpMsgTypeCsun"
	case avpMsgTypeCsurq:
		return "avpMsgTypeCsurq"
	}
	return ""
}

// String represents the AVP as a human-readable string.
// Implements the fmt.Stringer() interface.
var _ fmt.Stringer = (*avp)(nil)

func (avp avp) String() string {
	return fmt.Sprintf("%s %s", avp.header, avp.payload)
}

// String represents the vendor ID as a human-readable string.
// Implements the fmt.Stringer() interface.
var _ fmt.Stringer = (*avpVendorID)(nil)

func (v avpVendorID) String() string {
	if v == vendorIDIetf {
		return "IETF"
	}
	return fmt.Sprintf("Vendor %d", v)
}

// String represents the AVP data type as a human-readable string.
// Implements the fmt.Stringer() interface.
var _ fmt.Stringer = (*avpDataType)(nil)

func (t avpDataType) String() string {
	switch t {
	case avpDataTypeEmpty:
		return "no data"
	case avpDataTypeUint16:
		return "uint16"
	case avpDataTypeUint32:
		return "uint32"
	case avpDataTypeUint64:
		return "uint64"
	case avpDataTypeString:
		return "string"
	case avpDataTypeBytes:
		return "byte array"
	case avpDataTypeResultCode:
		return "result code"
	case avpDataTypeMsgID:
		return "message ID"
	case avpDataTypeUnimplemented:
		return "unimplemented AVP data type"
	case avpDataTypeIllegal:
		return "illegal AVP"
	}
	return "Unrecognised AVP data type"
}

var _ fmt.Stringer = (*avpHeader)(nil)

func (hdr avpHeader) String() string {
	m := "-"
	h := "-"
	var t string
	if hdr.VendorID == vendorIDIetf {
		t = hdr.AvpType.String()
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

var _ fmt.Stringer = (*avpPayload)(nil)

func (p avpPayload) String() string {
	var str strings.Builder

	str.WriteString(fmt.Sprintf("(%s) ", p.dataType))

	switch p.dataType {
	case avpDataTypeUint16:
		v, _ := p.toUint16()
		str.WriteString(fmt.Sprintf("%d", v))
	case avpDataTypeUint32:
		v, _ := p.toUint32()
		str.WriteString(fmt.Sprintf("%d", v))
	case avpDataTypeUint64:
		v, _ := p.toUint64()
		str.WriteString(fmt.Sprintf("%d", v))
	case avpDataTypeString:
		s, _ := p.toString()
		str.WriteString(s)
	case avpDataTypeBytes:
		str.WriteString(fmt.Sprintf("%s", p.data))
	case avpDataTypeEmpty, avpDataTypeUnimplemented, avpDataTypeIllegal:
		str.WriteString("")
	}

	return str.String()
}

func (hdr *avpHeader) isMandatory() bool {
	return (0x8000 & hdr.FlagLen) == 0x8000
}

func (hdr *avpHeader) isHidden() bool {
	return (0x4000 & hdr.FlagLen) == 0x4000
}

func (hdr *avpHeader) totalLen() int {
	return int(0x3ff & hdr.FlagLen)
}

func (hdr *avpHeader) dataLen() int {
	return hdr.totalLen() - avpHeaderLen
}

func newAvpHeader(isMandatory, isHidden bool,
	payloadBytes uint,
	vid avpVendorID,
	typ avpType) *avpHeader {
	var flagLen avpFlagLen = 0x0
	if isMandatory {
		flagLen = flagLen ^ 0x8000
	}
	if isHidden {
		flagLen = flagLen ^ 0x4000
	}
	flagLen = flagLen ^ avpFlagLen(0x3ff&(payloadBytes+avpHeaderLen))
	return &avpHeader{
		FlagLen:  flagLen,
		VendorID: vid,
		AvpType:  typ,
	}
}

// isMandatory returns true if a given AVP is flagged as being mandatory.
// The RFCs state that if an unrecognised AVP with the mandatory flag set
// is received by an implementation, the implementation MUST terminate the
// associated tunnel or session instance.
func (avp *avp) isMandatory() bool {
	return avp.header.isMandatory()
}

// isHidden returns true if a given AVP has been obscured using the hiding
// algorithm described by RFC2661 Section 4.3.
func (avp *avp) isHidden() bool {
	return avp.header.isHidden()
}

// type returns the type identifier for the AVP.
func (avp *avp) getType() avpType {
	return avp.header.AvpType
}

// vendorID returns the vendor ID for the AVP.
// Standard AVPs per RFC2661 and RFC3931 will use the IETF namespace.
// Vendor-specific AVPs will use a per-vendor ID.
func (avp *avp) vendorID() avpVendorID {
	return avp.header.VendorID
}

// totalLen returns the total number of bytes consumed by the AVP, inclusive
// of the AVP header and data payload.
func (avp *avp) totalLen() int {
	return avp.header.totalLen()
}

func getAVPInfo(avpType avpType, VendorID avpVendorID) (*avpInfo, error) {
	for _, info := range avpInfoTable {
		if info.avpType == avpType && info.VendorID == VendorID {
			return &info, nil
		}
	}
	return nil, errors.New("unrecognised AVP type")
}

// parseAVPBuffer takes a byte slice of encoded AVP data and parses it
// into an array of AVP instances.
func parseAVPBuffer(b []byte) (avps []avp, err error) {
	r := bytes.NewReader(b)
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
				return nil, fmt.Errorf("failed to parse mandatory AVP: %v", err)
			}
			// RFC2661 section 4.1 says unrecognised AVPs without the
			// mandatory bit set MUST be ignored
			continue
		}

		// Bounds check the AVP
		if h.dataLen() > r.Len() {
			return nil, errors.New("malformed AVP buffer: current AVP length exceeds buffer length")
		}

		if cursor, err = r.Seek(0, io.SeekCurrent); err != nil {
			return nil, errors.New("malformed AVP buffer: unable to determine offset of current AVP")
		}

		avps = append(avps, avp{
			header: h,
			payload: avpPayload{
				dataType: info.dataType,
				data:     b[cursor : cursor+int64(h.dataLen())],
			},
		})

		// Step on to the next AVP in the buffer
		if _, err := r.Seek(int64(h.dataLen()), io.SeekCurrent); err != nil {
			return nil, errors.New("malformed AVP buffer: invalid length for current AVP")
		}
	}

	// We must have parsed at least one AVP
	if len(avps) == 0 {
		return nil, errors.New("no AVPs present in the input buffer")
	}

	return avps, nil
}

func encodeResultCode(rc *resultCode) ([]byte, error) {
	encBuf := new(bytes.Buffer)
	err := binary.Write(encBuf, binary.BigEndian, rc.result)
	if err != nil {
		return nil, err
	}
	err = binary.Write(encBuf, binary.BigEndian, rc.errCode)
	if err != nil {
		return nil, err
	}
	if rc.errMsg != "" {
		err = binary.Write(encBuf, binary.BigEndian, []byte(rc.errMsg))
		if err != nil {
			return nil, err
		}
	}
	return encBuf.Bytes(), nil
}

func encodePayload(info *avpInfo, value interface{}) ([]byte, error) {
	var ok bool

	switch info.dataType {
	case avpDataTypeEmpty:
	case avpDataTypeUint16:
		_, ok = value.(uint16)
	case avpDataTypeUint32:
		_, ok = value.(uint32)
	case avpDataTypeUint64:
		_, ok = value.(uint64)
	case avpDataTypeString:
		var s string
		s, ok = value.(string)
		value = []byte(s)
	case avpDataTypeBytes:
		_, ok = value.([]byte)
	case avpDataTypeMsgID:
		_, ok = value.(avpMsgType)
	case avpDataTypeResultCode:
		var rc resultCode
		rc, ok = value.(resultCode)
		if ok {
			return encodeResultCode(&rc)
		} else {
			var rcp *resultCode
			rcp, ok = value.(*resultCode)
			if ok {
				return encodeResultCode(rcp)
			}
		}
	case avpDataTypeUnimplemented, avpDataTypeIllegal:
		return nil, fmt.Errorf("AVP %v is not currently supported", info.avpType)
	}

	if !ok {
		return nil, fmt.Errorf("wrong data type %T passed for %v", value, info.avpType)
	}

	encBuf := new(bytes.Buffer)
	err := binary.Write(encBuf, binary.BigEndian, value)
	if err != nil {
		return nil, err
	}
	return encBuf.Bytes(), nil
}

// newAvp builds an AVP containing the specified data
func newAvp(vendorID avpVendorID, avpType avpType, value interface{}) (a *avp, err error) {

	info, err := getAVPInfo(avpType, vendorID)
	if err != nil {
		return nil, err
	}

	buf, err := encodePayload(info, value)
	if err != nil {
		return nil, err
	}

	return &avp{
		header: *newAvpHeader(info.isMandatory, false, uint(len(buf)), vendorID, avpType),
		payload: avpPayload{
			dataType: info.dataType,
			data:     buf,
		},
	}, nil
}

// rawData returns the data type for the AVP, along with the raw byte
// slice for the data carried by the AVP.
func (avp *avp) rawData() (dataType avpDataType, buffer []byte) {
	return avp.payload.dataType, avp.payload.data
}

// isDataType returns true if the AVP holds the specified data type.
func (avp *avp) isDataType(dt avpDataType) bool {
	return avp.payload.dataType == dt
}

func (p *avpPayload) toUint16() (out uint16, err error) {
	if len(p.data) > 2 {
		return 0, fmt.Errorf("AVP payload length %v exceeds expected length 2", len(p.data))
	}
	r := bytes.NewReader(p.data)
	if err = binary.Read(r, binary.BigEndian, &out); err != nil {
		return 0, err
	}
	return out, err
}

func (p *avpPayload) toUint32() (out uint32, err error) {
	if len(p.data) > 4 {
		return 0, fmt.Errorf("AVP payload length %v exceeds expected length 4", len(p.data))
	}
	r := bytes.NewReader(p.data)
	if err = binary.Read(r, binary.BigEndian, &out); err != nil {
		return 0, err
	}
	return out, err
}

func (p *avpPayload) toUint64() (out uint64, err error) {
	if len(p.data) > 8 {
		return 0, fmt.Errorf("AVP payload length %v exceeds expected length 8", len(p.data))
	}
	r := bytes.NewReader(p.data)
	if err = binary.Read(r, binary.BigEndian, &out); err != nil {
		return 0, err
	}
	return out, err
}

func (p *avpPayload) toString() (out string, err error) {
	return string(p.data), nil
}

func (p *avpPayload) toResultCode() (out resultCode, err error) {
	var resCode, errCode uint16
	var errMsg string

	r := bytes.NewReader(p.data)

	if err = binary.Read(r, binary.BigEndian, &resCode); err != nil {
		return resultCode{}, err
	}
	if r.Len() > 0 {
		if err = binary.Read(r, binary.BigEndian, &errCode); err != nil {
			return resultCode{}, err
		}
		if r.Len() > 0 {
			errMsg = string(p.data[4:])
		}
	}
	return resultCode{
		result:  avpResultCode(resCode),
		errCode: avpErrorCode(errCode),
		errMsg:  errMsg,
	}, nil
}

// decode decodes an AVP based on its data type.
// An error is returned if the AVP cannot be decoded successfully.
func (avp *avp) decode() (interface{}, error) {
	switch avp.payload.dataType {
	case avpDataTypeEmpty:
		return nil, nil
	case avpDataTypeUint16:
		return avp.payload.toUint16()
	case avpDataTypeUint32:
		return avp.payload.toUint32()
	case avpDataTypeUint64:
		return avp.payload.toUint64()
	case avpDataTypeString:
		return avp.payload.toString()
	case avpDataTypeBytes:
		return avp.payload.data, nil
	case avpDataTypeResultCode:
		return avp.payload.toResultCode()
	case avpDataTypeMsgID:
		v, err := avp.payload.toUint16()
		if err != nil {
			return nil, err
		}
		return avpMsgType(v), nil
	}
	return nil, fmt.Errorf("unhandled AVP data type")
}

// decodeUint16Data decodes an AVP holding a uint16 value.
// It is an error to call this function on an AVP which doesn't
// contain a uint16 payload.
func (avp *avp) decodeUint16Data() (value uint16, err error) {
	if !avp.isDataType(avpDataTypeUint16) {
		return 0, errors.New("AVP data is not of type uint16, cannot decode")
	}
	return avp.payload.toUint16()
}

// decodeUint32Data decodes an AVP holding a uint32 value.
// It is an error to call this function on an AVP which doesn't
// contain a uint32 payload.
func (avp *avp) decodeUint32Data() (value uint32, err error) {
	if !avp.isDataType(avpDataTypeUint32) {
		return 0, errors.New("AVP data is not of type uint32, cannot decode")
	}
	return avp.payload.toUint32()
}

// decodeUint64Data decodes an AVP holding a uint64 value.
// It is an error to call this function on an AVP which doesn't
// contain a uint64 payload.
func (avp *avp) decodeUint64Data() (value uint64, err error) {
	if !avp.isDataType(avpDataTypeUint64) {
		return 0, errors.New("AVP data is not of type uint64, cannot decode")
	}
	return avp.payload.toUint64()
}

// decodeStringData decodes an AVP holding a string value.
// It is an error to call this function on an AVP which doesn't
// contain a string payload.
func (avp *avp) decodeStringData() (value string, err error) {
	if !avp.isDataType(avpDataTypeString) {
		return "", errors.New("AVP data is not of type string, cannot decode")
	}
	return avp.payload.toString()
}

// decodeResultCode decodes an AVP holding a RFC2661/RFC3931 Result Code.
// It is an error to call this function on an AVP which doesn't contain
// a result code payload.
func (avp *avp) decodeResultCode() (value resultCode, err error) {
	if !avp.isDataType(avpDataTypeResultCode) {
		return resultCode{}, errors.New("AVP is not of type result code, cannot decode")
	}
	return avp.payload.toResultCode()
}

// decodeMsgType decodes an AVP holding a message type ID.
// It is an error to call this function on an AVP which doesn't contain
// a message ID payload.
func (avp *avp) decodeMsgType() (value avpMsgType, err error) {
	if !avp.isDataType(avpDataTypeMsgID) {
		return avpMsgTypeIllegal, errors.New("AVP is not of type message ID, cannot decode")
	}
	out, err := avp.payload.toUint16()
	return avpMsgType(out), err
}

// avpsLengthBytes returns the length of a slice of AVPs in bytes
func avpsLengthBytes(avps []avp) int {
	var nb int
	for _, avp := range avps {
		nb += avp.totalLen()
	}
	return nb
}

// findAvp looks up a specific AVP in a slice of AVPs
// An error will be returned if the requested AVP isn't present in the slice.
func findAvp(avps []avp, vendorID avpVendorID, typ avpType) (*avp, error) {
	for _, a := range avps {
		if a.vendorID() == vendorID && a.getType() == typ {
			return &a, nil
		}
	}
	return nil, fmt.Errorf("AVP %v %v not found", vendorID, typ)
}

// findUint16Avp looks up a specific AVP in a slice of AVPs and decodes as uint16.
// An error will be returned if the AVP isn't present or is of the wrong type.
func findUint16Avp(avps []avp, vendorID avpVendorID, typ avpType) (uint16, error) {
	avp, err := findAvp(avps, vendorID, typ)
	if err != nil {
		return 0, err
	}
	val, err := avp.decodeUint16Data()
	if err != nil {
		return 0, fmt.Errorf("failed to decode %v: %v", typ, err)
	}
	return val, nil
}

// findUint32Avp looks up a specific AVP in a slice of AVPs and decodes as uint32.
// An error will be returned if the AVP isn't present or is of the wrong type.
func findUint32Avp(avps []avp, vendorID avpVendorID, typ avpType) (uint32, error) {
	avp, err := findAvp(avps, vendorID, typ)
	if err != nil {
		return 0, err
	}
	val, err := avp.decodeUint32Data()
	if err != nil {
		return 0, fmt.Errorf("failed to decode %v: %v", typ, err)
	}
	return val, nil
}

// findUint64Avp looks up a specific AVP in a slice of AVPs and decodes as uint64.
// An error will be returned if the AVP isn't present or is of the wrong type.
func findUint64Avp(avps []avp, vendorID avpVendorID, typ avpType) (uint64, error) {
	avp, err := findAvp(avps, vendorID, typ)
	if err != nil {
		return 0, err
	}
	val, err := avp.decodeUint64Data()
	if err != nil {
		return 0, fmt.Errorf("failed to decode %v: %v", typ, err)
	}
	return val, nil
}

// findBytesAvp looks up a specific AVP in a slice of AVPs and decodes as a byte slice.
// An error will be returned if the AVP isn't present or is of the wrong type.
func findBytesAvp(avps []avp, vendorID avpVendorID, typ avpType) ([]byte, error) {
	avp, err := findAvp(avps, vendorID, typ)
	if err != nil {
		return nil, err
	}
	return avp.payload.data, nil
}

// findStringAvp looks up a specific AVP in a slice of AVPs and decodes as a string.
// An error will be returned if the AVP isn't present or is of the wrong type.
func findStringAvp(avps []avp, vendorID avpVendorID, typ avpType) (string, error) {
	avp, err := findAvp(avps, vendorID, typ)
	if err != nil {
		return "", err
	}
	val, err := avp.decodeStringData()
	if err != nil {
		return "", fmt.Errorf("failed to decode %v: %v", typ, err)
	}
	return val, nil
}
