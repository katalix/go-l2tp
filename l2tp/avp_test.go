package l2tp

import (
	"fmt"
	"reflect"
	"testing"
)

func TestParseAVPBufferGood(t *testing.T) {
	cases := []struct {
		in   []byte
		want []avp
	}{
		{
			in: []byte{0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06}, // message type
			want: []avp{
				avp{
					header:  avpHeader{FlagLen: 0x8008, VendorID: 0, AvpType: avpTypeMessage},
					payload: avpPayload{dataType: avpDataTypeMsgID, data: []byte{0x00, 0x06}},
				},
			},
		},
		{
			in: []byte{
				0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // message type
				0x00, 0x08, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, // protocol version
				0x80, 0x0a, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, // framing cap
				0x00, 0x34, 0x00, 0x00, 0x00, 0x08, 0x70, 0x72, 0x6f, 0x6c, 0x32, 0x74, 0x70, 0x20, 0x31, 0x2e,
				0x37, 0x2e, 0x33, 0x20, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x2d, 0x33, 0x2e, 0x31, 0x33, 0x2e, 0x30,
				0x2d, 0x37, 0x31, 0x2d, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x20, 0x28, 0x78, 0x38, 0x36,
				0x5f, 0x36, 0x34, 0x29, /* vendor-name AVP */
			},
			want: []avp{
				avp{
					header:  avpHeader{FlagLen: 0x8008, VendorID: 0, AvpType: avpTypeMessage},
					payload: avpPayload{dataType: avpDataTypeMsgID, data: []byte{0x00, 0x01}},
				},
				avp{
					header:  avpHeader{FlagLen: 0x0008, VendorID: 0, AvpType: avpTypeProtocolVersion},
					payload: avpPayload{dataType: avpDataTypeBytes, data: []byte{0x01, 0x00}},
				},
				avp{
					header:  avpHeader{FlagLen: 0x800a, VendorID: 0, AvpType: avpTypeFramingCap},
					payload: avpPayload{dataType: avpDataTypeUint32, data: []byte{0x00, 0x00, 0x00, 0x03}},
				},
				avp{
					header: avpHeader{FlagLen: 0x0034, VendorID: 0, AvpType: avpTypeVendorName},
					payload: avpPayload{dataType: avpDataTypeString,
						data: []byte{
							0x70, 0x72, 0x6f, 0x6c, 0x32, 0x74, 0x70, 0x20,
							0x31, 0x2e, 0x37, 0x2e, 0x33, 0x20, 0x4c, 0x69,
							0x6e, 0x75, 0x78, 0x2d, 0x33, 0x2e, 0x31, 0x33,
							0x2e, 0x30, 0x2d, 0x37, 0x31, 0x2d, 0x67, 0x65,
							0x6e, 0x65, 0x72, 0x69, 0x63, 0x20, 0x28, 0x78,
							0x38, 0x36, 0x5f, 0x36, 0x34, 0x29,
						},
					},
				},
			},
		},
		{
			in: []byte{
				0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // message type
				0x80, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, // result code
				0x80, 0x08, 0x00, 0x00, 0x00, 0x09, 0x5f, 0x2b, // assigned tunnel id
			},
			want: []avp{
				avp{
					header:  avpHeader{FlagLen: 0x8008, VendorID: 0, AvpType: avpTypeMessage},
					payload: avpPayload{dataType: avpDataTypeMsgID, data: []byte{0x00, 0x04}},
				},
				avp{
					header:  avpHeader{FlagLen: 0x8008, VendorID: 0, AvpType: avpTypeResultCode},
					payload: avpPayload{dataType: avpDataTypeResultCode, data: []byte{0x00, 0x01}},
				},
				avp{
					header:  avpHeader{FlagLen: 0x8008, VendorID: 0, AvpType: avpTypeTunnelID},
					payload: avpPayload{dataType: avpDataTypeUint16, data: []byte{0x5f, 0x2b}},
				},
			},
		},
	}
	for _, c := range cases {
		got, err := parseAVPBuffer(c.in)
		if err == nil {
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("parseAVPBuffer() == %q; want %q", got, c.want)
			}
		} else {
			t.Errorf("parseAVPBuffer(%q) failed: %q", c.in, err)
		}
	}
}

func TestParseAVPBufferBad(t *testing.T) {
	cases := []struct {
		in []byte
	}{
		{
			in: []byte{}, // no avp data
		},
		{
			in: []byte{0x1, 0x2, 0x3, 0x4}, // short avp data
		},
		{
			in: []byte{0x80, 0x08, 0x01, 0xef, 0x00, 0x00, 0x00, 0x06}, // mandatory vendor AVP
		},
	}
	for _, c := range cases {
		avps, err := parseAVPBuffer(c.in)
		if err == nil {
			t.Errorf("parseAVPBuffer(%q): expected error, but did not get one", c.in)
		}
		if len(avps) != 0 {
			t.Errorf("parseAVPBuffer(%q): expect zero-length AVP buffer output, but didn't get it", c.in)
		}
	}
}

type avpMetadata struct {
	mandatory, hidden bool
	typ               avpType
	vid               avpVendorID
	dtyp              avpDataType
	nbytes            int
}

func (md avpMetadata) String() string {
	return fmt.Sprintf("%s %s mandatory: %v, hidden: %v, dtyp: %v, len: %v", md.vid, md.typ, md.mandatory, md.hidden, md.dtyp, md.nbytes)
}

func TestAVPMetadata(t *testing.T) {
	cases := []struct {
		in   []byte
		want []avpMetadata
	}{
		{
			in: []byte{0x80, 0x0c, 0x00, 0x00, 0x00, 0x07, 0x6f, 0x70, 0x65, 0x6e, 0x76, 0x33}, // hostname AVP
			want: []avpMetadata{
				avpMetadata{mandatory: true, hidden: false, typ: avpTypeHostName, vid: vendorIDIetf, dtyp: avpDataTypeString, nbytes: 6},
			},
		},
		{
			in: []byte{0x80, 0x08, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a}, // receive window size
			want: []avpMetadata{
				avpMetadata{mandatory: true, hidden: false, typ: avpTypeRxWindowSize, vid: vendorIDIetf, dtyp: avpDataTypeUint16, nbytes: 2},
			},
		},
	}
	for _, c := range cases {
		got, err := parseAVPBuffer(c.in)
		if err == nil {
			for i, gi := range got {
				dtyp, buf := gi.rawData()
				gotmd := avpMetadata{
					mandatory: gi.isMandatory(),
					hidden:    gi.isHidden(),
					typ:       gi.getType(),
					vid:       gi.vendorID(),
					dtyp:      dtyp,
					nbytes:    len(buf),
				}
				if !reflect.DeepEqual(gotmd, c.want[i]) {
					t.Errorf("metadata == %s; want %s", gotmd, c.want[i])
				}
			}
		} else {
			t.Errorf("parseAVPBuffer(%q) failed: %q", c.in, err)
		}
	}
}

func TestAVPDecodeUint16(t *testing.T) {
	cases := []struct {
		in       []byte
		wantVal  uint16
		wantType avpType
	}{
		{
			in:       []byte{0x80, 0x08, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00},
			wantVal:  0,
			wantType: avpTypeSessionID,
		},
		{
			in:       []byte{0x80, 0x08, 0x00, 0x00, 0x00, 0x09, 0x5f, 0x2b},
			wantVal:  24363,
			wantType: avpTypeTunnelID,
		},
	}
	for _, c := range cases {
		got, err := parseAVPBuffer(c.in)
		if err == nil {
			if c.wantType != got[0].getType() {
				t.Errorf("Wanted type %q, got %q", c.wantType, got[0].getType())
			}
			if val, err := got[0].decodeUint16Data(); err == nil {
				if val != c.wantVal {
					t.Errorf("Wanted value %q, got %q", c.wantVal, val)
				}
			}
		} else {
			t.Errorf("parseAVPBuffer(%q) failed: %q", c.in, err)
		}
	}
}

func TestAVPDecodeUint32(t *testing.T) {
	cases := []struct {
		in       []byte
		wantVal  uint32
		wantType avpType
	}{
		{
			in:       []byte{0x00, 0x0a, 0x00, 0x00, 0x00, 0x3d, 0x28, 0x46, 0xf1, 0x81},
			wantVal:  675737985,
			wantType: avpTypeAssignedConnID,
		},
		{
			in:       []byte{0x00, 0x0a, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00},
			wantVal:  0,
			wantType: avpTypeRouterID,
		},
		{
			in:       []byte{0x80, 0x0a, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03},
			wantVal:  3,
			wantType: avpTypeBearerCap,
		},
	}
	for _, c := range cases {
		got, err := parseAVPBuffer(c.in)
		if err == nil {
			if c.wantType != got[0].getType() {
				t.Errorf("Wanted type %q, got %q", c.wantType, got[0].getType())
			}
			if val, err := got[0].decodeUint32Data(); err == nil {
				if val != c.wantVal {
					t.Errorf("Wanted value %q, got %q", c.wantVal, val)
				}
			}
		} else {
			t.Errorf("parseAVPBuffer(%q) failed: %q", c.in, err)
		}
	}
}

func TestAVPDecodeUint64(t *testing.T) {
	cases := []struct {
		in       []byte
		wantVal  uint64
		wantType avpType
	}{
		{
			in:       []byte{0x00, 0x0e, 0x00, 0x00, 0x00, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x9a, 0xca, 0x00},
			wantVal:  1000000000,
			wantType: avpTypeRxConnectSpeedBps,
		},
	}
	for _, c := range cases {
		got, err := parseAVPBuffer(c.in)
		if err == nil {
			if c.wantType != got[0].getType() {
				t.Errorf("Wanted type %q, got %q", c.wantType, got[0].getType())
			}
			if val, err := got[0].decodeUint64Data(); err == nil {
				if val != c.wantVal {
					t.Errorf("Wanted value %q, got %q", c.wantVal, val)
				}
			}
		} else {
			t.Errorf("parseAVPBuffer(%q) failed: %q", c.in, err)
		}
	}
}

func TestAVPDecodeString(t *testing.T) {
	cases := []struct {
		in       []byte
		wantVal  string
		wantType avpType
	}{
		{
			in:       []byte{0x80, 0x0c, 0x00, 0x00, 0x00, 0x07, 0x77, 0x68, 0x6f, 0x6f, 0x73, 0x68},
			wantVal:  "whoosh",
			wantType: avpTypeHostName,
		},
		{
			in: []byte{
				0x00, 0x34, 0x00, 0x00, 0x00, 0x08, 0x70, 0x72, 0x6f, 0x6c, 0x32, 0x74, 0x70,
				0x20, 0x31, 0x2e, 0x38, 0x2e, 0x32, 0x20, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x2d,
				0x33, 0x2e, 0x31, 0x33, 0x2e, 0x30, 0x2d, 0x38, 0x35, 0x2d, 0x67, 0x65, 0x6e,
				0x65, 0x72, 0x69, 0x63, 0x20, 0x28, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x29,
			},
			wantVal:  "prol2tp 1.8.2 Linux-3.13.0-85-generic (x86_64)",
			wantType: avpTypeVendorName,
		},
	}
	for _, c := range cases {
		got, err := parseAVPBuffer(c.in)
		if err == nil {
			if c.wantType != got[0].getType() {
				t.Errorf("Wanted type %q, got %q", c.wantType, got[0].getType())
			}
			if val, err := got[0].decodeStringData(); err == nil {
				if val != c.wantVal {
					t.Errorf("Wanted value %q, got %q", c.wantVal, val)
				}
			}
		} else {
			t.Errorf("parseAVPBuffer(%q) failed: %q", c.in, err)
		}
	}
}

func TestAVPDecodeResultCode(t *testing.T) {
	cases := []struct {
		in       []byte
		wantVal  resultCode
		wantType avpType
	}{
		{
			in: []byte{0x80, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01},
			wantVal: resultCode{
				result:  avpStopCCNResultCodeClearConnection,
				errCode: avpErrorCodeNoError,
				errMsg:  "",
			},
			wantType: avpTypeResultCode,
		},
		{
			in: []byte{
				0x80, 0x1a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02,
				0x00, 0x03, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69,
				0x64, 0x20, 0x41, 0x72, 0x67, 0x75, 0x6d, 0x65,
				0x6e, 0x74},
			wantVal: resultCode{
				result:  avpStopCCNResultCodeGeneralError,
				errCode: avpErrorCodeBadValue,
				errMsg:  "Invalid Argument",
			},
			wantType: avpTypeResultCode,
		},
	}
	for _, c := range cases {
		got, err := parseAVPBuffer(c.in)
		if err == nil {
			if c.wantType != got[0].getType() {
				t.Errorf("Wanted type %q, got %q", c.wantType, got[0].getType())
			}
			if val, err := got[0].decodeResultCode(); err == nil {
				if val != c.wantVal {
					t.Errorf("Wanted value %q, got %q", c.wantVal, val)
				}
			}
		} else {
			t.Errorf("parseAVPBuffer(%q) failed: %q", c.in, err)
		}
	}
}

func TestAVPDecodeMsgID(t *testing.T) {
	cases := []struct {
		in       []byte
		wantVal  avpMsgType
		wantType avpType
	}{
		{
			in:       []byte{0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			wantVal:  avpMsgTypeSccrq,
			wantType: avpTypeMessage,
		},
		{
			in:       []byte{0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
			wantVal:  avpMsgTypeScccn,
			wantType: avpTypeMessage,
		},
		{
			in:       []byte{0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14},
			wantVal:  avpMsgTypeAck,
			wantType: avpTypeMessage,
		},
	}
	for _, c := range cases {
		got, err := parseAVPBuffer(c.in)
		if err == nil {
			if c.wantType != got[0].getType() {
				t.Errorf("Wanted type %q, got %q", c.wantType, got[0].getType())
			}
			if val, err := got[0].decodeMsgType(); err == nil {
				if val != c.wantVal {
					t.Errorf("Wanted value %q, got %q", c.wantVal, val)
				}
			}
		} else {
			t.Errorf("parseAVPBuffer(%q) failed: %q", c.in, err)
		}
	}
}

func TestEncodeUint16(t *testing.T) {
	cases := []struct {
		vendorID avpVendorID
		avpType  avpType
		value    interface{}
	}{
		{vendorID: vendorIDIetf, avpType: avpTypeTunnelID, value: uint16(9010)},
		{vendorID: vendorIDIetf, avpType: avpTypeSessionID, value: uint16(59182)},
		{vendorID: vendorIDIetf, avpType: avpTypeRxWindowSize, value: uint16(5)},
	}
	for _, c := range cases {
		if avp, err := newAvp(c.vendorID, c.avpType, c.value); err == nil {
			if !avp.isDataType(avpDataTypeUint16) {
				t.Errorf("Data type check failed")
			}
			if val, err := avp.decodeUint16Data(); err == nil {
				if val != c.value {
					t.Errorf("encode/decode failed: expected %q, got %q", c.value, val)
				}
			} else {
				t.Errorf("DecodeUint16Data() failed: %q", err)
			}
		} else {
			t.Errorf("newAvp(%v, %v, %v) failed: %q", c.vendorID, c.avpType, c.value, err)
		}
	}
}

func TestAvpTypeStringer(t *testing.T) {
	for i := avpTypeMessage; i < avpTypeMax; i++ {
		s := i.String()
		if len(s) == 0 {
			t.Errorf("avpType stringer returned empty string for value %d", uint16(i))
		}
	}
}

func TestAvpMsgTypeStringer(t *testing.T) {
	for i := avpMsgTypeIllegal; i < avpMsgTypeMax; i++ {
		s := i.String()
		if len(s) == 0 {
			t.Errorf("avpMsgType stringer returned empty string for value %d", uint16(i))
		}
	}
}

func TestAvpDataTypeStringer(t *testing.T) {
	for i := avpDataTypeEmpty; i < avpDataTypeMax; i++ {
		s := i.String()
		if len(s) == 0 {
			t.Errorf("avpDataType stringer returned empty string for value %d", uint16(i))
		}
	}
}
