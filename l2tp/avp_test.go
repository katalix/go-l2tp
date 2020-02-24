package l2tp

import (
	"fmt"
	"reflect"
	"testing"
)

func TestParseAVPBufferGood(t *testing.T) {
	cases := []struct {
		in   []byte
		want []AVP
	}{
		{
			in: []byte{0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06}, // message type
			want: []AVP{
				AVP{
					header:  avpHeader{FlagLen: 0x8008, VendorID: 0, AvpType: AvpTypeMessage},
					payload: avpPayload{dataType: AvpDataTypeUint16, data: []byte{0x00, 0x06}},
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
			want: []AVP{
				AVP{
					header:  avpHeader{FlagLen: 0x8008, VendorID: 0, AvpType: AvpTypeMessage},
					payload: avpPayload{dataType: AvpDataTypeUint16, data: []byte{0x00, 0x01}},
				},
				AVP{
					header:  avpHeader{FlagLen: 0x0008, VendorID: 0, AvpType: AvpTypeProtocolVersion},
					payload: avpPayload{dataType: AvpDataTypeBytes, data: []byte{0x01, 0x00}},
				},
				AVP{
					header:  avpHeader{FlagLen: 0x800a, VendorID: 0, AvpType: AvpTypeFramingCap},
					payload: avpPayload{dataType: AvpDataTypeUint32, data: []byte{0x00, 0x00, 0x00, 0x03}},
				},
				AVP{
					header: avpHeader{FlagLen: 0x0034, VendorID: 0, AvpType: AvpTypeVendorName},
					payload: avpPayload{dataType: AvpDataTypeString,
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
	}
	for _, c := range cases {
		got, err := ParseAVPBuffer(c.in)
		if err == nil {
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("ParseAVPBuffer() == %q; want %q", got, c.want)
			}
		} else {
			t.Errorf("ParseAVPBuffer(%q) failed: %q", c.in, err)
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
		avps, err := ParseAVPBuffer(c.in)
		if err == nil {
			t.Errorf("ParseAVPBuffer(%q): expected error, but did not get one", c.in)
		}
		if len(avps) != 0 {
			t.Errorf("ParseAVPBuffer(%q): expect zero-length AVP buffer output, but didn't get it", c.in)
		}
	}
}

type avpMetadata struct {
	mandatory, hidden bool
	typ               AVPType
	vid               AVPVendorID
	dtyp              AVPDataType
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
				avpMetadata{mandatory: true, hidden: false, typ: AvpTypeHostName, vid: VendorIDIetf, dtyp: AvpDataTypeString, nbytes: 6},
			},
		},
		{
			in: []byte{0x80, 0x08, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a}, // receive window size
			want: []avpMetadata{
				avpMetadata{mandatory: true, hidden: false, typ: AvpTypeRxWindowSize, vid: VendorIDIetf, dtyp: AvpDataTypeUint16, nbytes: 2},
			},
		},
	}
	for _, c := range cases {
		got, err := ParseAVPBuffer(c.in)
		if err == nil {
			for i, gi := range got {
				dtyp, buf := gi.RawData()
				gotmd := avpMetadata{
					mandatory: gi.IsMandatory(),
					hidden:    gi.IsHidden(),
					typ:       gi.Type(),
					vid:       gi.VendorID(),
					dtyp:      dtyp,
					nbytes:    len(buf),
				}
				if !reflect.DeepEqual(gotmd, c.want[i]) {
					t.Errorf("metadata == %s; want %s", gotmd, c.want[i])
				}
			}
		} else {
			t.Errorf("ParseAVPBuffer(%q) failed: %q", c.in, err)
		}
	}
}

func TestAVPTypeStringer(t *testing.T) {
	for i := AvpTypeMessage; i < AvpTypeMax; i++ {
		s := i.String()
		if len(s) == 0 {
			t.Errorf("AVPType stringer returned empty string for value %d", uint16(i))
		}
	}
}

func TestAVPMsgTypeStringer(t *testing.T) {
	for i := AvpMsgTypeIllegal; i < AvpMsgTypeMax; i++ {
		s := i.String()
		if len(s) == 0 {
			t.Errorf("AVPMsgType stringer returned empty string for value %d", uint16(i))
		}
	}
}

func TestAVPDataTypeStringer(t *testing.T) {
	for i := AvpDataTypeEmpty; i < AvpDataTypeMax; i++ {
		s := i.String()
		if len(s) == 0 {
			t.Errorf("AVPDataType stringer returned empty string for value %d", uint16(i))
		}
	}
}
