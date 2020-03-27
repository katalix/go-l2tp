package l2tp

import (
	"bytes"
	"testing"

	"github.com/katalix/go-l2tp/internal/nll2tp"
)

type msgInfo struct {
	version          nll2tp.L2tpProtocolVersion
	ns, nr, tid, sid uint16
	ccid             uint32
	navps            int
	msgType          avpMsgType
}

func TestParseMessageBuffer(t *testing.T) {
	cases := []struct {
		in   []byte
		want []msgInfo
	}{
		{
			in: []byte{
				0xc8, 0x02, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00,
				0x00, 0x01, 0x00, 0x01, 0x80, 0x08, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x06,
			},
			want: []msgInfo{
				{version: nll2tp.ProtocolVersion2, ns: 1, nr: 1, tid: 1, sid: 0, navps: 1, msgType: avpMsgTypeHello},
			},
		},
		{
			in: []byte{
				0xc8, 0x02, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00,
				0x00, 0x01, 0x00, 0x01,
			},
			want: []msgInfo{
				{version: nll2tp.ProtocolVersion2, tid: 1, sid: 0, ns: 1, nr: 1, navps: 0, msgType: avpMsgTypeAck},
			},
		},
		{
			in: []byte{
				0xc8, 0x03, 0x00, 0x7c, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x80, 0x08, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01, 0x80, 0x0c, 0x00, 0x00,
				0x00, 0x07, 0x6f, 0x70, 0x65, 0x6e, 0x76, 0x33,
				0x00, 0x34, 0x00, 0x00, 0x00, 0x08, 0x70, 0x72,
				0x6f, 0x6c, 0x32, 0x74, 0x70, 0x20, 0x31, 0x2e,
				0x37, 0x2e, 0x33, 0x20, 0x4c, 0x69, 0x6e, 0x75,
				0x78, 0x2d, 0x33, 0x2e, 0x31, 0x33, 0x2e, 0x30,
				0x2d, 0x33, 0x30, 0x2d, 0x67, 0x65, 0x6e, 0x65,
				0x72, 0x69, 0x63, 0x20, 0x28, 0x78, 0x38, 0x36,
				0x5f, 0x36, 0x34, 0x29, 0x80, 0x08, 0x00, 0x00,
				0x00, 0x0a, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x00,
				0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
				0x00, 0x00, 0x00, 0x3d, 0x28, 0x46, 0xf1, 0x81,
				0x00, 0x0c, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x07,
				0x00, 0x05, 0x00, 0x04,
			},
			want: []msgInfo{
				{version: nll2tp.ProtocolVersion3, ns: 0, nr: 0, ccid: 0, navps: 7, msgType: avpMsgTypeSccrq},
			},
		},
	}
	for _, c := range cases {
		got, err := parseMessageBuffer(c.in)
		if err == nil {
			for i, g := range got {
				// common checks
				if g.protocolVersion() != c.want[i].version {
					t.Errorf("ProtocolVersion() == %q, want %q", g.protocolVersion(), c.want[i].version)
				}
				if g.getLen() != len(c.in) {
					t.Errorf("Len() == %q, want %q", g.getLen(), len(c.in))
				}
				if g.ns() != c.want[i].ns {
					t.Errorf("Ns() == %q, want %q", g.ns(), c.want[i].ns)
				}
				if g.nr() != c.want[i].nr {
					t.Errorf("Nr() == %q, want %q", g.nr(), c.want[i].nr)
				}
				if len(g.getAvps()) != c.want[i].navps {
					t.Errorf("AVP count failed: got %q, want %q", len(g.getAvps()), c.want[i].navps)
				}
				if g.getType() != c.want[i].msgType {
					t.Errorf("Type() == %q, want %q", g.getType(), c.want[i].msgType)
				}
				// version specifics
				switch c.want[i].version {
				case nll2tp.ProtocolVersion2:
					v2msg, ok := g.(*v2ControlMessage)
					if ok {
						if v2msg.Tid() != c.want[i].tid {
							t.Errorf("Tid() == %q, want %q", v2msg.Tid(), c.want[i].tid)
						}
						if v2msg.Sid() != c.want[i].sid {
							t.Errorf("Sid() == %q, want %q", v2msg.Sid(), c.want[i].sid)
						}
					} else {
						t.Errorf("Expected V2ControlMessage, but didn't receive one")
					}
				case nll2tp.ProtocolVersion3:
					v3msg, ok := g.(*v3ControlMessage)
					if ok {
						if v3msg.ControlConnectionID() != c.want[i].ccid {
							t.Errorf("ControlConnectionID() == %q, want %q", v3msg.ControlConnectionID(), c.want[i].ccid)
						}
					} else {
						t.Errorf("Expected V3ControlMessage, but didn't receive one")
					}
				}
			}
		} else {
			t.Errorf("parseMessageBuffer(%q) failed: %q", c.in, err)
		}
	}
}

type msgTestAvpMetadata struct {
	isMandatory, isHidden bool
	avpType               avpType
	vendorID              avpVendorID
	dataType              avpDataType
	data                  interface{}
}

func TestV2MessageBuild(t *testing.T) {
	cases := []struct {
		tid  ControlConnID
		sid  ControlConnID
		avps []msgTestAvpMetadata
	}{
		{
			tid: 42, sid: 42, avps: []msgTestAvpMetadata{
				{true, false, avpTypeMessage, vendorIDIetf, avpDataTypeMsgID, avpMsgTypeHello},
			},
		},
	}
	for _, c := range cases {

		msg, err := newV2ControlMessage(c.tid, c.sid, []avp{})
		if err != nil {
			t.Fatalf("newV2ControlMessage(%v, %v, []) said: %v", c.tid, c.sid, err)
		}

		for _, in := range c.avps {
			avp, err := newAvp(in.vendorID, in.avpType, in.data)
			if err != nil {
				t.Fatalf("newAvp(%v, %v, %v) said: %v", in.vendorID, in.avpType, in.data, err)
			}
			msg.appendAvp(avp)
		}

		if msg.getType() != c.avps[0].data {
			t.Fatalf("%v != %v", msg.getType(), c.avps[0].data)
		}
	}
}

func TestV3MessageBuild(t *testing.T) {
	cases := []struct {
		ccid ControlConnID
		avps []msgTestAvpMetadata
	}{
		{
			ccid: 90210, avps: []msgTestAvpMetadata{
				{true, false, avpTypeMessage, vendorIDIetf, avpDataTypeMsgID, avpMsgTypeHello},
			},
		},
	}
	for _, c := range cases {

		msg, err := newV3ControlMessage(c.ccid, []avp{})
		if err != nil {
			t.Fatalf("newV3ControlMessage(%v, []) said: %v", c.ccid, err)
		}

		for _, in := range c.avps {
			avp, err := newAvp(in.vendorID, in.avpType, in.data)
			if err != nil {
				t.Fatalf("newAvp(%v, %v, %v) said: %v", in.vendorID, in.avpType, in.data, err)
			}
			msg.appendAvp(avp)
		}

		if msg.getType() != c.avps[0].data {
			t.Fatalf("%v != %v", msg.getType(), c.avps[0].data)
		}
	}
}

func TestParseEncode(t *testing.T) {
	cases := []struct {
		in []byte
	}{
		{in: []byte{
			0xc8, 0x02, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x01, 0x00, 0x01, 0x80, 0x08, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x06,
		},
		},
	}
	for _, c := range cases {
		got, err := parseMessageBuffer(c.in)
		if err != nil {
			t.Fatalf("parseMessageBuffer(%v) failed: %v", c.in, err)
		}
		if len(got) != 1 {
			t.Fatalf("parseMessageBuffer(%v): wanted 1 message, got %d", c.in, len(got))
		}
		mb, err := got[0].toBytes()
		if err != nil {
			t.Fatalf("toBytes() failed: %v", err)
		}
		if !bytes.Equal(mb, c.in) {
			t.Fatalf("toBytes(): wanted %v, got %v", c.in, mb)
		}
	}
}
