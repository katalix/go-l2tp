package l2tp

import (
	//"fmt"
	//	"reflect"
	"testing"

	"github.com/katalix/sl2tpd/internal/nll2tp"
)

type msgInfo struct {
	version          nll2tp.L2tpProtocolVersion
	ns, nr, tid, sid uint16
	ccid             uint32
	navps            int
	msgType          AVPMsgType
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
				{version: nll2tp.ProtocolVersion2, ns: 1, nr: 1, tid: 1, sid: 0, navps: 1, msgType: AvpMsgTypeHello},
			},
		},
		{
			in: []byte{
				0xc8, 0x02, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00,
				0x00, 0x01, 0x00, 0x01,
			},
			want: []msgInfo{
				{version: nll2tp.ProtocolVersion2, tid: 1, sid: 0, ns: 1, nr: 1, navps: 0, msgType: AvpMsgTypeAck},
			},
		},
	}
	for _, c := range cases {
		got, err := ParseMessageBuffer(c.in)
		if err == nil {
			for i, g := range got {
				// common checks
				if g.ProtocolVersion() != c.want[i].version {
					t.Errorf("ProtocolVersion() == %q, want %q", g.ProtocolVersion(), c.want[i].version)
				}
				if g.Len() != len(c.in) {
					t.Errorf("Len() == %q, want %q", g.Len(), len(c.in))
				}
				if g.Ns() != c.want[i].ns {
					t.Errorf("Ns() == %q, want %q", g.Ns(), c.want[i].ns)
				}
				if g.Nr() != c.want[i].nr {
					t.Errorf("Nr() == %q, want %q", g.Nr(), c.want[i].nr)
				}
				if len(g.Avps()) != c.want[i].navps {
					t.Errorf("AVP count failed: got %q, want %q", len(g.Avps()), c.want[i].navps)
				}
				if g.Type() != c.want[i].msgType {
					t.Errorf("Type() == %q, want %q", g.Type(), c.want[i].msgType)
				}
				// version specifics
				switch c.want[i].version {
				case nll2tp.ProtocolVersion2:
					v2msg, ok := g.(*V2ControlMessage)
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
					v3msg, ok := g.(*V3ControlMessage)
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
			t.Errorf("ParseMessageBuffer(%q) failed: %q", c.in, err)
		}
	}
}

type msgTestAvpMetadata struct {
	isMandatory, isHidden bool
	avpType               AVPType
	vendorID              AVPVendorID
	dataType              AVPDataType
	data                  interface{}
}

func TestV2MessageBuild(t *testing.T) {
	cases := []struct {
		tid  uint16
		sid  uint16
		avps []msgTestAvpMetadata
	}{
		{
			tid: 42, sid: 42, avps: []msgTestAvpMetadata{
				{true, false, AvpTypeMessage, VendorIDIetf, AvpDataTypeMsgID, AvpMsgTypeHello},
			},
		},
	}
	for _, c := range cases {
		avps := []AVP{}

		for _, avp := range c.avps {
			a, err := NewAvp(avp.vendorID, avp.avpType, avp.data)
			if err != nil {
				t.Fatalf("NewAvp(%v, %v, %v) said: %v", avp.vendorID, avp.avpType, avp.data, err)
			}
			avps = append(avps, *a)
		}

		msg, err := NewV2ControlMessage(c.tid, c.sid, avps)
		if err != nil {
			t.Fatalf("NewV2ControlMessage(%v, %v, %v) said: %v", c.tid, c.sid, avps, err)
		}

		if msg.Type() != c.avps[0].data {
			t.Fatalf("%v != %v", msg.Type(), c.avps[0].data)
		}
	}
}
