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
					v2msg, ok := g.(*L2tpV2ControlMessage)
					if ok {
						if v2msg.Tid() != c.want[i].tid {
							t.Errorf("Tid() == %q, want %q", v2msg.Tid(), c.want[i].tid)
						}
						if v2msg.Sid() != c.want[i].sid {
							t.Errorf("Sid() == %q, want %q", v2msg.Sid(), c.want[i].sid)
						}
					} else {
						t.Errorf("Expected L2tpV2ControlMessage, but didn't receive one")
					}
				case nll2tp.ProtocolVersion3:
					v3msg, ok := g.(*L2tpV3ControlMessage)
					if ok {
						if v3msg.ControlConnectionID() != c.want[i].ccid {
							t.Errorf("ControlConnectionID() == %q, want %q", v3msg.ControlConnectionID(), c.want[i].ccid)
						}
					} else {
						t.Errorf("Expected L2tpV3ControlMessage, but didn't receive one")
					}
				}
			}
		} else {
			t.Errorf("ParseMessageBuffer(%q) failed: %q", c.in, err)
		}
	}
}
