package l2tp

import (
	"testing"
)

func TestOpenClose(t *testing.T) {
	xport, err := NewTransport(nil, DefaultTransportConfig())
	if xport != nil {
		t.Fatalf("NewTransport() with nil controlplane succeeded")
	} else if err == nil {
		t.Fatalf("NewTransport() with nil controlplane didn't report error")
	}

	cp, err := newL2tpControlPlane("127.0.0.1:5000", "127.0.0.1:6000", false)
	if err != nil {
		t.Fatalf("newL2tpControlPlane() failed: %v", err)
	}

	xport, err = NewTransport(cp, DefaultTransportConfig())
	if xport == nil {
		t.Fatalf("NewTransport() returned nil controlplane")
	} else if err != nil {
		t.Fatalf("NewTransport() error")
	}

	xport.Close()
}
