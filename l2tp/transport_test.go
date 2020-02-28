package l2tp

import (
	"testing"
	"time"
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

	// Sleep briefly to allow the go routines to get scheduled:
	// we want to at least run the code there to give us a chance
	// to trip over e.g. uninitialised fields
	time.Sleep(1 * time.Millisecond)

	xport.Close()
}
