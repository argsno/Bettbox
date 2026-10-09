//go:build darwin || linux

package sockstat

import (
	"io"
	"net"
	"testing"
)

// TestSampleLiveSocket exercises the platform sampleFD hook through Sample on
// a real loopback TCP socket. Both platforms covered by this build tag ship a
// collector, and the loss penalty silently disappears if it regresses to the
// fallback stub.
func TestSampleLiveSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	payload := make([]byte, 256*1024)
	readDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			readDone <- err
			return
		}
		defer conn.Close()
		_, err = io.CopyN(io.Discard, conn, int64(len(payload)))
		readDone <- err
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("peer read: %v", err)
	}

	stats, ok := Sample(conn)
	if !ok {
		t.Fatalf("Sample must report counters for a live TCP socket")
	}
	if _, ok := stats.RetransmitRatio(); !ok {
		t.Fatalf("transmitted traffic must yield packet or byte counters, got %+v", stats)
	}
}
