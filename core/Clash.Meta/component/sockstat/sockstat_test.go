package sockstat

import (
	"errors"
	"io"
	"math"
	"net"
	"syscall"
	"testing"
)

func TestTCPStatsRetransmitRatio(t *testing.T) {
	// packet counters are preferred
	stats := TCPStats{TxPackets: 1000, RetransPackets: 25, TxBytes: 100000, RetransBytes: 9999}
	ratio, ok := stats.RetransmitRatio()
	if !ok || math.Abs(ratio-0.025) > 0.0001 {
		t.Fatalf("packet ratio mismatch: got %v ok %v", ratio, ok)
	}

	// byte counters are the fallback
	stats = TCPStats{TxBytes: 10000, RetransBytes: 100}
	ratio, ok = stats.RetransmitRatio()
	if !ok || math.Abs(ratio-0.01) > 0.0001 {
		t.Fatalf("byte ratio mismatch: got %v ok %v", ratio, ok)
	}

	// no counters at all
	if _, ok = (TCPStats{}).RetransmitRatio(); ok {
		t.Fatalf("empty stats must not report a ratio")
	}

	// zero retransmissions on a busy socket is a valid zero ratio
	ratio, ok = (TCPStats{TxPackets: 500}).RetransmitRatio()
	if !ok || ratio != 0 {
		t.Fatalf("clean socket must report ratio 0, got %v ok %v", ratio, ok)
	}
}

func TestTCPStatsSub(t *testing.T) {
	base := TCPStats{TxPackets: 100, RetransPackets: 2, TxBytes: 1000, RetransBytes: 20}
	current := TCPStats{TxPackets: 350, RetransPackets: 5, TxBytes: 4000, RetransBytes: 44}
	delta := current.Sub(base)
	want := TCPStats{TxPackets: 250, RetransPackets: 3, TxBytes: 3000, RetransBytes: 24}
	if delta != want {
		t.Fatalf("delta mismatch: got %+v want %+v", delta, want)
	}

	// counters that went backwards (socket reuse) clamp to zero
	if got := base.Sub(current); got != (TCPStats{}) {
		t.Fatalf("regressed counters must clamp, got %+v", got)
	}
}

type fakeUpstream struct {
	inner any
}

func (f *fakeUpstream) Upstream() any {
	return f.inner
}

// fakeNetConnWrapper exposes its inner value through the tls.Conn NetConn() contract.
type fakeNetConnWrapper struct {
	inner net.Conn
}

func (f *fakeNetConnWrapper) NetConn() net.Conn {
	return f.inner
}

// fakeTCPLikeConn is a minimal net.Conn that can expose its socket fd.
type fakeTCPLikeConn struct {
	net.Conn
}

func (f *fakeTCPLikeConn) SyscallConn() (syscall.RawConn, error) {
	return nil, errors.New("fake")
}

func TestFindSyscallConn(t *testing.T) {
	target := &fakeTCPLikeConn{}

	cases := []struct {
		name  string
		value any
	}{
		{"direct", target},
		{"upstream chain", &fakeUpstream{inner: &fakeUpstream{inner: target}}},
		{"netconn chain", &fakeUpstream{inner: &fakeNetConnWrapper{inner: target}}},
	}
	for _, tc := range cases {
		if _, ok := findSyscallConn(tc.value, 0); !ok {
			t.Fatalf("%s: must find the syscall conn", tc.name)
		}
	}

	if _, ok := findSyscallConn(nil, 0); ok {
		t.Fatalf("nil must not resolve")
	}
	if _, ok := findSyscallConn(io.Discard, 0); ok {
		t.Fatalf("plain reader must not resolve")
	}
	if _, ok := findSyscallConn(&fakeNetConnWrapper{inner: nil}, 0); ok {
		t.Fatalf("nil inner conn must not resolve")
	}

	// depth limit guards against self-referencing chains
	loop := &fakeUpstream{}
	loop.inner = loop
	if _, ok := findSyscallConn(loop, 0); ok {
		t.Fatalf("self-referencing chain must hit the depth limit")
	}
}

func TestSampleUnavailableWithoutSocket(t *testing.T) {
	if _, ok := Sample(&fakeTCPLikeConn{}); ok {
		t.Fatalf("Sample must fail when SyscallConn errors")
	}
	if _, ok := Sample(io.Discard); ok {
		t.Fatalf("Sample must fail for non-connection values")
	}
}
