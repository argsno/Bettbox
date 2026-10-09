package sockstat

import (
	"io"
	"net"
	"syscall"

	N "github.com/metacubex/mihomo/common/net"
)

// TCPStats holds cumulative TCP transmission counters reported by the platform
// for a single socket.
type TCPStats struct {
	TxPackets      uint64
	RetransPackets uint64
	TxBytes        uint64
	RetransBytes   uint64
}

// RetransmitRatio returns the fraction of transmitted data that had to be
// retransmitted, preferring packet counters and falling back to byte counters.
// ok is false when the platform reported no transmit counters at all, in which
// case callers should skip the loss penalty.
func (s TCPStats) RetransmitRatio() (float64, bool) {
	if s.TxPackets > 0 {
		return float64(s.RetransPackets) / float64(s.TxPackets), true
	}
	if s.TxBytes > 0 {
		return float64(s.RetransBytes) / float64(s.TxBytes), true
	}
	return 0, false
}

// Sub returns the counter delta since an earlier snapshot. Negative deltas
// (counters reset by socket reuse) are clamped to zero.
func (s TCPStats) Sub(base TCPStats) TCPStats {
	return TCPStats{
		TxPackets:      subClamp(s.TxPackets, base.TxPackets),
		RetransPackets: subClamp(s.RetransPackets, base.RetransPackets),
		TxBytes:        subClamp(s.TxBytes, base.TxBytes),
		RetransBytes:   subClamp(s.RetransBytes, base.RetransBytes),
	}
}

func subClamp(current, base uint64) uint64 {
	if current < base {
		return 0
	}
	return current - base
}

type syscallConner interface {
	SyscallConn() (syscall.RawConn, error)
}

const maxUnwrapDepth = 16

// Sample extracts TCP retransmission counters from an (optionally wrapped)
// connection. It walks the wrapper chain to reach the raw TCP socket; ok is
// false when none is reachable — multiplexed streams and UDP-based transports
// report false, and callers should skip the loss penalty for them, since a
// shared socket's counters cannot be attributed to a single session.
//
// Sample must be called while the socket is still open: counters of a closed
// socket cannot be read.
func Sample(conn any) (TCPStats, bool) {
	raw, ok := findSyscallConn(conn, 0)
	if !ok {
		return TCPStats{}, false
	}

	syscallConn, err := raw.SyscallConn()
	if err != nil {
		return TCPStats{}, false
	}

	var stats TCPStats
	var sampled bool
	if err = syscallConn.Control(func(fd uintptr) {
		stats, sampled = sampleFD(int(fd))
	}); err != nil {
		return TCPStats{}, false
	}
	return stats, sampled
}

// findSyscallConn walks the wrapper conventions used across the core
// (Upstream, NetConn, UpstreamReader/UpstreamWriter and the tracker's
// UnwrapReader contract) until it reaches a value that can expose its socket
// file descriptor.
func findSyscallConn(value any, depth int) (syscallConner, bool) {
	if value == nil || depth > maxUnwrapDepth {
		return nil, false
	}

	if sc, ok := value.(syscallConner); ok {
		return sc, true
	}

	switch wrapper := value.(type) {
	case N.WithUpstream:
		return findSyscallConn(wrapper.Upstream(), depth+1)
	case interface{ NetConn() net.Conn }:
		return findSyscallConn(wrapper.NetConn(), depth+1)
	case interface{ UpstreamReader() any }:
		return findSyscallConn(wrapper.UpstreamReader(), depth+1)
	case interface{ UpstreamWriter() any }:
		return findSyscallConn(wrapper.UpstreamWriter(), depth+1)
	case interface {
		UnwrapReader() (io.Reader, []N.CountFunc)
	}:
		reader, _ := wrapper.UnwrapReader()
		return findSyscallConn(reader, depth+1)
	}

	return nil, false
}
