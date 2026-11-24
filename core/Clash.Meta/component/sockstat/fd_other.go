//go:build !darwin && !linux && !windows

package sockstat

// sampleFD is the fallback for platforms without a retransmission collector.
// Callers treat ok=false as "loss counters unavailable" and skip the
// retransmission penalty, so scoring degrades to latency-only.
func sampleFD(fd int) (TCPStats, bool) {
	return TCPStats{}, false
}
