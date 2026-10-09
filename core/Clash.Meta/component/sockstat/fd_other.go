//go:build !darwin

package sockstat

// sampleFD is the fallback for platforms without a retransmission collector.
// Callers treat ok=false as "loss counters unavailable" and skip the
// retransmission penalty, so scoring degrades to latency-only.
//
// Porting notes:
//   - linux: unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO) —
//     pack counters from Total_retrans/Segs_out, byte counters from
//     Bytes_retrans/Bytes_sent.
//   - windows: WSAIoctl with SIO_TCP_INFO (0xD8000027), version 0 in the input
//     buffer, TCP_INFO_v0 out — BytesRetrans/BytesOut. Requires Windows 10
//     1703+ and, unlike the ESTATS API, no elevated privileges.
func sampleFD(fd int) (TCPStats, bool) {
	return TCPStats{}, false
}
