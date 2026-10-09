//go:build linux

package sockstat

import "golang.org/x/sys/unix"

// sampleFD reads TCP transmission counters from a Linux socket via TCP_INFO.
// The linux build tag also matches Android, whose outbound connections are
// regular kernel TCP sockets.
//
// The kernel fills only as much of the struct as it has: segs_out/total_retrans
// exist since Linux 4.6 and bytes_sent/bytes_retrans since 4.19, so on older
// kernels the missing counters read as zero and callers fall back to the
// counters the kernel does provide, or skip the penalty entirely.
func sampleFD(fd int) (TCPStats, bool) {
	info, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil {
		return TCPStats{}, false
	}
	return TCPStats{
		TxPackets:      uint64(info.Segs_out),
		RetransPackets: uint64(info.Total_retrans),
		TxBytes:        info.Bytes_sent,
		RetransBytes:   info.Bytes_retrans,
	}, true
}
