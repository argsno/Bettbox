//go:build darwin

package sockstat

import "golang.org/x/sys/unix"

// sampleFD reads TCP transmission counters from a Darwin socket via
// TCP_CONNECTION_INFO. The option is available since macOS 10.13; on older
// systems the syscall fails and the loss penalty is skipped.
func sampleFD(fd int) (TCPStats, bool) {
	info, err := unix.GetsockoptTCPConnectionInfo(fd, unix.IPPROTO_TCP, unix.TCP_CONNECTION_INFO)
	if err != nil {
		return TCPStats{}, false
	}
	return TCPStats{
		TxPackets:      info.Txpackets,
		RetransPackets: info.Txretransmitpackets,
		TxBytes:        info.Txbytes,
		RetransBytes:   info.Txretransmitbytes,
	}, true
}
