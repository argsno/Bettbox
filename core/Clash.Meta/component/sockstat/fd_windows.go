//go:build windows

package sockstat

import (
	"syscall"
	"time"
	"unsafe"
)

const sioTCPInfo = 0xD8000027

// tcpInfoV0 mirrors the Windows TCP_INFO_v0 layout (mstcpip.h, Windows 10 1703+).
type tcpInfoV0 struct {
	State             uint32
	Mss               uint32
	ConnectionTimeMs  uint64
	TimestampsEnabled uint8
	_                 [3]byte
	RttUs             uint32
	MinRttUs          uint32
	BytesInFlight     uint32
	Cwnd              uint32
	SndWnd            uint32
	RcvWnd            uint32
	RcvBuf            uint32
	BytesOut          uint64
	BytesIn           uint64
	BytesReordered    uint32
	BytesRetrans      uint32
	FastRetrans       uint32
	DupAcksIn         uint32
	TimeoutEpisodes   uint32
	SynRetrans        uint8
	_                 [3]byte
}

func sampleFD(fd int) (TCPStats, bool) {
	var version uint32
	var info tcpInfoV0
	var returned uint32
	err := syscall.WSAIoctl(
		syscall.Handle(fd),
		sioTCPInfo,
		(*byte)(unsafe.Pointer(&version)),
		uint32(unsafe.Sizeof(version)),
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		&returned,
		nil,
		0,
	)
	if err != nil || returned < uint32(unsafe.Sizeof(info)) {
		return TCPStats{}, false
	}
	return TCPStats{
		TxBytes:      info.BytesOut,
		RetransBytes: uint64(info.BytesRetrans),
		RTT:          time.Duration(info.RttUs) * time.Microsecond,
	}, true
}
