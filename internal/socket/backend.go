package socket

import (
	"errors"
	"fmt"
	"runtime"

	"paqet/internal/conf"
)

// errTimeout reports that no frame arrived within the backend's poll
// interval. Readers use it to re-check for shutdown.
var errTimeout = errors.New("socket: capture timeout")

// rxSource delivers captured frames.
type rxSource interface {
	// next returns the next captured frame. The slice is only valid until
	// the following call to next or close. It returns errTimeout when no
	// frame arrived within the poll interval. next is never called
	// concurrently.
	next() ([]byte, error)
	// drops returns the cumulative number of frames the kernel dropped
	// because the capture buffer was full. It is safe to call concurrently
	// with next.
	drops() uint64
	// wake makes a blocked next return soon. It is safe to call
	// concurrently with next.
	wake()
	// close releases the source. It is never called concurrently with
	// next.
	close()
}

// txSink transmits complete frames. write may be called concurrently.
type txSink interface {
	write(frame []byte) error
	close()
}

// Frame sizes. Received frames never exceed the interface MTU (at most
// 1500 for paqet) plus an Ethernet header, two VLAN tags and the largest
// IPv6+TCP headers, about 1626 bytes. Capturing more only wastes buffer.
const (
	captureSnapLen = 2048
	sendBufSize    = 64 * 1024 // the send handle captures nothing
)

const (
	backendAuto     = "auto"
	backendAFPacket = "afpacket"
	backendPcap     = "libpcap"
)

func useAFPacket(cfg *conf.Network) (bool, error) {
	switch cfg.PCAP.Backend {
	case "", backendAuto:
		return afpacketSupported, nil
	case backendAFPacket:
		if !afpacketSupported {
			return false, fmt.Errorf("pcap backend %q is not supported on %s", backendAFPacket, runtime.GOOS)
		}
		return true, nil
	case backendPcap:
		return false, nil
	}
	return false, fmt.Errorf("unknown pcap backend %q", cfg.PCAP.Backend)
}

// newRx opens the receive side for cfg.Port. With readers > 1 it opens
// that many sources sharing the traffic by flow hash, when the backend
// supports it; otherwise it returns a single source.
func newRx(cfg *conf.Network, readers int) ([]rxSource, error) {
	af, err := useAFPacket(cfg)
	if err != nil {
		return nil, err
	}
	if af {
		return newAFPacketRx(cfg, readers)
	}
	src, err := newPcapRx(cfg)
	if err != nil {
		return nil, err
	}
	return []rxSource{src}, nil
}

func newTx(cfg *conf.Network) (txSink, error) {
	af, err := useAFPacket(cfg)
	if err != nil {
		return nil, err
	}
	if af {
		return newAFPacketTx(cfg)
	}
	return newPcapTx(cfg)
}
