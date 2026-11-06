package socket

import (
	"errors"
	"fmt"
	"runtime"

	"paqet/internal/conf"
)

// errTimeout means no frame arrived within the backend's poll interval.
var errTimeout = errors.New("socket: capture timeout")

type rxSource interface {
	// next returns the next captured frame, valid until the following call
	// to next or close. Never called concurrently.
	next() ([]byte, error)
	// drops returns how many frames the kernel dropped because the capture
	// buffer was full. Safe to call concurrently with next.
	drops() uint64
	// wake makes a blocked next return soon. Safe to call concurrently.
	wake()
	// close is never called concurrently with next.
	close()
}

type txSink interface {
	write(frame []byte) error // safe for concurrent use
	close()
}

// captureSnapLen bounds captured frames. paqet never receives more than
// MTU (<= 1500) plus Ethernet, two VLAN tags and IPv6+TCP headers.
const captureSnapLen = 2048

const (
	backendAuto     = "auto"
	backendAFPacket = "afpacket"
	backendPcap     = "libpcap"
)

func openBackend(cfg *conf.Network) (rxSource, txSink, error) {
	af, err := useAFPacket(cfg.PCAP.Backend)
	if err != nil {
		return nil, nil, err
	}
	newRx, newTx := newPcapRx, newPcapTx
	if af {
		newRx, newTx = newAFPacketRx, newAFPacketTx
	}

	tx, err := newTx(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create send handle on %s: %w", cfg.Interface.Name, err)
	}
	rx, err := newRx(cfg)
	if err != nil {
		tx.close()
		return nil, nil, fmt.Errorf("failed to create receive handle on %s: %w", cfg.Interface.Name, err)
	}
	return rx, tx, nil
}

func useAFPacket(backend string) (bool, error) {
	switch backend {
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
	return false, fmt.Errorf("unknown pcap backend %q", backend)
}
