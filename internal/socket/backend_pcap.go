package socket

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/gopacket/gopacket/pcap"

	"paqet/internal/conf"
)

func newHandle(cfg *conf.Network, sockbuf int, snapLen int, timeout time.Duration) (*pcap.Handle, error) {
	// On Windows, use the GUID field to construct the NPF device name
	// On other platforms, use the interface name directly
	ifaceName := cfg.Interface.Name
	if runtime.GOOS == "windows" {
		ifaceName = cfg.GUID
	}

	inactive, err := pcap.NewInactiveHandle(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to create inactive pcap handle for %s: %v", cfg.Interface.Name, err)
	}
	defer inactive.CleanUp()

	if err = inactive.SetBufferSize(sockbuf); err != nil {
		return nil, fmt.Errorf("failed to set pcap buffer size to %d: %v", sockbuf, err)
	}
	// libpcap on Linux sizes every ring slot from the snap length when
	// immediate mode is on, so a 64KB snap length leaves only ~64 slots in
	// a 4MB buffer and bursts overflow it.
	if err = inactive.SetSnapLen(snapLen); err != nil {
		return nil, fmt.Errorf("failed to set pcap snap length: %v", err)
	}
	if err = inactive.SetPromisc(false); err != nil {
		return nil, fmt.Errorf("failed to set promiscuous mode: %v", err)
	}
	if err = inactive.SetTimeout(timeout); err != nil {
		return nil, fmt.Errorf("failed to set pcap timeout: %v", err)
	}
	if err = inactive.SetImmediateMode(true); err != nil {
		return nil, fmt.Errorf("failed to enable immediate mode: %v", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("failed to activate pcap handle on %s: %v", cfg.Interface.Name, err)
	}

	return handle, nil
}

type pcapRx struct {
	h *pcap.Handle
}

func newPcapRx(cfg *conf.Network) (*pcapRx, error) {
	handle, err := newHandle(cfg, cfg.PCAP.Sockbuf, captureSnapLen, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionIn); err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to set pcap direction in: %v", err)
		}
	}

	filter := fmt.Sprintf("tcp and dst port %d", cfg.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}
	return &pcapRx{h: handle}, nil
}

func (r *pcapRx) next() ([]byte, error) {
	data, _, err := r.h.ZeroCopyReadPacketData()
	if errors.Is(err, pcap.NextErrorTimeoutExpired) {
		return nil, errTimeout
	}
	return data, err
}

func (r *pcapRx) drops() uint64 {
	s, err := r.h.Stats()
	if err != nil {
		return 0
	}
	return uint64(s.PacketsDropped)
}

// wake is a no-op: reads time out every 100ms on their own.
func (r *pcapRx) wake() {}

func (r *pcapRx) close() { r.h.Close() }

type pcapTx struct {
	h  *pcap.Handle
	mu sync.Mutex // pcap_sendpacket is not guaranteed thread-safe
}

func newPcapTx(cfg *conf.Network) (*pcapTx, error) {
	handle, err := newHandle(cfg, sendBufSize, 128, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionOut); err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to set pcap direction out: %v", err)
		}
	}

	if err := handle.SetBPFFilter("less 0"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}
	return &pcapTx{h: handle}, nil
}

func (t *pcapTx) write(frame []byte) error {
	t.mu.Lock()
	err := t.h.WritePacketData(frame)
	t.mu.Unlock()
	return err
}

func (t *pcapTx) close() { t.h.Close() }
