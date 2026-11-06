package conf

import (
	"fmt"
	"paqet/internal/flog"
	"runtime"
	"slices"
)

type PCAP struct {
	Sockbuf int `yaml:"sockbuf"`
	// Backend selects the packet capture implementation: "auto" (AF_PACKET
	// on Linux, libpcap elsewhere), "afpacket" or "libpcap".
	Backend string `yaml:"backend"`
	// Readers is how many goroutines receive packets on the server, each
	// with its own share of sockbuf (Linux AF_PACKET only). Clients are
	// split between them by flow, so it only helps with several clients.
	// 0 picks a value from the CPU count.
	Readers int `yaml:"readers"`
}

// maxAutoReaders caps the automatic server reader count. Each reader is a
// goroutine blocked in poll on its own OS thread when idle.
const maxAutoReaders = 4

func (p *PCAP) setDefaults(role string) {
	if p.Sockbuf == 0 {
		if role == "server" {
			p.Sockbuf = 8 * 1024 * 1024
		} else {
			p.Sockbuf = 4 * 1024 * 1024
		}
	}
	if p.Backend == "" {
		p.Backend = "auto"
	}
	if p.Readers == 0 {
		p.Readers = 1
		if role == "server" {
			p.Readers = min(runtime.NumCPU(), maxAutoReaders)
		}
	}
}

func (p *PCAP) validate() []error {
	var errors []error

	if p.Sockbuf < 1024 {
		errors = append(errors, fmt.Errorf("PCAP sockbuf must be >= 1024 bytes"))
	}

	if p.Sockbuf > 100*1024*1024 {
		errors = append(errors, fmt.Errorf("PCAP sockbuf too large (max 100MB)"))
	}

	// Should be power of 2 for optimal performance, but not required
	if p.Sockbuf&(p.Sockbuf-1) != 0 {
		flog.Warnf("PCAP sockbuf (%d bytes) is not a power of 2 - consider using values like 4MB, 8MB, or 16MB for better performance", p.Sockbuf)
	}

	backends := []string{"auto", "afpacket", "libpcap"}
	if !slices.Contains(backends, p.Backend) {
		errors = append(errors, fmt.Errorf("PCAP backend must be one of: %v", backends))
	} else if p.Backend == "afpacket" && runtime.GOOS != "linux" {
		errors = append(errors, fmt.Errorf("PCAP backend \"afpacket\" is only available on Linux"))
	}

	if p.Readers < 1 || p.Readers > 64 {
		errors = append(errors, fmt.Errorf("PCAP readers must be between 1-64"))
	}

	return errors
}
