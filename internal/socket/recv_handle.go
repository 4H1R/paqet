package socket

import (
	"fmt"
	"net"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"paqet/internal/conf"
	"paqet/internal/pkg/hash"
)

type decoder struct {
	parser  *gopacket.DecodingLayerParser
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	decoded []gopacket.LayerType
}

// maxCachedAddrs bounds the source address cache. Clients use one source
// per connection, so this is only reached by scans or spoofed traffic.
const maxCachedAddrs = 4096

type RecvHandle struct {
	handle *pcap.Handle
	dec    *decoder
	addrs  map[uint64]*net.UDPAddr // guarded by mu
	mu     sync.Mutex
}

func NewRecvHandle(cfg *conf.Network) (*RecvHandle, error) {
	handle, err := newHandle(cfg, cfg.PCAP.Sockbuf, 65536, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionIn); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction in: %v", err)
		}
	}

	filter := fmt.Sprintf("tcp and dst port %d", cfg.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	d := &decoder{decoded: make([]gopacket.LayerType, 0, 4)}
	d.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &d.eth, &d.ip4, &d.ip6, &d.tcp)
	d.parser.IgnoreUnsupported = true

	return &RecvHandle{handle: handle, dec: d, addrs: make(map[uint64]*net.UDPAddr)}, nil
}

func (h *RecvHandle) Read(data []byte) (int, net.Addr, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	zdata, _, err := h.handle.ZeroCopyReadPacketData()
	if err != nil {
		return 0, nil, err
	}

	// Reads are serialized by mu, so one decoder is reused for every packet.
	d := h.dec
	if err := d.parser.DecodeLayers(zdata, &d.decoded); err != nil {
		return 0, nil, errNoPayload
	}

	var ip net.IP
	var port int
	var payload []byte
	for _, t := range d.decoded {
		switch t {
		case layers.LayerTypeIPv4:
			ip = d.ip4.SrcIP
		case layers.LayerTypeIPv6:
			ip = d.ip6.SrcIP
		case layers.LayerTypeTCP:
			port = int(d.tcp.SrcPort)
			payload = d.tcp.Payload
		}
	}

	if ip == nil || len(payload) == 0 {
		return 0, nil, errNoPayload
	}

	return copy(data, payload), h.addr(ip, port), nil
}

// addr returns a shared *net.UDPAddr for the source, so steady traffic from a
// peer allocates nothing. ip points into the capture buffer and is copied
// before being cached. Callers must not modify the returned address.
func (h *RecvHandle) addr(ip net.IP, port int) *net.UDPAddr {
	key := hash.IPAddr(ip, uint16(port))
	if a, ok := h.addrs[key]; ok && a.Port == port && a.IP.Equal(ip) {
		return a
	}
	if len(h.addrs) >= maxCachedAddrs {
		clear(h.addrs)
	}
	a := &net.UDPAddr{IP: slices.Clone(ip), Port: port}
	h.addrs[key] = a
	return a
}

func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
