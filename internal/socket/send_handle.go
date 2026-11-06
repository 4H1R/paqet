package socket

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"paqet/internal/conf"
	"paqet/internal/pkg/hash"
	"paqet/internal/pkg/iterator"
)

var (
	errNoIPv4 = errors.New("socket: no IPv4 address configured")
	errNoIPv6 = errors.New("socket: no IPv6 address configured")
)

// maxPayload is the largest packet kcp-go sends.
const maxPayload = 1500

// sendHandle builds frames and hands them to a transmit sink. It is safe
// for concurrent use.
type sendHandle struct {
	sink      txSink
	v4, v6    frameAddrs // dstIP is filled in per packet
	srcPort   uint16
	time      uint32
	tsCounter atomic.Uint32
	bufs      sync.Pool // *[]byte

	flagsMu     sync.RWMutex
	flags       iterator.Iterator[conf.TCPF]
	clientFlags map[uint64]*iterator.Iterator[conf.TCPF] // guarded by flagsMu
}

func newSendHandle(cfg *conf.Network, sink txSink) *sendHandle {
	h := &sendHandle{
		sink:        sink,
		srcPort:     uint16(cfg.Port),
		time:        uint32(time.Now().UnixMilli()),
		flags:       iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF},
		clientFlags: make(map[uint64]*iterator.Iterator[conf.TCPF]),
		bufs: sync.Pool{New: func() any {
			b := make([]byte, 0, maxHdrLen+maxPayload)
			return &b
		}},
	}
	tos := uint8(cfg.DSCP << 2)
	var srcMAC []byte
	if cfg.Interface != nil {
		srcMAC = cfg.Interface.HardwareAddr
	}
	if cfg.IPv4.Addr != nil {
		h.v4 = frameAddrs{srcMAC: srcMAC, dstMAC: cfg.IPv4.Router, srcIP: cfg.IPv4.Addr.IP.To4(), tos: tos}
	}
	if cfg.IPv6.Addr != nil {
		h.v6 = frameAddrs{srcMAC: srcMAC, dstMAC: cfg.IPv6.Router, srcIP: cfg.IPv6.Addr.IP.To16(), tos: tos}
	}
	return h
}

// segment fills the per-packet TCP fields. The sequence, ack and timestamp
// pattern is part of paqet's wire fingerprint and must not change.
func (h *sendHandle) segment(dstPort uint16, f conf.TCPF) tcpSegment {
	counter := h.tsCounter.Add(1)
	tsVal := h.time + (counter >> 3)
	s := tcpSegment{srcPort: h.srcPort, dstPort: dstPort, flags: f, tsVal: tsVal}
	if f.SYN {
		s.seq = 1 + (counter & 0x7)
		if f.ACK {
			s.ack = s.seq + 1
		}
	} else {
		s.tsEcr = tsVal - (counter%200 + 50)
		s.seq = h.time + (counter << 7)
		s.ack = s.seq - (counter & 0x3FF) + 1400
	}
	return s
}

func (h *sendHandle) write(payload []byte, dst *Addr) error {
	fa := h.v4
	if len(dst.IP) == 16 {
		fa = h.v6
	}
	if fa.srcIP == nil {
		if len(dst.IP) == 16 {
			return errNoIPv6
		}
		return errNoIPv4
	}
	fa.dstIP = dst.IP

	dstPort := uint16(dst.Port)
	seg := h.segment(dstPort, h.flagsFor(dst.IP, dstPort))

	bp := h.bufs.Get().(*[]byte)
	frame := encodeFrame(*bp, &fa, &seg, payload)
	err := h.sink.write(frame)
	*bp = frame[:0]
	h.bufs.Put(bp)
	return err
}

func (h *sendHandle) flagsFor(ip net.IP, port uint16) conf.TCPF {
	h.flagsMu.RLock()
	defer h.flagsMu.RUnlock()
	if it := h.clientFlags[hash.IPAddr(ip, port)]; it != nil {
		return it.Next()
	}
	return h.flags.Next()
}

func (h *sendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {
	a, ok := AddrOf(addr)
	if !ok {
		return
	}
	h.flagsMu.Lock()
	h.clientFlags[hash.IPAddr(a.IP, uint16(a.Port))] = &iterator.Iterator[conf.TCPF]{Items: f}
	h.flagsMu.Unlock()
}

func (h *sendHandle) deleteClientTCPF(addr net.Addr) {
	a, ok := AddrOf(addr)
	if !ok {
		return
	}
	h.flagsMu.Lock()
	delete(h.clientFlags, hash.IPAddr(a.IP, uint16(a.Port)))
	h.flagsMu.Unlock()
}

func (h *sendHandle) close() { h.sink.close() }
