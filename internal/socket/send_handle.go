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

type tcpF struct {
	tcpF       iterator.Iterator[conf.TCPF]
	clientTCPF map[uint64]*iterator.Iterator[conf.TCPF]
	mu         sync.RWMutex
}

// SendHandle builds frames and hands them to a transmit sink. It is safe
// for concurrent use and can be shared by several PacketConns.
type SendHandle struct {
	sink      txSink
	v4, v6    frameAddrs // templates; dstIP is filled in per packet
	srcPort   uint16
	time      uint32
	tsCounter atomic.Uint32
	tcpF      tcpF
	bufs      sync.Pool // *[]byte frame buffers
}

var (
	errNoIPv4 = errors.New("socket: no IPv4 address configured")
	errNoIPv6 = errors.New("socket: no IPv6 address configured")
)

func newSendHandle(cfg *conf.Network, sink txSink) *SendHandle {
	sh := &SendHandle{
		sink:    sink,
		srcPort: uint16(cfg.Port),
		tcpF:    tcpF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
		time:    uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		bufs: sync.Pool{New: func() any {
			b := make([]byte, 0, maxHdrLen+mtuLimit)
			return &b
		}},
	}
	tos := uint8(cfg.DSCP << 2)
	var srcMAC []byte
	if cfg.Interface != nil {
		srcMAC = cfg.Interface.HardwareAddr
	}
	if cfg.IPv4.Addr != nil {
		sh.v4 = frameAddrs{srcMAC: srcMAC, dstMAC: cfg.IPv4.Router, srcIP: cfg.IPv4.Addr.IP.To4(), tos: tos}
	}
	if cfg.IPv6.Addr != nil {
		sh.v6 = frameAddrs{srcMAC: srcMAC, dstMAC: cfg.IPv6.Router, srcIP: cfg.IPv6.Addr.IP.To16(), tos: tos}
	}
	return sh
}

// mtuLimit is kcp-go's largest packet.
const mtuLimit = 1500

// segment fills the per-packet TCP fields. The sequence, ack and timestamp
// values follow the pattern paqet has always sent.
func (h *SendHandle) segment(dstPort uint16, f conf.TCPF) tcpSegment {
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
		seq := h.time + (counter << 7)
		s.seq = seq
		s.ack = seq - (counter & 0x3FF) + 1400
	}
	return s
}

// Write sends payload to dst in one frame.
func (h *SendHandle) Write(payload []byte, dst *Addr) error {
	var fa frameAddrs
	if len(dst.IP) == 16 {
		if h.v6.srcIP == nil {
			return errNoIPv6
		}
		fa = h.v6
	} else {
		if h.v4.srcIP == nil {
			return errNoIPv4
		}
		fa = h.v4
	}
	fa.dstIP = dst.IP

	dstPort := uint16(dst.Port)
	seg := h.segment(dstPort, h.getClientTCPF(dst.IP, dstPort))

	bp := h.bufs.Get().(*[]byte)
	frame := encodeFrame(*bp, &fa, &seg, payload)
	err := h.sink.write(frame)
	*bp = frame[:0]
	h.bufs.Put(bp)
	return err
}

func (h *SendHandle) getClientTCPF(dstIP net.IP, dstPort uint16) conf.TCPF {
	h.tcpF.mu.RLock()
	defer h.tcpF.mu.RUnlock()
	if ff := h.tcpF.clientTCPF[hash.IPAddr(dstIP, dstPort)]; ff != nil {
		return ff.Next()
	}
	return h.tcpF.tcpF.Next()
}

func (h *SendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {
	a, ok := AddrOf(addr)
	if !ok {
		return
	}
	h.tcpF.mu.Lock()
	h.tcpF.clientTCPF[hash.IPAddr(a.IP, uint16(a.Port))] = &iterator.Iterator[conf.TCPF]{Items: f}
	h.tcpF.mu.Unlock()
}

func (h *SendHandle) deleteClientTCPF(addr net.Addr) {
	a, ok := AddrOf(addr)
	if !ok {
		return
	}
	h.tcpF.mu.Lock()
	delete(h.tcpF.clientTCPF, hash.IPAddr(a.IP, uint16(a.Port)))
	h.tcpF.mu.Unlock()
}

func (h *SendHandle) Close() {
	if h.sink != nil {
		h.sink.close()
	}
}
