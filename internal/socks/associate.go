package socks

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"

	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"paqet/internal/tnet"
)

// associate is one UDP ASSOCIATE session with one stream per destination.
type associate struct {
	conn  *net.UDPConn
	cIP   netip.Addr // expected client IP, unmapped
	cPort uint16     // expected client port; 0 until the first datagram
	cStr  string     // client address as a string, set with cPort

	mu    sync.Mutex
	dests map[string]*udpDest // keyed by the raw SOCKS address (ATYP..PORT)
}

// udpDest queues datagrams for one destination. Its own goroutine opens the
// stream, so a slow setup never stalls the other destinations.
type udpDest struct {
	ch   chan *[]byte // pooled buffers, see buffer.GetUDP
	done chan struct{}
	once sync.Once
}

func (d *udpDest) stop() { d.once.Do(func() { close(d.done) }) }

// udpQueueLen bounds datagrams queued per destination; extras are dropped.
const udpQueueLen = 64

func (a *associate) accept(src netip.AddrPort) bool {
	if src.Addr().Unmap() != a.cIP {
		return false
	}
	if a.cPort == 0 {
		a.cPort = src.Port()
		a.cStr = netip.AddrPortFrom(a.cIP, a.cPort).String()
	}
	return src.Port() == a.cPort
}

func (a *associate) clientAddr() netip.AddrPort { return netip.AddrPortFrom(a.cIP, a.cPort) }

func (s *Server) handleAssociate(ctx context.Context, tConn net.Conn, req *request) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	lAddr := tConn.LocalAddr().(*net.TCPAddr)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: lAddr.IP, Port: 0})
	if err != nil {
		flog.Errorf("SOCKS5 failed to open UDP relay socket: %v", err)
		s.write(tConn, repFailure)
		return
	}
	defer conn.Close()

	bAddr := conn.LocalAddr().(*net.UDPAddr)
	if _, err := tConn.Write(append([]byte{ver, repSuccess, 0x00}, putAddr(nil, bAddr.IP, bAddr.Port)...)); err != nil {
		return
	}

	a := &associate{conn: conn, dests: make(map[string]*udpDest)}
	if req.atyp == atypDomain || net.IP(req.addr).IsUnspecified() {
		ip, _ := netip.AddrFromSlice(tConn.RemoteAddr().(*net.TCPAddr).IP)
		a.cIP = ip.Unmap()
	} else {
		ip, _ := netip.AddrFromSlice(req.addr)
		a.cIP = ip.Unmap()
		if p := uint16(req.port[0])<<8 | uint16(req.port[1]); p != 0 {
			a.cPort = p
			a.cStr = a.clientAddr().String()
		}
	}
	flog.Debugf("SOCKS5 UDP_ASSOCIATE from %s relay=%s expect=%s", tConn.RemoteAddr(), bAddr, a.cIP)

	go func() {
		io.Copy(io.Discard, tConn)
		conn.Close()
	}()
	context.AfterFunc(ctx, func() {
		conn.Close()
		tConn.Close()
	})

	s.serveUDP(ctx, a)
	flog.Debugf("SOCKS5 UDP_ASSOCIATE control connection %s closed", tConn.RemoteAddr())
}

func (s *Server) serveUDP(ctx context.Context, a *associate) {
	buf := make([]byte, 4+1+255+2+buffer.UDPSize+1)
	for {
		n, src, err := a.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if n == len(buf) {
			flog.Debugf("SOCKS5 UDP %s: datagram too large, at least %d bytes", src, n)
			continue
		}
		if !a.accept(src) {
			flog.Debugf("SOCKS5 UDP %s: unexpected source (want %s)", src, a.cIP)
			continue
		}
		d, key, err := decodeDatagram(buf[:n])
		if err != nil {
			flog.Debugf("SOCKS5 UDP %s: malformed datagram: %v", src, err)
			continue
		}
		s.udpToStrm(ctx, a, d, key)
	}
}

// udpToStrm queues a datagram. For a known destination it allocates nothing.
func (s *Server) udpToStrm(ctx context.Context, a *associate, d datagram, key []byte) {
	if len(d.data) > buffer.UDPSize {
		flog.Debugf("SOCKS5 UDP %s -> %s: payload too large, %d bytes", a.cStr, d.address(), len(d.data))
		return
	}

	a.mu.Lock()
	dst, ok := a.dests[string(key)]
	if !ok {
		dst = &udpDest{ch: make(chan *[]byte, udpQueueLen), done: make(chan struct{})}
		k := string(key)
		a.dests[k] = dst
		hdr := (&datagram{atyp: d.atyp, addr: d.addr, port: d.port}).bytes()
		go s.pumpUDP(ctx, a, k, d.address(), hdr, dst)
	}
	a.mu.Unlock()

	bp := buffer.GetUDP()
	*bp = (*bp)[:copy(*bp, d.data)]
	select {
	case dst.ch <- bp:
	default:
		buffer.PutUDP(bp) // queue full: drop
	}
}

// pumpUDP opens dst's stream and writes its queue to it.
func (s *Server) pumpUDP(ctx context.Context, a *associate, key, target string, hdr []byte, dst *udpDest) {
	defer s.dropDest(a, key, dst)

	strm, isNew, k, err := s.client.UDP(ctx, a.cStr, target)
	if err != nil {
		flog.Errorf("SOCKS5 failed to establish UDP stream for %s -> %s: %v", a.cStr, target, err)
		return
	}
	if isNew {
		flog.Infof("SOCKS5 accepted UDP connection %s -> %s", a.cStr, target)
		go func() {
			defer s.client.CloseUDP(k, strm)
			s.strmToUDP(ctx, strm, a, hdr, k)
			dst.stop()
		}()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-dst.done:
			return
		case bp := <-dst.ch:
			if _, err := strm.Write(*bp); err != nil {
				// Not recycled: a failed smux write may still reference it.
				s.client.CloseUDP(k, strm)
				return
			}
			buffer.PutUDP(bp)
			s.client.Touch(k)
		}
	}
}

// dropDest makes the next datagram for the destination open a new stream.
func (s *Server) dropDest(a *associate, key string, dst *udpDest) {
	dst.stop()
	a.mu.Lock()
	if a.dests[key] == dst {
		delete(a.dests, key)
	}
	a.mu.Unlock()
	for {
		select {
		case bp := <-dst.ch:
			buffer.PutUDP(bp)
		default:
			return
		}
	}
}

func (s *Server) strmToUDP(ctx context.Context, strm tnet.Strm, a *associate, hdr []byte, k uint64) {
	stop := context.AfterFunc(ctx, func() { strm.Close() })
	defer stop()

	buf := make([]byte, len(hdr)+buffer.UDPSize)
	hlen := copy(buf, hdr)
	dst := a.clientAddr()
	for {
		n, err := strm.Read(buf[hlen:])
		if err != nil {
			return
		}
		s.client.Touch(k)
		if _, err := a.conn.WriteToUDPAddrPort(buf[:hlen+n], dst); err != nil {
			return
		}
	}
}
