package socket

import (
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"paqet/internal/conf"
)

// PacketConn is a net.PacketConn over raw TCP frames.
//
// It also implements kcp-go's PacketPusher, which kcp-go prefers over
// ReadFrom: a goroutine decodes each frame and hands kcp-go the payload
// straight from the capture buffer.
type PacketConn struct {
	local         *Addr
	send          *sendHandle
	recv          *recvHandle
	readDeadline  atomic.Value
	writeDeadline atomic.Value

	recvFn  atomic.Pointer[func([]byte, net.Addr, error)]
	pushMu  sync.Mutex
	pushing bool // guarded by pushMu

	closeOnce sync.Once
}

// New opens a PacketConn on cfg. A zero cfg.Port is replaced with a random
// one.
func New(cfg *conf.Network) (*PacketConn, error) {
	if cfg.Port == 0 {
		cfg.Port = 32768 + rand.Intn(32768)
	}
	rx, tx, err := openBackend(cfg)
	if err != nil {
		return nil, err
	}
	return &PacketConn{
		local: localAddr(cfg),
		send:  newSendHandle(cfg, tx),
		recv:  newRecvHandle(rx, cfg.Port),
	}, nil
}

// localAddr is the configured source address (IPv4 preferred) on cfg.Port.
func localAddr(cfg *conf.Network) *Addr {
	ip := net.IPv4zero
	if cfg.IPv4.Addr != nil {
		ip = cfg.IPv4.Addr.IP
	} else if cfg.IPv6.Addr != nil {
		ip = cfg.IPv6.Addr.IP
	}
	return NewAddr(ip, cfg.Port)
}

// SetPacketReceiver implements kcp-go's PacketPusher. fn is never called
// concurrently, and b is only valid during the call.
func (c *PacketConn) SetPacketReceiver(fn func(b []byte, addr net.Addr, err error)) {
	if fn == nil {
		c.recvFn.Store(nil)
		c.recv.src.wake()
		return
	}
	c.recvFn.Store(&fn)
	c.pushMu.Lock()
	defer c.pushMu.Unlock()
	if !c.pushing {
		c.pushing = true
		go c.pushLoop()
	}
}

func (c *PacketConn) pushLoop() {
	for {
		fn := c.recvFn.Load()
		if fn == nil {
			if c.stopPushing() {
				return
			}
			continue
		}
		err := c.recv.read(func(p []byte, from *Addr) { (*fn)(p, from, nil) })
		if err == nil || skippable(err) {
			continue
		}
		if fn := c.recvFn.Load(); fn != nil {
			(*fn)(nil, nil, err)
		}
		c.pushMu.Lock()
		c.pushing = false
		c.pushMu.Unlock()
		return
	}
}

// stopPushing ends the push loop unless a receiver was set meanwhile.
func (c *PacketConn) stopPushing() bool {
	c.pushMu.Lock()
	defer c.pushMu.Unlock()
	if c.recvFn.Load() != nil {
		return false
	}
	c.pushing = false
	return true
}

// ReadFrom copies the next payload into data. It must not be used while a
// packet receiver is set.
func (c *PacketConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	for {
		if deadlinePassed(&c.readDeadline) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		err := c.recv.read(func(p []byte, from *Addr) {
			n, addr = copy(data, p), from
		})
		if !skippable(err) {
			return n, addr, err
		}
	}
}

func (c *PacketConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	if deadlinePassed(&c.writeDeadline) {
		return 0, os.ErrDeadlineExceeded
	}
	dst, ok := AddrOf(addr)
	if !ok {
		return 0, net.InvalidAddrError("invalid address")
	}
	if err := c.send.write(data, dst); err != nil {
		return 0, err
	}
	return len(data), nil
}

func deadlinePassed(v *atomic.Value) bool {
	d, ok := v.Load().(time.Time)
	return ok && !d.IsZero() && !time.Now().Before(d)
}

func (c *PacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.recv.close()
		c.send.close()
	})
	return nil
}

func (c *PacketConn) LocalAddr() net.Addr {
	if c.local == nil {
		return nil // never wrap a nil *Addr: its String would panic
	}
	return c.local
}

func (c *PacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetDSCP(int) error { return nil }

func (c *PacketConn) SetClientTCPF(addr net.Addr, f []conf.TCPF) {
	c.send.setClientTCPF(addr, f)
}

func (c *PacketConn) DeleteClientTCPF(addr net.Addr) {
	c.send.deleteClientTCPF(addr)
}
