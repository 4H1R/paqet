package socket

import (
	"errors"
	"fmt"
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
// It also implements kcp-go's PacketPusher: once a receiver is set, a
// dedicated goroutine decodes each frame and hands the payload to kcp-go
// straight from the capture buffer, with no intermediate copy and no
// separate kcp-go read goroutine.
type PacketConn struct {
	cfg           *conf.Network
	send          *sharedSend
	recv          *RecvHandle
	readDeadline  atomic.Value
	writeDeadline atomic.Value

	recvFn  atomic.Pointer[func([]byte, net.Addr, error)]
	pushMu  sync.Mutex
	pushing bool // guarded by pushMu

	closeOnce sync.Once
}

// sharedSend reference counts a SendHandle shared by a group of conns.
type sharedSend struct {
	h    *SendHandle
	refs atomic.Int32
}

func (s *sharedSend) release() {
	if s.refs.Add(-1) == 0 {
		s.h.Close()
	}
}

// New opens a PacketConn on cfg. A zero cfg.Port is replaced with a random
// one.
func New(cfg *conf.Network) (*PacketConn, error) {
	conns, err := NewGroup(cfg, 1)
	if err != nil {
		return nil, err
	}
	return conns[0], nil
}

// NewGroup opens up to readers PacketConns on cfg that share one send path
// and split received traffic between them by flow, so each peer always
// arrives on the same conn. Backends that cannot split traffic return a
// single conn.
func NewGroup(cfg *conf.Network, readers int) ([]*PacketConn, error) {
	if cfg.Port == 0 {
		cfg.Port = 32768 + rand.Intn(32768)
	}

	sink, err := newTx(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create send handle on %s: %v", cfg.Interface.Name, err)
	}
	srcs, err := newRx(cfg, readers)
	if err != nil {
		sink.close()
		return nil, fmt.Errorf("failed to create receive handle on %s: %v", cfg.Interface.Name, err)
	}

	send := &sharedSend{h: newSendHandle(cfg, sink)}
	send.refs.Store(int32(len(srcs)))
	conns := make([]*PacketConn, len(srcs))
	for i, src := range srcs {
		conns[i] = &PacketConn{cfg: cfg, send: send, recv: newRecvHandle(src, cfg.Port)}
	}
	return conns, nil
}

// SetPacketReceiver implements kcp-go's PacketPusher. fn is called from one
// goroutine at a time; b is only valid during the call.
func (c *PacketConn) SetPacketReceiver(fn func(b []byte, addr net.Addr, err error)) {
	if fn == nil {
		c.recvFn.Store(nil)
		c.recv.src.wake()
		return
	}
	c.recvFn.Store(&fn)
	c.pushMu.Lock()
	if !c.pushing {
		c.pushing = true
		go c.pushLoop()
	}
	c.pushMu.Unlock()
}

func (c *PacketConn) pushLoop() {
	h := c.recv
	for {
		fp := c.recvFn.Load()
		if fp == nil {
			c.pushMu.Lock()
			if c.recvFn.Load() != nil {
				c.pushMu.Unlock()
				continue
			}
			c.pushing = false
			c.pushMu.Unlock()
			return
		}

		h.mu.Lock()
		payload, addr, err := h.readLocked()
		if err == nil {
			(*fp)(payload, addr, nil)
		}
		h.unlock()

		if err == nil || err == errTimeout || err == errNoPayload {
			continue
		}
		if fp := c.recvFn.Load(); fp != nil {
			(*fp)(nil, nil, err)
		}
		c.pushMu.Lock()
		c.pushing = false
		c.pushMu.Unlock()
		return
	}
}

// ReadFrom copies the next payload into data. It must not be used while a
// packet receiver is set.
func (c *PacketConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	h := c.recv
	for {
		if d, ok := c.readDeadline.Load().(time.Time); ok && !d.IsZero() && !time.Now().Before(d) {
			return 0, nil, os.ErrDeadlineExceeded
		}

		h.mu.Lock()
		payload, a, err := h.readLocked()
		n := copy(data, payload)
		h.unlock()

		if err != nil {
			if errors.Is(err, errTimeout) || errors.Is(err, errNoPayload) {
				continue
			}
			return 0, nil, err
		}
		return n, a, nil
	}
}

func (c *PacketConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	if d, ok := c.writeDeadline.Load().(time.Time); ok && !d.IsZero() && !time.Now().Before(d) {
		return 0, os.ErrDeadlineExceeded
	}

	var daddr *Addr
	switch a := addr.(type) {
	case *Addr:
		daddr = a
	case *net.UDPAddr:
		daddr = NewAddr(a.IP, a.Port)
	default:
		return 0, net.InvalidAddrError("invalid address")
	}

	if err := c.send.h.Write(data, daddr); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (c *PacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.recv.Close()
		c.send.release()
	})
	return nil
}

func (c *PacketConn) LocalAddr() net.Addr {
	return nil
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

func (c *PacketConn) SetDSCP(dscp int) error {
	return nil
}

func (c *PacketConn) SetClientTCPF(addr net.Addr, f []conf.TCPF) {
	c.send.h.setClientTCPF(addr, f)
}

func (c *PacketConn) DeleteClientTCPF(addr net.Addr) {
	c.send.h.deleteClientTCPF(addr)
}
