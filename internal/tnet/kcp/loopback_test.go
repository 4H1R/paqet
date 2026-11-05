package kcp

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"paqet/internal/conf"
)

// memNet is an in-memory datagram network between two endpoints with
// optional one-way delay and random loss, standing in for the pcap socket.
type memNet struct {
	delay time.Duration
	loss  float64 // 0..1
}

type memPacket struct {
	data []byte
	from net.Addr
}

type memConn struct {
	net   *memNet
	local *net.UDPAddr
	peer  *memConn
	in    chan memPacket

	mu       sync.Mutex
	deadline time.Time
	done     chan struct{}
	once     sync.Once
}

func (n *memNet) pair() (*memConn, *memConn) {
	a := &memConn{net: n, local: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1001}, in: make(chan memPacket, 4096), done: make(chan struct{})}
	b := &memConn{net: n, local: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2002}, in: make(chan memPacket, 4096), done: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}

func (c *memConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()
	var timeout <-chan time.Time
	if !d.IsZero() {
		t := time.NewTimer(time.Until(d))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case pkt := <-c.in:
		return copy(p, pkt.data), pkt.from, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *memConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	if c.net.loss > 0 && rand.Float64() < c.net.loss {
		return len(p), nil
	}
	pkt := memPacket{data: bytes.Clone(p), from: c.local}
	deliver := func() {
		select {
		case c.peer.in <- pkt:
		default: // receiver queue full: drop, like a real NIC
		}
	}
	if c.net.delay > 0 {
		time.AfterFunc(c.net.delay, deliver)
	} else {
		deliver()
	}
	return len(p), nil
}

func (c *memConn) Close() error                  { c.once.Do(func() { close(c.done) }); return nil }
func (c *memConn) LocalAddr() net.Addr           { return c.local }
func (c *memConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }
func (c *memConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

func testKCPConf(t testing.TB, mode string, sndwnd, rcvwnd int) *conf.KCP {
	t.Helper()
	k := &conf.KCP{Mode: mode, Key: "test-key", Sndwnd: sndwnd, Rcvwnd: rcvwnd}
	if err := k.Init("client"); err != nil {
		t.Fatal(err)
	}
	return k
}

// pipe returns a connected client/server stream pair over the memory network.
func pipe(t testing.TB, n *memNet, cfg *conf.KCP) (client, server io.ReadWriteCloser) {
	t.Helper()
	ca, sa := n.pair()

	l, err := listenOn(cfg, sa)
	if err != nil {
		t.Fatal(err)
	}
	c, err := dialOn(sa.local, cfg, ca)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); l.Close(); ca.Close() })

	cs, err := c.OpenStrm()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Write([]byte{0}); err != nil { // smux opens lazily on the server side
		t.Fatal(err)
	}

	sconn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sconn.Close() })
	ss, err := sconn.AcceptStrm()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ss, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	return cs, ss
}

func TestLoopbackTransfer(t *testing.T) {
	n := &memNet{delay: 5 * time.Millisecond, loss: 0.02}
	cs, ss := pipe(t, n, testKCPConf(t, "fast2", 256, 256))

	want := make([]byte, 1<<20)
	crand.Read(want)
	go func() {
		cs.Write(want)
		cs.Close()
	}()

	got, err := io.ReadAll(ss)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func TestStrmImplementsWriterTo(t *testing.T) {
	var s any = &Strm{}
	if _, ok := s.(io.WriterTo); !ok {
		t.Fatal("Strm must implement io.WriterTo for zero-copy relaying")
	}
}

// BenchmarkThroughput measures one-stream bulk throughput for KCP modes and
// windows over a simulated link. Example:
//
//	go test ./internal/tnet/kcp -run x -bench Throughput -benchtime 4x
func BenchmarkThroughput(b *testing.B) {
	const chunk = 4 << 20
	cases := []struct {
		name           string
		rtt            time.Duration
		loss           float64
		mode           string
		sndwnd, rcvwnd int
	}{
		{"rtt40ms/fast/128x512", 40 * time.Millisecond, 0, "fast", 128, 512},
		{"rtt40ms/fast2/1024x2048", 40 * time.Millisecond, 0, "fast2", 1024, 2048},
		{"rtt40ms-loss1%/fast2/1024x2048", 40 * time.Millisecond, 0.01, "fast2", 1024, 2048},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			n := &memNet{delay: tc.rtt / 2, loss: tc.loss}
			cs, ss := pipe(b, n, testKCPConf(b, tc.mode, tc.sndwnd, tc.rcvwnd))
			wbuf, rbuf := make([]byte, chunk), make([]byte, chunk)
			b.SetBytes(chunk)
			b.ResetTimer()
			for range b.N {
				errCh := make(chan error, 1)
				go func() { _, err := cs.Write(wbuf); errCh <- err }()
				if _, err := io.ReadFull(ss, rbuf); err != nil {
					b.Fatal(err)
				}
				if err := <-errCh; err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
