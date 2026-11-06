package socket

import (
	"bytes"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"paqet/internal/conf"
)

// fakeRx is an rxSource fed from a channel. It zeroes its frame buffer on
// close, so a payload used after close shows up as corrupted.
type fakeRx struct {
	frames  chan []byte
	wakeCh  chan struct{}
	buf     []byte
	closed  atomic.Bool
	inNext  atomic.Bool
	dropped atomic.Uint64
	done    chan struct{}
}

func newFakeRx() *fakeRx {
	return &fakeRx{frames: make(chan []byte, 64), wakeCh: make(chan struct{}, 1), buf: make([]byte, 2048), done: make(chan struct{})}
}

func (r *fakeRx) next() ([]byte, error) {
	if r.closed.Load() {
		panic("next after close")
	}
	r.inNext.Store(true)
	defer r.inNext.Store(false)
	select {
	case f := <-r.frames:
		return r.buf[:copy(r.buf, f)], nil
	case <-r.wakeCh:
		return nil, errTimeout
	case <-time.After(20 * time.Millisecond):
		return nil, errTimeout
	}
}

func (r *fakeRx) drops() uint64 { return r.dropped.Load() }

func (r *fakeRx) wake() {
	select {
	case r.wakeCh <- struct{}{}:
	default:
	}
}

func (r *fakeRx) close() {
	if r.inNext.Load() {
		panic("close during next")
	}
	if r.closed.Swap(true) {
		panic("double close")
	}
	clear(r.buf)
	close(r.done)
}

type fakeTx struct {
	mu     sync.Mutex
	frames [][]byte
	closed bool
}

func (t *fakeTx) write(f []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.frames = append(t.frames, bytes.Clone(f))
	return nil
}

func (t *fakeTx) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
}

func testNetConf(port int) *conf.Network {
	cfg := &conf.Network{Port: port}
	cfg.IPv4.Addr = &net.UDPAddr{IP: testV4.srcIP, Port: port}
	cfg.IPv4.Router = testDstMAC
	cfg.TCP.LF = []conf.TCPF{{PSH: true, ACK: true}}
	return cfg
}

func testConn(t *testing.T, port int) (*PacketConn, *fakeRx, *fakeTx) {
	t.Helper()
	rx, tx := newFakeRx(), &fakeTx{}
	cfg := testNetConf(port)
	return &PacketConn{send: newSendHandle(cfg, tx), recv: newRecvHandle(rx, port)}, rx, tx
}

func inbound(srcPort, dstPort uint16, payload string) []byte {
	a := frameAddrs{srcMAC: testDstMAC, dstMAC: testSrcMAC, srcIP: testV4.dstIP, dstIP: testV4.srcIP}
	s := tcpSegment{srcPort: srcPort, dstPort: dstPort, flags: conf.TCPF{PSH: true, ACK: true}}
	return encodeFrame(nil, &a, &s, []byte(payload))
}

func TestReadFromAndWriteTo(t *testing.T) {
	c, rx, tx := testConn(t, 9999)
	defer c.Close()

	rx.frames <- inbound(4000, 1234, "wrong port")
	rx.frames <- inbound(4000, 9999, "") // no payload
	rx.frames <- inbound(4000, 9999, "hello")
	buf := make([]byte, 100)
	n, addr, err := c.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "hello" || addr.String() != "10.0.0.2:4000" {
		t.Fatalf("ReadFrom = %q, %v, %v", buf[:n], addr, err)
	}

	// Replies work both to the returned address and to a *net.UDPAddr.
	if _, err := c.WriteTo([]byte("reply"), addr); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteTo([]byte("reply"), &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4000}); err != nil {
		t.Fatal(err)
	}
	if len(tx.frames) != 2 || !bytes.Equal(tx.frames[0][:ethHdrLen+ipv4HdrLen], tx.frames[1][:ethHdrLen+ipv4HdrLen]) {
		t.Fatalf("want 2 identical IP headers, got %d frames", len(tx.frames))
	}
	var d decodedFrame
	if !decodeFrame(tx.frames[0], &d) || string(d.payload) != "reply" || d.dstPort != 4000 || d.srcPort != 9999 {
		t.Fatalf("bad frame %x", tx.frames[0])
	}

	if _, err := c.WriteTo([]byte("x"), &net.UDPAddr{IP: net.ParseIP("2001:db8::9"), Port: 1}); !errors.Is(err, errNoIPv6) {
		t.Fatalf("IPv6 without a source address: %v", err)
	}
}

func TestLocalAddr(t *testing.T) {
	v4 := testNetConf(9999)
	v6 := &conf.Network{Port: 8443}
	v6.IPv6.Addr = &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8443}
	both := testNetConf(7000)
	both.IPv6.Addr = &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 7000}
	for _, tc := range []struct {
		name string
		cfg  *conf.Network
		want string
	}{
		{"ipv4", v4, "10.0.0.1:9999"},
		{"ipv6 only", v6, "[2001:db8::1]:8443"},
		{"ipv4 preferred", both, "10.0.0.1:7000"},
		{"none", &conf.Network{Port: 1234}, "0.0.0.0:1234"},
	} {
		if got := localAddr(tc.cfg); got.String() != tc.want || got.Network() != "udp" {
			t.Errorf("%s: localAddr = %s/%s, want %s/udp", tc.name, got.Network(), got, tc.want)
		}
	}

	c := &PacketConn{local: localAddr(v4)}
	if a := c.LocalAddr(); a == nil || a.String() != "10.0.0.1:9999" {
		t.Fatalf("LocalAddr = %v", a)
	}
	if a := (&PacketConn{}).LocalAddr(); a != nil {
		t.Fatalf("LocalAddr without an address = %#v, want untyped nil", a)
	}
}

func TestReadDeadline(t *testing.T) {
	c, _, _ := testConn(t, 9999)
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err := c.ReadFrom(make([]byte, 10)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestPusherDeliversAndStops(t *testing.T) {
	c, rx, _ := testConn(t, 9999)
	defer c.Close()

	got := make(chan string, 10)
	c.SetPacketReceiver(func(b []byte, addr net.Addr, err error) {
		if err != nil {
			got <- "err:" + err.Error()
			return
		}
		got <- addr.String() + " " + string(b)
	})
	rx.frames <- inbound(4000, 9999, "one")
	rx.frames <- inbound(4001, 9999, "two")
	for _, want := range []string{"10.0.0.2:4000 one", "10.0.0.2:4001 two"} {
		select {
		case g := <-got:
			if g != want {
				t.Fatalf("got %q want %q", g, want)
			}
		case <-time.After(time.Second):
			t.Fatal("packet not pushed")
		}
	}

	c.SetPacketReceiver(nil)
	time.Sleep(50 * time.Millisecond)
	rx.frames <- inbound(4000, 9999, "late")
	select {
	case g := <-got:
		t.Fatalf("pushed after the receiver was removed: %q", g)
	case <-time.After(100 * time.Millisecond):
	}

	// A new receiver picks up where the old one stopped.
	c.SetPacketReceiver(func(b []byte, _ net.Addr, err error) {
		if err == nil {
			got <- string(b)
		}
	})
	select {
	case g := <-got:
		if g != "late" {
			t.Fatalf("got %q", g)
		}
	case <-time.After(time.Second):
		t.Fatal("restarted receiver got nothing")
	}
}

func TestCloseWhileReceiving(t *testing.T) {
	// Closing while the receiver still uses a payload must not release the
	// capture buffer under it.
	c, rx, tx := testConn(t, 9999)
	inCallback := make(chan struct{})
	release := make(chan struct{})
	errs := make(chan error, 1)
	var seen []byte
	c.SetPacketReceiver(func(b []byte, _ net.Addr, err error) {
		if err != nil {
			errs <- err
			return
		}
		if seen == nil {
			close(inCallback)
			<-release
			seen = bytes.Clone(b)
		}
	})
	rx.frames <- inbound(4000, 9999, "payload")
	<-inCallback
	c.Close()
	if rx.closed.Load() {
		t.Fatal("source closed while a payload was in use")
	}
	close(release)
	select {
	case <-rx.done:
	case <-time.After(time.Second):
		t.Fatal("source never closed")
	}
	if string(seen) != "payload" {
		t.Fatalf("payload corrupted: %q", seen)
	}
	select {
	case err := <-errs:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receiver got %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("receiver not told about the close")
	}
	if !tx.closed {
		t.Fatal("send side not closed")
	}
}

func TestCloseIdle(t *testing.T) {
	c, rx, tx := testConn(t, 9999)
	c.Close()
	c.Close()
	if !rx.closed.Load() || !tx.closed {
		t.Fatal("idle conn did not release its handles")
	}
}

func TestDropsAccounting(t *testing.T) {
	base := Drops()
	c, rx, _ := testConn(t, 9999)
	rx.dropped.Store(5)
	if d := Drops() - base; d != 5 {
		t.Fatalf("live drops %d", d)
	}
	c.Close()
	if d := Drops() - base; d != 5 {
		t.Fatalf("drops lost on close: %d", d)
	}
}

func BenchmarkSendHandleWrite(b *testing.B) {
	h := newSendHandle(testNetConf(9999), discardTx{})
	dst := NewAddr(testV4.dstIP, 4000)
	payload := make([]byte, 1350)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for range b.N {
		h.write(payload, dst)
	}
}

type discardTx struct{}

func (discardTx) write([]byte) error { return nil }
func (discardTx) close()             {}
