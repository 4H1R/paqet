package client

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"paqet/internal/tnet"
)

type fakeConn struct {
	closed  atomic.Bool
	streams int
	opens   atomic.Int32
}

func (f *fakeConn) OpenStrm() (tnet.Strm, error) {
	if f.closed.Load() {
		return nil, net.ErrClosed
	}
	f.opens.Add(1)
	c, _ := net.Pipe()
	return fakeStrm{c}, nil
}
func (f *fakeConn) AcceptStrm() (tnet.Strm, error)   { return nil, errors.New("unused") }
func (f *fakeConn) Close() error                     { f.closed.Store(true); return nil }
func (f *fakeConn) IsClosed() bool                   { return f.closed.Load() }
func (f *fakeConn) NumStreams() int                  { return f.streams }
func (f *fakeConn) RTT() time.Duration               { return 0 }
func (f *fakeConn) LocalAddr() net.Addr              { return nil }
func (f *fakeConn) RemoteAddr() net.Addr             { return nil }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeStrm struct{ net.Conn }

func (fakeStrm) SID() int { return 0 }

func slot(conn tnet.Conn, dial func() (tnet.Conn, error)) *timedConn {
	tc := &timedConn{dial: dial}
	if conn != nil {
		tc.setLocked(conn)
	}
	return tc
}

func noDial() (tnet.Conn, error) { return nil, errors.New("dial disabled") }

func TestPickPrefersLeastLoadedLiveConn(t *testing.T) {
	busy := &fakeConn{streams: 9}
	idle := &fakeConn{streams: 1}
	dead := &fakeConn{}
	dead.Close()
	c := &Client{conns: []*timedConn{slot(busy, noDial), slot(dead, noDial), slot(idle, noDial)}}

	for range 6 {
		if got := c.pick().current(); got != idle {
			t.Fatalf("picked %p, want the least-loaded live conn %p", got, idle)
		}
	}
}

func TestPickSpreadsTies(t *testing.T) {
	a, b := &fakeConn{}, &fakeConn{}
	c := &Client{conns: []*timedConn{slot(a, noDial), slot(b, noDial)}}
	seen := map[tnet.Conn]bool{}
	for range 4 {
		seen[c.pick().current()] = true
	}
	if len(seen) != 2 {
		t.Fatal("equally loaded conns should be used round-robin")
	}
}

func TestNewStrmRedialsDeadConn(t *testing.T) {
	dead := &fakeConn{}
	dead.Close()
	fresh := &fakeConn{}
	var dials atomic.Int32
	c := &Client{conns: []*timedConn{slot(dead, func() (tnet.Conn, error) {
		dials.Add(1)
		return fresh, nil
	})}}

	s, err := c.newStrm(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if dials.Load() != 1 || fresh.opens.Load() != 1 {
		t.Fatalf("dials=%d opens=%d, want 1/1", dials.Load(), fresh.opens.Load())
	}
}

func TestNewStrmOpensNoExtraStreams(t *testing.T) {
	live := &fakeConn{}
	c := &Client{conns: []*timedConn{slot(live, noDial)}}
	for range 5 {
		s, err := c.newStrm(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
	}
	if n := live.opens.Load(); n != 5 {
		t.Fatalf("opened %d streams for 5 requests; want exactly 5 (no ping/TCPF streams)", n)
	}
}

func TestNewStrmBacksOffAndHonorsContext(t *testing.T) {
	var dials atomic.Int32
	c := &Client{conns: []*timedConn{slot(nil, func() (tnet.Conn, error) {
		dials.Add(1)
		return nil, errors.New("server unreachable")
	})}}

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.newStrm(ctx); err == nil {
		t.Fatal("expected error")
	}
	if time.Since(start) > time.Second {
		t.Fatal("newStrm ignored context cancellation")
	}
	// 50+100+200 ms backoff fits ~4 attempts in 400ms; a tight loop would make thousands.
	if n := dials.Load(); n > 6 {
		t.Fatalf("%d dial attempts in 400ms: retry loop is not backing off", n)
	}
}

func TestClosedSlotStopsRetrying(t *testing.T) {
	tc := slot(&fakeConn{}, noDial)
	tc.close()
	c := &Client{conns: []*timedConn{tc}}
	if _, err := c.newStrm(context.Background()); !errors.Is(err, errClientClosed) {
		t.Fatalf("got %v, want errClientClosed", err)
	}
}
