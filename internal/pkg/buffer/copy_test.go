package buffer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type writerToReader struct {
	r      io.Reader
	called bool
}

func (w *writerToReader) Read(p []byte) (int, error) { return w.r.Read(p) }
func (w *writerToReader) WriteTo(dst io.Writer) (int64, error) {
	w.called = true
	n, err := io.Copy(dst, w.r)
	if err == nil {
		err = io.EOF // smux streams report EOF from WriteTo
	}
	return n, err
}

func TestCopyTCleanEOF(t *testing.T) {
	src := strings.Repeat("x", 3*TCPSize+7)
	var dst bytes.Buffer
	// Hide strings.Reader's WriteTo so the pooled read/write loop is exercised.
	if err := CopyT(&dst, struct{ io.Reader }{strings.NewReader(src)}); err != nil {
		t.Fatal(err)
	}
	if dst.String() != src {
		t.Fatal("payload mismatch")
	}
}

func TestCopyTUsesWriterTo(t *testing.T) {
	src := &writerToReader{r: strings.NewReader("hello")}
	var dst bytes.Buffer
	if err := CopyT(&dst, src); err != nil {
		t.Fatalf("EOF from WriteTo must be treated as clean: %v", err)
	}
	if !src.called || dst.String() != "hello" {
		t.Fatalf("WriteTo not used or wrong data: called=%v data=%q", src.called, dst.String())
	}
}

func TestCopyTSkipsOSConnWriterTo(t *testing.T) {
	if !isOSConn(&net.TCPConn{}) {
		t.Fatal("*net.TCPConn must use the pooled buffer path")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestCopyTWriteError(t *testing.T) {
	if err := CopyT(errWriter{}, struct{ io.Reader }{strings.NewReader("x")}); err == nil {
		t.Fatal("expected write error")
	}
}

// retainingWriter keeps the slice it was given and fails, like a smux stream
// whose session died while the frame was still queued.
type retainingWriter struct{ kept []byte }

func (w *retainingWriter) Write(p []byte) (int, error) {
	w.kept = p
	return 0, errors.New("session closed")
}

func TestCopyTDoesNotRecycleBufferAfterFailedWrite(t *testing.T) {
	w := &retainingWriter{}
	CopyT(w, struct{ io.Reader }{strings.NewReader("original")})

	// A buffer returned to the pool would almost certainly be handed to the
	// next copy and overwritten while w still references it.
	for range 4 {
		var dst bytes.Buffer
		CopyT(&dst, struct{ io.Reader }{strings.NewReader("OVERWRITTEN")})
	}
	if string(w.kept) != "original" {
		t.Fatalf("buffer still referenced by a failed write was reused: %q", w.kept)
	}
}

func TestRelay(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Relay(context.Background(), a2, b1) }()

	go a1.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(b2, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("a->b: %q %v", buf, err)
	}
	go b2.Write([]byte("pong"))
	if _, err := io.ReadFull(a1, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("b->a: %q %v", buf, err)
	}

	a1.Close()
	if err := <-done; err != nil {
		t.Fatalf("clean close should return nil, got %v", err)
	}
}

func tcpPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	if s == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	return c.(*net.TCPConn), s.(*net.TCPConn)
}

func TestCopyTReleasesBufferWhileIdle(t *testing.T) {
	old := idleRelease
	idleRelease = 30 * time.Millisecond
	released := make(chan struct{}, 16)
	testHookIdleRelease = func() { released <- struct{}{} }
	t.Cleanup(func() { idleRelease = old; testHookIdleRelease = nil })

	c, s := tcpPair(t)
	var dst bytes.Buffer
	var mu sync.Mutex
	done := make(chan error, 1)
	go func() { done <- CopyT(lockedWriter{&dst, &mu}, s) }()

	var want bytes.Buffer
	for i := range 3 {
		chunk := bytes.Repeat([]byte{byte('a' + i)}, 100_000) // several reads per burst
		want.Write(chunk)
		if _, err := c.Write(chunk); err != nil {
			t.Fatal(err)
		}
		select {
		case <-released:
		case <-time.After(2 * time.Second):
			t.Fatalf("burst %d: buffer not released after going idle", i)
		}
	}
	c.Close()
	if err := <-done; err != nil {
		t.Fatalf("clean close should return nil, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !bytes.Equal(dst.Bytes(), want.Bytes()) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", dst.Len(), want.Len())
	}
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestCopyTSocketEOFWithoutData(t *testing.T) {
	c, s := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- CopyT(io.Discard, s) }()
	c.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("EOF on an idle socket was not noticed")
	}
}

func TestRelayUnblocksOtherDirection(t *testing.T) {
	// a's peer closes; Relay must return even though nothing ever arrives
	// on b, and must close b so its peer sees EOF.
	a1, a2 := tcpPair(t)
	b1, b2 := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- Relay(context.Background(), a2, b1) }()
	a1.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Relay did not return")
	}
	b2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := b2.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("peer of b should see EOF, got %v", err)
	}
}

func TestRelayContextCancel(t *testing.T) {
	_, a2 := tcpPair(t)
	b1, _ := tcpPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Relay(ctx, a2, b1) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancellation should return nil, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Relay ignored cancellation")
	}
}
