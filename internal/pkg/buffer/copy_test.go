package buffer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
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
