package buffer

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

const (
	TCPSize = 32 * 1024
	UDPSize = 4 * 1024
	_       = uint(0xFFFF - UDPSize)
)

var tcpPool = sync.Pool{New: func() any {
	b := make([]byte, TCPSize)
	return &b
}}

var udpPool = sync.Pool{New: func() any {
	b := make([]byte, UDPSize)
	return &b
}}

// GetUDP returns a pooled datagram buffer of UDPSize bytes.
func GetUDP() *[]byte {
	bp := udpPool.Get().(*[]byte)
	*bp = (*bp)[:UDPSize]
	return bp
}

// PutUDP returns a buffer obtained from GetUDP.
func PutUDP(bp *[]byte) { udpPool.Put(bp) }

// idleRelease is how long a socket copy keeps its buffer without data.
var idleRelease = 2 * time.Second

var testHookIdleRelease func()

// socket is an OS socket whose readiness can be awaited without a buffer.
type socket interface {
	io.Reader
	SetReadDeadline(time.Time) error
	SyscallConn() (syscall.RawConn, error)
}

// CopyT copies src to dst until EOF. A clean EOF returns nil.
//
// Sources that hand out their own buffers (smux streams implement WriterTo)
// are drained without an extra copy. Other sources are copied through a
// pooled buffer; for OS sockets the buffer goes back to the pool while the
// connection is idle, so idle connections hold no buffer memory.
func CopyT(dst io.Writer, src io.Reader) error {
	sock, isSock := src.(socket)
	// OS sockets implement WriterTo too, but with a fresh 32KB buffer per call.
	if wt, ok := src.(io.WriterTo); ok && !isSock {
		_, err := wt.WriteTo(dst)
		return cleanEOF(err)
	}

	var (
		rc   syscall.RawConn
		wait func(uintptr) bool
	)
	if isSock {
		if rc, _ = sock.SyscallConn(); rc != nil {
			wait = readableWaiter()
		}
	}
	for {
		if rc != nil {
			if err := rc.Read(wait); err != nil {
				return cleanEOF(err)
			}
			// One deadline per busy period rather than per read; if it fires
			// mid-transfer the loop just goes around once more.
			sock.SetReadDeadline(time.Now().Add(idleRelease))
		}

		bp := tcpPool.Get().(*[]byte)
		reusable, err := copyBuffer(dst, src, *bp)
		if reusable {
			tcpPool.Put(bp)
		}
		if rc != nil && errors.Is(err, os.ErrDeadlineExceeded) {
			if testHookIdleRelease != nil {
				testHookIdleRelease()
			}
			if err := sock.SetReadDeadline(time.Time{}); err != nil {
				return err
			}
			continue
		}
		return cleanEOF(err)
	}
}

// copyBuffer copies until src or dst fails. reusable is false after a
// failed write: dst may still reference buf (smux returns as soon as its
// session dies while its send loop can still be reading the frame).
func copyBuffer(dst io.Writer, src io.Reader, buf []byte) (reusable bool, err error) {
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			w, werr := dst.Write(buf[:n])
			if werr != nil {
				return false, werr
			}
			if w < n {
				return true, io.ErrShortWrite
			}
		}
		if rerr != nil {
			return true, rerr
		}
	}
}

func cleanEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// Relay copies data both ways between a and b until either direction ends
// or ctx is cancelled, and returns the first copy error (nil on a clean EOF
// or cancellation). It closes a and b, if they are io.Closers, as soon as
// one direction ends so the other unblocks. One direction runs on the
// calling goroutine.
func Relay(ctx context.Context, a, b io.ReadWriter) error {
	var (
		once  sync.Once
		first error
	)
	finish := func(err error) {
		once.Do(func() {
			first = err
			closeRW(a)
			closeRW(b)
		})
	}
	defer context.AfterFunc(ctx, func() { finish(nil) })()

	go func() { finish(CopyT(a, b)) }()
	finish(CopyT(b, a))
	return first
}

func closeRW(rw io.ReadWriter) {
	if c, ok := rw.(io.Closer); ok {
		c.Close()
	}
}

func CopyU(dst io.Writer, src io.Reader) error {
	buf := make([]byte, UDPSize+1)
	for {
		n, err := src.Read(buf)
		switch {
		case n > UDPSize:
		case n > 0:
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			return cleanEOF(err)
		}
	}
}
