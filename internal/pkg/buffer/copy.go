package buffer

import (
	"context"
	"errors"
	"io"
	"net"
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

// PutUDP returns a buffer obtained from GetUDP to the pool.
func PutUDP(bp *[]byte) { udpPool.Put(bp) }

// idleRelease is how long a socket copy keeps its pooled buffer while no
// data arrives. After that the buffer goes back to the pool and the copy
// waits for the socket to become readable without holding one, so idle
// connections cost no buffer memory.
var idleRelease = 2 * time.Second

var testHookIdleRelease func()

// CopyT copies src to dst until EOF. A clean EOF returns nil.
//
// Sources that hand out their own buffers (smux streams implement WriterTo)
// are drained without an extra copy. OS sockets also implement WriterTo, but
// their generic fallback allocates a fresh 32KB buffer per call, so they use
// a pooled buffer instead, released while the connection is idle.
func CopyT(dst io.Writer, src io.Reader) error {
	if wt, ok := src.(io.WriterTo); ok && !isOSConn(src) {
		_, err := wt.WriteTo(dst)
		return cleanEOF(err)
	}
	if c, ok := src.(osConn); ok {
		if rc, err := c.SyscallConn(); err == nil {
			return copyIdleAware(dst, c, rc)
		}
	}

	bp := tcpPool.Get().(*[]byte)
	buf := *bp
	for {
		n, err := src.Read(buf)
		if n > 0 {
			w, werr := dst.Write(buf[:n])
			if werr != nil {
				// Deliberately not returned to the pool: a failed write may
				// still be referenced by dst. smux, for one, returns as soon
				// as the session dies while its send loop can still be
				// reading the frame.
				return werr
			}
			if w < n {
				tcpPool.Put(bp)
				return io.ErrShortWrite
			}
		}
		if err != nil {
			tcpPool.Put(bp)
			return cleanEOF(err)
		}
	}
}

type osConn interface {
	net.Conn
	SyscallConn() (syscall.RawConn, error)
}

// copyIdleAware is CopyT for OS sockets. It holds a pooled buffer while
// data flows and gives it back after idleRelease without data.
func copyIdleAware(dst io.Writer, src osConn, rc syscall.RawConn) error {
	wait := readableWaiter()
	for {
		// Block until data (or EOF, or an error) is ready, without a buffer.
		if err := rc.Read(wait); err != nil {
			return cleanEOF(err)
		}

		bp := tcpPool.Get().(*[]byte)
		buf := *bp
		// One deadline per active period, not per read: if it fires while
		// data still flows, the loop just takes another trip around.
		src.SetReadDeadline(time.Now().Add(idleRelease))
		for {
			n, err := src.Read(buf)
			if n > 0 {
				w, werr := dst.Write(buf[:n])
				if werr != nil {
					src.SetReadDeadline(time.Time{})
					return werr // buffer may still be referenced; see CopyT
				}
				if w < n {
					tcpPool.Put(bp)
					src.SetReadDeadline(time.Time{})
					return io.ErrShortWrite
				}
			}
			if err != nil {
				tcpPool.Put(bp)
				if errors.Is(err, os.ErrDeadlineExceeded) {
					if testHookIdleRelease != nil {
						testHookIdleRelease()
					}
					break // idle: release the buffer and wait again
				}
				return cleanEOF(err)
			}
		}
		if err := src.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
	}
}

func isOSConn(r io.Reader) bool {
	switch r.(type) {
	case *net.TCPConn, *net.UnixConn:
		return true
	}
	return false
}

func cleanEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// Relay copies data both ways between a and b. It returns when either
// direction ends or ctx is cancelled, with the first copy error (nil on a
// clean EOF or cancellation). Relay closes a and b (if they implement
// io.Closer) as soon as one direction ends so the other one unblocks;
// callers may close them again.
//
// One direction runs on the calling goroutine, so a relay costs one extra
// goroutine instead of two.
func Relay(ctx context.Context, a, b io.ReadWriter) error {
	var (
		once  sync.Once
		first error
	)
	finish := func(err error, record bool) {
		once.Do(func() {
			if record {
				first = err
			}
			closeRW(a)
			closeRW(b)
		})
	}
	stop := context.AfterFunc(ctx, func() { finish(nil, false) })
	defer stop()

	go func() { finish(CopyT(a, b), true) }()
	finish(CopyT(b, a), true)
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
