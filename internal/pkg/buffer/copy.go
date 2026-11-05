package buffer

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
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

// CopyT copies src to dst until EOF. A clean EOF returns nil.
//
// Sources that hand out their own buffers (smux streams implement WriterTo)
// are drained without an extra copy. OS sockets also implement WriterTo, but
// their generic fallback allocates a fresh 32KB buffer per call, so they use
// a pooled buffer instead.
func CopyT(dst io.Writer, src io.Reader) error {
	if wt, ok := src.(io.WriterTo); ok && !isOSConn(src) {
		_, err := wt.WriteTo(dst)
		return cleanEOF(err)
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
// clean EOF). Callers must close a and b afterwards to stop the other
// direction.
func Relay(ctx context.Context, a, b io.ReadWriter) error {
	errCh := make(chan error, 2)
	go func() { errCh <- CopyT(a, b) }()
	go func() { errCh <- CopyT(b, a) }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return nil
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
