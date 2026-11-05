package tnet

import (
	"net"
	"time"
)

type Conn interface {
	OpenStrm() (Strm, error)
	AcceptStrm() (Strm, error)
	Close() error
	// IsClosed reports whether the multiplexed session is dead and must be redialed.
	IsClosed() bool
	// NumStreams returns the number of streams currently open on the session.
	NumStreams() int
	// RTT returns the transport's smoothed round-trip time estimate.
	RTT() time.Duration
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}
