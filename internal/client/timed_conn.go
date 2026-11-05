package client

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
)

var errClientClosed = errors.New("client: closed")

const tcpfTimeout = 5 * time.Second

type connRef struct{ tnet.Conn }

// timedConn is one slot of the client's connection pool. It owns a single
// transport session and redials it when the session dies.
type timedConn struct {
	cfg  *conf.Conf
	dial func() (tnet.Conn, error)

	mu     sync.Mutex // serializes redials and close
	conn   tnet.Conn
	closed bool

	cur atomic.Pointer[connRef] // lock-free view of conn for pick()
}

func (tc *timedConn) setLocked(conn tnet.Conn) {
	tc.conn = conn
	if conn == nil {
		tc.cur.Store(nil)
	} else {
		tc.cur.Store(&connRef{conn})
	}
}

func newTimedConn(cfg *conf.Conf) (*timedConn, error) {
	tc := &timedConn{cfg: cfg}
	tc.dial = tc.dialKCP
	conn, err := tc.dial()
	if err != nil {
		return nil, err
	}
	tc.setLocked(conn)
	return tc, nil
}

func (tc *timedConn) dialKCP() (tnet.Conn, error) {
	conn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, tc.cfg.Network)
	if err != nil {
		return nil, err
	}
	if err := sendTCPF(conn, tc.cfg.Network.TCP.RF); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// get returns a live session, redialing first if the current one is dead.
func (tc *timedConn) get() (tnet.Conn, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.closed {
		return nil, errClientClosed
	}
	if tc.conn != nil && !tc.conn.IsClosed() {
		return tc.conn, nil
	}
	return tc.redialLocked()
}

func (tc *timedConn) redialLocked() (tnet.Conn, error) {
	if tc.conn != nil {
		tc.conn.Close()
		tc.setLocked(nil)
		flog.Infof("connection lost, reconnecting...")
	}
	conn, err := tc.dial()
	if err != nil {
		return nil, err
	}
	tc.setLocked(conn)
	return conn, nil
}

// current returns the session without locking or redialing. It may be nil
// or closed.
func (tc *timedConn) current() tnet.Conn {
	if r := tc.cur.Load(); r != nil {
		return r.Conn
	}
	return nil
}

// maintain redials a dead session, or re-announces the TCP flags on a live
// one so the server recovers them after a restart.
func (tc *timedConn) maintain() {
	tc.mu.Lock()
	if tc.closed {
		tc.mu.Unlock()
		return
	}
	if tc.conn == nil || tc.conn.IsClosed() {
		if _, err := tc.redialLocked(); err != nil {
			flog.Debugf("background reconnect failed: %v", err)
		}
		tc.mu.Unlock()
		return
	}
	conn := tc.conn
	tc.mu.Unlock()

	// Outside the lock: a congested session must not stall redials or close.
	if err := sendTCPF(conn, tc.cfg.Network.TCP.RF); err != nil {
		flog.Debugf("failed to refresh TCP flags: %v", err)
	}
}

func (tc *timedConn) close() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.closed = true
	if tc.conn != nil {
		tc.conn.Close()
		tc.setLocked(nil)
	}
}

func sendTCPF(conn tnet.Conn, f []conf.TCPF) error {
	strm, err := conn.OpenStrm()
	if err != nil {
		return err
	}
	defer strm.Close()
	strm.SetWriteDeadline(time.Now().Add(tcpfTimeout))

	p := protocol.Proto{Type: protocol.PTCPF, TCPF: f}
	return p.Write(strm)
}
