package kcp

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"

	"paqet/internal/conf"
	"paqet/internal/socket"
	"paqet/internal/tnet"
)

// Listener accepts KCP sessions from one or more kcp-go listeners. On Linux
// the server can receive on several packet sockets that split clients by
// flow; each gets its own kcp-go listener, so decryption and KCP input for
// different clients run on different cores.
type Listener struct {
	PacketConns []*socket.PacketConn
	cfg         *conf.KCP
	listeners   []*kcp.Listener

	accepted chan acceptResult
	done     chan struct{}
	once     sync.Once
}

type acceptResult struct {
	sess *kcp.UDPSession
	err  error
}

func Listen(cfg *conf.KCP, netCfg conf.Network) (tnet.Listener, error) {
	nCfg := netCfg
	conns, err := socket.NewGroup(&nCfg, nCfg.PCAP.Readers)
	if err != nil {
		return nil, fmt.Errorf("kcp: failed to create packetconn: %w", err)
	}
	pcs := make([]net.PacketConn, len(conns))
	for i, c := range conns {
		pcs[i] = c
	}

	l, err := listenOn(cfg, pcs...)
	if err != nil {
		for _, c := range conns {
			c.Close()
		}
		return nil, err
	}
	l.PacketConns = conns
	return l, nil
}

// listenOn serves KCP sessions over existing packet conns.
func listenOn(cfg *conf.KCP, pcs ...net.PacketConn) (*Listener, error) {
	l := &Listener{
		cfg:      cfg,
		accepted: make(chan acceptResult),
		done:     make(chan struct{}),
	}
	for _, pc := range pcs {
		kl, err := kcp.ServeConn(cfg.Block, cfg.Dshard, cfg.Pshard, pc)
		if err != nil {
			for _, kl := range l.listeners {
				kl.Close()
			}
			return nil, fmt.Errorf("kcp: failed to serve connection: %w", err)
		}
		l.listeners = append(l.listeners, kl)
	}
	for _, kl := range l.listeners {
		go l.acceptLoop(kl)
	}
	return l, nil
}

func (l *Listener) acceptLoop(kl *kcp.Listener) {
	for {
		sess, err := kl.AcceptKCP()
		select {
		case l.accepted <- acceptResult{sess, err}:
		case <-l.done:
			if sess != nil {
				sess.Close()
			}
			return
		}
		if err != nil {
			return
		}
	}
}

func (l *Listener) Accept() (tnet.Conn, error) {
	var r acceptResult
	select {
	case r = <-l.accepted:
	case <-l.done:
		return nil, fmt.Errorf("kcp: failed to accept connection: %w", net.ErrClosed)
	}
	if r.err != nil {
		return nil, fmt.Errorf("kcp: failed to accept connection: %w", r.err)
	}
	conn := r.sess
	aplConf(conn, l.cfg)
	sess, err := smux.Server(conn, smuxConf(l.cfg))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("kcp: failed to create smux session: %w", err)
	}
	return &Conn{nil, conn, sess}, nil
}

func (l *Listener) Close() error {
	var errs []error
	l.once.Do(func() {
		close(l.done)
		for _, kl := range l.listeners {
			errs = append(errs, kl.Close())
		}
		for _, pc := range l.PacketConns {
			errs = append(errs, pc.Close())
		}
	})
	return errors.Join(errs...)
}

func (l *Listener) Addr() net.Addr {
	return l.listeners[0].Addr()
}

// All conns of a group share one send handle, so setting the flags on the
// first applies to every reader.
func (l *Listener) SetClientTCPF(addr net.Addr, f []conf.TCPF) {
	if len(l.PacketConns) > 0 {
		l.PacketConns[0].SetClientTCPF(addr, f)
	}
}

func (l *Listener) DeleteClientTCPF(addr net.Addr) {
	if len(l.PacketConns) > 0 {
		l.PacketConns[0].DeleteClientTCPF(addr)
	}
}
