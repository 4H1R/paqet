package server

import (
	"context"
	"fmt"
	"sync"

	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/pkg/memtrim"
	"paqet/internal/stats"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
)

type Server struct {
	cfg      *conf.Conf
	listener tnet.Listener

	mu    sync.Mutex
	conns map[tnet.Conn]struct{} // live client sessions, for stats
}

func New(cfg *conf.Conf) (*Server, error) {
	s := &Server{cfg: cfg, conns: make(map[tnet.Conn]struct{})}
	return s, nil
}

func (s *Server) Start(ctx context.Context) error {
	listener, err := kcp.Listen(s.cfg.Transport.KCP, s.cfg.Network)
	if err != nil {
		return fmt.Errorf("could not start KCP listener: %w", err)
	}
	s.listener = listener
	flog.Infof("server listening for packets on :%d", s.cfg.Listen.Addr.Port)

	go s.listen(ctx, listener)
	go memtrim.Run(ctx, stats.Traffic)
	context.AfterFunc(ctx, func() { listener.Close() })
	if s.cfg.Log.StatsInterval > 0 {
		go stats.Run(ctx, s.cfg.Log.StatsInterval, s.sessions)
	}

	return nil
}

func (s *Server) listen(ctx context.Context, listener tnet.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		flog.Infof("accepted new connection from %s (local: %s)", conn.RemoteAddr(), conn.LocalAddr())

		s.track(conn, true)
		go func() {
			defer s.track(conn, false)
			defer conn.Close()
			defer s.listener.DeleteClientTCPF(conn.RemoteAddr())
			s.handleConn(ctx, conn)
		}()
	}
}

func (s *Server) track(conn tnet.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[conn] = struct{}{}
	} else {
		delete(s.conns, conn)
	}
}

func (s *Server) sessions() []tnet.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]tnet.Conn, 0, len(s.conns))
	for c := range s.conns {
		out = append(out, c)
	}
	return out
}
