package client

import (
	"context"
	"sync/atomic"
	"time"

	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/pkg/memtrim"
	"paqet/internal/stats"
	"paqet/internal/tnet"
)

const maintainInterval = 10 * time.Second

type Client struct {
	cfg     *conf.Conf
	conns   []*timedConn
	next    atomic.Uint64
	udpPool *udpPool
}

func New(cfg *conf.Conf) (*Client, error) {
	c := &Client{
		cfg:     cfg,
		udpPool: newUDPPool(),
	}
	return c, nil
}

func (c *Client) Start(ctx context.Context) error {
	for i := range c.cfg.Transport.Conn {
		tc, err := newTimedConn(c.cfg)
		if err != nil {
			flog.Errorf("failed to create connection %d: %v", i+1, err)
			for _, tc := range c.conns {
				tc.close()
			}
			return err
		}
		c.conns = append(c.conns, tc)
	}
	context.AfterFunc(ctx, func() {
		for _, tc := range c.conns {
			tc.close()
		}
	})

	go c.maintain(ctx)
	go c.udpPool.ticker(ctx)
	go memtrim.Run(ctx, stats.Traffic)
	if c.cfg.Log.StatsInterval > 0 {
		go stats.Run(ctx, c.cfg.Log.StatsInterval, c.sessions)
	}

	ipv4Addr := "<nil>"
	ipv6Addr := "<nil>"
	if c.cfg.Network.IPv4.Addr != nil {
		ipv4Addr = c.cfg.Network.IPv4.Addr.IP.String()
	}
	if c.cfg.Network.IPv6.Addr != nil {
		ipv6Addr = c.cfg.Network.IPv6.Addr.IP.String()
	}
	flog.Infof("client IPv4:%s IPv6:%s -> %s (%d connections)", ipv4Addr, ipv6Addr, c.cfg.Server.Addr, len(c.conns))
	return nil
}

// sessions returns the current transport sessions, skipping empty slots.
func (c *Client) sessions() []tnet.Conn {
	out := make([]tnet.Conn, 0, len(c.conns))
	for _, tc := range c.conns {
		if conn := tc.current(); conn != nil {
			out = append(out, conn)
		}
	}
	return out
}
