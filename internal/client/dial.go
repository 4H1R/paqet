package client

import (
	"context"
	"errors"
	"time"

	"paqet/internal/flog"
	"paqet/internal/tnet"
)

const (
	retryMin  = 50 * time.Millisecond
	retryMax  = 2 * time.Second
	retryWait = 10 * time.Second // give up opening a stream after this long
)

var errNoConn = errors.New("client: no usable connection to server")

// pick chooses the live connection with the fewest open streams. The scan
// starts at a rotating offset so ties are spread round-robin. If no live
// connection exists, it returns the next slot so the caller redials it.
func (c *Client) pick() *timedConn {
	items := c.conns
	n := uint64(len(items))
	start := c.next.Add(1) - 1

	var best *timedConn
	bestStreams := 0
	for i := range n {
		tc := items[(start+i)%n]
		conn := tc.current()
		if conn == nil || conn.IsClosed() {
			continue
		}
		if s := conn.NumStreams(); best == nil || s < bestStreams {
			best, bestStreams = tc, s
		}
	}
	if best == nil {
		return items[start%n]
	}
	return best
}

func (c *Client) newStrm(ctx context.Context) (tnet.Strm, error) {
	ctx, cancel := context.WithTimeout(ctx, retryWait)
	defer cancel()

	delay := retryMin
	for {
		conn, err := c.pick().get()
		if err == nil {
			strm, serr := conn.OpenStrm()
			if serr == nil {
				return strm, nil
			}
			err = serr
		}
		if errors.Is(err, errClientClosed) {
			return nil, err
		}
		flog.Debugf("failed to open stream, retrying in %v: %v", delay, err)

		select {
		case <-ctx.Done():
			return nil, errors.Join(errNoConn, err)
		case <-time.After(delay):
		}
		delay = min(delay*2, retryMax)
	}
}

// maintain periodically redials dead connections in the background so user
// traffic does not pay the reconnect cost.
func (c *Client) maintain(ctx context.Context) {
	t := time.NewTicker(maintainInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			for _, tc := range c.conns {
				tc.maintain()
			}
		case <-ctx.Done():
			return
		}
	}
}
