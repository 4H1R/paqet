package stats

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"paqet/internal/tnet"
)

type conn struct {
	tnet.Conn
	rtt     time.Duration
	streams int
	closed  bool
}

func (c conn) RTT() time.Duration { return c.rtt }
func (c conn) NumStreams() int    { return c.streams }
func (c conn) IsClosed() bool     { return c.closed }
func (c conn) RemoteAddr() net.Addr {
	return nil
}

func TestFormat(t *testing.T) {
	prev := &kcp.Snmp{}
	cur := &kcp.Snmp{InBytes: 1_250_000, OutBytes: 125_000, OutSegs: 1000, RetransSegs: 20, LostSegs: 5}
	got := Format(prev, cur, time.Second, []tnet.Conn{
		conn{rtt: 80 * time.Millisecond, streams: 3},
		conn{rtt: 100 * time.Millisecond, streams: 1},
		conn{rtt: time.Hour, closed: true}, // ignored
	})
	for _, want := range []string{"sessions=2", "streams=4", "rtt=80ms/90ms/100ms", "rx=10.00Mbit/s", "tx=1.00Mbit/s", "retrans=20.0/s", "lost=5.0/s"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}

func TestFormatIdle(t *testing.T) {
	got := Format(&kcp.Snmp{}, &kcp.Snmp{}, 0, nil)
	if !strings.Contains(got, "rtt=n/a") || !strings.Contains(got, "retrans=0.0/s") {
		t.Fatalf("unexpected idle output: %q", got)
	}
}
