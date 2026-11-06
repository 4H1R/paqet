// Package stats periodically logs transport health: throughput, retransmits,
// loss and per-session RTT. It is the baseline for tuning KCP settings.
package stats

import (
	"context"
	"fmt"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"paqet/internal/flog"
	"paqet/internal/socket"
	"paqet/internal/tnet"
)

// Run logs a stats line every interval until ctx is done. conns returns the
// sessions to report RTT and stream counts for.
func Run(ctx context.Context, interval time.Duration, conns func() []tnet.Conn) {
	t := time.NewTicker(interval)
	defer t.Stop()

	prev := kcp.DefaultSnmp.Copy()
	prevDrops := socket.Drops()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			cur := kcp.DefaultSnmp.Copy()
			line := Format(prev, cur, now.Sub(last), conns())
			if drops := socket.Drops(); drops > prevDrops {
				line += fmt.Sprintf(" capture_drops=%d", drops-prevDrops)
				prevDrops = drops
			}
			flog.Statsf("%s", line)
			prev, last = cur, now
		}
	}
}

// Format renders the delta between two snapshots taken elapsed apart.
func Format(prev, cur *kcp.Snmp, elapsed time.Duration, conns []tnet.Conn) string {
	secs := elapsed.Seconds()
	if secs <= 0 {
		secs = 1
	}
	d := func(a, b uint64) uint64 { return b - a }
	// Rates, not percentages: kcp-go's OutSegs also counts ACK segments, so
	// a ratio against it understates loss badly on a receive-heavy side.
	// Retransmits only cover what this side sends: check the server's stats
	// for download health and the client's for upload.
	rate := func(a, b uint64) float64 { return float64(d(a, b)) / secs }

	var live, streams int
	var minRTT, maxRTT, sumRTT time.Duration
	for _, c := range conns {
		if c == nil || c.IsClosed() {
			continue
		}
		rtt := c.RTT()
		if live == 0 || rtt < minRTT {
			minRTT = rtt
		}
		maxRTT = max(maxRTT, rtt)
		sumRTT += rtt
		streams += c.NumStreams()
		live++
	}
	rtt := "rtt=n/a"
	if live > 0 {
		rtt = fmt.Sprintf("rtt=%v/%v/%v (min/avg/max)", minRTT, (sumRTT / time.Duration(live)).Round(time.Millisecond), maxRTT)
	}

	s := fmt.Sprintf("sessions=%d streams=%d %s rx=%.2fMbit/s tx=%.2fMbit/s retrans=%.1f/s lost=%.1f/s (fast=%d early=%d)",
		live, streams, rtt,
		float64(d(prev.InBytes, cur.InBytes))*8/secs/1e6,
		float64(d(prev.OutBytes, cur.OutBytes))*8/secs/1e6,
		rate(prev.RetransSegs, cur.RetransSegs),
		rate(prev.LostSegs, cur.LostSegs),
		d(prev.FastRetransSegs, cur.FastRetransSegs),
		d(prev.EarlyRetransSegs, cur.EarlyRetransSegs),
	)
	if fec := d(prev.FECRecovered, cur.FECRecovered); fec > 0 || cur.FECParityShards > 0 {
		s += fmt.Sprintf(" fec_recovered=%d", fec)
	}
	if errs := d(prev.InCsumErrors, cur.InCsumErrors) + d(prev.KCPInErrors, cur.KCPInErrors); errs > 0 {
		s += fmt.Sprintf(" in_errors=%d", errs)
	}
	return s
}
