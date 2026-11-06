//go:build linux

package socket

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"paqet/internal/conf"
)

// TestAFPacketLoopback sends frames through the transmit ring (and the
// per-packet fallback) and receives them through the receive ring on the
// loopback interface. It needs CAP_NET_RAW.
func TestAFPacketLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for AF_PACKET")
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no loopback interface")
	}
	for i, name := range []string{"ring", "raw"} {
		t.Run(name, func(t *testing.T) {
			port := 40000 + i
			cfg := &conf.Network{Interface: lo, Port: port}
			cfg.PCAP.Sockbuf = 16 << 20 // holds the whole burst; reading starts after sending
			cfg.PCAP.Backend = backendAFPacket

			rx, tx, err := openBackend(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := tx.(*ringTx); !ok {
				t.Fatalf("expected the TX ring, got %T", tx)
			}
			if name == "raw" {
				tx.close()
				if tx, err = newRawTx(lo.Index); err != nil {
					t.Fatal(err)
				}
			}
			h := newRecvHandle(rx, port)
			defer h.close()
			defer tx.close()

			const flows, perFlow = 8, 100
			a := frameAddrs{srcMAC: make([]byte, 6), dstMAC: make([]byte, 6), srcIP: net.IPv4(127, 0, 0, 1).To4(), dstIP: net.IPv4(127, 0, 0, 1).To4()}
			send := func(sport, dport uint16, payload string) {
				s := tcpSegment{srcPort: sport, dstPort: dport, flags: conf.TCPF{PSH: true, ACK: true}}
				if err := tx.write(encodeFrame(nil, &a, &s, []byte(payload))); err != nil {
					t.Fatal(err)
				}
			}
			for i := range perFlow {
				for f := range flows {
					send(uint16(20000+f), uint16(port), fmt.Sprintf("%d:%d", f, i))
				}
				send(1, uint16(port+1000), "other port") // must be filtered out
			}

			next := map[int]int{}
			total := 0
			deadline := time.Now().Add(5 * time.Second)
			for total < flows*perFlow && time.Now().Before(deadline) {
				err := h.read(func(p []byte, from *Addr) {
					var f, i int
					fmt.Sscanf(string(p), "%d:%d", &f, &i)
					if from.Port != 20000+f || i != next[f] {
						t.Fatalf("frame %q from %v out of order (want seq %d)", p, from, next[f])
					}
					next[f]++
					total++
				})
				if err != nil && !skippable(err) {
					t.Fatal(err)
				}
			}
			if total != flows*perFlow {
				t.Fatalf("received %d of %d frames", total, flows*perFlow)
			}
			if d := rx.drops(); d != 0 {
				t.Errorf("kernel dropped %d frames", d)
			}
		})
	}
}
