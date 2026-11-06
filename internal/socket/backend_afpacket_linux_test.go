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

// TestAFPacketLoopback sends frames through the TX ring and receives them
// through RX rings on the loopback interface. It needs CAP_NET_RAW.
func TestAFPacketLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for AF_PACKET")
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no loopback interface")
	}
	for _, readers := range []int{1, 3} {
		t.Run(fmt.Sprintf("readers=%d", readers), func(t *testing.T) {
			port := 40000 + readers
			cfg := &conf.Network{Interface: lo, Port: port}
			cfg.PCAP.Sockbuf = 16 << 20 // holds the whole burst; the test reads after sending
			cfg.PCAP.Backend = backendAFPacket

			srcs, err := newRx(cfg, readers)
			if err != nil {
				t.Fatal(err)
			}
			if len(srcs) != readers {
				t.Fatalf("got %d readers, want %d", len(srcs), readers)
			}
			tx, err := newTx(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := tx.(*ringTx); !ok {
				t.Fatalf("expected the TX ring, got %T", tx)
			}

			// Many flows (source ports), so fanout spreads them; each flow
			// must land on exactly one reader, in order.
			const flows, perFlow = 16, 50
			a := frameAddrs{srcMAC: make([]byte, 6), dstMAC: make([]byte, 6), srcIP: net.IPv4(127, 0, 0, 1).To4(), dstIP: net.IPv4(127, 0, 0, 1).To4()}
			for i := range perFlow {
				for f := range flows {
					s := tcpSegment{srcPort: uint16(20000 + f), dstPort: uint16(port), flags: conf.TCPF{PSH: true, ACK: true}}
					if err := tx.write(encodeFrame(nil, &a, &s, []byte(fmt.Sprintf("%d:%d", f, i)))); err != nil {
						t.Fatal(err)
					}
				}
				// A different port must be filtered out.
				s := tcpSegment{srcPort: 1, dstPort: uint16(port + 1000), flags: conf.TCPF{PSH: true, ACK: true}}
				tx.write(encodeFrame(nil, &a, &s, []byte("other")))
			}

			type got struct{ reader, seq int }
			seen := map[int][]got{}
			total := 0
			deadline := time.Now().Add(5 * time.Second)
			for total < flows*perFlow && time.Now().Before(deadline) {
				for ri, src := range srcs {
					h := newRecvHandle(src, port)
					for {
						h.mu.Lock()
						p, addr, err := h.readLocked()
						var f, i int
						if err == nil {
							fmt.Sscanf(string(p), "%d:%d", &f, &i)
						}
						h.mu.Unlock()
						if err == errTimeout {
							break
						}
						if err == errNoPayload {
							continue
						}
						if err != nil {
							t.Fatal(err)
						}
						if string(p) == "other" || addr.Port != 20000+f {
							t.Fatalf("unexpected frame %q from %v", p, addr)
						}
						seen[f] = append(seen[f], got{ri, i})
						total++
						if total == flows*perFlow {
							break
						}
					}
					unregisterRx(h)
				}
			}
			if total != flows*perFlow {
				t.Fatalf("received %d of %d frames", total, flows*perFlow)
			}
			used := map[int]bool{}
			for f, gs := range seen {
				for i, g := range gs {
					if g.seq != i || g.reader != gs[0].reader {
						t.Fatalf("flow %d: frame %d arrived as seq %d on reader %d (first on %d)", f, i, g.seq, g.reader, gs[0].reader)
					}
				}
				used[gs[0].reader] = true
			}
			if readers > 1 && len(used) < 2 {
				t.Errorf("fanout sent all %d flows to one reader", flows)
			}
			for _, s := range srcs {
				if d := s.drops(); d != 0 {
					t.Errorf("kernel dropped %d frames", d)
				}
				s.close()
			}
			tx.close()
		})
	}
}
