# End-to-end A/B benchmark

Compares two paqet builds over a real raw-packet path: a client and a server
in two Linux network namespaces joined by a veth pair, with the README's
iptables rules. The client forwards a local TCP port through the tunnel to an
`iperf3` server next to the paqet server.

```
pqc: iperf3 -c ─► paqet client ─► vc 10.77.0.1 ══veth══ vs 10.77.0.2 ─► paqet server ─► iperf3 -s
```

For every run it records iperf3 throughput, the CPU time (`utime+stime` from
`/proc`) and peak RSS of both paqet processes, and the KCP retransmit rate
from paqet's own stats line. **CPU seconds per transferred GB** is the main
efficiency metric: on this link both builds are mostly paced by KCP rather
than by CPU, so equal throughput at less CPU is the expected win.

Run as root (needs iproute2, iptables, iperf3, python3, curl, Go and the libpcap
headers):

```bash
bash bench/e2e/run_all.sh          # builds master and HEAD, ~45 minutes
python3 bench/e2e/report.py --lan $PQBENCH_DIR/results-lan-single-*.jsonl ...
```

Variants: `old` is the baseline build. The candidate runs as `new-libpcap`
(`pcap.backend: libpcap`), `new-afpacket-1r` (AF_PACKET, one reader) and `new`
(defaults when measured: AF_PACKET with `pcap.readers` = 4. The default was then
changed to 1, which is the `new-afpacket-1r` row).

## Results

Measured 2026-11-06 on WSL2 (Linux 6.18, Ryzen 9 7950X, 32 vCPU), KCP
`mode: fast`, all other settings default. Baseline `07a6009` (master) and
candidate `25c76be`.

### LAN, 1 connection, 1 stream

**Upload (client → server)** — median of 3 runs

| build | Mbit/s | client CPU s/GB | server CPU s/GB | client peak RSS | server peak RSS | KCP retrans/s (sender) |
|---|---:|---:|---:|---:|---:|---:|
| old (master) | 554 | 10.05 | 7.78 | 34 MB | 42 MB | 0.0 |
| new, libpcap backend | 550 (-1%) | 9.65 (-4%) | 7.48 (-4%) | 33 MB (-2%) | 41 MB (-2%) | 0.0 |
| new, AF_PACKET, 1 reader | 554 (+0%) | 8.18 (-19%) | 5.89 (-24%) | 30 MB (-12%) | 35 MB (-17%) | 0.0 |
| new, AF_PACKET, 4 readers | 554 (-0%) | 8.19 (-18%) | 5.96 (-23%) | 30 MB (-11%) | 35 MB (-17%) | 0.0 |

**Download (server → client)** — median of 3 runs

| build | Mbit/s | client CPU s/GB | server CPU s/GB | client peak RSS | server peak RSS | KCP retrans/s (sender) |
|---|---:|---:|---:|---:|---:|---:|
| old (master) | 542 | 7.50 | 9.36 | 36 MB | 46 MB | 14.9 |
| new, libpcap backend | 530 (-2%) | 7.48 (-0%) | 9.33 (-0%) | 33 MB (-8%) | 45 MB (-3%) | 0.0 |
| new, AF_PACKET, 1 reader | 513 (-5%) | 5.77 (-23%) | 7.69 (-18%) | 30 MB (-16%) | 39 MB (-14%) | 0.0 |
| new, AF_PACKET, 4 readers | 547 (+1%) | 6.20 (-17%) | 7.93 (-15%) | 31 MB (-14%) | 39 MB (-15%) | 0.0 |

### WAN (40 ms RTT, 0.1% loss each way), 1 connection, 1 stream

**Upload (client → server)** — median of 3 runs

| build | Mbit/s | client CPU s/GB | server CPU s/GB | client peak RSS | server peak RSS | KCP retrans/s (sender) |
|---|---:|---:|---:|---:|---:|---:|
| old (master) | 28 | 12.00 | 10.70 | 27 MB | 36 MB | 2.2 |
| new, libpcap backend | 28 (+0%) | 12.03 (+0%) | 10.49 (-2%) | 25 MB (-8%) | 35 MB (-3%) | 2.7 |
| new, AF_PACKET, 1 reader | 28 (+1%) | 11.37 (-5%) | 10.82 (+1%) | 23 MB (-16%) | 29 MB (-20%) | 2.2 |
| new, AF_PACKET, 4 readers | 28 (-1%) | 11.47 (-4%) | 10.90 (+2%) | 23 MB (-16%) | 29 MB (-20%) | 2.2 |

**Download (server → client)** — median of 3 runs

| build | Mbit/s | client CPU s/GB | server CPU s/GB | client peak RSS | server peak RSS | KCP retrans/s (sender) |
|---|---:|---:|---:|---:|---:|---:|
| old (master) | 93 | 5.58 | 7.78 | 35 MB | 43 MB | 93.0 |
| new, libpcap backend | 96 (+4%) | 5.60 (+0%) | 7.45 (-4%) | 33 MB (-4%) | 40 MB (-7%) | 25.8 |
| new, AF_PACKET, 1 reader | 94 (+2%) | 5.78 (+3%) | 6.97 (-10%) | 30 MB (-13%) | 34 MB (-21%) | 38.8 |
| new, AF_PACKET, 4 readers | 97 (+4%) | 5.62 (+1%) | 6.70 (-14%) | 31 MB (-12%) | 34 MB (-20%) | 25.3 |

### LAN, transport.conn 4, 8 parallel streams

**Upload (client → server)** — median of 3 runs

| build | Mbit/s | client CPU s/GB | server CPU s/GB | client peak RSS | server peak RSS | KCP retrans/s (sender) |
|---|---:|---:|---:|---:|---:|---:|
| old (master) | 2012 | 9.34 | 5.53 | 66 MB | 46 MB | 1140.2 |
| new, libpcap backend | 3743 (+86%) | 8.74 (-6%) | 4.79 (-13%) | 64 MB (-3%) | 43 MB (-6%) | 0.0 |
| new, AF_PACKET, 1 reader | 3986 (+98%) | 7.65 (-18%) | 4.46 (-19%) | 52 MB (-21%) | 38 MB (-18%) | 0.0 |
| new, AF_PACKET, 4 readers | 3866 (+92%) | 7.78 (-17%) | 4.92 (-11%) | 52 MB (-21%) | 37 MB (-19%) | 0.0 |

**Download (server → client)** — median of 3 runs

| build | Mbit/s | client CPU s/GB | server CPU s/GB | client peak RSS | server peak RSS | KCP retrans/s (sender) |
|---|---:|---:|---:|---:|---:|---:|
| old (master) | 852 | 12.08 | 18.33 | 62 MB | 63 MB | 0.0 |
| new, libpcap backend | 912 (+7%) | 11.25 (-7%) | 17.62 (-4%) | 60 MB (-4%) | 62 MB (-3%) | 0.0 |
| new, AF_PACKET, 1 reader | 1517 (+78%) | 8.21 (-32%) | 10.97 (-40%) | 47 MB (-24%) | 55 MB (-13%) | 0.0 |
| new, AF_PACKET, 4 readers | 1342 (+58%) | 9.10 (-25%) | 12.18 (-34%) | 48 MB (-23%) | 55 MB (-13%) | 0.0 |

### LAN, 1 connection, raw-table DROP firewall rule instead of README rules

**Upload (client → server)** — median of 2 runs

| build | Mbit/s | client CPU s/GB | server CPU s/GB | client peak RSS | server peak RSS | KCP retrans/s (sender) |
|---|---:|---:|---:|---:|---:|---:|
| old (master) | 544 | 6.99 | 5.30 | 34 MB | 42 MB | 0.0 |
| new, AF_PACKET, 4 readers | 520 (-5%) | 6.13 (-12%) | 4.12 (-22%) | 30 MB (-10%) | 35 MB (-16%) | 0.0 |

**Download (server → client)** — median of 2 runs

| build | Mbit/s | client CPU s/GB | server CPU s/GB | client peak RSS | server peak RSS | KCP retrans/s (sender) |
|---|---:|---:|---:|---:|---:|---:|
| old (master) | 549 | 5.25 | 6.70 | 35 MB | 46 MB | 56.8 |
| new, AF_PACKET, 4 readers | 554 (+1%) | 3.69 (-30%) | 5.46 (-19%) | 30 MB (-15%) | 39 MB (-14%) | 0.0 |

### 2,000 idle connections (each did one 32 KB echo round trip)

| build | client RSS @30s | server RSS @30s | client RSS @300s | server RSS @300s | client live heap | server live heap |
|---|---:|---:|---:|---:|---:|---:|
| old (master) | 134 MB | 151 MB | 134 MB | 151 MB | 71 MB | 71 MB |
| new, AF_PACKET, 4 readers | 120 MB | 135 MB | 96 MB | 104 MB | 7 MB | 7 MB |

"Live heap" is the Go heap after the last garbage collection, from
`GODEBUG=gctrace=1`. The old build keeps a 32 KB copy buffer referenced by
every idle connection; the new one returns it to the pool after 2 s idle,
and the pool releases it at the next collections (an idle process is
collected every 2 minutes, which is why RSS only drops by the 300 s mark).

### Micro-benchmarks (per packet, `go test -bench`)

| | old (gopacket) | new |
|---|---:|---:|
| build one frame (1350 B payload) | ~395 ns, 1 alloc | ~90 ns, 0 allocs |
| full `SendHandle.Write` path | encode + pool + mutex | 123 ns, 0 allocs |
| decode one frame | ~107 ns | ~4 ns |
| `addr.String()` per received packet (kcp-go Listener) | 56 ns, 3 allocs | cached, 0 allocs |

## Reading the numbers

- **The biggest single CPU cost was the system call per sent packet** (~60%
  of each process in a CPU profile). The AF_PACKET backend's transmit ring
  turns that into one call per burst; most of what remains is the kernel's
  own per-packet transmit work.
- **The old build dropped received packets under bursts.** libpcap on Linux
  sizes each ring slot from the snap length (64 KB) when NIC offloads are
  on, so the default 4 MB buffer held ~64 packets. KCP retransmitted the
  losses: 1,140 retransmits/s and half the throughput in the multi-stream
  upload, 93/s on the lossy WAN download. A 2 KB snap length fixes this
  even with the libpcap backend.
- **On a veth pair the sender is charged for the receiver's kernel work**
  (the peer's input path runs in the sender's context), so absolute CPU
  numbers are higher than on real NICs. The relative differences between
  builds are what matter.
- **Server fanout (`pcap.readers`) did not help** with a single client
  process and cost some CPU, so it defaults to 1. It is meant for servers
  with many busy clients, which this testbed does not model.
- WAN results are noisy at 3 runs; the CPU differences there are within
  noise, but the retransmit reduction is consistent.
