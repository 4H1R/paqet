"""Aggregates bench.py results into median tables (markdown)."""
import glob
import json
import statistics
import sys

ORDER = ["old", "new-libpcap", "new"]
LABEL = {
    "old": "old (master)",
    "new-libpcap": "new, libpcap backend",
    "new": "new",
}


def load(pattern):
    rows = []
    for f in sorted(glob.glob(pattern)):
        for line in open(f):
            r = json.loads(line)
            if "error" not in r:
                rows.append(r)
            else:
                print(f"<!-- error: {r} -->")
    return rows


def med(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else float("nan")


def pct(new, old):
    return f"{(new - old) / old * 100:+.0f}%" if old else "n/a"


def throughput_table(rows, title):
    out = [f"### {title}", ""]
    for d in ("up", "down"):
        sel = [r for r in rows if r["dir"] == d]
        if not sel:
            continue
        out.append(f"**{'Upload (client → server)' if d == 'up' else 'Download (server → client)'}** — median of {max(r['rep'] for r in sel) + 1} runs")
        out.append("")
        out.append("| build | Mbit/s | client CPU s/GB | server CPU s/GB | client peak RSS | server peak RSS | KCP retrans/s (sender) |")
        out.append("|---|---:|---:|---:|---:|---:|---:|")
        base = None
        for v in ORDER:
            vs = [r for r in sel if r["variant"] == v]
            if not vs:
                continue
            m = {
                "mbps": med(r["mbps"] for r in vs),
                "c": med(r["client_cpu_s_per_gb"] for r in vs),
                "s": med(r["server_cpu_s_per_gb"] for r in vs),
                "crss": med(r["client_rss_peak_mb"] for r in vs),
                "srss": med(r["server_rss_peak_mb"] for r in vs),
                "rt": med((r["server_kcp"] if d == "down" else r["client_kcp"])["retrans"] for r in vs),
            }
            if v == "old":
                base = m
                out.append(f"| {LABEL[v]} | {m['mbps']:.0f} | {m['c']:.2f} | {m['s']:.2f} | {m['crss']:.0f} MB | {m['srss']:.0f} MB | {m['rt']:.1f} |")
            else:
                b = base or m
                out.append(f"| {LABEL[v]} | {m['mbps']:.0f} ({pct(m['mbps'], b['mbps'])}) | {m['c']:.2f} ({pct(m['c'], b['c'])}) | {m['s']:.2f} ({pct(m['s'], b['s'])}) | {m['crss']:.0f} MB ({pct(m['crss'], b['crss'])}) | {m['srss']:.0f} MB ({pct(m['srss'], b['srss'])}) | {m['rt']:.1f} |")
        out.append("")
    return "\n".join(out)


def idle_table(rows):
    out = ["### 2,000 idle connections (each did one 32 KB echo round trip)", ""]
    out.append("| build | client RSS @30s | server RSS @30s | client RSS @300s | server RSS @300s | client live heap | server live heap |")
    out.append("|---|---:|---:|---:|---:|---:|---:|")
    for r in rows:
        lh = r.get("live_heap_mb") or [None, None]
        out.append(f"| {LABEL.get(r['variant'], r['variant'])} | {r['rss_mb_t30'][0]:.0f} MB | {r['rss_mb_t30'][1]:.0f} MB | {r['rss_mb_t300'][0]:.0f} MB | {r['rss_mb_t300'][1]:.0f} MB | {lh[0]} MB | {lh[1]} MB |")
    return "\n".join(out)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Median tables from bench.py results")
    for k in ("lan", "wan", "multi", "drop", "idle"):
        ap.add_argument(f"--{k}", help=f"{k} results .jsonl")
    a = ap.parse_args()
    titles = {
        "lan": "LAN, 1 connection, 1 stream",
        "wan": "WAN (40 ms RTT, 0.1% loss each way), 1 connection, 1 stream",
        "multi": "LAN, transport.conn 4, 8 parallel streams",
        "drop": "LAN, 1 connection, raw-table DROP firewall rule instead of README rules",
    }
    for k, t in titles.items():
        if getattr(a, k):
            print(throughput_table(load(getattr(a, k)), t))
    if a.idle:
        print(idle_table(load(a.idle)))


if __name__ == "__main__":
    main()
