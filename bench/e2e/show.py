import sys,json
for l in sys.stdin:
    try: r=json.loads(l)
    except Exception: print(l.rstrip()); continue
    if 'error' in r: print(r['variant'], r['dir'], 'ERROR', r['error']); continue
    print(f"{r['variant']:16} {r['dir']:4} {r['mbps']:8.1f} Mbps  cli {r['client_cpu_pct']:5.1f}% srv {r['server_cpu_pct']:5.1f}%  cli {r['client_cpu_s_per_gb'] or 0:.2f}s/GB srv {r['server_cpu_s_per_gb'] or 0:.2f}s/GB  rss {r['client_rss_peak_mb']:.0f}/{r['server_rss_peak_mb']:.0f}MB thr {r['client_threads']}/{r['server_threads']}  kcp-c {r['client_kcp']} kcp-s {r['server_kcp']}")
