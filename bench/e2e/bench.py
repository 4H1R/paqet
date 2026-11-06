#!/usr/bin/env python3
"""A/B benchmark for paqet (see README.md in this directory).

Usage (root, Linux): bench.py SUITE [REPS] [SECS] [VARIANTS]
  SUITE: lan:single | wan:single | lan:multi | idle:N | idleheap:N | profile:lan:up|down

A/B benchmark for paqet: two network namespaces joined by a veth pair.

  pqc (client) 10.77.0.1/vc <--veth--> vs/10.77.0.2 (server) pqs

The paqet client forwards 127.0.0.1:5201.. in pqc to iperf3 servers on
127.0.0.1:5201.. in pqs through the tunnel. For each run it records
iperf3 throughput, CPU time and peak RSS of both paqet processes, and the
KCP retransmit/loss rates and capture drops from the stats line.
"""
import json
import os
import re
import signal
import socket
import statistics
import subprocess
import sys
import time

W = os.environ.get("PQBENCH_DIR", "/root/pqbench")
BIN = f"{W}/bin"
LOGS = f"{W}/logs"
CLK = os.sysconf("SC_CLK_TCK")
PORT = 9999


def sh(cmd, check=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd}: {r.stderr.strip()}")
    return r.stdout.strip()


def setup_net(delay_ms=0, loss=0.0, rate=None):
    sh("ip netns del pqc", check=False)
    sh("ip netns del pqs", check=False)
    sh("ip netns add pqc && ip netns add pqs")
    sh("ip link add vc netns pqc type veth peer name vs netns pqs")
    sh("ip -n pqc addr add 10.77.0.1/24 dev vc && ip -n pqs addr add 10.77.0.2/24 dev vs")
    for ns, dev in (("pqc", "vc"), ("pqs", "vs")):
        sh(f"ip -n {ns} link set lo up && ip -n {ns} link set {dev} up")
        if delay_ms or loss or rate:
            q = f"ip netns exec {ns} tc qdisc add dev {dev} root netem limit 100000"
            if delay_ms:
                q += f" delay {delay_ms}ms"
            if loss:
                q += f" loss {loss}%"
            if rate:
                q += f" rate {rate}"
            sh(q)
    # README firewall rules: keep the kernel from tracking or resetting
    # the raw TCP flows.
    rules = {
        "pqs": [f"-t raw -A PREROUTING -p tcp --dport {PORT} -j NOTRACK",
                f"-t raw -A OUTPUT -p tcp --sport {PORT} -j NOTRACK",
                f"-t mangle -A OUTPUT -p tcp --sport {PORT} --tcp-flags RST RST -j DROP"],
        "pqc": [f"-t raw -A PREROUTING -p tcp --sport {PORT} -j NOTRACK",
                f"-t raw -A OUTPUT -p tcp --dport {PORT} -j NOTRACK",
                f"-t mangle -A OUTPUT -p tcp --dport {PORT} --tcp-flags RST RST -j DROP"],
    }
    if os.environ.get("PQ_RULES") == "drop":
        # Drop paqet's packets in raw PREROUTING. Packet sockets capture
        # before netfilter, so paqet still sees them, but the kernel TCP
        # stack never processes them or answers with RSTs.
        rules = {
            "pqs": [f"-t raw -A PREROUTING -p tcp --dport {PORT} -j DROP"],
            "pqc": [f"-t raw -A PREROUTING -p tcp --sport {PORT} -j DROP"],
        }
    for ns, rs in rules.items():
        for r in rs:
            sh(f"ip netns exec {ns} iptables {r}")
    mac = lambda ns, dev: sh(f"ip -n {ns} -j link show {dev}") and json.loads(sh(f"ip -n {ns} -j link show {dev}"))[0]["address"]
    return mac("pqc", "vc"), mac("pqs", "vs")


def write_configs(variant, client_mac, server_mac, conns, forwards, extra_pcap):
    pcap = ""
    if extra_pcap:
        pcap = "  pcap:\n" + "".join(f"    {k}: {v}\n" for k, v in extra_pcap.items())
    server = f"""role: server
log:
  level: error
  stats_interval: 2
listen:
  addr: ":{PORT}"
network:
  interface: vs
  ipv4:
    addr: "10.77.0.2:{PORT}"
    router_mac: "{client_mac}"
{pcap}transport:
  protocol: kcp
  conn: 1
  kcp:
    mode: fast
    key: bench-key
"""
    fwd = "".join(f'  - listen: "127.0.0.1:{p}"\n    target: "127.0.0.1:{p}"\n    protocol: tcp\n' for p in forwards)
    client = f"""role: client
log:
  level: error
  stats_interval: 2
forward:
{fwd}network:
  interface: vc
  ipv4:
    addr: "10.77.0.1:0"
    router_mac: "{server_mac}"
{pcap}server:
  addr: "10.77.0.2:{PORT}"
transport:
  protocol: kcp
  conn: {conns}
  kcp:
    mode: fast
    key: bench-key
"""
    os.makedirs(f"{W}/cfg", exist_ok=True)
    sp, cp = f"{W}/cfg/{variant}-server.yaml", f"{W}/cfg/{variant}-client.yaml"
    open(sp, "w").write(server)
    open(cp, "w").write(client)
    return sp, cp


def cpu_ticks(pid):
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return int(f[11]) + int(f[12])  # utime + stime


def mem_kb(pid, key):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith(key + ":"):
            return int(line.split()[1])
    return 0


def wait_port(ns, port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        # Check for the listener without connecting: a probe connection
        # would travel the tunnel and confuse the iperf3 server.
        if sh(f"ip netns exec {ns} ss -Hltn 'sport = :{port}'", check=False):
            return True
        time.sleep(0.2)
    return False


class Paqet:
    def __init__(self, ns, binary, cfg, log, env=None):
        self.log = open(log, "w")
        e = dict(os.environ)
        e.update(env or {})
        self.p = subprocess.Popen(["ip", "netns", "exec", ns, binary, "run", "-c", cfg],
                                  stdout=self.log, stderr=subprocess.STDOUT, env=e)
        self.path = log

    def stop(self):
        self.p.send_signal(signal.SIGTERM)
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
        self.log.close()

    def stats(self, since):
        """Average KCP stats lines logged after `since` (epoch seconds)."""
        rows = []
        for line in open(self.path):
            if "[STATS]" not in line:
                continue
            ts = time.mktime(time.strptime(line[:19], "%Y-%m-%d %H:%M:%S"))
            if ts < since:
                continue
            g = lambda k: float(m.group(1)) if (m := re.search(k + r"=([\d.]+)", line)) else 0.0
            rows.append({"retrans": g("retrans"), "lost": g("lost"), "drops": g("capture_drops")})
        if not rows:
            return {"retrans": 0, "lost": 0, "drops": 0}
        return {"retrans": statistics.mean(r["retrans"] for r in rows),
                "lost": statistics.mean(r["lost"] for r in rows),
                "drops": sum(r["drops"] for r in rows)}


IDLE_TIMES = (2, 30, 300)

VARIANTS = {
    "new-pprof": ("paqet-new-pprof", None),
    "old": ("paqet-old", None),
    "new-libpcap": ("paqet-new", {"backend": "libpcap"}),
    "new-afpacket-1r": ("paqet-new", {"backend": "afpacket", "readers": 1}),
    "new": ("paqet-new", None),  # candidate defaults
    "new-afpacket-4r": ("paqet-new", {"backend": "afpacket", "readers": 4}),
}


def iperf_run(variant, net, conns, streams, reverse, secs, rep, profile=None):
    binary, pcap = VARIANTS[variant]
    cmac, smac = net
    ports = [5201]
    sp, cp = write_configs(variant, cmac, smac, conns, ports, pcap)
    tag = f"{variant}-c{conns}-P{streams}-{'down' if reverse else 'up'}-{rep}"
    env = {"PAQET_PPROF": "127.0.0.1:6060"} if profile else None
    srv = Paqet("pqs", f"{BIN}/{binary}", sp, f"{LOGS}/{tag}-server.log", env)
    time.sleep(0.5)
    cli = Paqet("pqc", f"{BIN}/{binary}", cp, f"{LOGS}/{tag}-client.log", env)
    ip3 = subprocess.Popen("ip netns exec pqs iperf3 -s -B 127.0.0.1 -p 5201", shell=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_port("pqc", 5201):
            raise RuntimeError("client forward did not come up")
        time.sleep(1.5)
        c0, s0, t0 = cpu_ticks(cli.p.pid), cpu_ticks(srv.p.pid), time.time()
        profs = []
        if profile:
            for ns, who in (("pqc", "client"), ("pqs", "server")):
                profs.append(subprocess.Popen(
                    f"ip netns exec {ns} curl -s -o {profile}-{who}.pprof 'http://127.0.0.1:6060/debug/pprof/profile?seconds={secs - 2}'",
                    shell=True))
        out = sh(f"ip netns exec pqc iperf3 -c 127.0.0.1 -p 5201 -t {secs} -P {streams} {'-R' if reverse else ''} -J -O 1",
                 check=False)
        c1, s1, t1 = cpu_ticks(cli.p.pid), cpu_ticks(srv.p.pid), time.time()
        for pr in profs:
            pr.wait()
        res = json.loads(out)
        if "error" in res:
            raise RuntimeError(res["error"])
        recv = res["end"]["sum_received"]
        gbytes = recv["bytes"] / 1e9
        dt = t1 - t0
        ccpu, scpu = (c1 - c0) / CLK, (s1 - s0) / CLK
        r = {
            "variant": variant, "conns": conns, "streams": streams, "dir": "down" if reverse else "up", "rep": rep,
            "mbps": recv["bits_per_second"] / 1e6,
            "client_cpu_pct": 100 * ccpu / dt, "server_cpu_pct": 100 * scpu / dt,
            "client_cpu_s_per_gb": ccpu / gbytes if gbytes else None,
            "server_cpu_s_per_gb": scpu / gbytes if gbytes else None,
            "client_rss_peak_mb": mem_kb(cli.p.pid, "VmHWM") / 1024,
            "server_rss_peak_mb": mem_kb(srv.p.pid, "VmHWM") / 1024,
            "client_threads": mem_kb(cli.p.pid, "Threads"),
            "server_threads": mem_kb(srv.p.pid, "Threads"),
        }
        time.sleep(2.2)  # let the last stats line land
        r["client_kcp"] = cli.stats(t0)
        r["server_kcp"] = srv.stats(t0)
        return r
    finally:
        cli.stop()
        srv.stop()
        ip3.kill()
        ip3.wait()
        sh("pkill -x iperf3", check=False)
        time.sleep(0.3)


def last_live_heap(log):
    """Live heap (MB) after the most recent GC, from GODEBUG=gctrace=1."""
    live = None
    for line in open(log):
        if m := re.search(r"(\d+)->(\d+)->(\d+) MB", line):
            live = int(m.group(3))
    return live


def idle_run(variant, net, n, rep, heap=None):
    """RSS of both ends with n idle connections that each did one round trip."""
    binary, pcap = VARIANTS[variant]
    cmac, smac = net
    here = os.path.dirname(os.path.abspath(__file__))
    sp, cp = write_configs(variant, cmac, smac, 1, [7000], pcap)
    tag = f"{variant}-idle{n}-{rep}"
    echo = subprocess.Popen(["ip", "netns", "exec", "pqs", "python3", f"{here}/echo_server.py", "7000"])
    env = {"GODEBUG": "gctrace=1"}
    if heap:
        env["PAQET_PPROF"] = "127.0.0.1:6060"
    srv = Paqet("pqs", f"{BIN}/{binary}", sp, f"{LOGS}/{tag}-server.log", env)
    time.sleep(0.5)
    cli = Paqet("pqc", f"{BIN}/{binary}", cp, f"{LOGS}/{tag}-client.log", env)
    opener = None
    try:
        if not wait_port("pqc", 7000):
            raise RuntimeError("client forward did not come up")
        time.sleep(1)
        base = (mem_kb(cli.p.pid, "VmRSS"), mem_kb(srv.p.pid, "VmRSS"))
        opener = subprocess.Popen(["ip", "netns", "exec", "pqc", "python3", f"{here}/opener.py", "7000", str(n)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        status = opener.stdout.readline().strip()
        t0 = time.time()
        r = {"variant": variant, "n": n, "rep": rep, "opener": status,
             "base_rss_mb": [base[0] / 1024, base[1] / 1024]}
        for at in IDLE_TIMES:
            time.sleep(max(0, t0 + at - time.time()))
            r[f"rss_mb_t{at}"] = [mem_kb(cli.p.pid, "VmRSS") / 1024, mem_kb(srv.p.pid, "VmRSS") / 1024]
        r["peak_rss_mb"] = [mem_kb(cli.p.pid, "VmHWM") / 1024, mem_kb(srv.p.pid, "VmHWM") / 1024]
        if heap:
            for ns, who in (("pqc", "client"), ("pqs", "server")):
                # Two GCs: the first moves sync.Pool contents to the victim
                # cache, the second frees them.
                sh(f"ip netns exec {ns} curl -s -o /dev/null 'http://127.0.0.1:6060/debug/pprof/heap?gc=1'")
                sh(f"ip netns exec {ns} curl -s -o {heap}-{who}.heap 'http://127.0.0.1:6060/debug/pprof/heap?gc=1'")
                sh(f"ip netns exec {ns} curl -s -o {heap}-{who}.goroutines 'http://127.0.0.1:6060/debug/pprof/goroutine?debug=1'")
        r["threads"] = [mem_kb(cli.p.pid, "Threads"), mem_kb(srv.p.pid, "Threads")]
        r["live_heap_mb"] = [last_live_heap(cli.path), last_live_heap(srv.path)]
        return r
    finally:
        if opener:
            opener.stdin.close()
            opener.wait()
        cli.stop()
        srv.stop()
        echo.kill()
        echo.wait()


def main():
    os.makedirs(LOGS, exist_ok=True)
    suite = sys.argv[1]
    reps = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    secs = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    variants = sys.argv[4].split(",") if len(sys.argv) > 4 else [v for v in VARIANTS if v != "new-pprof"]
    nets = {
        "lan": dict(),                                     # CPU bound
        "wan": dict(delay_ms=20, loss=0.1),                # 40ms RTT, 0.1% loss each way
    }
    cases = {
        "single": [(1, 1)],
        "multi": [(4, 8)],
    }
    if suite.startswith("profile:"):
        _, net_name, direction = suite.split(":")
        net = setup_net(**nets[net_name])
        r = iperf_run("new-pprof", net, 1, 1, direction == "down", secs, 0, profile=f"{W}/prof-{net_name}-{direction}")
        print(json.dumps(r))
        return
    if suite.startswith("idleheap:"):
        n = int(suite.split(":")[1])
        global IDLE_TIMES
        IDLE_TIMES = (2, 10)
        net = setup_net()
        print(json.dumps(idle_run("new-pprof", net, n, 0, heap=f"{W}/idle{n}")))
        return
    if suite.startswith("idle:"):
        n = int(suite.split(":")[1])
        net = setup_net()
        out = open(f"{W}/results-idle{n}-{time.strftime('%H%M%S')}.jsonl", "w")
        for rep in range(reps):
            for v in variants:
                try:
                    r = idle_run(v, net, n, rep)
                except Exception as e:
                    r = {"variant": v, "n": n, "rep": rep, "error": str(e)}
                out.write(json.dumps(r) + "\n")
                out.flush()
                print(json.dumps(r), flush=True)
        return
    net_name, case_name = suite.split(":")
    net = setup_net(**nets[net_name])
    out = open(f"{W}/results-{net_name}-{case_name}-{time.strftime('%H%M%S')}.jsonl", "w")
    for rep in range(reps):
        for reverse in (False, True):
            for conns, streams in cases[case_name]:
                for v in variants:
                    try:
                        r = iperf_run(v, net, conns, streams, reverse, secs, rep)
                    except Exception as e:
                        r = {"variant": v, "conns": conns, "streams": streams, "dir": "down" if reverse else "up",
                             "rep": rep, "error": str(e)}
                    r["net"] = net_name
                    r["rules"] = os.environ.get("PQ_RULES", "readme")
                    out.write(json.dumps(r) + "\n")
                    out.flush()
                    print(json.dumps(r), flush=True)


if __name__ == "__main__":
    main()
