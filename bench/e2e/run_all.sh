#!/bin/bash
# Full suite (~45 min). Needs root, iproute2, iptables, iperf3, python3, curl.
set -e
E=$(cd "$(dirname "$0")" && pwd)
bash "$E/build.sh"
python3 "$E/bench.py" lan:single 3 10
python3 "$E/bench.py" wan:single 3 10
python3 "$E/bench.py" lan:multi 3 10
PQ_RULES=drop python3 "$E/bench.py" lan:single 2 10 old,new
python3 "$E/bench.py" idle:2000 1 0 old,new
