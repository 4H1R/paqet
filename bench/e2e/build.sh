#!/bin/bash
# Builds the baseline and candidate binaries into $PQBENCH_DIR/bin.
#   BASE_REF (default master) and NEW_REF (default HEAD) select the commits.
set -euo pipefail
REPO=${REPO:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}
W=${PQBENCH_DIR:-/root/pqbench}
BASE_REF=${BASE_REF:-master}
NEW_REF=${NEW_REF:-$(git -C "$REPO" rev-parse HEAD)}
export CGO_ENABLED=1
mkdir -p "$W/bin"
declare -A REF=([old]=$BASE_REF [new]=$NEW_REF)
for v in old new; do
  [ -d "$W/src-$v/.git" ] || git clone -q "$REPO" "$W/src-$v"
  git -C "$W/src-$v" fetch -q "$REPO" "${REF[$v]}"
  git -C "$W/src-$v" checkout -q --detach FETCH_HEAD
  echo "$v: $(git -C "$W/src-$v" log -1 --oneline)"
  (cd "$W/src-$v" && go build -trimpath -ldflags "-s -w" -gcflags "all=-l=4" -o "$W/bin/paqet-$v" ./cmd)
done
(cd "$W/src-new" && go build -trimpath -ldflags "-s -w" -gcflags "all=-l=4" -tags pprof -o "$W/bin/paqet-new-pprof" ./cmd)
