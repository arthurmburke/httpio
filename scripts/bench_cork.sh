#!/usr/bin/env bash
# Run as root in the DPDK devcontainer (NET_ADMIN and network namespaces).
# Reaction time of a corked request over the DPDK stack: from
# FlushHandle::flush() to the held segment reaching the NIC. See
# examples/bench_cork.rs for the cases and columns.
# Uses dedicated names and refuses to overwrite existing network resources.
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
SERVER_BIN="$TARGET_DIR/release/examples/bench_h2"
BIN="$TARGET_DIR/release/examples/bench_cork"
REPEATS="${BENCH_CORK_REPEATS:-3}"
NS=httpio-cork-bench
DEV=corkbench0
if ip link show "$DEV" >/dev/null 2>&1 || ip netns list | grep -q "^$NS\b"; then
    echo 'Benchmark network already exists; refusing to overwrite it' >&2
    exit 1
fi
command -v ethtool >/dev/null || { echo 'Install ethtool before running this benchmark' >&2; exit 1; }
if [[ "${BENCH_CORK_SKIP_BUILD:-0}" != 1 ]]; then
    cargo build --release --features tx-probe --example bench_h2 --example bench_cork
fi
SERVER_PID=
cleanup() {
    if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; fi
    ip link del "$DEV" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT
ip netns add "$NS"
ip link add "$DEV" type veth peer name corksrv0 netns "$NS"
ip addr add 10.73.0.1/24 dev "$DEV"
ip link set "$DEV" up
ip -n "$NS" addr add 10.73.0.2/24 dev corksrv0
ip -n "$NS" link set corksrv0 up
ip -n "$NS" link set lo up
ethtool -K "$DEV" tx off tso off gso off gro off >/dev/null
ip netns exec "$NS" ethtool -K corksrv0 tx off tso off gso off gro off >/dev/null
# Server core separate from the application (0) and DPDK worker (1).
ip netns exec "$NS" taskset -c 2 "$SERVER_BIN" server 10.73.0.2 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID"
ip addr del 10.73.0.1/24 dev "$DEV"
# Packet sockets receive before tc ingress; keep the kernel from forwarding
# traffic addressed to the userspace stack.
tc qdisc add dev "$DEV" ingress
tc filter add dev "$DEV" ingress matchall action drop
for ((r=1; r<=REPEATS; r++)); do
    echo "# repeat=$r"
    # A fresh source IP per process: the server may still hold the previous
    # one's connections in TIME_WAIT.
    ${BENCH_CORK_WRAP:-} "$BIN" -l 0-1 --no-huge --no-pci --log-level=error --vdev=net_af_packet0,iface="$DEV" -- "10.73.0.$((10 + r))" 10.73.0.2
done
