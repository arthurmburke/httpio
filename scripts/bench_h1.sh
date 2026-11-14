#!/usr/bin/env bash
# Run as root in the DPDK devcontainer (NET_ADMIN and network namespaces).
# Same server, veth link, MTU, NODELAY and disabled offloads for all clients.
# Uses dedicated names and refuses to overwrite existing network resources.
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
BIN="${BENCH_H1_BIN:-$TARGET_DIR/release/examples/bench_h1}"
REPEATS="${BENCH_H1_REPEATS:-3}"
NS=httpio-h1-bench
DEV=h1bench0
if ip link show "$DEV" >/dev/null 2>&1 || ip netns list | grep -q "^$NS\b"; then
    echo 'Benchmark network already exists; refusing to overwrite it' >&2
    exit 1
fi
command -v ethtool >/dev/null || { echo 'Install ethtool before running this benchmark' >&2; exit 1; }
if [[ "${BENCH_H1_SKIP_BUILD:-0}" != 1 ]]; then
    features=()
    if [[ "${BENCH_H1_METRICS:-0}" == 1 ]]; then features=(--features tcp-metrics); fi
    cargo build --release --example bench_h1 "${features[@]}"
fi
SERVER_PID=
cleanup() {
    if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; fi
    ip link del "$DEV" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT
ip netns add "$NS"
ip link add "$DEV" type veth peer name h1srv0 netns "$NS"
ip addr add 10.71.0.1/24 dev "$DEV"
ip link set "$DEV" up
ip -n "$NS" addr add 10.71.0.2/24 dev h1srv0
ip -n "$NS" link set h1srv0 up
ip -n "$NS" link set lo up
ethtool -K "$DEV" tx off tso off gso off gro off >/dev/null
ip netns exec "$NS" ethtool -K h1srv0 tx off tso off gso off gro off >/dev/null
# Server core separate from the application (0) and DPDK worker (1).
ip netns exec "$NS" taskset -c 2 "$BIN" server 10.71.0.2 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID"
for ((r=1; r<=REPEATS; r++)); do
    echo "# repeat=$r backend=kernel-hyper"
    taskset -c 0 "$BIN" kernel 10.71.0.2
done
ip addr del 10.71.0.1/24 dev "$DEV"
# Packet sockets receive before tc ingress; keep the kernel from forwarding
# traffic addressed to the userspace stack.
tc qdisc add dev "$DEV" ingress
tc filter add dev "$DEV" ingress matchall action drop
for ((r=1; r<=REPEATS; r++)); do
    # Alternate order to reduce consistent order bias.
    modes=(dpdk-h1 dpdk-hyper)
    if ((r % 2 == 0)); then modes=(dpdk-hyper dpdk-h1); fi
    for mode in "${modes[@]}"; do
        echo "# repeat=$r backend=$mode"
        # A fresh source IP prevents server TIME_WAIT from a previous process
        # colliding with the new stack's independently chosen ephemeral ports.
        if [[ "$mode" == dpdk-hyper ]]; then host=$((11 + r * 2)); else host=$((10 + r * 2)); fi
        "$BIN" "$mode" -l 0-1 --no-huge --no-pci --log-level=error --vdev=net_af_packet0,iface="$DEV" -- "10.71.0.$host" 10.71.0.2
    done
done
