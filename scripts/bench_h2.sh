#!/usr/bin/env bash
# Run as root in the DPDK devcontainer (NET_ADMIN and network namespaces).
# Same server, veth link, MTU, NODELAY and disabled offloads for every client:
# this crate's HTTP codecs (dpdk-h2) and hyper's (dpdk-hyper) over the DPDK TCP
# and TLS streams, and hyper over kernel sockets (kernel). See
# examples/bench_h2.rs for the protocols, workloads and columns; client_us is
# the one that leaves the kernel side out.
# Uses dedicated names and refuses to overwrite existing network resources.
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
BIN="${BENCH_H2_BIN:-$TARGET_DIR/release/examples/bench_h2}"
REPEATS="${BENCH_H2_REPEATS:-3}"
NS=httpio-h2-bench
DEV=h2bench0
if ip link show "$DEV" >/dev/null 2>&1 || ip netns list | grep -q "^$NS\b"; then
    echo 'Benchmark network already exists; refusing to overwrite it' >&2
    exit 1
fi
command -v ethtool >/dev/null || { echo 'Install ethtool before running this benchmark' >&2; exit 1; }
if [[ "${BENCH_H2_SKIP_BUILD:-0}" != 1 ]]; then
    cargo build --release --example bench_h2
fi
SERVER_PID=
cleanup() {
    if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; fi
    ip link del "$DEV" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT
ip netns add "$NS"
ip link add "$DEV" type veth peer name h2srv0 netns "$NS"
ip addr add 10.72.0.1/24 dev "$DEV"
ip link set "$DEV" up
ip -n "$NS" addr add 10.72.0.2/24 dev h2srv0
ip -n "$NS" link set h2srv0 up
ip -n "$NS" link set lo up
ethtool -K "$DEV" tx off tso off gso off gro off >/dev/null
ip netns exec "$NS" ethtool -K h2srv0 tx off tso off gso off gro off >/dev/null
# Server core separate from the application (0) and DPDK worker (1).
ip netns exec "$NS" taskset -c 2 "$BIN" server 10.72.0.2 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID"
# hyper over kernel sockets, while the kernel still owns the client address.
# BENCH_H2_KERNEL=0 leaves it out.
if [[ "${BENCH_H2_KERNEL:-1}" == 1 ]]; then
    for ((r=1; r<=REPEATS; r++)); do
        echo "# repeat=$r backend=kernel"
        taskset -c 0 "$BIN" kernel 10.72.0.2
    done
fi
ip addr del 10.72.0.1/24 dev "$DEV"
# Packet sockets receive before tc ingress; keep the kernel from forwarding
# traffic addressed to the userspace stack.
tc qdisc add dev "$DEV" ingress
tc filter add dev "$DEV" ingress matchall action drop
for ((r=1; r<=REPEATS; r++)); do
    # Alternate order to reduce consistent order bias.
    modes=(dpdk-h2 dpdk-hyper)
    if ((r % 2 == 0)); then modes=(dpdk-hyper dpdk-h2); fi
    # BENCH_H2_MODES="dpdk-h2" runs one client only; "dpdk-client" runs the
    # TLS cases through the crate's HTTP client and checks that streamed
    # uploads and every other request share one pooled connection.
    if [[ -n "${BENCH_H2_MODES:-}" ]]; then read -ra modes <<<"$BENCH_H2_MODES"; fi
    for mode in "${modes[@]}"; do
        echo "# repeat=$r backend=$mode"
        # A fresh source IP prevents server TIME_WAIT from a previous process
        # colliding with the new stack's independently chosen ephemeral ports.
        case "$mode" in
            dpdk-hyper) host=$((11 + r * 2)) ;;
            dpdk-client) host=$((100 + r)) ;;
            *) host=$((10 + r * 2)) ;;
        esac
        # BENCH_H2_WRAP="perf record -o /tmp/perf.data" profiles the client.
        ${BENCH_H2_WRAP:-} "$BIN" "$mode" -l 0-1 --no-huge --no-pci --log-level=error --vdev=net_af_packet0,iface="$DEV" -- "10.72.0.$host" 10.72.0.2
    done
done
