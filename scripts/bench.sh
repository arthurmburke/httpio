#!/usr/bin/env bash
# Benchmarks the DPDK TCP stack against the kernel's, and the stack's parts
# in isolation.
#
# Run as root in a --privileged devcontainer (network namespaces, veth and
# tap devices, ethtool):
#   scripts/bench.sh [components|e2e|all]
#
# End-to-end wiring. Every client talks to the same kernel server program,
# across one virtual link:
#
#   kernel client (root ns, 10.10.0.1) --veth--> server (ns "srv", 10.10.0.2)
#   DPDK net_af_packet on that same veth ------> server (ns "srv", 10.10.0.2)
#   DPDK net_tap (10.9.0.1) --dtap0--> server (root ns, 10.9.0.2)
#
# A second server at 10.10.0.3 busy-polls its echo sockets, and `raw` runs
# the engine with no worker lcore; together they split a round trip into
# link, server wake-up, engine and application-crossing shares.
#
# The kernel client is measured twice: with the veth's default offloads
# (checksums skipped, 64 KB TSO/GRO super-segments) and with them off, which
# is the per-packet work the DPDK stack does.
set -euo pipefail
cd "$(dirname "$0")/.."

WHAT="${1:-all}"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
cargo build --release --examples 2>&1 | tail -1
E2E="$TARGET_DIR/release/examples/bench_e2e"
COMPONENTS="$TARGET_DIR/release/examples/bench_components"

if [[ "$WHAT" == components || "$WHAT" == all ]]; then
    "$COMPONENTS" -l 0 --no-huge --vdev=net_ring0 --log-level=error
fi
[[ "$WHAT" == e2e || "$WHAT" == all ]] || exit 0

command -v ethtool >/dev/null || { apt-get update -qq && apt-get install -y -qq ethtool >/dev/null; }

PIDS=()
cleanup() {
    kill "${PIDS[@]}" 2>/dev/null || true
    ip link del vc 2>/dev/null || true
    ip link del dtap0 2>/dev/null || true
    ip netns del srv 2>/dev/null || true
}
trap cleanup EXIT
cleanup

ip netns add srv
ip link add vc type veth peer name vs netns srv
ip addr add 10.10.0.1/24 dev vc
ip link set vc up
ip -n srv addr add 10.10.0.2/24 dev vs
ip -n srv link set vs up
ip -n srv link set lo up
ip netns exec srv "$E2E" server 10.10.0.2 &
PIDS+=($!)

ip tuntap add dev dtap0 mode tap multi_queue
ip addr add 10.9.0.2/24 dev dtap0
ip link set dtap0 up
"$E2E" server 10.9.0.2 &
PIDS+=($!)
sleep 1

echo "# kernel sockets over veth, default offloads"
"$E2E" blocking 10.10.0.2 kernel-blocking
"$E2E" kernel 10.10.0.2 kernel-tokio

# Per-packet kernel path: full checksums, MSS-sized segments.
for dev_ns in "vc:" "vs:srv"; do
    dev=${dev_ns%%:*} ns=${dev_ns##*:}
    ${ns:+ip netns exec $ns} ethtool -K "$dev" tx off tso off gso off gro off >/dev/null
done
echo "# kernel sockets over veth, offloads off"
"$E2E" blocking 10.10.0.2 kernel-blocking-nooffload
"$E2E" kernel 10.10.0.2 kernel-tokio-nooffload

# A second server whose echo handler never sleeps, to take the server
# thread's wake-up out of the round trip.
ip -n srv addr add 10.10.0.3/24 dev vs
ip netns exec srv "$E2E" server 10.10.0.3 spin &
PIDS+=($!)
sleep 1
echo "# kernel sockets, busy-polling echo server (latency only)"
BENCH_WORKLOADS=latency "$E2E" blocking 10.10.0.3 kernel-blocking-spinserver
BENCH_WORKLOADS=latency "$E2E" kernel 10.10.0.3 kernel-tokio-spinserver

# The kernel must not also own 10.10.0.1, or it would answer for it.
ip addr del 10.10.0.1/24 dev vc
# Nor may it route what the DPDK port receives. With the address gone the
# kernel treats every frame for 10.10.0.1 as transit traffic: conntrack, a
# route lookup, and a forward out of the container's own NIC, all charged
# to the server's CPU. Packet sockets see a frame before tc ingress does,
# so dropping there leaves the DPDK port's view untouched.
tc qdisc add dev vc ingress
tc filter add dev vc ingress matchall action drop
AFP=(-l 0-1 --no-huge --log-level=error --vdev=net_af_packet0,iface=vc --)
TAP=(-l 0-1 --no-huge --log-level=error --vdev=net_tap0,iface=dtap0 --)

echo "# DPDK stack, net_af_packet on the same veth"
"$E2E" dpdk "${AFP[@]}" 10.10.0.1 10.10.0.2 dpdk-af_packet || echo "dpdk-af_packet FAILED"
echo "# DPDK stack, net_tap"
"$E2E" dpdk "${TAP[@]}" 10.9.0.1 10.9.0.2 dpdk-tap || echo "dpdk-tap FAILED"

echo "# DPDK stack, busy-polling echo server (latency only)"
BENCH_WORKLOADS=latency "$E2E" dpdk "${AFP[@]}" 10.10.0.1 10.10.0.3 dpdk-af_packet-spinserver \
    || echo "dpdk-af_packet-spinserver FAILED"

echo "# short uploads on fresh connections, from a clean stack"
BENCH_WORKLOADS=short "$E2E" dpdk "${AFP[@]}" 10.10.0.1 10.10.0.2 dpdk-af_packet-fresh \
    || echo "dpdk-af_packet-fresh FAILED"

echo "# engine alone on one thread: no worker lcore, rings or runtime"
"$E2E" raw "${AFP[@]}" 10.10.0.1 10.10.0.2 raw-af_packet || echo "raw-af_packet FAILED"
"$E2E" raw "${AFP[@]}" 10.10.0.1 10.10.0.3 raw-af_packet-spinserver \
    || echo "raw-af_packet-spinserver FAILED"
"$E2E" raw "${TAP[@]}" 10.9.0.1 10.9.0.2 raw-tap || echo "raw-tap FAILED"
