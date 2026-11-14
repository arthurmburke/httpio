# Isolated TCP library versus Linux

Measured 2026-11-13. The earlier AF_PACKET HTTP results do not establish a
bare-metal driver bottleneck. This experiment excludes AF_PACKET, HTTP, worker
queues, Tokio, server scheduling, connection establishment, and physical NICs.

**Result:** against ordinary optimized loopback, our software-segmenting engine
pair costs about **3.76×** as much CPU for 1 MiB. With loopback MTU 1500 and
TSO/GSO/GRO disabled, the measured costs are **252 versus 251 µs**, within
variation. The remaining small-message deficit of **0.48 µs** includes a
forwarding harness whose diagnostic cost is larger than that deficit. We have
not established a library-only regression against the kernel under equivalent
bare-metal conditions.

## Workload and controls

`examples/bench_library.rs` drives two established TCP endpoints on one pinned
thread. Each iteration sends a preallocated payload, copies the received bytes
into a preallocated application buffer, and returns one application byte. The
return byte acknowledges completion of delivery. Each size has a fresh pair of
connections, 100 warmups, then 3,000 measured exchanges. Payload equality is
checked after warmup and measurement. Five trials run kernel then DPDK, serially;
reported CPU costs are medians of those five trials, not latency percentiles.

The kernel uses nonblocking TCP sockets on loopback. DPDK uses two real
`TcpEngine`s with MTU 1500, connected by two `net_ring` PMDs. The harness moves
mbufs from one port's loopback ring to the other. Ring ports assert that TSO and
TX/RX checksum offload are disabled. Both engines and both socket endpoints run
on CPU 0. CPU time uses Linux `CLOCK_THREAD_CPUTIME_ID`; wall time is also emitted.
Other CPU work, including deferred kernel work on another CPU, is not charged to
this thread. Wall time is an additional check, not a system-wide CPU accounting
substitute. There were no concurrent builds during measured trials.

Environment: Docker Desktop Linux VM, aarch64, 18 virtual CPUs,
Linux 7.0.14-linuxkit, Rust 1.96.1, DPDK 22.11.11, release build without
`tcp-metrics`. This is a development VM, not a bare-metal NIC result.

## CPU microseconds per exchange

Default-loopback reference, from one set of five paired trials:

| Payload | Kernel default loopback | DPDK rings | DPDK/kernel |
|---|---:|---:|---:|
| 64 B | 2.020 | 2.478 | 1.23× |
| 1,460 B | 2.197 | 2.565 | 1.17× |
| 16 KiB | 2.654 | 5.623 | 2.12× |
| 64 KiB | 6.020 | 16.631 | 2.76× |
| 1 MiB | 63.738 | 239.605 | 3.76× |

Segmentation-controlled reference, in a temporary isolated network namespace
with loopback MTU 1500 and TSO/GSO/GRO off:

| Payload | Kernel median (min–max) | DPDK median (min–max) | DPDK/kernel |
|---|---:|---:|---:|
| 64 B | 2.094 (1.989–2.246) | 2.574 (2.402–2.703) | 1.23× |
| 1,460 B | 2.899 (2.881–2.947) | 2.776 (2.512–2.982) | 0.96× |
| 16 KiB | 6.064 (5.769–6.143) | 5.898 (5.556–6.215) | 0.97× |
| 64 KiB | 17.817 (16.864–17.853) | 17.941 (16.734–18.510) | 1.01× |
| 1 MiB | 251.397 (215.799–254.477) | 252.369 (240.617–263.176) | 1.004× |

The MTU/offload change is a combined intervention; it does not isolate each
kernel feature individually. It demonstrates how much the comparison depends
on segmentation/aggregation. Kernel loopback still has fixed checksum shortcuts
and different packet metadata and TCP options. A 1,460-byte payload need not
produce the same packet count on both stacks. DPDK sends cloned `Bytes`; kernel
`write` copies from a borrowed slice. Both copy into the receive application
buffer, but intermediate copies and ownership differ. These are native API
costs, not instruction-for-instruction equivalents.

## Where DPDK time goes

Separate coarse diagnostic run (`BENCH_LIBRARY_BREAKDOWN=1`, no `tcp-metrics`),
3,000 iterations. Values below are wall microseconds per exchange. Each engine
column includes its RX and TX work; “sender” identifies the payload sender, not
an exclusively transmit-only timer.

| Payload | Sending engine | Receiving engine | Forwarding harness | Application APIs + copy | Total |
|---|---:|---:|---:|---:|---:|
| 64 B | 0.852 | 0.860 | 0.635 | 0.311 | 3.047 |
| 1 MiB | 120.272 | 74.637 | 4.532 | 43.301 | 244.573 |

Loop control, timer boundaries, and bookkeeping account for the remainder.
Timings perturb the path. Do not subtract this separate run's forwarding cost
from uninstrumented medians to manufacture a corrected library/kernel ratio.
For small messages, harness cost is large enough to prevent attribution of the
observed deficit to the library.

A second run with `tcp-metrics` enabled gives finer, **nested** measurements for
1 MiB: packet construction 140.956 µs, checksum routines 106.806 µs, and ring TX
driver calls 1.798 µs. Total exchange time rises to 385.982 µs under this heavier
instrumentation. Checksum time includes TX and RX; its TX portion overlaps packet
construction, so these figures must not be added together. Driver counters
include engine TX and harness forwarding TX. There are 733 packet constructions,
52 driver calls and 1,466 packet acceptances per exchange (each packet traverses
two ring TX calls), with zero retransmissions. These diagnostics rank work to
investigate; they are not estimates of uninstrumented savings.

This points to three next investigations relevant to a real polling NIC:

1. Validate checksum and segmentation offloads with an actual supported PMD.
   Software checksums and per-segment construction dominate this ring workload;
   the kernel comparison changes substantially when its segmentation shortcuts
   are removed. This does not prove our existing hardware-offload path is slow.
2. Profile receive delivery and buffer ownership. Application API/copy work is
   about 18% of the coarse 1 MiB diagnostic. That bucket also includes send,
   receive bookkeeping and the reply, so it is not a pure memcpy measurement.
3. Replace forwarding with directly cross-connected queues for a tighter
   small-message experiment. Only then use the remaining gap to prioritize
   engine polling, connection lookup, and ACK costs. The present measurements
   do not justify optimizing AF_PACKET or claiming slow physical driver TX.

This benchmark intentionally excludes fresh-connection congestion growth and
worker send-credit limits. Those require separate end-to-end measurements;
these results do not explain the entire HTTP throughput gap.

## Reproduce

Inside the DPDK devcontainer:

```sh
bash scripts/bench_library.sh
```

For the controlled kernel reference, run in a **disposable privileged container
with its own network namespace** (`--network none`), with the repository and
Cargo target volume mounted and `ip`/`ethtool` available:

```sh
ip link set lo up
ip link set lo mtu 1500
ethtool -K lo tso off gso off gro off
ip link show lo
ethtool -k lo
BENCH_LIBRARY_OUT=benchmarks/library-controlled bash scripts/bench_library.sh
```

Do not apply that network configuration to the host or a shared namespace.
The script builds without `tcp-metrics`, pins CPU 0, and defaults to five trials
of 3,000 exchanges per size. Override `BENCH_LIBRARY_CORE`,
`BENCH_LIBRARY_ROUNDS`, `BENCH_LIBRARY_TRIALS`, or supply EAL arguments to the
script. `BENCH_LIBRARY_SKIP_BUILD=1` and `BENCH_LIBRARY_BIN` allow a saved binary;
ensure it was built without metrics for headline measurements.

## Emulating NIC offloads

`net_ring` has no offloads, so the default run measures software checksums
and MSS-sized packet construction, which a physical NIC with checksum offload
and TSO does not do. `BENCH_LIBRARY_OFFLOAD` makes the stack take the paths it
takes on such a NIC; the harness then does the NIC's part between the two
engines (segments TSO packets, delivers single-segment packets marked
checksum-verified). Checksums are never computed in these modes.

```sh
# cksum: TX/RX checksum offload. tso: checksum offload plus TSO with a DMA payload.
BENCH_LIBRARY_OFFLOAD=tso BENCH_LIBRARY_BREAKDOWN=1 taskset -c 0 \
  "${CARGO_TARGET_DIR:-target}/release/examples/bench_library" dpdk \
  -l 0 -m 512 --no-huge --no-pci --log-level=error \
  --vdev=net_ring0 --vdev=net_ring1
```

Read the `sender_engine_us` and `receiver_engine_us` columns: the harness
column now includes the emulated NIC's segmentation copy, so total and CPU
time are not comparable with the kernel or with the default mode.
`BENCH_LIBRARY_BYTES=1048576` runs one size (for `perf record -e cpu-clock`),
and `BENCH_LIBRARY_GRO=0` disables receive aggregation.

For the separate nested diagnostics:

```sh
cargo build --release --features tcp-metrics --example bench_library
BENCH_LIBRARY_ROUNDS=3000 BENCH_LIBRARY_BREAKDOWN=1 taskset -c 0 \
  "${CARGO_TARGET_DIR:-target}/release/examples/bench_library" dpdk \
  -l 0 -m 256 --no-huge --no-pci --log-level=error \
  --vdev=net_ring0 --vdev=net_ring1
```

Raw trial TSVs and environment metadata for this run are in the ignored local
`benchmarks/library/` directory: `kernel-*`, `dpdk-*`, `kernel1500-*`,
`dpdk1500-*`, `breakdown.tsv`, `instrumented.tsv`, `instrumented.jsonl`, and
`controlled-environment.txt`. Re-running the default script overwrites the
uncontrolled TSVs; use another output directory to preserve them.

Validation: portable strict Clippy for the example; DPDK release builds with and
without metrics; five full trials per reference; final script smoke run through
all five sizes, including payload and offload assertions. No production TCP
behavior was changed for this experiment. The metrics module now exposes its
existing thread-local reset/snapshot operations for directly driven engines.
