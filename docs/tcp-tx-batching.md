# TX batching and output budget

The default engine output budget is now **64 packets per connection per poll**,
up from 32. The driver TX burst remains **64 packets**. Both limits can be tuned
without rebuilding; neither waits for a full batch before sending.

The engine retains the global 256-packet pending-TX bound. Its effective
per-connection budget is the minimum of the configured budget, remaining queue
space, and an equal share of the global bound among connections processed this
poll (at least one packet). For example, eight active connections get at most
32 packets each, even if configured for 256. This is a bounded per-poll share,
not a guarantee of equal bandwidth or bounded latency under driver backpressure.

```rust
use std::num::NonZeroU16;
// Configure before moving engine and port into WorkerHandle::spawn.
engine.set_tx_budget(NonZeroU16::new(64).unwrap());
port.set_tx_burst_limit(NonZeroU16::new(64).unwrap());
```

Both setters clamp at 256. Receive and congestion windows still constrain
output. Partially accepted driver batches retain their suffix in order, and
only accepted mbufs transfer ownership. The port reuses one pointer scratch
array within a flush instead of recreating it for every sub-burst.

## Why not larger driver bursts?

The [DPDK 22.11 AF_PACKET implementation](https://raw.githubusercontent.com/DPDK/dpdk/v22.11/drivers/net/af_packet/rte_eth_af_packet.c)
copies packets into its mmap TX ring and invokes `sendto` once per burst to
kick transmission. Queue-disc bypass is already on by default. Batching can
reduce the number of kicks, but does not remove packet copies or kernel-side
transmit processing. The driver itself was not patched.

Three diagnostic repetitions of 300 measured + 20 warmup 1 MiB POSTs per backend,
using default send credit and initial window:

| Engine budget | Driver burst | Driver calls/request | Driver µs/request |
|---:|---:|---:|---:|
| 32 | 64 | 29.6 | 722 |
| 64 | 64 | 20.5 | 698 |
| 128 | 64 | 23.9 | 709 |
| 128 | 128 | 19.4 | 910 |
| 256 | 256 | 19.3 | 920 |

These are medians of per-run statistics for optimized h1, including warmups
in worker metrics. Call count falls about 31% at 64/64, but measured driver time
falls only about 3%. Larger requested budgets do not necessarily produce larger
actual batches because ACKs and windows affect runnable output. Results reject
128/256 driver bursts as defaults for this AF_PACKET setup.

## Uninstrumented confirmation

The final comparison used instrumentation-disabled release builds, three runs
per configuration, 300 requests per workload after 20 warmups. Configuration
order was 64 then 32, reversing the earlier exploratory order. No test/build
jobs ran alongside this confirmation. An earlier exploratory full-matrix run
overlapped briefly with test compilation and is not used for these conclusions.

| Optimized h1 workload | Budget 32 p50 µs | Budget 64 p50 µs |
|---|---:|---:|
| GET 64 B | 30.21 | 29.58 |
| GET 16 KiB | 35.71 | 37.21 |
| GET 1 MiB | 366.29 | 362.71 |
| POST 64 B | 26.92 | 26.46 |
| POST 16 KiB | 48.83 | 49.29 |
| POST 1 MiB | 1310.42 | 1291.00 |

1 MiB upload payload throughput increased from **6.38 to 6.49 Gbit/s** (about
1.7%); p99 fell from 1373 to 1340 µs. Other workloads showed mixed small changes,
not a general speedup. These are virtual-link results, with no confidence
intervals; hardware-driver behavior may differ. The remaining upload cost is
not primarily the old 32-packet cap.

## Reproduce

```sh
# Uninstrumented; standard benchmark prerequisites apply.
BENCH_TX_BUDGET=64 BENCH_TX_BURST=64 BENCH_H1_ROUNDS=300 \
  bash scripts/bench_h1.sh

# Diagnostic single-workload run.
BENCH_H1_METRICS=1 BENCH_TX_BUDGET=64 BENCH_TX_BURST=64 \
BENCH_H1_METHOD=POST BENCH_H1_BYTES=1048576 BENCH_H1_ROUNDS=300 \
  bash scripts/bench_h1.sh
```

Raw local outputs are in the ignored `benchmarks/` directory:
`h1-batch-metrics-*.{log,tsv}` and `h1-batch-confirm-*.{log,tsv}`.

Validation covers eight connections sharing the output budget without losing
unsent data, and native ring backpressure with burst limits 1, 32, 64, 128, 256
and the clamped maximum. Tests check ordering, retained suffix ownership,
zero Rust allocations during TX, and full mbuf reclamation. DPDK all-target
suites passed with metrics enabled and disabled.
