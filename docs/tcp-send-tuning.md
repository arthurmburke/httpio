# TCP send credit and startup window

The DPDK worker now supports per-handle send configuration. This removes the
hard-coded 256 KiB ceiling for applications that need more queued/in-flight
data and allows an explicit initial congestion window for controlled networks.
The defaults remain 256 KiB and ten segments: the HTTP benchmark did not show
that increasing either globally would be a consistent improvement.

Configure the worker before passing it to the HTTP client:

```rust
use std::num::{NonZeroU16, NonZeroUsize};
use httpio::dpdk::tcp::worker::SendConfig;
use httpio::dpdk::http::client::builder::Builder;

// `worker` comes from WorkerHandle::spawn(...).
let worker = worker.with_send_config(SendConfig {
    capacity: NonZeroUsize::new(2 * 1024 * 1024).unwrap(),
    initial_window_segments: NonZeroU16::new(16).unwrap(),
});
let client = Builder::new().build(worker);
```

This is a measured tuning candidate, not a universal recommendation. A larger
initial window sends more data before feedback; use it only on networks whose
capacity and loss behavior you control. RTO still resets the congestion window
to one MSS, fast recovery still reduces it, and the peer's advertised window
always limits transmission. The initial window uses the smaller of the peer
MSS and the local segment limit after handshake negotiation.

Credit counts queued plus unacknowledged logical bytes. Dequeuing a command
does not restore credit: ACKs or discards do. Raising the limit does not
preallocate payload storage, but allows more outstanding data per connection.
The command-ring limit remains independently enforced. Nonzero types reject
zero-byte credit and zero-segment startup windows at construction.

`with_send_config` affects future connections opened through the returned
handle and clones made from it. Existing connections and previously cloned
handles keep their settings. The existing `TcpOptions`, `connect`, and `open`
APIs are unchanged. Non-DPDK code has no new dependency or behavior change.

## HTTP benchmark comparison

Three repetitions, 300 measured requests per workload per repetition after
20 warmups; same fresh-connection plaintext veth setup as
[the original benchmark](../benchmarks/h1-2026-11-13.md). Numbers below are
medians of per-run statistics for optimized h1. These are separate sequential
configuration runs, not randomized trials; small changes may be noise.

| Credit | Initial segments | 16 KiB POST p50 µs | 1 MiB POST p50 µs | 1 MiB POST payload Gbit/s |
|---|---:|---:|---:|---:|
| 256 KiB | 10 (baseline) | 50.21 | 1304.71 | 6.35 |
| 2 MiB | 10 | 49.83 | 1288.33 | 6.42 |
| 256 KiB | 64 | 44.50 | 1379.12 | 5.75 |
| 2 MiB | 64 | 44.71 | 1361.88 | 5.94 |
| 2 MiB | 16 | 43.71 | 1286.67 | 6.52 |

The 16-segment / 2 MiB combination reduced 16 KiB POST median latency by
about 13%; 1 MiB throughput changed by only about 3%, which is not a proven
bulk-transfer improvement. Larger credit alone was essentially neutral.
64-segment startup windows regressed bulk throughput. These results correct
the earlier suspicion that the fixed credit and startup window were the main
1 MiB upload bottlenecks; packet processing and ACK behavior still need profiling.

The benchmark accepts `BENCH_SEND_CAPACITY` (bytes) and
`BENCH_INITIAL_WINDOW` (segments), applied equally to both DPDK backends:

```sh
BENCH_SEND_CAPACITY=2097152 BENCH_INITIAL_WINDOW=16 \
BENCH_H1_ROUNDS=300 BENCH_H1_REPEATS=3 bash scripts/bench_h1.sh
```

Raw results and diagnostics are in `benchmarks/h1-send-*-iw*.tsv` and matching
`.log` files. Every configuration completed all requests and body validation.
