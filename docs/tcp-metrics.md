# TCP/HTTP benchmark diagnostics

Enable diagnostics with the `tcp-metrics` Cargo feature. Normal builds compile
out the counters, clocks, thread-local storage and report plumbing. Enabled
workers accumulate metrics in worker-local storage, without per-event shared
atomics or logging. A `WorkerHandle::metrics_report()` handle can outlive the
worker; its `get()` returns the completed report after all worker handles are
dropped and `WorkerJoin::wait()` returns. Reports are immutable and serialize
with serde. Workers are measured independently.

## Run

In a privileged DPDK devcontainer with ethtool and CPUs 0–2 available:

```sh
BENCH_H1_METRICS=1 BENCH_H1_METHOD=POST BENCH_H1_BYTES=1048576 \
BENCH_H1_ROUNDS=300 BENCH_H1_WARMUP=20 BENCH_H1_REPEATS=3 \
  bash scripts/bench_h1.sh > /tmp/h1-post.tsv 2> /tmp/h1-post.log
```

Use `GET` for download diagnostics. Omit the method/byte filters to run the
whole matrix, but then worker counters aggregate all workloads. The script
builds both server and clients with the feature. If using `BENCH_H1_SKIP_BUILD=1`,
first build with `cargo build --release --example bench_h1 --features tcp-metrics`.

Standard latency/throughput rows go to stdout. Stderr contains:

- `TCP_METRICS {json}`: one worker report per DPDK process, including warmups.
- `SERVER_METRICS ...`: per-case means over measured requests only. Receive
  time covers body collection, starting after request headers have arrived;
  validation time covers payload checking. Both are reported in response
  headers by the benchmark server. Receive time includes waiting for data,
  not just server CPU work. Response transmission is not measured separately.

## Interpret fields

- `output_batches`, `tx_batches`, `ack_segments` have eight buckets with upper
  bounds **1, 2, 4, 8, 16, 32, 64, infinity**. Zero-size output batches are omitted.
  ACK segment counts are acknowledged sequence bytes divided by negotiated
  send MSS, rounded up; ACK accounting can include FIN sequence space.
- `output_budget_exhausted`: output reached its local budget while more output
  remained runnable. The current default per-connection cap is 64 packets,
  further bounded by queue sharing; the initial observations below used 32.
- `tx_requested`, `tx_accepted`, `tx_partial_calls`, `tx_zero_calls`: actual
  driver calls, not merely engine flushes. Requested packets include retries.
  `pending_tx_peak` samples the local queue before flushing; `queued_tx_skips`
  counts production skipped because this connection already has queued TX.
- `packet_build_ns` covers pending TCP packet construction, including payload
  copy and software checksum. `checksum_ns` covers `sum16` calls on this worker,
  both RX and TX. ARP/reset construction is not in the packet-build timer.
- `tx_driver_ns` times `rte_eth_tx_burst`, not the whole Rust port wrapper.
  `engine_poll_ns` includes construction, driver calls, RX and scheduling.
  These timers are **nested, not additive**.
- `cwnd_limited_ns` and `peer_window_limited_ns` integrate observed window
  states between processed-connection polls, only while application data is
  queued. These are connection-nanoseconds, can overlap, and are not CPU time.
  Abrupt removal/shutdown can leave a final interval unaccounted. They are
  diagnostic state estimates, not packet-capture-level attribution.
- `worker_ns` is elapsed worker lifetime, including idle spinning, startup,
  application validation gaps and shutdown. All timers measure wall time and
  include possible scheduler preemption; this is **not a sampled CPU profile**.

Clocks and thread-local updates perturb the enabled path, and additional server
headers change the response size. Do not treat diagnostic throughput as the
uninstrumented baseline. Never add server time and worker time: they overlap.

## Initial observations — 2026-11-13

Three repetitions per backend and method; each process ran only 1 MiB requests,
with 20 warmups + 300 measured requests. Default 256 KiB credit and ten-segment
initial window; same virtual-link setup as the send-tuning experiments.
All requests and payload checks passed. These are medians of per-run values.

For optimized h1 **uploads**:

| Metric | Observation |
|---|---:|
| Driver elapsed time per request, including warmups | 693 µs |
| Driver time / worker lifetime | 47.8% |
| Packet construction per request | 151 µs |
| Software checksum per request (overlaps construction) | 71 µs |
| Observed congestion-window-limited time per request | 70 µs |
| Observed receive-window-limited time per request | 32 µs |
| Partial / zero-acceptance driver calls | 0 / 0 |
| Local pending queue peak | 33 packets |
| Output budget exhaustion | 6,357 events per 320 requests |
| ACKs covering more than two MSS | approximately 50% of advancing ACKs |
| Server receive/collect mean | 1,068 µs |
| Server payload validation mean | 247 µs |

Hyper over DPDK showed a similar split: approximately 702 µs in the driver and
157 µs constructing packets per upload. No driver partial acceptance was
observed in either backend. This points to **driver transmit cost**, rather
than driver refusal, as the first place to investigate. The 32-packet budget
is frequently exhausted, so batching remains a testable second candidate.
ACK aggregation is real, but observed congestion-window stalls were only
about 5% of worker lifetime; this does not support blaming most upload time
on congestion-window growth. Server validation is a material shared cost.

For optimized h1 **downloads**, driver time was approximately 63 µs per request,
with no observed send-window stalls or output-budget exhaustion. Its client TX
is mostly ACK/control traffic. The upload transmit findings should not be
extrapolated to download performance.

Raw local outputs: `benchmarks/h1-metrics-POST.{log,tsv}` and
`benchmarks/h1-metrics-GET.{log,tsv}`. The benchmarks directory is ignored by git.
