# RX/TX hot-path review

The retained change moves cheap GRO eligibility checks ahead of IPv4 parsing
and checksumming. Pure ACKs, control packets, PSH packets and packets with
options cannot enter the current GRO path; they now go directly to normal RX
processing. Normal RX still validates them. Eligible GRO packets still undergo
IPv4 and TCP validation before being marked checksum-good or merged.

Duplicate eligibility checks after parsing were removed. Tests cover truncated
frames, control/PSH flags, IPv4 options and TCP options; existing native GRO,
corrupted-packet and engine tests cover full processing.

An experiment grouping TX completion updates by connection was removed. Although
it reduced hash-table lookups, before/after benchmark runs did not establish a
benefit, and one reverse-order comparison regressed bulk uploads. The original
per-packet completion accounting remains intact.

## Isolated GRO result

Saved baseline release binary versus GRO-only release binary, instrumentation
disabled, unchanged 64-packet engine/driver limits and default send tuning.
Three alternating before/after trials, 1,000 measured 1 MiB POSTs per backend
per trial, after 20 warmups. All status/body checks passed. No builds or tests
ran concurrently. Same isolated veth/AF_PACKET environment as earlier runs.

Medians of per-trial statistics for optimized h1:

| Metric | Before | GRO-only |
|---|---:|---:|
| p50 request latency | 1294.12 µs | 1291.46 µs |
| Mean request latency | 1300.44 µs | 1300.63 µs |
| Payload throughput | 6.4506 Gbit/s | 6.4497 Gbit/s |

There is **no demonstrated end-to-end throughput gain**. Retain the simpler
eligibility path as redundant-work removal, not as a claimed performance win.
The remaining upload bottleneck needs profiling inside the driver/kernel path;
these Rust bookkeeping changes do not account for most of it.

Raw local results: `benchmarks/h1-gro-{before,after}-{1,2,3}.{log,tsv}`.
Earlier combined experiments: `benchmarks/h1-hotpath-*`.
The benchmark script now accepts `BENCH_H1_BIN` for saved-binary comparisons;
use it with `BENCH_H1_SKIP_BUILD=1`. These local results are ignored by git.
