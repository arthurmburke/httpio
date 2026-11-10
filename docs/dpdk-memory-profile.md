# DPDK allocation profiling

Run inside the DPDK development container (Linux, libdpdk and the `net_ring`
PMD). No physical NIC, hugepages, TAP device or root access is needed:

```sh
DPDK_PROFILE_ITERS=10000 \
DPDK_PROFILE_OUTPUT=target/dpdk-memory-profile.json \
cargo test --release --test dpdk_memory_profile -- \
  --ignored --nocapture --test-threads=1
```

The test is ignored in normal test runs. Without DPDK it fails explicitly
instead of silently producing an empty profile. `DPDK_PROFILE_ITERS` accepts
100–1,000,000. The default is 10,000 iterations **per pass per scenario**.

The fixture initializes real EAL, pins its calling thread to an available CPU,
creates a cache-disabled mbuf pool and uses the `net_ring` loopback PMD. A
synthetic TCP peer completes a handshake, injects checksummed packets and
acknowledges transmitted data. Protocol time stays fixed to prevent host
scheduling delays from triggering retransmission timeouts.

## Measurements

Each scenario warms up for 128 iterations, then runs two passes:

1. **Baseline:** allocator instrumentation disabled; records work latency
   (mean, p50, p95). The inactive thread-local hook and two clock reads remain.
2. **Instrumented:** counts allocation, zeroed-allocation, reallocation,
   deallocation and failure calls, requested/released bytes, and elapsed time
   inside `System` allocation/deallocation calls. Also records work latency.

The console prints per-operation counts, requested bytes, allocation/free
nanoseconds and baseline latency percentiles. The JSON includes raw totals,
average allocation-call time, instrumented latency, setup counts, CPU and
optimization mode. A reallocation counts as one allocation operation and its
**new total size** contributes to requested bytes; this is allocation traffic,
not peak live memory or RSS. Released bytes include old layouts on successful
reallocation and layouts passed to deallocation.

Only the measured operation is included. Packet injection, ACK generation,
reporting, sample storage and cleanup between iterations are outside the
window. In particular, TX retransmission buffers are released by peer ACKs in
cleanup, so TX allocation and free counts need not balance inside a row.
RX data includes application consumption and dropping its `Bytes` owner.
Setup is reported separately and includes Rust allocations for EAL arguments,
engine construction and the initial handshake.

| Scenario | One measured operation |
| --- | --- |
| `timer_overhead` | Empty work; indicates sampling floor |
| `mbuf_alloc_free` | Acquire and return one mbuf from the DPDK pool |
| `mbuf_bytes_owner` | Acquire mbuf, initialize 64 bytes, create/drop shared `Bytes` owner |
| `idle_poll` | Poll an idle established connection |
| `rx_ack` | Process one ACK |
| `rx_rejected` | Reject an out-of-window 64-byte payload and emit ACK |
| `rx_data_1024` | Receive, read and release 1,024 bytes |
| `tx_owned_1024` | Send a static owned `Bytes` and build/transmit its packet |
| `tx_copied_1024` | Copy 1,024 borrowed bytes into `Bytes`, then send (models the transport write copy, not the async ring) |
| `tx_4_fragments` | Send four static slices totaling 1,024 bytes |
| `tx_32_fragments` | Send 32 static slices totaling 1,024 bytes; exercises overflow metadata |

## Interpretation and limits

- The global allocator observes **Rust allocations on the measured thread**.
  It does not intercept DPDK/C `malloc`, hugepage allocation, NIC DMA memory,
  other threads, TLS, HTTP or the asynchronous worker command rings.
- DPDK mbuf acquisition is not a Rust heap allocation. Its cost appears in
  `mbuf_alloc_free` baseline latency. Pool availability before and after each
  workload is also recorded and must match, detecting leaked mbufs.
- Allocator durations include clock overhead and may include descheduling.
  They are elapsed nanoseconds, not CPU cycles. Compare baseline versus
  instrumented means to see observer overhead; do not interpret their
  difference as time saved by removing allocations.
- Count regressions are asserted for warmed-up allocation-free scenarios.
  Timing is reported, never used as a flaky pass/fail threshold. Other rows
  deliberately expose remaining allocations rather than asserting a fixed
  implementation-specific size/count.
- Use release builds and repeat runs on a quiet host. Container measurements
  are useful for relative investigation, not production-NIC latency claims.
  This is a single established connection with sequential packets; it does
  not model concurrency, loss, out-of-order traffic or slow consumers.

A non-ignored accounting test checks that alloc/zeroed/realloc/free calls and
byte totals are recorded correctly:

```sh
cargo test --test dpdk_memory_profile allocator_accounting
```
