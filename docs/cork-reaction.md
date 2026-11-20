# Reaction time of a corked request

Measured 2026-11-19 with `scripts/bench_cork.sh`. A corked request does
its work ahead of time -- connection, TLS handshake, encoding, encryption
-- and waits in the TCP engine as one held segment. Its reaction time is
how long `FlushHandle::flush()` takes to get that segment to the NIC.

**Result:** 0.79 us from `flush()` to the packet being ready for the
driver (median; 0.38 us at best, 1.08 us at the 90th percentile), and it no
longer depends on what the calling thread does next. Before, it was
1.17 us when the caller yielded to the runtime at once and 11.1 us when it
kept working for 10 us first. Sending the same upload from scratch on an
open HTTP/2 connection takes 1.71 us.

## What is measured

Each round stages a 64-byte POST through the HTTP client with
`TcpOptions::cork`, waits until the connection has been quiet for 3 ms,
then flushes. The worker's transmit probe (`dpdk::probe`, `tx-probe`
feature) stamps the first burst that follows:

- `ready`: the packet is built and about to be handed to the driver. The
  stack's own reaction time, and the figure that carries over to a
  poll-mode NIC.
- `sent`: the driver call returned. On this setup that adds a `sendto`
  system call (`af_packet`), 7-9 us that a poll-mode driver does not have.

`yield` and `busy10` differ in what the flushing task does after
`flush()`: yield to the runtime at once, or work for 10 us first.
`h2-reused` is the alternative to corking: the same upload sent as a new
stream on an open HTTP/2 connection, timed from the start of the request.

Same environment as [h2-benchmark.md](h2-benchmark.md): a Docker
development VM, not a bare-metal NIC. The clock ticks every 42 ns.

## Results

`ready`, microseconds; medians of three repeats of 500 flushes (the
"before" column is one repeat of 300):

| Case | Trigger | Before, p50 | p50 | min | p90 | p99 |
|---|---|---:|---:|---:|---:|---:|
| cork, HTTP/1.1 | yield | 1.17 | 0.79 | 0.38 | 1.08 | 2.83 |
| cork, HTTP/1.1 | busy10 | 11.08 | 0.79 | 0.38 | 1.08 | 2.83 |
| cork, HTTP/1.1 over TLS | yield | 1.21 | 0.79 | 0.38 | 1.08 | 3.62 |
| cork, HTTP/1.1 over TLS | busy10 | 11.12 | 0.88 | 0.33 | 1.08 | 3.50 |
| HTTP/2, reused connection | send | 1.58 | 1.71 | 1.17 | 4.33 | 12.83 |

`sent` p50 is 8-10 us in every case, the system call.

## What changed

`flush()` used to set a flag and wake the request's task. The flush
reached the worker only once the runtime had scheduled that task and
polled it down through the HTTP codec and TLS stream to the TCP stream,
which then put a command on its ring. A caller that did not yield
immediately delayed its own flush by however long it kept the thread.

Now `flush()` tells the worker itself:

- **A request past the command ring.** The handle bumps a counter the
  connection shares with its worker. The worker releases the tail when it
  next visits the connection, after applying every command already on the
  ring, so the flush still follows whatever the stream had written.
  Nothing on the application side has to run.
- **Watched connections.** The worker reads that counter for corked
  connections (up to 16) on every turn of its loop rather than waiting for
  a notification, which had to carry three cache lines between the cores
  before the worker knew. The counter sits on a line of its own and is the
  first thing `flush()` writes, so a request costs one line crossing.

A flush made before the connection exists still goes through the stream,
as before.

## Where the rest goes

With temporary stage timers (each costs about 40 ns, so the total reads
high), a flush after 3 ms of quiet spends roughly:

| Stage | ns |
|---|---:|
| `flush()` until the worker has taken the request | ~290 |
| the worker's turn up to the connection's output (clock, receive burst, timers) | ~125 |
| generating the segment (TCP state) | ~170 |
| building the packet (mbuf, headers, payload copy, checksum) | ~170 |

The worker's idle loop turns in 30-140 ns, so the first stage is mostly
cache lines moving between the two cores, not waiting for the loop.

**It depends on how long the request has been staged.** Held for 50 ms
before the flush, the median rises to 1.0-1.2 us and the 90th percentile to
3-4 us: the connection's state and the payload are no longer in the
worker's cache. On this VM that is aggravated by the host moving virtual
CPUs around; how much remains on a pinned core of a real machine is not
something this setup can tell.

## What could still be done

- **Build the packet when the request is staged**, and reuse it at the
  flush if the header the TCP state produces then is the same. Removes the
  build stage, which is also the part that reads the payload from another
  core's cache. Estimated 150-200 ns, more for a request held long.
- **Send before receiving on a turn that has a flush**: skips the receive
  burst and timer pass ahead of the output. Estimated under 100 ns.

Neither is done here. Both touch the engine's output loop, and the second
stage of the first idea (committing the segment ahead of time, so a flush
is only a transmit) would change when ACKs can be sent while a tail is
held.

## Reproduce

```sh
scripts/bench_cork.sh > cork.tsv
```

`BENCH_CORK_ROUNDS`, `BENCH_CORK_REPEATS` and `BENCH_CORK_HOLD_MS` (extra
time staged before each flush) vary the run.
