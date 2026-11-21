# Reaction time of a corked request

Measured 2026-11-20 with `scripts/bench_cork.sh`. A corked request does
its work ahead of time -- connection, TLS handshake, encoding, encryption
-- and waits in the TCP engine as one held segment. Its reaction time is
how long `FlushHandle::flush()` takes to get that segment to the NIC.

**Result:** 0.67 us from `flush()` to the packet being ready for the
driver (median; 0.3 us at best, 0.9 us at the 90th percentile), and it no
longer depends on what the calling thread does next. Before, it was
1.17 us when the caller yielded to the runtime at once and 11.1 us when it
kept working for 10 us first. Sending the same upload from scratch on an
open HTTP/2 connection takes about 2 us.

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

`ready`, microseconds; medians of three repeats of 500 flushes ("before"
is one repeat of 300, "direct" is the first change below on its own):

| Case | Trigger | Before, p50 | Direct, p50 | Now, p50 | min | p90 | p99 |
|---|---|---:|---:|---:|---:|---:|---:|
| cork, HTTP/1.1 | yield | 1.17 | 0.79 | 0.67 | 0.33 | 0.92 | 2.29 |
| cork, HTTP/1.1 | busy10 | 11.08 | 0.79 | 0.67 | 0.33 | 0.88 | 2.67 |
| cork, HTTP/1.1 over TLS | yield | 1.21 | 0.79 | 0.67 | 0.29 | 0.92 | 2.46 |
| cork, HTTP/1.1 over TLS | busy10 | 11.12 | 0.88 | 0.67 | 0.29 | 0.83 | 2.42 |
| HTTP/2, reused connection | send | 1.58 | 1.71 | 2.17 | 1.17 | 5.83 | 10.38 |

`sent` p50 is 8-10 us in every case, the system call. The HTTP/2 row is
untouched by either change; its spread between runs is its own.

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

- **A flush is final, and cannot come too early.** It used to be a
  one-shot release of whatever tail was held at that moment. One made
  while the request was still being staged -- during the connect or the
  TLS handshake -- found nothing to release, was spent, and left the
  request held for good: flushing 2 or 20 turns of the runtime after
  starting a request lost it eight times out of eight. Now a flush
  uncorks the connection, and the handle remembers it, so a stream that
  comes to cork after the flush does not. The benchmark checks this
  before it measures: requests flushed at eight points from "at once" to
  "long since staged", cleartext and TLS, must all be answered.

Then the packet itself is built ahead:

- **A prebuilt packet per held tail.** Whenever the engine visits a
  corked connection and leaves a tail held, it builds the packet a flush
  would send right then -- mbuf, headers, payload copy, checksum -- and
  keeps it with the connection. At the flush the TCP state machine
  produces the segment exactly as it always did, and the packet is used
  only if that segment's header is the predicted one, byte for byte, with
  the same payload length and next hop; a header names its sequence
  number, and a connection's bytes at a sequence number never change, so a
  match is the same packet. If the peer sent data in between, or the
  application read some or wrote more, the engine has either rebuilt the
  packet on that visit or simply builds one at the flush as before. The
  state machine knows nothing of any of this.

The benchmark's `prebuilt` column counts the flushes that went out this
way: all of them, in every corked case.

## Where the rest goes

With temporary stage timers (each costs about 40 ns, so the total reads
high), a flush after 3 ms of quiet spent roughly this before the packet
was prebuilt:

| Stage | ns |
|---|---:|
| `flush()` until the worker has taken the request | ~290 |
| the worker's turn up to the connection's output (clock, receive burst, timers) | ~125 |
| generating the segment (TCP state) | ~170 |
| building the packet (mbuf, headers, payload copy, checksum) | ~170 |

Prebuilding removes the last row; the median fell by 120 ns. The worker's
idle loop turns in 30-140 ns, so the first row is mostly cache lines
moving between the two cores, not waiting for the loop.

**It depends on how long the request has been staged.** Held for 50 ms
before the flush, the median is 0.9-1.2 us and the 90th percentile 3-4 us,
with or without the prebuilt packet (which was used every time): the
connection's state is no longer in the worker's cache, and that costs more
than the build did. On this VM that is aggravated by the host moving
virtual CPUs around; how much remains on a pinned core of a real machine
is not something this setup can tell.

Over seconds it is far worse. Measured later the same day, 6-10 flushes
per point, cleartext, the caller kept busy for the hold so that its own
wake-up is not part of it:

| Held for | `ready` p50, us |
|---|---:|
| 3 ms | 0.67 |
| 50 ms | 0.8-1.2 |
| 2 s | 4-8 |
| 10 s | 10-11 |
| 62 s | 13 |

The prebuilt packet was used every time; the time goes in reaching it. An
experiment that had the worker re-read each held connection's state every
100 us brought the 2 s figure down to 3-5 us in some runs and not in
others, so cold data is part of it but not all. These are small samples on
a VM whose virtual CPUs move between cores; the shape needs confirming on
a pinned core before it is worth engineering against.

## What could still be done

- **Send before receiving on a turn that has a flush**: skips the receive
  burst and timer pass ahead of the output. Estimated under 100 ns.
- **Commit the segment ahead of time**, so that a flush is only a
  transmit and the TCP bookkeeping follows it. That would remove the
  segment-generation stage as well, and the part of the long-hold cost
  that is TCP state gone cold, but it changes the state machine: what the
  held segment acknowledges would be fixed when it is staged, and ACKs for
  data arriving meanwhile would need their own path.

Neither is done here.

## Reproduce

```sh
scripts/bench_cork.sh > cork.tsv
```

`BENCH_CORK_ROUNDS`, `BENCH_CORK_REPEATS` and `BENCH_CORK_HOLD_MS` (extra
time staged before each flush) vary the run.
