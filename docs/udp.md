# UDP

The stack carries UDP datagrams alongside TCP: a synchronous, engine-owned
layer (`dpdk::udp::UdpEngine`) and an async application API
(`dpdk::udp::UdpSocket`, which splits into a `Sink` and a `Stream`). This
note explains how it is put together and why. The code is in
`src/dpdk/udp/` (`engine.rs`, `worker.rs`, `socket.rs`) and
`src/dpdk/net/udp.rs` (wire format).

```rust
let (stack, join) = Stack::builder(0, "10.9.0.1".parse()?).build()?;
let mut socket = UdpSocket::bind(&stack, 7007).await?;
loop {
    let datagram = socket.recv_from().await?;          // a view of the RX mbuf
    let src = datagram.src;
    socket.send_to(datagram.into_bytes(), src).await?; // no copy either way
}
```

`src/bin/udp_echo.rs` is this as a CLI (server mode), plus a client mode
that measures round trips; `scripts/e2e.sh` runs both against kernel UDP
sockets over a tap device.

## Why UDP shares the TCP worker and engine

Each worker lcore owns one NIC queue exclusively, and with it the queue's
receive burst, its ARP table, its next-hop routing and its transmit batch,
all inside that worker's `TcpEngine`. A separate UDP worker on the same
queue would need all of those shared across lcores (locks or another ring
hop on the per-packet path); a UDP worker on its own queue would need the
NIC to split traffic by protocol and would duplicate ARP. So UDP is a layer
of the same engine instead: `UdpEngine` is a field of `TcpEngine`
(`engine.udp()` / `engine.udp_mut()`).

- **Receive.** `handle_ipv4` dispatches protocol 17 to
  `UdpEngine::on_datagram`, after the same destination check as TCP
  (extended, for UDP only, to the limited broadcast 255.255.255.255).
  The TCP per-packet path pays one protocol branch.
- **Transmit.** The engine's poll calls UDP output after TCP has queued its
  segments, ARP replies and resets, and before ARP requests are drained, so
  a datagram whose next hop misses ARP sends its request in the same poll.
  UDP packets join the same transmit batch (with no owning connection), so
  the stall and flush logic is TCP's. Output is bounded by the batch's
  remaining room, less a few slots kept for ARP requests, and a per-poll
  budget of 64 datagrams, so a UDP flood cannot starve TCP. Control frames
  (ARP replies and requests, resets for unknown connections) are never
  held back by the batch's cap, so a saturated transmit ring cannot make
  the host unreachable.
- **Idle cost.** With no UDP traffic a poll costs a few loads and two
  emptiness checks.

On the worker, `UdpWorker` (in `worker.rs`) runs at fixed points of the
TCP worker loop: register new bindings, apply notified sockets' commands,
(engine poll), deliver received datagrams to sockets. TCP's own ring and
readiness types are untouched; UDP mirrors them with its own (a control
MPSC ring for binds, per-socket SPSC command and inbound rings, and a
coalescing readiness queue keyed by local port with an overflow scan).
The application side waits with the same lost-wakeup-safe try / park / try
scheme and `AppWake` driver as `TcpStream`.

## Steering and fan-in

With one worker there is nothing to choose. With several, a datagram is
only useful on the worker whose engine holds its binding, and which
worker receives it is up to the NIC:

- The port requests `RTE_ETH_RSS_NONFRAG_IPV4_UDP` where the device
  supports it, so UDP is spread over the queues rather than piled onto
  one.
- When steering uses flow rules, the same per-queue rules that steer TCP's
  ephemeral ports (`PortSteering`) are installed for UDP destination ports
  too. TCP's rules are mandatory, as before. UDP's are **best effort**: if
  the device rejects them, the ones already created are removed and the
  port reports `udp_steered() == false`; TCP keeps working unchanged.

`WorkerHandle::bind_udp` then picks the workers:

| local port | `udp_steered` | bound on |
|---|---|---|
| ephemeral, steered to queue *q* | true | worker *q* only |
| anything else (a well-known server port, or no UDP rules) | either | **every** worker (fan-in) |

A fan-in socket has one pair of rings per worker. Its receiver polls them
round-robin, so no worker starves another, and parks on every worker's
wake handle. It sends through the first worker only, which therefore
carries all of that socket's transmit traffic and ARP. Binding port 0
picks ephemeral ports from a cursor shared by all clones of the handle,
retrying on `AddrInUse`.

## Backpressure and drop policy

UDP has no flow control, so nothing in the worker ever waits; every queue
is bounded, and what happens when it is full depends on the direction.

**Sending** applies backpressure, without loss, as far as the worker:

1. `send_to` pushes onto the socket's command ring (1024). A full ring
   makes `send_to` wait (`try_send_to` returns `WouldBlock`; `Sink`
   reports not ready).
2. The worker takes a command off the ring only while the engine's
   outbound queue (1024, engine-wide) has room, and wakes the sender when
   it frees ring space. The room is shared out among the sockets waiting
   for it, with a different one first each iteration, so one busy sender
   cannot starve another.
3. The engine hands at most 64 datagrams to the port per poll. A datagram
   the pool has no mbuf for stays queued for the next poll.

After that, UDP may drop, and each drop is counted in the binding's
`tx_dropped`:

- A next hop that misses ARP moves the datagram to an awaiting-ARP queue
  (64 datagrams; beyond that the oldest is dropped), retried every poll
  and dropped after 3 s. The request is repeated at most once a second.
- A datagram that no longer fits (the port's limits shrank after it was
  accepted) is dropped.
- Sends still on the ring when the socket is closed go out as far as the
  outbound queue has room; the rest are dropped.
- A subnet-directed broadcast (e.g. 10.0.0.255 on a /24) is sent to the
  broadcast MAC only when a gateway is configured, since that is where the
  prefix comes from. Without one it waits on ARP, which nobody answers for
  a broadcast address, and is dropped after 3 s.

Oversized payloads are refused up front with `InvalidInput` (`TooLarge` in
the engine), before anything is queued: **the stack never fragments**, and
every packet carries Don't Fragment and TTL 64. The limit,
`max_datagram_size()`, is `min(MTU, pool buffer - 14) - 28`: 1472 bytes on
a 1500-byte MTU with the default pools.

**Receiving** drops the newest, as a kernel socket buffer does:

- Each binding queues up to 1024 received datagrams in the engine (set
  another default with `engine.udp_mut().set_default_rx_queue_capacity(n)`
  in `StackBuilder::configure`). A full queue drops the new datagram
  (`rx_dropped_queue_full`) and never stalls the receive loop that TCP
  shares.
- After each poll the worker moves datagrams to the socket's inbound ring,
  which holds at most as many as the queue's capacity (and never more than
  1024). If the ring is full they stay in the engine queue, and the worker
  retries that socket on every iteration until it is empty.
- So a socket pins at most twice its capacity in receive mbufs per worker
  it is bound on, plus the datagrams the application still holds. That
  bound is per socket; their sum is bounded by the pool instead: a
  datagram is also dropped (and counted in `rx_dropped_queue_full`) when
  its worker's receive pool is down to a quarter of its mbufs, which held
  datagrams never take. That share is the NIC's to refill its receive
  ring, so stalled UDP readers can never starve TCP or ARP on the queue.
  Size `pool_mbufs` for the sockets' capacities anyway, as dropping at the
  reserve is a last resort.
- When the receiving half of a socket is dropped (after `split`), what was
  on its inbound ring is freed, and later datagrams are freed on arrival.
- With a connected peer (`connect`), datagrams from other sources are
  dropped on arrival (`rx_dropped_filtered`); the socket also skips any
  that were already queued when it connected (those are not counted).
  `disconnect` clears the peer.
- Dropped and counted engine-wide (`UdpEngine::counters()`), not per
  binding: datagrams to an unbound port (no ICMP port-unreachable is
  sent; their checksum is not verified), IP fragments, malformed headers,
  bad checksums (verified in software for a bound port, or flagged bad by
  the NIC, for any port), and chained (multi-segment) datagrams.

## Checksums

- **Transmit:** when the port negotiated `RTE_ETH_TX_OFFLOAD_UDP_CKSUM`,
  the engine writes the pseudo-header sum and sets the mbuf's UDP L4 flag
  (the L4 field is two bits wide, so it is replaced, never OR'ed with
  TCP's); otherwise it computes the checksum in software, sending a
  computed 0 as 0xFFFF (RFC 768).
- **Receive:** the NIC's "L4 good" flag is trusted only when
  `RTE_ETH_RX_OFFLOAD_UDP_CKSUM` was negotiated; otherwise the checksum is
  verified in software. A checksum field of 0 means the sender computed
  none, and the datagram is accepted.
- UDP offloads are negotiated independently of TCP's, so a device without
  UDP offload keeps TCP's fast path.

## Zero-copy paths

- **Receive:** a `Datagram`'s `data` is an `MbufSlice`, a view of the
  payload inside the mbuf it arrived in. `into_bytes()` keeps it a view
  (`Bytes::from_owner`), and the mbuf returns to its pool when the last
  reference drops. `recv_from_buf` copies into a caller's buffer instead,
  truncating like the kernel. Holding many small datagrams pins whole
  mbufs, so a slow reader costs pool memory, bounded per socket by the
  queue depths above and overall by the pool reserve.
- **Transmit:** a datagram that fits one pool buffer is copied into one
  mbuf: for a payload of at most one MTU that costs less than attaching it
  (the same measurement that keeps TCP from attaching single-MSS segments).
  Only a payload larger than a pool buffer (pools with buffers smaller
  than the MTU) is attached as an external buffer, from DMA-able (EAL)
  memory such as a received datagram's `into_bytes()` or a `DmaWriter`
  buffer, on ports that support multi-segment transmit. `send_to_slice`
  copies borrowed bytes into heap `Bytes`; it never uses a `DmaWriter`,
  whose short writes would split a datagram.

## Stats

Each binding has an `Arc<UdpStats>` of relaxed atomic counters written only
by its engine (a plain load and store, no locked add on the receive path)
and readable from the application. `UdpSocket::stats()` returns a
`UdpStatsSnapshot`, summed over the workers of a fan-in socket:

| counter | meaning |
|---|---|
| `rx_datagrams`, `rx_bytes` | queued for the reader |
| `rx_dropped_queue_full` | the binding's receive queue was full, or the receive pool was at its reserve |
| `rx_dropped_filtered` | not from the connected peer |
| `tx_datagrams`, `tx_bytes` | handed to the port |
| `tx_dropped` | ARP timeout or overflow, too large after acceptance, or socket closed with sends still queued and no room for them |

## Limits

- No IP fragmentation or reassembly (fragments are dropped and counted;
  sends are capped at one packet).
- Received datagrams that span chained mbufs are dropped and counted.
- No ICMP, so no port-unreachable for an unbound port.
- No multicast group membership (IGMP): datagrams can be *sent* to a
  multicast address (to `01:00:5e` plus the low 23 bits), and the limited
  broadcast address is both sent and received, but no group is joined.
  Subnet-directed broadcasts are not received (and are sent as broadcasts
  only with a gateway configured; see above).
- No IPv4 options, no IPv6.
- A NIC that reports a UDP datagram's L4 checksum as bad gets it dropped
  before dispatch, even with UDP RX offload off (the pre-dispatch check is
  shared with TCP); it is counted in `rx_bad_checksum`.

## Tests

- `src/dpdk/net/udp.rs`: wire format and checksum unit tests.
- `tests/dpdk_udp.rs`: the engine against a `net_ring` peer (receive,
  drops, connected filter, ARP miss and timeout, broadcast/multicast MACs,
  emulated offloads, zero-copy transmit, TCP alongside UDP).
- `src/dpdk/udp/worker.rs`, `src/dpdk/udp/socket.rs`: rings, backpressure,
  teardown and wakeups without a worker.
- `tests/dpdk_udp_worker.rs`: a real worker on a second lcore driven by
  `UdpSocket` from a tokio runtime.
- `tests/dpdk_multiqueue.rs`: two real engines on an emulated two-queue
  NIC that the test plays: a steered ephemeral port lands on one engine,
  a server port bound on both receives on either queue, and the
  `udp_steered = false` routing binds every port on every worker.
- `scripts/e2e.sh`: `udp_echo` client and server against kernel sockets
  over a tap device.

Not covered by a test: the flow rules themselves on a real device
(`net_ring` has no `rte_flow`).
