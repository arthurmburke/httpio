# Bulk transfer offloads

The port automatically enables IPv4/TCP checksum offload when supported.
It additionally enables TCP segmentation offload (TSO) when checksum, TSO,
and multi-segment transmit capabilities are available together. Query
`EthPort::offloads()` for the negotiated settings, or run:

```sh
cargo run --release --example offload_caps -- --no-huge --no-pci --vdev=net_ring0
```

`tso_max_payload == 0` means ordinary MSS-sized transmission. A supported
port uses up to 32 KiB of payload per TSO packet, further bounded by the
congestion window, peer receive window, and driver descriptor limits. The
wire MSS remains unchanged. A header mbuf and payload chain carry the
packet to the device. DMA-capable payloads are attached as external buffers
without copying; ordinary heap-backed payloads are copied into the pool.
There is no intermediate coalescing buffer.

The retransmit queue retains byte ranges. Partial ACKs trim those ranges;
loss recovery retransmits at most one MSS from the first unacknowledged
byte. Local pool or NIC backpressure does not arm the network RTO before
transmission acceptance. Devices without TSO keep the software segmentation
path; this implementation does not use DPDK software GSO.

Receive processing validates checksums before burst-local DPDK TCP/IPv4
GRO (`TcpEngine::set_rx_gro(false)` disables it for comparisons). Only contiguous runs of eligible ACK-only data packets without TCP
options enter GRO; control and other packets form boundaries. No packets
are held for a later burst. Merged packets retain their mbuf chains and
application delivery shares each segment without flattening or copying.
Hardware LRO is not enabled by this change. Scatter/gather RX requires the
Ethernet/IP/TCP headers to fit in the first segment.

Window scaling is offered on active opens and echoed on passive opens
when the peer offers it. SYN windows remain unscaled. Negotiated connections
use a 1 MiB receive buffer and advertise shift 4; peers without scaling
retain the legacy 64 KiB buffer. Pool sizing must account for these larger
receive windows and data retained by applications.

For virtual offload testing, use a driver that advertises TSO (for example
virtio-user with vhost-net, if `/dev/vhost-net` is available). Check its
negotiated capabilities with `offload_caps` before comparing it with kernel
TSO/GRO. `net_ring` validates software behavior but performs no segmentation;
AF_PACKET/TAP support depends on the installed DPDK driver. Enabling veth
features alone does not make a DPDK driver advertise TSO.

Validation includes native pool reclamation and GRO merge/delivery,
corrupted RX rejection, TSO chain/metadata/checksum-seed checks with simulated
wire segmentation, partial-ACK loss recovery, and scale option negotiation.
Actual NIC/vhost segmentation and end-to-end throughput still require an
offload-capable device. RSS, multiple worker queues, hardware LRO, and
multi-worker flow steering remain future work.

## External-buffer zero-copy TX

Generate application data directly in EAL-managed memory and freeze it into
`Bytes` before sending through `TcpStream::send` or `TcpEngine::send`:

```rust,ignore
let mut buffer = httpio::dpdk::DmaBuffer::new(32 * 1024).expect("EAL allocation");
produce_payload(buffer.as_mut_slice());
stream.send(buffer.freeze()).await?;
```

The initial allocation is zero-initialized. Freezing transfers ownership and
allocates the `Bytes` owner metadata once; it does not copy payload. Slices
and clones share that ownership. EAL must remain initialized until every
buffer, frozen reference, and transmission using it has been released.
Borrowed `AsyncWrite` still copies; use the owned `send` API for this path.

TX recognizes EAL memory (including mbuf-backed receive `Bytes`), splits at
DMA-contiguous memseg boundaries and the external buffer's 16-bit length
limit, and checks the port's descriptor budget. Multi-segment TX is now
negotiated independently of TSO. Both ordinary TCP and TSO packets can use
external payloads. If memory is not EAL-managed or exceeds the segment
budget, TX keeps the copying fallback. This does not register arbitrary
heap allocations for DMA or assume virtual addresses are DMA addresses.

Each external attachment reserves two pool objects: its mbuf and a separate
mbuf containing the shared-info/Bytes owner record. No Rust heap allocation
is needed for the attachment record. The separate object keeps metadata
alive even if a driver makes an indirect clone and frees the original
attachment first. DPDK's final external-buffer callback releases the Bytes
reference and returns the record object. TCP independently holds the payload
until ACK or abort. Size pools for this additional metadata occupancy.

External mbufs expose immutable data: `data_mut` rejects them and
`append`/`prepend` return `None`. `reset` detaches external ownership before
making the mbuf writable again. Header mbufs remain writable.

`tests/dpdk_external_tx.rs` verifies original pointer identity, zero attachment
allocations, ACK-before-completion lifetime, driver clones, cross-thread
completion, ethdev loopback ownership, immutable access, reset, and allocation
failure cleanup. Engine tests also check normal/TSO external packet chains,
checksums across odd fragment boundaries, and descriptor-budget fallback.
Physical NIC DMA remains unverified in the no-NIC devcontainer.
