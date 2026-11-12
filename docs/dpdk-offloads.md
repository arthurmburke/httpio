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
wire MSS remains unchanged. A header mbuf and pool-backed payload chain
carry the packet to the device. Payload is copied once into the pool;
there is no intermediate coalescing buffer. Arbitrary `Bytes` memory is
not attached as external DMA memory.

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
external-buffer zero-copy TX remain future work.
