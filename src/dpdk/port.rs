//! Safe wrapper around a single ethdev port: configure, start, rx/tx burst.

use std::ptr;

use super::ffi;
use super::mbuf::Mbuf;
use super::mempool::Mempool;
use super::net::eth::EthAddr;

#[derive(Debug)]
pub struct PortError {
    pub what: &'static str,
    pub rc: i32,
}

impl std::fmt::Display for PortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed with rc={}", self.what, self.rc)
    }
}
impl std::error::Error for PortError {}

fn check(what: &'static str, rc: i32) -> Result<(), PortError> {
    if rc < 0 {
        Err(PortError { what, rc })
    } else {
        Ok(())
    }
}

/// Negotiated device features. Unsupported features stay disabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct Offloads {
    pub tx_checksum: bool,
    pub rx_checksum: bool,
    pub tso_max_payload: usize,
    pub tx_multi_segment: bool,
    pub tx_max_segments: usize,
}

/// Maximum number of packet pointers passed to one driver TX call.
pub const MAX_TX_BURST: usize = 256;
pub const DEFAULT_TX_BURST: usize = 64;

/// How segments of a connection this host opened find their way back to
/// the queue of the worker that owns it, on a port with several queues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueSteering {
    /// Program the device with `rte_flow` rules matching
    /// [`PortSteering`](super::steering::PortSteering). Initialization
    /// fails if the device cannot take them.
    FlowRules,
    /// Install nothing: something else delivers each local port to the
    /// queue `PortSteering` assigns it. For tests and benchmarks on
    /// software devices, where a harness plays the NIC.
    Unmanaged,
}

/// The started device behind one or more [`EthPort`] queue handles. It is
/// stopped and closed when the last of them is dropped.
struct Device {
    port_id: u16,
}

impl Drop for Device {
    fn drop(&mut self) {
        // Stop *and* close: `rte_eth_dev_stop` alone leaves the device
        // configured and, for the tap PMD, keeps the kernel tap attached
        // with its multi-queue ownership held -- so a subsequent process
        // re-attaching to the same persistent tap can't move packets
        // ("Exclusivity flag on, cannot modify"). `rte_eth_dev_close`
        // fully releases it, flow rules included.
        unsafe {
            ffi::rte_eth_dev_stop(self.port_id);
            ffi::rte_eth_dev_close(self.port_id);
        }
    }
}

/// One RX/TX queue pair of a started port. A single-queue port is one of
/// these; a multi-queue port is one per worker, each used by one thread.
pub struct EthPort {
    /// Held only to keep the device started while any queue is in use.
    _device: std::sync::Arc<Device>,
    queue_id: u16,
    /// How many queues the port was started with.
    queues: u16,
    tx_burst_limit: usize,
    offloads: Offloads,
    port_id: u16,
    mtu: u32,
    /// The NIC will compute IPv4 + TCP checksums on TX (both offloads were
    /// available and enabled), so the stack writes only the TCP
    /// pseudo-header checksum and leaves the IP checksum zero.
    tx_cksum_offload: bool,
    /// The NIC validates IPv4 + TCP checksums on RX and reports the result
    /// via mbuf flags, so the stack can skip software verification when the
    /// flag says GOOD.
    rx_cksum_offload: bool,
}

impl EthPort {
    pub fn count_avail() -> u16 {
        unsafe { ffi::rte_eth_dev_count_avail() }
    }

    /// Configures, sets up a single RX/TX queue pair, and starts the given
    /// port. `mtu` bounds the largest frame the device will accept
    /// (payload, not including the Ethernet header/CRC).
    pub fn init(
        port_id: u16,
        rx_pool: &Mempool,
        nb_rx_desc: u16,
        nb_tx_desc: u16,
        mtu: u32,
        socket_id: i32,
    ) -> Result<Self, PortError> {
        let mut queues = Self::init_queues(
            port_id,
            &[rx_pool],
            nb_rx_desc,
            nb_tx_desc,
            mtu,
            socket_id,
            QueueSteering::Unmanaged,
        )?;
        Ok(queues.pop().expect("one pool, one queue"))
    }

    /// The NUMA socket the device is attached to, or `-1` if unknown (a
    /// virtual device). Allocate each queue's pool, and run its worker,
    /// on this socket.
    pub fn socket(port_id: u16) -> i32 {
        unsafe { ffi::rte_eth_dev_socket_id(port_id) }
    }

    /// Configures and starts the port with one RX/TX queue pair per entry
    /// of `rx_pools`, and returns a handle to each, in queue order. Queue
    /// `i` receives into `rx_pools[i]`; give each worker its own pool, on
    /// the device's NUMA socket (see [`EthPort::socket`]).
    ///
    /// With more than one queue the device must deliver every segment of
    /// a connection to one queue:
    /// - connections this host opens are steered by local port, as
    ///   `steering` says (see [`PortSteering`](super::steering::PortSteering));
    /// - everything else TCP is spread by RSS where the device has it, so
    ///   a connection accepted on a listening port stays on the queue its
    ///   SYN arrived on;
    /// - anything else (ARP) arrives on queue 0.
    ///
    /// Fails, leaving the port closed, if the device has too few queues
    /// or rejects a flow rule.
    pub fn init_queues(
        port_id: u16,
        rx_pools: &[&Mempool],
        nb_rx_desc: u16,
        nb_tx_desc: u16,
        mtu: u32,
        socket_id: i32,
        steering: QueueSteering,
    ) -> Result<Vec<Self>, PortError> {
        let queues = u16::try_from(rx_pools.len())
            .ok()
            .filter(|n| (1..=super::steering::MAX_QUEUES).contains(n))
            .ok_or(PortError {
                what: "queue count out of range",
                rc: -libc::EINVAL,
            })?;
        let mut info: ffi::rte_eth_dev_info = unsafe { core::mem::zeroed() };
        check("rte_eth_dev_info_get", unsafe {
            ffi::rte_eth_dev_info_get(port_id, &mut info)
        })?;

        // Enable IPv4 + TCP checksum offload where the device supports it,
        // masking the desired bits against the reported capabilities so
        // `rte_eth_dev_configure` never rejects an unsupported offload.
        // Port-level offloads apply to all queues in DPDK, so setting them
        // in `[rt]xmode.offloads` here (with a NULL per-queue conf below)
        // is sufficient.
        let tx_want =
            (ffi::RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | ffi::RTE_ETH_TX_OFFLOAD_TCP_CKSUM) as u64;
        let rx_want =
            (ffi::RTE_ETH_RX_OFFLOAD_IPV4_CKSUM | ffi::RTE_ETH_RX_OFFLOAD_TCP_CKSUM) as u64;
        let mut tx_en = tx_want & info.tx_offload_capa;
        let rx_en = rx_want & info.rx_offload_capa;
        // Take the fast path only when BOTH IPv4 and TCP checksums can be
        // offloaded together (our frames always carry both); otherwise fall
        // back to full software checksums to avoid a mixed hardware/software
        // state per packet.
        let tx_cksum_offload = tx_en == tx_want;
        let rx_cksum_offload = rx_en == rx_want;

        let multi = info.tx_offload_capa & ffi::RTE_ETH_TX_OFFLOAD_MULTI_SEGS as u64 != 0;
        let tx_max_segments = if multi {
            let total = usize::from(info.tx_desc_lim.nb_seg_max);
            let per_packet = usize::from(info.tx_desc_lim.nb_mtu_seg_max);
            total
                .min(if per_packet == 0 { total } else { per_packet })
                .min(32)
        } else {
            1
        };
        if multi {
            tx_en |= ffi::RTE_ETH_TX_OFFLOAD_MULTI_SEGS as u64;
        }
        // `net_tap` advertises TSO but segments in software, slower than the
        // stack's own segmentation, and it rejects a TSO packet unless MSS
        // plus all headers, Ethernet included, fits the MTU. A full-MSS
        // packet is 14 bytes over and is refused on every retry, stalling
        // the connection. Leave TSO off for it.
        // SAFETY: `driver_name` is null or a NUL-terminated string owned by
        // the driver for the life of the process.
        let software_tso = !info.driver_name.is_null()
            && unsafe { std::ffi::CStr::from_ptr(info.driver_name) }.to_bytes() == b"net_tap";
        let tso = multi
            && !software_tso
            && (info.tx_desc_lim.nb_mtu_seg_max == 0 || info.tx_desc_lim.nb_mtu_seg_max >= 2)
            && tx_cksum_offload
            && info.tx_offload_capa & ffi::RTE_ETH_TX_OFFLOAD_TCP_TSO as u64 != 0;
        let tso_max_payload = if tso {
            tx_en |=
                ffi::RTE_ETH_TX_OFFLOAD_MULTI_SEGS as u64 | ffi::RTE_ETH_TX_OFFLOAD_TCP_TSO as u64;
            // Respect descriptor limits and keep IPv4 packet length below 65536.
            let max_segments = usize::from(info.tx_desc_lim.nb_seg_max).min(32);
            (max_segments.saturating_sub(1) * usize::from(rx_pools[0].packet_capacity()))
                .saturating_sub(54)
                .min(32768)
        } else {
            0
        };
        let offloads = Offloads {
            tx_checksum: tx_cksum_offload,
            rx_checksum: rx_cksum_offload,
            tso_max_payload,
            tx_multi_segment: multi,
            tx_max_segments,
        };

        if queues > info.max_rx_queues || queues > info.max_tx_queues {
            return Err(PortError {
                what: "device has fewer queues than requested",
                rc: -libc::ENOSPC,
            });
        }

        // A zeroed `rte_eth_conf` is the DPDK-conventional starting point
        // (like the sample apps' memset); the MTU and offloads are then set.
        // SAFETY: `rte_eth_conf` is plain C config data; all-zero is valid.
        let mut conf: ffi::rte_eth_conf = unsafe { core::mem::zeroed() };
        conf.rxmode.mtu = mtu;
        conf.txmode.offloads = tx_en;
        conf.rxmode.offloads = rx_en;
        // Traffic no flow rule claims is spread by RSS over the TCP
        // 4-tuple, with the device's default key: all that matters is that
        // one connection always hashes to one queue.
        let rss = (ffi::RTE_ETH_RSS_IPV4 | ffi::RTE_ETH_RSS_NONFRAG_IPV4_TCP) as u64
            & info.flow_type_rss_offloads;
        if queues > 1 && rss != 0 {
            conf.rxmode.mq_mode = ffi::RTE_ETH_MQ_RX_RSS;
            conf.rx_adv_conf.rss_conf.rss_hf = rss;
        }

        check("rte_eth_dev_configure", unsafe {
            ffi::rte_eth_dev_configure(port_id, queues, queues, &conf)
        })?;
        // From here the device is closed again on any failure.
        let device = std::sync::Arc::new(Device { port_id });

        for (queue, pool) in rx_pools.iter().enumerate() {
            let queue = queue as u16;
            check("rte_eth_rx_queue_setup", unsafe {
                ffi::rte_eth_rx_queue_setup(
                    port_id,
                    queue,
                    nb_rx_desc,
                    socket_id as u32,
                    ptr::null(),
                    pool.as_raw(),
                )
            })?;
            check("rte_eth_tx_queue_setup", unsafe {
                ffi::rte_eth_tx_queue_setup(
                    port_id,
                    queue,
                    nb_tx_desc,
                    socket_id as u32,
                    ptr::null(),
                )
            })?;
        }

        check("rte_eth_dev_start", unsafe {
            ffi::rte_eth_dev_start(port_id)
        })?;

        // Promiscuous mode: this stack terminates TCP at the DPDK port
        // itself rather than relying on the kernel/ARP for delivery, so it
        // needs to see frames addressed to the port's own MAC without
        // depending on switch/NIC filtering being set up in advance.
        check("rte_eth_promiscuous_enable", unsafe {
            ffi::rte_eth_promiscuous_enable(port_id)
        })?;

        if steering == QueueSteering::FlowRules {
            for rule in super::steering::PortSteering::new(queues).rules() {
                install_flow_rule(port_id, rule)?;
            }
        }

        Ok((0..queues)
            .map(|queue_id| Self {
                _device: device.clone(),
                queue_id,
                queues,
                tx_burst_limit: DEFAULT_TX_BURST,
                offloads,
                port_id,
                mtu,
                tx_cksum_offload,
                rx_cksum_offload,
            })
            .collect())
    }

    /// Which of the port's queues this handle is.
    pub fn queue_id(&self) -> u16 {
        self.queue_id
    }

    /// How the port's queues divide the local ports among themselves.
    pub fn steering(&self) -> super::steering::PortSteering {
        super::steering::PortSteering::new(self.queues)
    }

    /// Sets the driver TX call size, clamped to MAX_TX_BURST. This never
    /// waits for a full batch; small writes and control packets go immediately.
    pub fn set_tx_burst_limit(&mut self, packets: std::num::NonZeroU16) {
        self.tx_burst_limit = usize::from(packets.get()).min(MAX_TX_BURST);
    }

    pub fn offloads(&self) -> Offloads {
        self.offloads
    }

    /// Makes the stack behave as if the device had negotiated `offloads`,
    /// without reconfiguring the device. For benchmarks and tests on
    /// software devices (`net_ring`), where the harness plays the NIC:
    /// it must then segment TSO packets and mark received checksums good
    /// itself. Never use this on a device that carries real traffic.
    #[doc(hidden)]
    pub fn emulate_offloads(&mut self, offloads: Offloads) {
        self.offloads = offloads;
        self.tx_cksum_offload = offloads.tx_checksum;
        self.rx_cksum_offload = offloads.rx_checksum;
    }

    /// Whether IPv4 + TCP TX checksum offload is active on this port. When
    /// true, outgoing frames should carry only the TCP pseudo-header
    /// checksum (IP checksum zero) with the mbuf offload flags set.
    pub fn tx_cksum_offload(&self) -> bool {
        self.tx_cksum_offload
    }

    /// Whether IPv4 + TCP RX checksum offload is active on this port.
    pub fn rx_cksum_offload(&self) -> bool {
        self.rx_cksum_offload
    }

    pub fn mac_addr(&self) -> Result<EthAddr, PortError> {
        // SAFETY: `rte_ether_addr` is a plain 6-byte struct; zeroed is a
        // valid placeholder that `rte_eth_macaddr_get` overwrites.
        let mut addr: ffi::rte_ether_addr = unsafe { core::mem::zeroed() };
        check("rte_eth_macaddr_get", unsafe {
            ffi::rte_eth_macaddr_get(self.port_id, &mut addr)
        })?;
        Ok(EthAddr::new(addr.addr_bytes))
    }

    /// Collects up to `max` packets (at most 64) into an owned vector.
    /// Use `rx_packets` to avoid the collection allocation on hot paths.
    pub fn rx_burst(&self, max: usize) -> Vec<Mbuf> {
        self.rx_packets(max).collect()
    }

    /// Receives up to `out.len()` packets into caller storage and returns
    /// the filled prefix. The caller owns every returned packet and must
    /// convert each to an [`Mbuf`] (or free it) exactly once. Unlike
    /// [`EthPort::rx_packets`] this initializes and moves nothing, which
    /// is what an idle poll costs.
    pub(crate) fn rx_burst_raw<'a>(
        &self,
        out: &'a mut [std::mem::MaybeUninit<*mut ffi::rte_mbuf>],
    ) -> &'a mut [*mut ffi::rte_mbuf] {
        let max = out.len().min(usize::from(u16::MAX)) as u16;
        // SAFETY: `out` has room for `max` pointers; the driver writes the
        // first `received` of them.
        unsafe {
            let received =
                ffi::rte_eth_rx_burst(self.port_id, self.queue_id, out.as_mut_ptr().cast(), max);
            std::slice::from_raw_parts_mut(out.as_mut_ptr().cast(), usize::from(received))
        }
    }

    /// Allocation-free RX batch. Unconsumed packets are freed on drop.
    pub fn rx_packets(&self, max: usize) -> impl ExactSizeIterator<Item = Mbuf> {
        let mut packets: [Option<Mbuf>; 64] = std::array::from_fn(|_| None);
        let mut raw = [ptr::null_mut(); 64];
        let received = unsafe {
            ffi::rte_eth_rx_burst(
                self.port_id,
                self.queue_id,
                raw.as_mut_ptr(),
                max.min(64) as u16,
            )
        } as usize;
        for i in 0..received {
            packets[i] = Some(unsafe { Mbuf::from_raw(raw[i]) });
        }
        packets.into_iter().take(received).map(Option::unwrap)
    }

    /// Transmits a batch, returning packets the driver did not accept.
    pub fn tx_burst(&self, mut mbufs: Vec<Mbuf>) -> Vec<Mbuf> {
        self.tx_burst_in_place(&mut mbufs);
        mbufs
    }

    /// Keeps the caller's allocation; removes only packets owned by the NIC.
    pub fn tx_burst_in_place(&self, mbufs: &mut Vec<Mbuf>) {
        let mut accepted = 0;
        while accepted < mbufs.len() {
            let n = (mbufs.len() - accepted).min(self.tx_burst_limit);
            // SAFETY: an `Mbuf` is exactly its `*mut rte_mbuf`
            // (`repr(transparent)`), so the vector's storage is the pointer
            // array the driver expects. The driver reads the `n` pointers
            // and takes ownership of the packets it accepts.
            let raw = unsafe { mbufs.as_mut_ptr().add(accepted).cast::<*mut ffi::rte_mbuf>() };
            #[cfg(feature = "tcp-metrics")]
            let metrics_start = std::time::Instant::now();
            let sent = unsafe {
                ffi::rte_eth_tx_burst(self.port_id, self.queue_id, raw, n as u16)
            } as usize;
            #[cfg(feature = "tcp-metrics")]
            super::metrics::record(|m| {
                m.tx_calls += 1;
                m.tx_requested += n as u64;
                m.tx_accepted += sent as u64;
                m.tx_partial_calls += u64::from(sent < n);
                m.tx_zero_calls += u64::from(sent == 0);
                m.tx_batches[super::metrics::bucket(n)] += 1;
                m.tx_driver_ns += metrics_start.elapsed().as_nanos() as u64;
            });
            accepted += sent;
            if sent < n {
                break;
            }
        }
        for packet in mbufs.drain(..accepted) {
            // The NIC owns these packets now; do not run Mbuf::drop.
            std::mem::forget(packet);
        }
    }

    pub fn port_id(&self) -> u16 {
        self.port_id
    }

    pub fn mtu(&self) -> u32 {
        self.mtu
    }
}

/// Programs the device to deliver TCP segments whose destination port
/// matches `rule` to its queue: `eth / ipv4 / tcp dst is PORT mask MASK`,
/// action `queue`.
fn install_flow_rule(port_id: u16, rule: super::steering::FlowRule) -> Result<(), PortError> {
    // SAFETY: every structure is plain C data for which all-zero is valid,
    // and all of it outlives the two calls that read it.
    unsafe {
        let mut attr: ffi::rte_flow_attr = core::mem::zeroed();
        attr.set_ingress(1);
        let mut spec: ffi::rte_flow_item_tcp = core::mem::zeroed();
        let mut mask: ffi::rte_flow_item_tcp = core::mem::zeroed();
        spec.hdr.dst_port = rule.dst_port.to_be();
        mask.hdr.dst_port = rule.mask.to_be();
        let item = |type_| ffi::rte_flow_item {
            type_,
            spec: ptr::null(),
            last: ptr::null(),
            mask: ptr::null(),
        };
        let pattern = [
            item(ffi::RTE_FLOW_ITEM_TYPE_ETH),
            item(ffi::RTE_FLOW_ITEM_TYPE_IPV4),
            ffi::rte_flow_item {
                type_: ffi::RTE_FLOW_ITEM_TYPE_TCP,
                spec: (&raw const spec).cast(),
                last: ptr::null(),
                mask: (&raw const mask).cast(),
            },
            item(ffi::RTE_FLOW_ITEM_TYPE_END),
        ];
        let queue = ffi::rte_flow_action_queue { index: rule.queue };
        let actions = [
            ffi::rte_flow_action {
                type_: ffi::RTE_FLOW_ACTION_TYPE_QUEUE,
                conf: (&raw const queue).cast(),
            },
            ffi::rte_flow_action {
                type_: ffi::RTE_FLOW_ACTION_TYPE_END,
                conf: ptr::null(),
            },
        ];
        let mut error: ffi::rte_flow_error = core::mem::zeroed();
        check(
            "rte_flow_validate (device cannot steer by TCP destination port)",
            ffi::rte_flow_validate(
                port_id,
                &attr,
                pattern.as_ptr(),
                actions.as_ptr(),
                &mut error,
            ),
        )?;
        let flow = ffi::rte_flow_create(
            port_id,
            &attr,
            pattern.as_ptr(),
            actions.as_ptr(),
            &mut error,
        );
        if flow.is_null() {
            return Err(PortError {
                what: "rte_flow_create",
                rc: -libc::EIO,
            });
        }
    }
    Ok(())
}
