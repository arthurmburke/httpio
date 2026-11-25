//! The engine-owned UDP layer: bindings, their receive queues, and the
//! outbound queue that the owning [`TcpEngine`] drains onto the wire.
//!
//! Everything here runs on the worker lcore, inside the engine's poll, and
//! is synchronous: datagrams are queued and dequeued, never waited for.
//! UDP has no flow control, so every queue is bounded and a full one
//! drops (the newest datagram on receive, a refused send on transmit)
//! rather than ever stalling the receive loop that TCP shares.
//!
//! [`TcpEngine`]: crate::dpdk::tcp::engine::TcpEngine

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

use crate::core::hashmap::HashMap;
use crate::core::time::{Duration, Instant};
use crate::dpdk::net::arp::ArpTable;
use crate::dpdk::net::eth::{self, EthAddr};
use crate::dpdk::net::ipv4::{self, Ipv4Header};
use crate::dpdk::net::udp::{self, UDP_HDR_LEN, UdpHeader};
use crate::dpdk::tcp::engine::EngineConfig;
use crate::dpdk::{EthPort, Mbuf, MbufSlice, Mempool};

/// Ethernet + IPv4 + UDP headers: where a datagram's payload starts.
const HEADERS_LEN: usize = eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN + UDP_HDR_LEN;

/// Datagrams a binding holds for its reader before it drops new ones.
pub const DEFAULT_RX_QUEUE_CAPACITY: usize = 1024;
/// Datagrams accepted by [`UdpEngine::send_to`] and not yet handed to the
/// port, across all bindings.
pub const DEFAULT_OUTBOUND_CAPACITY: usize = 1024;
/// Datagrams held while their next hop's MAC is being resolved. Beyond
/// this the oldest is dropped: a burst to an unreachable host must not
/// hold the pool hostage.
pub const MAX_AWAITING_ARP: usize = 64;
/// Most datagrams one poll hands to the port. The poll is shared with
/// TCP; this keeps a UDP flood from starving it.
pub const TX_BUDGET: usize = 64;
/// How long a datagram may wait for its next hop to resolve before it is
/// dropped. Far shorter than TCP's ARP timeout: a datagram is usually
/// worthless after a few seconds, and nothing will retransmit it anyway.
pub const ARP_WAIT: Duration = Duration::from_secs(3);
/// Payload limit assumed before the engine has seen its port: a standard
/// 1500-byte MTU.
const DEFAULT_MAX_PAYLOAD: usize = 1500 - ipv4::IPV4_HDR_LEN - UDP_HDR_LEN;

/// Why a UDP operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpError {
    /// The local port is already bound.
    AddrInUse,
    /// The local port is not bound.
    NotBound,
    /// The datagram does not fit one packet. This stack never fragments
    /// (every packet carries Don't Fragment); see
    /// [`UdpEngine::max_payload`].
    TooLarge,
    /// The outbound queue is full; retry after a poll has drained it.
    QueueFull,
    /// Port 0, or a destination with port 0 or address 0.0.0.0: neither
    /// can appear on the wire.
    InvalidAddress,
}

impl std::fmt::Display for UdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            UdpError::AddrInUse => "UDP port already bound",
            UdpError::NotBound => "UDP port not bound",
            UdpError::TooLarge => "datagram larger than one packet can carry",
            UdpError::QueueFull => "UDP outbound queue full",
            UdpError::InvalidAddress => "invalid UDP address",
        })
    }
}

impl std::error::Error for UdpError {}

impl From<UdpError> for std::io::Error {
    fn from(error: UdpError) -> Self {
        use std::io::ErrorKind;
        let kind = match error {
            UdpError::AddrInUse => ErrorKind::AddrInUse,
            UdpError::NotBound => ErrorKind::NotConnected,
            UdpError::TooLarge | UdpError::InvalidAddress => ErrorKind::InvalidInput,
            UdpError::QueueFull => ErrorKind::WouldBlock,
        };
        std::io::Error::new(kind, error)
    }
}

/// One received datagram. Its payload is a view of the mbuf it arrived in:
/// nothing was copied, and the mbuf returns to its pool when the last view
/// of it drops.
#[derive(Debug, Clone)]
pub struct Datagram {
    /// The sender.
    pub src: SocketAddrV4,
    /// Where it was sent: this host's address, or the limited broadcast
    /// address `255.255.255.255`, and the bound port.
    pub dst: SocketAddrV4,
    pub data: MbufSlice,
}

impl Datagram {
    /// The payload as [`Bytes`], still without copying (one small
    /// allocation for the shared owner; see [`MbufSlice::into_bytes`]).
    pub fn into_bytes(self) -> Bytes {
        self.data.into_bytes()
    }
}

/// Per-binding counters. Written only by the engine that owns the binding,
/// read by anyone holding the `Arc` (the application side of a socket, in
/// time). Relaxed throughout: they are statistics, ordered with nothing.
#[derive(Debug, Default)]
pub struct UdpStats {
    rx_datagrams: AtomicU64,
    rx_bytes: AtomicU64,
    rx_dropped_queue_full: AtomicU64,
    rx_dropped_filtered: AtomicU64,
    tx_datagrams: AtomicU64,
    tx_bytes: AtomicU64,
    tx_dropped: AtomicU64,
}

/// A single writer needs no read-modify-write: a plain load and store
/// keeps the lock prefix of `fetch_add` off the receive path.
fn bump(counter: &AtomicU64, by: u64) {
    counter.store(counter.load(Ordering::Relaxed) + by, Ordering::Relaxed);
}

impl UdpStats {
    /// Counts a datagram accepted from a socket and then not sent: the
    /// worker found the engine would not take it after all (its limits
    /// shrank), or the socket went away with it still on its ring. Only
    /// the worker that owns the binding calls this, so it is still a
    /// single writer.
    pub(crate) fn count_tx_dropped(&self, datagrams: u64) {
        bump(&self.tx_dropped, datagrams);
    }

    pub fn snapshot(&self) -> UdpStatsSnapshot {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        UdpStatsSnapshot {
            rx_datagrams: get(&self.rx_datagrams),
            rx_bytes: get(&self.rx_bytes),
            rx_dropped_queue_full: get(&self.rx_dropped_queue_full),
            rx_dropped_filtered: get(&self.rx_dropped_filtered),
            tx_datagrams: get(&self.tx_datagrams),
            tx_bytes: get(&self.tx_bytes),
            tx_dropped: get(&self.tx_dropped),
        }
    }
}

/// A point-in-time copy of [`UdpStats`]. Snapshots add up, for a socket
/// bound on several engines.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UdpStatsSnapshot {
    /// Datagrams queued for the reader.
    pub rx_datagrams: u64,
    /// Their payload bytes.
    pub rx_bytes: u64,
    /// Datagrams dropped because the binding's receive queue was full, or
    /// because the receive pool was down to the share kept for the NIC's
    /// ring (a quarter of it), which held datagrams may not take.
    pub rx_dropped_queue_full: u64,
    /// Datagrams dropped because they came from someone other than the
    /// connected peer.
    pub rx_dropped_filtered: u64,
    /// Datagrams handed to the port.
    pub tx_datagrams: u64,
    /// Their payload bytes.
    pub tx_bytes: u64,
    /// Datagrams accepted for sending and then dropped: their next hop did
    /// not resolve within [`ARP_WAIT`], too many were waiting on ARP, they
    /// no longer fit the port's packets, or the socket was closed with
    /// them still queued and no outbound room left.
    pub tx_dropped: u64,
}

impl std::ops::AddAssign for UdpStatsSnapshot {
    fn add_assign(&mut self, other: Self) {
        self.rx_datagrams += other.rx_datagrams;
        self.rx_bytes += other.rx_bytes;
        self.rx_dropped_queue_full += other.rx_dropped_queue_full;
        self.rx_dropped_filtered += other.rx_dropped_filtered;
        self.tx_datagrams += other.tx_datagrams;
        self.tx_bytes += other.tx_bytes;
        self.tx_dropped += other.tx_dropped;
    }
}

impl std::iter::Sum for UdpStatsSnapshot {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), |total, snapshot| total + snapshot)
    }
}

impl std::ops::Add for UdpStatsSnapshot {
    type Output = Self;

    fn add(mut self, other: Self) -> Self {
        self += other;
        self
    }
}

/// Engine-wide receive drops that belong to no binding.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UdpEngineCounters {
    /// Datagrams to a port nothing is bound to, whatever their checksum
    /// (it is not verified for them). (This stack sends no ICMP
    /// port-unreachable.)
    pub rx_unbound: u64,
    /// Truncated packets or impossible UDP lengths.
    pub rx_malformed: u64,
    /// IPv4 fragments, which this stack does not reassemble.
    pub rx_fragmented: u64,
    /// Datagrams to a bound port whose checksum did not verify in
    /// software, plus UDP frames the NIC flagged with a bad IPv4 or UDP
    /// checksum (dropped before dispatch, whatever their port).
    pub rx_bad_checksum: u64,
    /// Datagrams that arrived in more than one mbuf (larger than one
    /// receive buffer). Not delivered: a datagram is handed over as one
    /// contiguous view, and size the receive pool's buffers for the MTU.
    pub rx_chained: u64,
}

struct Binding {
    /// When set, only datagrams from this peer are delivered.
    connected: Option<SocketAddrV4>,
    rx: VecDeque<Datagram>,
    rx_capacity: usize,
    /// Whether this binding is on the engine's `updated` list, which
    /// therefore never holds it twice.
    updated: bool,
    stats: Arc<UdpStats>,
}

/// A datagram accepted for sending. It carries its binding's stats, so it
/// is accounted for even if the binding goes before the datagram does.
struct Outbound {
    src_port: u16,
    dst: SocketAddrV4,
    data: Bytes,
    stats: Arc<UdpStats>,
}

struct AwaitingArp {
    datagram: Outbound,
    since: Instant,
}

/// What the engine last learned of its port and pool: how large a
/// datagram it can send, and how.
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// Largest payload that fits one pool mbuf and the MTU: always
    /// sendable, by copying.
    copy_max: usize,
    /// Largest payload the MTU allows. More than `copy_max` only on a pool
    /// with buffers smaller than the MTU, for payloads that can be
    /// attached rather than copied.
    zero_copy_max: usize,
    /// Most mbufs one packet may chain; 1 without multi-segment TX.
    max_segments: usize,
    tx_cksum_offload: bool,
    /// The NIC's L4-good flag is trusted only when it was asked to check
    /// UDP checksums.
    rx_cksum_offload: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            copy_max: DEFAULT_MAX_PAYLOAD,
            zero_copy_max: DEFAULT_MAX_PAYLOAD,
            max_segments: 1,
            tx_cksum_offload: false,
            rx_cksum_offload: false,
        }
    }
}

/// The UDP layer of one engine (see the [module docs](super)).
pub struct UdpEngine {
    bindings: HashMap<u16, Binding>,
    default_rx_capacity: usize,
    /// Bindings that received datagrams during the current poll.
    updated: Vec<u16>,
    outbound: VecDeque<Outbound>,
    outbound_capacity: usize,
    awaiting_arp: VecDeque<AwaitingArp>,
    limits: Limits,
    /// Whether the receive pool is too low to queue another datagram,
    /// sampled at most once per poll (on its first datagram to queue).
    pool_low: Option<bool>,
    counters: UdpEngineCounters,
}

/// The share of a receive pool that held datagrams may never take: what
/// the NIC needs to refill its receive ring, and what TCP and ARP need to
/// keep working, however many sockets have stalled readers.
const POOL_RESERVE_DIVISOR: u32 = 4;

impl Default for UdpEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpEngine {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::default(),
            default_rx_capacity: DEFAULT_RX_QUEUE_CAPACITY,
            updated: Vec::new(),
            outbound: VecDeque::new(),
            outbound_capacity: DEFAULT_OUTBOUND_CAPACITY,
            awaiting_arp: VecDeque::new(),
            limits: Limits::default(),
            pool_low: None,
            counters: UdpEngineCounters::default(),
        }
    }

    /// Binds `port` with the default receive queue capacity.
    pub fn bind(&mut self, port: u16) -> Result<(), UdpError> {
        self.bind_with_capacity(port, self.default_rx_capacity)
    }

    /// Binds `port`, holding at most `rx_capacity` received datagrams for
    /// it (at least one). A datagram that arrives to a full queue is
    /// dropped. Each held datagram pins one receive mbuf, so size the
    /// receive pool to match.
    pub fn bind_with_capacity(&mut self, port: u16, rx_capacity: usize) -> Result<(), UdpError> {
        self.bind_with_stats(port, rx_capacity, Arc::default())
    }

    /// [`bind_with_capacity`](Self::bind_with_capacity), counting into
    /// `stats`: a socket's application side creates them, so that it can
    /// read them without asking the worker.
    pub(crate) fn bind_with_stats(
        &mut self,
        port: u16,
        rx_capacity: usize,
        stats: Arc<UdpStats>,
    ) -> Result<(), UdpError> {
        if port == 0 {
            return Err(UdpError::InvalidAddress);
        }
        if self.bindings.contains_key(&port) {
            return Err(UdpError::AddrInUse);
        }
        self.bindings.insert(
            port,
            Binding {
                connected: None,
                rx: VecDeque::new(),
                rx_capacity: rx_capacity.max(1),
                updated: false,
                stats,
            },
        );
        Ok(())
    }

    /// Releases `port`. Datagrams it had received and not yet handed out
    /// are dropped (their mbufs freed); datagrams it had queued for sending
    /// still go out, as the kernel's do after `close`. Unbinding an
    /// unbound port does nothing.
    pub fn unbind(&mut self, port: u16) {
        self.bindings.remove(&port);
    }

    pub fn is_bound(&self, port: u16) -> bool {
        self.bindings.contains_key(&port)
    }

    /// Sets (or with `None` clears) the binding's connected peer: while
    /// set, datagrams from any other address are dropped and counted in
    /// `rx_dropped_filtered`. Datagrams already queued stay.
    pub fn connect(&mut self, port: u16, peer: Option<SocketAddrV4>) -> Result<(), UdpError> {
        let binding = self.bindings.get_mut(&port).ok_or(UdpError::NotBound)?;
        binding.connected = peer;
        Ok(())
    }

    /// The binding's connected peer, if any.
    pub fn peer(&self, port: u16) -> Option<SocketAddrV4> {
        self.bindings.get(&port)?.connected
    }

    /// Receive queue capacity for bindings made from now on by
    /// [`bind`](Self::bind), and by `UdpSocket::bind` on a worker running
    /// this engine (set it through `StackBuilder::configure`).
    pub fn set_default_rx_queue_capacity(&mut self, datagrams: usize) {
        self.default_rx_capacity = datagrams.max(1);
    }

    /// See [`set_default_rx_queue_capacity`](Self::set_default_rx_queue_capacity).
    pub fn default_rx_queue_capacity(&self) -> usize {
        self.default_rx_capacity
    }

    /// The binding's receive queue capacity.
    pub fn rx_queue_capacity(&self, port: u16) -> Option<usize> {
        self.bindings.get(&port).map(|binding| binding.rx_capacity)
    }

    /// Changes a binding's receive queue capacity. Datagrams already queued
    /// beyond a smaller capacity stay; new ones are dropped until the
    /// queue drains below it.
    pub fn set_rx_queue_capacity(&mut self, port: u16, datagrams: usize) -> Result<(), UdpError> {
        let binding = self.bindings.get_mut(&port).ok_or(UdpError::NotBound)?;
        binding.rx_capacity = datagrams.max(1);
        Ok(())
    }

    /// How many datagrams [`send_to`](Self::send_to) may have waiting
    /// for the port, across all bindings (at least one).
    pub fn set_outbound_capacity(&mut self, datagrams: usize) {
        self.outbound_capacity = datagrams.max(1);
    }

    /// The binding's counters, to share with whoever reports on it.
    pub fn stats(&self, port: u16) -> Option<&Arc<UdpStats>> {
        self.bindings.get(&port).map(|binding| &binding.stats)
    }

    /// Engine-wide receive drops (datagrams no binding was charged for).
    pub fn counters(&self) -> UdpEngineCounters {
        self.counters
    }

    /// The largest payload [`send_to`](Self::send_to) accepts whatever
    /// memory it is in: the port's MTU less the IPv4 and UDP headers, or
    /// less if the pool's buffers are smaller. Known exactly once the
    /// engine has polled its port; a 1500-byte MTU is assumed until then.
    pub fn max_payload(&self) -> usize {
        self.limits.copy_max
    }

    /// The largest payload accepted when it is in DMA-capable memory (a
    /// [`DmaWriter`](crate::dpdk::DmaWriter)'s, say) and the port chains
    /// mbufs, so that it is attached to the packet instead of copied into
    /// one buffer: the MTU less the headers. Equal to
    /// [`max_payload`](Self::max_payload) unless the pool's buffers are
    /// smaller than the MTU.
    pub fn max_zero_copy_payload(&self) -> usize {
        if self.limits.max_segments > 1 {
            self.limits.zero_copy_max
        } else {
            self.limits.copy_max
        }
    }

    /// Queues `data` as one datagram from local `port` to `dst`. It goes
    /// out on a following poll of the engine, once `dst`'s next hop
    /// resolves (it is dropped, and counted in `tx_dropped`, if that takes
    /// longer than [`ARP_WAIT`]). A datagram is never split.
    pub fn send_to(&mut self, port: u16, dst: SocketAddrV4, data: Bytes) -> Result<(), UdpError> {
        let binding = self.bindings.get(&port).ok_or(UdpError::NotBound)?;
        if dst.port() == 0 || dst.ip().is_unspecified() {
            return Err(UdpError::InvalidAddress);
        }
        if !self.fits(&data) {
            return Err(UdpError::TooLarge);
        }
        if self.outbound.len() >= self.outbound_capacity {
            return Err(UdpError::QueueFull);
        }
        self.outbound.push_back(Outbound {
            src_port: port,
            dst,
            data,
            stats: binding.stats.clone(),
        });
        Ok(())
    }

    /// Room left in the outbound queue: how many more datagrams
    /// [`send_to`](Self::send_to) takes before it refuses with
    /// [`UdpError::QueueFull`].
    pub fn outbound_room(&self) -> usize {
        self.outbound_capacity.saturating_sub(self.outbound.len())
    }

    /// Datagrams accepted and not yet handed to the port, including those
    /// waiting on ARP.
    pub fn pending_tx(&self) -> usize {
        self.outbound.len() + self.awaiting_arp.len()
    }

    /// Takes the binding's oldest received datagram.
    pub fn recv_from(&mut self, port: u16) -> Option<Datagram> {
        self.bindings.get_mut(&port)?.rx.pop_front()
    }

    /// Hands the binding's received datagrams, oldest first, to `deliver`,
    /// with one lookup for the whole run. `deliver` gives back a datagram
    /// it cannot take (a full ring, say) as `Err`; it goes back to the head
    /// of the queue and the run stops.
    pub fn recv_each(
        &mut self,
        port: u16,
        mut deliver: impl FnMut(Datagram) -> Result<(), Datagram>,
    ) {
        let Some(binding) = self.bindings.get_mut(&port) else {
            return;
        };
        while let Some(datagram) = binding.rx.pop_front() {
            if let Err(datagram) = deliver(datagram) {
                binding.rx.push_front(datagram);
                break;
            }
        }
    }

    /// Received datagrams the binding holds.
    pub fn pending_rx(&self, port: u16) -> usize {
        self.bindings
            .get(&port)
            .map_or(0, |binding| binding.rx.len())
    }

    /// Bindings that received datagrams during the most recent poll, each
    /// once. A binding whose datagrams are not all taken after a poll is
    /// not listed again until another arrives: whoever drains them keeps
    /// track of that (see [`pending_rx`](Self::pending_rx)).
    pub fn updated_bindings(&self) -> &[u16] {
        &self.updated
    }

    fn fits(&self, data: &Bytes) -> bool {
        let len = data.len();
        len <= self.limits.copy_max
            || (len <= self.limits.zero_copy_max
                && dma_segment_count(data, self.limits.max_segments).is_some())
    }

    /// Start of a poll: forgets the previous poll's updated bindings and
    /// refreshes what the engine knows of its port and pool (a few loads;
    /// they could change only through `emulate_offloads`).
    pub(crate) fn begin_poll(&mut self, port: &EthPort, pool: &Mempool) {
        for port in self.updated.drain(..) {
            if let Some(binding) = self.bindings.get_mut(&port) {
                binding.updated = false;
            }
        }
        self.pool_low = None;
        self.refresh_limits(port, pool);
    }

    /// Counts a UDP frame the NIC flagged with a bad checksum, which the
    /// engine drops before it reaches [`on_datagram`](Self::on_datagram).
    pub(crate) fn count_nic_bad_checksum(&mut self) {
        self.counters.rx_bad_checksum += 1;
    }

    /// Learns the port's MTU and offloads and the pool's buffer size, which
    /// decide [`max_payload`](Self::max_payload). Each poll does this; the
    /// worker also does it before telling a new socket its limit, which may
    /// be before the engine's first poll.
    pub(crate) fn refresh_limits(&mut self, port: &EthPort, pool: &Mempool) {
        let offloads = port.offloads();
        let mtu_max = (port.mtu() as usize).saturating_sub(ipv4::IPV4_HDR_LEN + UDP_HDR_LEN);
        let buffer_max = usize::from(pool.packet_capacity()).saturating_sub(HEADERS_LEN);
        self.limits = Limits {
            copy_max: mtu_max.min(buffer_max),
            zero_copy_max: mtu_max,
            max_segments: if offloads.tx_multi_segment {
                offloads.tx_max_segments
            } else {
                1
            },
            tx_cksum_offload: offloads.tx_udp_checksum,
            rx_cksum_offload: offloads.rx_udp_checksum,
        };
    }

    /// Takes one received IPv4 packet of protocol 17 whose IPv4 header
    /// (`ip`) has already been parsed (and its checksum verified).
    /// `l4_ok` is the NIC's L4-good flag, trusted only with UDP RX checksum
    /// offload on. Anything not deliverable is dropped, freeing the mbuf.
    pub(crate) fn on_datagram(
        &mut self,
        mbuf: Mbuf,
        ip: &Ipv4Header,
        local_ip: Ipv4Addr,
        l4_ok: bool,
    ) {
        // Limited broadcast is UDP's (DHCP, discovery protocols); TCP
        // accepts only its own address.
        if ip.dst != local_ip && ip.dst != Ipv4Addr::BROADCAST {
            return;
        }
        if ip.flags_fragment_offset & 0x3fff != 0 {
            self.counters.rx_fragmented += 1;
            return;
        }
        let total_len = usize::from(ip.total_length);
        if total_len < ipv4::IPV4_HDR_LEN + UDP_HDR_LEN
            || eth::ETH_HDR_LEN + total_len > mbuf.pkt_len() as usize
        {
            self.counters.rx_malformed += 1;
            return;
        }
        if mbuf.pkt_len() as usize != mbuf.data().len() {
            self.counters.rx_chained += 1;
            return;
        }
        if self.bindings.is_empty() {
            // Nothing to deliver to (a TCP-only worker): count it without
            // reading the payload.
            self.counters.rx_unbound += 1;
            return;
        }
        let frame = mbuf.data();
        let l4 = &frame[eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN..eth::ETH_HDR_LEN + total_len];
        let Some((header, payload_len)) = UdpHeader::parse(l4, ip.src, ip.dst, false) else {
            self.counters.rx_malformed += 1;
            return;
        };
        // The binding and the peer filter first: they are O(1), and only a
        // datagram that would be delivered is worth a pass over its payload.
        let Some(binding) = self.bindings.get_mut(&header.dst_port) else {
            self.counters.rx_unbound += 1;
            return;
        };
        let src = SocketAddrV4::new(ip.src, header.src_port);
        if binding.connected.is_some_and(|peer| peer != src) {
            bump(&binding.stats.rx_dropped_filtered, 1);
            return;
        }
        let verify = !(l4_ok && self.limits.rx_cksum_offload);
        if verify && !udp::checksum_ok(&l4[..usize::from(header.length)], ip.src, ip.dst) {
            self.counters.rx_bad_checksum += 1;
            return;
        }
        if binding.rx.len() >= binding.rx_capacity {
            // UDP semantics: the newest is dropped, as a full socket
            // buffer drops it in the kernel; the receive loop never waits.
            bump(&binding.stats.rx_dropped_queue_full, 1);
            return;
        }
        // Every held datagram pins a receive mbuf, from the pool the NIC
        // refills its ring from. Per-binding limits do not bound their sum,
        // so the pool's last share is kept for the ring: below it, a
        // datagram is dropped as if its queue were full.
        let pool_low = *self.pool_low.get_or_insert_with(|| {
            let (free, size) = mbuf.pool_level();
            free < size / POOL_RESERVE_DIVISOR
        });
        if pool_low {
            bump(&binding.stats.rx_dropped_queue_full, 1);
            return;
        }
        bump(&binding.stats.rx_datagrams, 1);
        bump(&binding.stats.rx_bytes, payload_len as u64);
        binding.rx.push_back(Datagram {
            src,
            dst: SocketAddrV4::new(ip.dst, header.dst_port),
            data: MbufSlice::new(mbuf, HEADERS_LEN, payload_len),
        });
        if !binding.updated {
            binding.updated = true;
            self.updated.push(header.dst_port);
        }
    }

    /// Whether [`poll_output`](Self::poll_output) has anything to do.
    pub(crate) fn has_output(&self) -> bool {
        !self.outbound.is_empty() || !self.awaiting_arp.is_empty()
    }

    /// Builds packets for queued datagrams and hands each to `emit`, at
    /// most `room` of them and [`TX_BUDGET`] per poll. Datagrams waiting
    /// on ARP go first, being older. A datagram whose next hop is unknown
    /// moves to the ARP wait (its request is queued in `arp` for the
    /// engine to send this same poll); one the pool has no mbuf for stays
    /// where it is, for the next poll.
    pub(crate) fn poll_output(
        &mut self,
        pool: &Mempool,
        config: &EngineConfig,
        arp: &mut ArpTable,
        now: Instant,
        room: usize,
        mut emit: impl FnMut(Mbuf),
    ) {
        let mut budget = TX_BUDGET.min(room);
        let limits = self.limits;
        let mut pool_empty = false;

        let mut i = 0;
        while i < self.awaiting_arp.len() && budget > 0 {
            let entry = &self.awaiting_arp[i];
            if now.saturating_duration_since(entry.since) >= ARP_WAIT {
                if let Some(entry) = self.awaiting_arp.remove(i) {
                    bump(&entry.datagram.stats.tx_dropped, 1);
                }
                continue;
            }
            let Some(mac) = next_hop_mac(config, arp, *entry.datagram.dst.ip(), now) else {
                i += 1;
                continue;
            };
            let Some(mbuf) = build_udp_frame(pool, config, mac, &entry.datagram, limits) else {
                pool_empty = true;
                break;
            };
            emit(mbuf);
            budget -= 1;
            if let Some(entry) = self.awaiting_arp.remove(i) {
                sent(&entry.datagram);
            }
        }

        while !pool_empty && budget > 0 {
            let Some(datagram) = self.outbound.front() else {
                break;
            };
            // Accepted under limits the port no longer has (accepted before
            // the first poll, say).
            let len = datagram.data.len();
            if len > limits.copy_max
                && (len > limits.zero_copy_max
                    || dma_segment_count(&datagram.data, limits.max_segments).is_none())
            {
                if let Some(datagram) = self.outbound.pop_front() {
                    bump(&datagram.stats.tx_dropped, 1);
                }
                continue;
            }
            budget -= 1;
            let Some(mac) = next_hop_mac(config, arp, *datagram.dst.ip(), now) else {
                if self.awaiting_arp.len() >= MAX_AWAITING_ARP
                    && let Some(oldest) = self.awaiting_arp.pop_front()
                {
                    bump(&oldest.datagram.stats.tx_dropped, 1);
                }
                if let Some(datagram) = self.outbound.pop_front() {
                    self.awaiting_arp.push_back(AwaitingArp {
                        datagram,
                        since: now,
                    });
                }
                continue;
            };
            let Some(mbuf) = build_udp_frame(pool, config, mac, datagram, limits) else {
                break;
            };
            emit(mbuf);
            if let Some(datagram) = self.outbound.pop_front() {
                sent(&datagram);
            }
        }
    }
}

fn sent(datagram: &Outbound) {
    bump(&datagram.stats.tx_datagrams, 1);
    bump(&datagram.stats.tx_bytes, datagram.data.len() as u64);
}

/// The MAC a datagram to `dst` is addressed to: all ones for the limited
/// broadcast address and for the local subnet's directed broadcast (known
/// only with a gateway configured, which carries the prefix; not for /31
/// and /32, which have none, RFC 3021), the RFC 1112 §6.4 mapping for a
/// multicast group (`01:00:5e` and the group's low 23 bits), else the next
/// hop's, from ARP. `None` while ARP resolves it (a request is then
/// queued).
fn next_hop_mac(
    config: &EngineConfig,
    arp: &mut ArpTable,
    dst: Ipv4Addr,
    now: Instant,
) -> Option<EthAddr> {
    if dst.is_broadcast() {
        return Some(EthAddr::BROADCAST);
    }
    if let Some(gw) = config.gateway
        && gw.prefix_len < 31
    {
        let host_mask = u32::MAX >> gw.prefix_len;
        let d = u32::from(dst);
        if (d ^ u32::from(config.local_ip)) & !host_mask == 0 && d & host_mask == host_mask {
            return Some(EthAddr::BROADCAST);
        }
    }
    if dst.is_multicast() {
        let [_, b, c, d] = dst.octets();
        return Some(EthAddr::new([0x01, 0x00, 0x5e, b & 0x7f, c, d]));
    }
    arp.resolve(config.next_hop(dst), now)
}

/// How many mbufs attaching `data` without copying takes, the header mbuf
/// included: `None` if any of it is not DMA-capable memory, or it would
/// take more than `max_segments`.
fn dma_segment_count(data: &[u8], max_segments: usize) -> Option<usize> {
    if max_segments < 2 || data.is_empty() {
        return None;
    }
    let mut count = 1;
    let mut rest = data;
    while !rest.is_empty() {
        let (n, _) = Mbuf::dma_prefix(rest)?;
        count += 1;
        if count > max_segments {
            return None;
        }
        rest = &rest[n..];
    }
    Some(count)
}

/// Builds the Ethernet + IPv4 + UDP packet for `datagram`. The payload is
/// copied after the headers, unless it is larger than one pool buffer, is
/// DMA-capable memory and the port chains mbufs: then it is attached. `None` if the pool cannot supply
/// the mbufs right now.
fn build_udp_frame(
    pool: &Mempool,
    config: &EngineConfig,
    dst_mac: EthAddr,
    datagram: &Outbound,
    limits: Limits,
) -> Option<Mbuf> {
    let payload = &datagram.data;
    // Attach only what one mbuf cannot hold. For a payload that fits, the
    // two extra pool objects and the chain an attachment costs exceed the
    // copy (the measurement behind `WorkerHandle::dma_writes`: for a
    // single MSS-sized segment, attaching is slightly slower), and a
    // datagram is never larger than one MTU.
    let zero_copy = payload.len() > limits.copy_max
        && dma_segment_count(payload, limits.max_segments).is_some();
    let mut mbuf = Mbuf::alloc(pool)?;
    let frame_len = if zero_copy {
        HEADERS_LEN
    } else {
        HEADERS_LEN + payload.len()
    };
    let buf = mbuf.append(frame_len as u16)?;
    let (headers, wire_payload) = buf.split_at_mut(HEADERS_LEN);
    if !zero_copy {
        wire_payload.copy_from_slice(payload);
    }
    eth::EthHeader {
        dst: dst_mac,
        src: config.local_mac,
        ethertype: eth::ETHERTYPE_IPV4,
    }
    .write(&mut headers[..eth::ETH_HDR_LEN]);
    let dst_ip = *datagram.dst.ip();
    Ipv4Header {
        dscp_ecn: 0,
        total_length: (ipv4::IPV4_HDR_LEN + UDP_HDR_LEN + payload.len()) as u16,
        identification: 0,
        flags_fragment_offset: 0x4000, // Don't Fragment
        ttl: 64,
        protocol: ipv4::PROTO_UDP,
        src: config.local_ip,
        dst: dst_ip,
    }
    .write(
        &mut headers[eth::ETH_HDR_LEN..eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN],
        limits.tx_cksum_offload,
    );
    // The software checksum reads the payload where it is, in the attached
    // memory or the copy just made; the offload reads none of it.
    UdpHeader {
        src_port: datagram.src_port,
        dst_port: datagram.dst.port(),
        length: 0,
        checksum: 0,
    }
    .write(
        &mut headers[eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN..],
        payload,
        config.local_ip,
        dst_ip,
        limits.tx_cksum_offload,
    );
    if zero_copy {
        let mut start = 0;
        while start < payload.len() {
            let (n, _) = Mbuf::dma_prefix(&payload[start..])?;
            let tail = Mbuf::from_external_bytes(pool, payload.slice(start..start + n))?;
            mbuf.chain(tail).ok()?;
            start += n;
        }
    }
    if limits.tx_cksum_offload {
        mbuf.set_tx_ipv4_udp_cksum(eth::ETH_HDR_LEN as u16, ipv4::IPV4_HDR_LEN as u16);
    }
    Some(mbuf)
}
