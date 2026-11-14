//! Wires the DPDK port to the per-connection TCP state machines: demuxes
//! received frames to the right `Tcb` (or spawns one for a SYN on a
//! listened port), drives timers, and serializes each `Tcb`'s pending
//! output back onto the wire.
//!
//! Addressing is a single default route: peers inside the local subnet are
//! reached directly, everything else through the configured gateway (see
//! [`EngineConfig::next_hop`]). Either way the next hop's MAC comes from a
//! minimal built-in ARP responder/resolver. With no gateway configured,
//! every peer is assumed to be on the local Ethernet segment.

mod gro;

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::core::hashmap::HashMap;
use crate::core::hashset::HashSet;
use crate::dpdk::net::arp::ArpTable;
use crate::dpdk::net::eth::EthAddr;
use crate::dpdk::net::{arp, eth, ipv4, tcp};
use crate::dpdk::{EthPort, Mbuf, Mempool};

use super::chunk::Chunk;
use super::seq::Seq;
use super::state::TcpState;
use super::tcb::{Event, FourTuple, OutSegment, Tcb};
use super::timers::Timers;
use super::tx_queue::Payload;

const MAX_RX_BURST: usize = 64;
const MAX_PENDING_TX: usize = 256;
pub const DEFAULT_TX_BUDGET: usize = 64;
const ARP_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the port may refuse the packet at the head of the transmit
/// queue before the engine gives up on that packet. Far longer than a
/// full transmit ring takes to drain, and shorter than the minimum
/// retransmission timeout.
const TX_STALL_TIMEOUT: Duration = Duration::from_millis(100);

struct PendingTcp {
    tuple: FourTuple,
    mac: EthAddr,
    header: tcp::TcpHeader,
    payload: Payload,
    /// Whether the connection is still tracked and counts this packet in
    /// [`Conn::queued_tx`]. The last segments of a connection that closed
    /// (its final reset) are unowned: the connection is already gone.
    owned: bool,
    tso_mss: u16,
}

/// Whether a connection came from a listener, and if so how far it is
/// from being handed to `accept()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptState {
    /// An active open (`connect`): never offered to `accept()`.
    NotApplicable,
    /// Spawned from a listener's SYN; waiting for its first
    /// `Event::Established`.
    AwaitingHandshake,
    /// Established and placed on its port's accept queue.
    Queued,
}

/// Next-hop MAC resolution as seen by one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NextHop {
    /// Not waiting on ARP: the last attempt resolved, or none was needed
    /// yet.
    Resolved,
    /// Output is held back until ARP answers. The connection is reset if
    /// that takes longer than [`ARP_TIMEOUT`] from `since`.
    Resolving { since: Instant },
}

/// One tracked connection: the TCP state machine plus the engine's own
/// bookkeeping for it.
struct Conn {
    tcb: Tcb,
    accept: AcceptState,
    next_hop: NextHop,
    /// Segments of this connection queued locally (awaiting pool space or
    /// NIC acceptance). No new output is produced while this is non-zero.
    queued_tx: usize,
    /// Already in the engine's `active` set, so marking it again (once per
    /// received packet) needs no hashing. May be false for a member that a
    /// due timer inserted; inserting such a tuple twice is harmless.
    active: bool,
}

impl Conn {
    fn new(tcb: Tcb, accept: AcceptState) -> Self {
        Self {
            tcb,
            accept,
            next_hop: NextHop::Resolved,
            queued_tx: 0,
            active: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineConfig {
    pub local_mac: EthAddr,
    pub local_ip: Ipv4Addr,
    /// Default route. `None`: every peer is on-link (ARP for it directly).
    pub gateway: Option<Gateway>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            local_mac: EthAddr::ZERO,
            local_ip: Ipv4Addr::UNSPECIFIED,
            gateway: None,
        }
    }
}

/// A default route: destinations outside `local_ip/prefix_len` are sent to
/// `ip`'s MAC address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gateway {
    pub ip: Ipv4Addr,
    /// Prefix length of the local subnet (0..=32). 32 sends every peer,
    /// even same-subnet ones, through the gateway.
    pub prefix_len: u8,
}

impl EngineConfig {
    /// Builds a config from CLI-style strings: `local` is `IP` or
    /// `IP/PREFIX` (like `ip addr add`), `gateway` an optional `IP` (like
    /// `ip route add default via`). A gateway with no prefix on `local`
    /// routes every peer through the gateway (prefix 32); a prefix with no
    /// gateway is accepted and ignored.
    pub fn from_cli(
        local_mac: EthAddr,
        local: &str,
        gateway: Option<&str>,
    ) -> Result<Self, String> {
        let (ip, prefix_len) = match local.split_once('/') {
            Some((ip, len)) => {
                let len: u8 = len
                    .parse()
                    .ok()
                    .filter(|l| *l <= 32)
                    .ok_or_else(|| format!("invalid prefix length in {local:?}"))?;
                (ip, len)
            }
            None => (local, 32),
        };
        let gateway = gateway
            .map(|gw| parse_ipv4(gw).map(|ip| Gateway { ip, prefix_len }))
            .transpose()?;
        Ok(Self {
            local_mac,
            local_ip: parse_ipv4(ip)?,
            gateway,
        })
    }

    /// The IP whose MAC a frame to `dst` is addressed to: `dst` itself when
    /// it is on-link, else the gateway.
    pub fn next_hop(&self, dst: Ipv4Addr) -> Ipv4Addr {
        match self.gateway {
            Some(gw) if !same_subnet(self.local_ip, dst, gw.prefix_len) => gw.ip,
            _ => dst,
        }
    }
}

fn parse_ipv4(s: &str) -> Result<Ipv4Addr, String> {
    s.parse::<Ipv4Addr>()
        .map_err(|_| format!("invalid IPv4 address {s:?}"))
}

fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix_len: u8) -> bool {
    // `checked_shl(32)` is None: a /0 mask matches everything.
    let mask = u32::MAX
        .checked_shl(32 - u32::from(prefix_len.min(32)))
        .unwrap_or(0);
    (u32::from(a) ^ u32::from(b)) & mask == 0
}

pub struct TcpEngine {
    tx_budget: usize,
    config: EngineConfig,
    rx_gro: bool,
    listeners: HashSet<u16>,
    connections: HashMap<FourTuple, Conn>,
    connections_opened: u64,
    accept_queues: HashMap<u16, VecDeque<FourTuple>>,
    /// Immediately runnable connections only. Future timers live in an
    /// indexed heap and enter this set when due, or on packet/app activity.
    timers: Timers,
    active: HashSet<FourTuple>,
    /// Scratch set for both poll phases; empty between polls. Swapping
    /// with `active` and clearing afterward retains both allocations.
    processing: HashSet<FourTuple>,
    tx_batch: Vec<Mbuf>,
    tx_owners: Vec<Option<(FourTuple, Seq)>>,
    /// When the port first refused the packet now at the head of
    /// `tx_batch`; `None` while the port is accepting packets.
    tx_stalled_since: Option<Instant>,
    tx_dropped: u64,
    pending_tx: VecDeque<PendingTcp>,
    updated: Vec<FourTuple>,
    segments: Vec<OutSegment>,

    /// Next-hop MAC resolution: expiring mappings plus the requests that
    /// fill them (see [`ArpTable`]).
    arp: ArpTable,
    pending_arp_replies: Vec<(EthAddr, Ipv4Addr)>,
    /// RSTs sent to a peer with no matching connection/listener. Built
    /// eagerly (mac already resolved) rather than routed through a Tcb,
    /// since there is no Tcb for an unknown 4-tuple.
    pending_raw_resets: Vec<(EthAddr, Ipv4Addr, tcp::TcpHeader)>,
}

impl TcpEngine {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            tx_budget: DEFAULT_TX_BUDGET,
            config,
            rx_gro: true,
            listeners: HashSet::default(),
            connections: HashMap::default(),
            connections_opened: 0,
            accept_queues: HashMap::default(),
            arp: ArpTable::new(),
            pending_arp_replies: Vec::new(),
            pending_raw_resets: Vec::new(),
            timers: Timers::default(),
            active: HashSet::default(),
            processing: HashSet::default(),
            tx_batch: Vec::new(),
            tx_owners: Vec::new(),
            tx_stalled_since: None,
            tx_dropped: 0,
            pending_tx: VecDeque::new(),
            updated: Vec::new(),
            segments: Vec::new(),
        }
    }

    /// Maximum output packets per connection per poll, clamped to the global
    /// pending-TX bound. Active connections share that bound; no packet waits
    /// for a full batch. This does not change congestion or receive windows.
    pub fn set_tx_budget(&mut self, packets: std::num::NonZeroU16) {
        self.tx_budget = usize::from(packets.get()).min(MAX_PENDING_TX);
    }

    fn output_budget(&self) -> usize {
        self.tx_budget
            .min((MAX_PENDING_TX / self.processing.len().max(1)).max(1))
    }

    /// Enable/disable burst-local receive aggregation for workload comparisons.
    pub fn set_rx_gro(&mut self, enabled: bool) {
        self.rx_gro = enabled;
    }

    /// Marks a connection as needing attention on the next `poll`. Cheap
    /// and idempotent; called from every path that can give a connection
    /// pending output (app ops, inbound segments). Its timer entry stays:
    /// a due timer only inserts into the same set, and the poll that
    /// processes the connection re-arms or removes it.
    fn mark_active(active: &mut HashSet<FourTuple>, conn: &mut Conn, tuple: FourTuple) {
        if !conn.active {
            conn.active = true;
            active.insert(tuple);
        }
    }

    pub fn listen(&mut self, port: u16) {
        self.listeners.insert(port);
        self.accept_queues.entry(port).or_default();
    }

    /// The local IPv4 address every connection of this engine uses.
    pub fn local_ip(&self) -> Ipv4Addr {
        self.config.local_ip
    }

    /// Starts an active open. Returns `None` -- without touching any
    /// existing connection or bumping `connections_opened` -- if the
    /// 4-tuple is already tracked (live, or still draining in TIME_WAIT);
    /// the caller should retry with a different local port.
    pub fn connect(
        &mut self,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        local_port: u16,
    ) -> Option<FourTuple> {
        let tuple = FourTuple {
            local_ip: self.config.local_ip,
            local_port,
            remote_ip,
            remote_port,
        };
        match self.connections.entry(tuple) {
            std::collections::hash_map::Entry::Occupied(_) => return None,
            std::collections::hash_map::Entry::Vacant(v) => {
                let conn = v.insert(Conn::new(
                    Tcb::new_active(tuple),
                    AcceptState::NotApplicable,
                ));
                // Has a SYN to send.
                Self::mark_active(&mut self.active, conn, tuple);
            }
        }
        self.connections_opened += 1;
        Some(tuple)
    }

    /// Total active opens since the engine was created (never decremented;
    /// a connection-reuse observability counter, not a live-count).
    pub fn connections_opened(&self) -> u64 {
        self.connections_opened
    }

    pub fn accept(&mut self, port: u16) -> Option<FourTuple> {
        self.accept_queues.get_mut(&port)?.pop_front()
    }

    /// Bytes queued for transmission or still awaiting acknowledgment.
    pub fn buffered_send_bytes(&self, tuple: FourTuple) -> usize {
        self.connections
            .get(&tuple)
            .map_or(0, |c| c.tcb.buffered_send_bytes())
    }

    /// Discards an abandoned connection and all its retained buffers.
    pub(crate) fn abort(&mut self, tuple: FourTuple) {
        self.connections.remove(&tuple);
        self.timers.remove(tuple);
        self.active.remove(&tuple);
        self.discard_queued(tuple);
    }

    fn discard_queued(&mut self, tuple: FourTuple) {
        self.pending_tx.retain(|p| p.tuple != tuple);
        for i in (0..self.tx_owners.len()).rev() {
            if self.tx_owners[i].is_some_and(|(owner, _)| owner == tuple) {
                self.tx_owners.remove(i);
                self.tx_batch.remove(i);
            }
        }
        if let Some(conn) = self.connections.get_mut(&tuple) {
            conn.queued_tx = 0;
        }
    }

    pub fn send(&mut self, tuple: FourTuple, data: Bytes) {
        if let Some(conn) = self.connections.get_mut(&tuple) {
            conn.tcb.send(data);
            Self::mark_active(&mut self.active, conn, tuple);
        }
    }

    pub fn recv(&mut self, tuple: FourTuple, max_len: usize) -> Bytes {
        let Some(conn) = self.connections.get_mut(&tuple) else {
            return Bytes::new();
        };
        let data = conn.tcb.recv(max_len);
        // Reading only needs a poll when it produced a window update.
        if !data.is_empty() && conn.tcb.has_pending_output() {
            Self::mark_active(&mut self.active, conn, tuple);
        }
        data
    }

    /// Hands every readable chunk to `deliver` until it returns `false` or
    /// nothing is left, with one connection lookup for the whole run.
    pub fn recv_each(
        &mut self,
        tuple: FourTuple,
        max_len: usize,
        mut deliver: impl FnMut(Bytes) -> bool,
    ) {
        self.recv_each_chunk(tuple, max_len, |chunk| deliver(chunk.into_bytes()));
    }

    pub(super) fn recv_each_chunk(
        &mut self,
        tuple: FourTuple,
        max_len: usize,
        mut deliver: impl FnMut(Chunk) -> bool,
    ) {
        let Some(conn) = self.connections.get_mut(&tuple) else {
            return;
        };
        let mut any = false;
        while let Some(data) = conn.tcb.recv_chunk(max_len) {
            any = true;
            if !deliver(data) {
                break;
            }
        }
        // Reading only needs a poll when it produced a window update.
        if any && conn.tcb.has_pending_output() {
            Self::mark_active(&mut self.active, conn, tuple);
        }
    }

    pub fn readable_len(&self, tuple: FourTuple) -> usize {
        self.connections
            .get(&tuple)
            .map(|c| c.tcb.readable_len())
            .unwrap_or(0)
    }

    pub fn close(&mut self, tuple: FourTuple) {
        if let Some(conn) = self.connections.get_mut(&tuple) {
            conn.tcb.close();
            Self::mark_active(&mut self.active, conn, tuple);
        }
    }

    /// Sets the initial congestion window for an active open before its
    /// handshake completes. An unknown connection is ignored.
    ///
    /// # Panics
    ///
    /// Panics if a tracked connection is outside SYN-SENT or `segments` is zero.
    pub fn set_initial_window(&mut self, tuple: FourTuple, segments: u16) {
        if let Some(conn) = self.connections.get_mut(&tuple) {
            conn.tcb.set_initial_window(segments);
        }
    }

    /// TCP_NODELAY: disable (or re-enable) Nagle's algorithm for one
    /// connection.
    pub fn set_nodelay(&mut self, tuple: FourTuple, nodelay: bool) {
        if let Some(conn) = self.connections.get_mut(&tuple) {
            conn.tcb.set_nodelay(nodelay);
            // May unblock a Nagle-held tail.
            Self::mark_active(&mut self.active, conn, tuple);
        }
    }

    /// TCP_CORK-style hold: while set, the trailing sub-MSS segment is
    /// held back until `flush()` (full-MSS segments still flow).
    pub fn set_cork(&mut self, tuple: FourTuple, corked: bool) {
        if let Some(conn) = self.connections.get_mut(&tuple) {
            conn.tcb.set_cork(corked);
            // Uncorking flushes a held tail.
            Self::mark_active(&mut self.active, conn, tuple);
        }
    }

    /// Manual trigger releasing a corked connection's held tail segment.
    pub fn flush(&mut self, tuple: FourTuple) {
        if let Some(conn) = self.connections.get_mut(&tuple) {
            conn.tcb.flush();
            Self::mark_active(&mut self.active, conn, tuple);
        }
    }

    pub fn state(&self, tuple: FourTuple) -> Option<TcpState> {
        self.connections.get(&tuple).map(|c| c.tcb.state)
    }

    /// One iteration of the poll loop: drains received frames, runs due
    /// timers, and transmits whatever each runnable connection
    /// (or the ARP layer) now has pending. Returns state-change events
    /// the socket layer may care about. This convenience method returns a
    /// fresh vector; use `poll_into` to retain event storage across polls.
    pub fn poll(
        &mut self,
        port: &EthPort,
        pool: &Mempool,
        now: Instant,
    ) -> Vec<(FourTuple, Event)> {
        let mut events = Vec::new();
        self.poll_into(port, pool, now, &mut events);
        events
    }

    /// Polls with reusable event storage; the worker uses this hot path.
    pub fn poll_into(
        &mut self,
        port: &EthPort,
        pool: &Mempool,
        now: Instant,
        events: &mut Vec<(FourTuple, Event)>,
    ) {
        #[cfg(feature = "tcp-metrics")]
        let metrics_start = Instant::now();
        events.clear();
        self.updated.clear();
        self.arp.expire(now);
        // The burst is received into uninitialized stack storage and each
        // packet is taken out of it exactly once: an idle poll (most polls)
        // must not pay for clearing or moving 64 slots. A run of
        // GRO-eligible packets is merged where it lies.
        let mut burst = [std::mem::MaybeUninit::uninit(); MAX_RX_BURST];
        let burst = port.rx_burst_raw(&mut burst);
        let mut run_start = 0;
        for i in 0..burst.len() {
            // SAFETY: the driver handed over ownership of this packet, and
            // each slot is converted once: here, or by `handle_gro` after
            // `into_raw` gives it back to the slot's pointer.
            let mut mbuf = unsafe { Mbuf::from_raw(burst[i]) };
            if self.rx_gro && gro::prepare(&mut mbuf) {
                let _ = mbuf.into_raw();
                continue;
            }
            self.handle_gro(&mut burst[run_start..i], now);
            run_start = i + 1;
            // RX checksum offload: if the NIC checked a checksum and it was
            // wrong, drop the frame; if it verified one as good, skip the
            // corresponding software check. When RX offload is off the
            // flags read UNKNOWN, so both fall back to software verify.
            if mbuf.rx_ip_cksum_bad() || mbuf.rx_l4_cksum_bad() {
                continue;
            }
            let ip_ok = mbuf.rx_ip_cksum_good();
            let l4_ok = mbuf.rx_l4_cksum_good();
            self.handle_frame(mbuf, ip_ok, l4_ok, now);
        }

        self.handle_gro(&mut burst[run_start..], now);
        self.flush_tx(port, pool, now);

        self.activate_due(now);

        // Process only the connections that need attention this poll.
        // Swap into retained scratch storage. Both phases visit the same
        // tuples; after TX, rescheduling separates runnable work from
        // future deadlines. Neither set's allocation is discarded.
        std::mem::swap(&mut self.active, &mut self.processing);

        // Phase 1: tick timers and drain events. Closed connections remain
        // until phase 2 has serialized any final reset.
        for &tuple in &self.processing {
            self.updated.push(tuple);
            let Some(conn) = self.connections.get_mut(&tuple) else {
                continue;
            };
            // `active` was swapped out: this connection is no longer in it.
            conn.active = false;
            conn.tcb.tick(now);
            let mut established = false;
            for ev in conn.tcb.events.drain(..) {
                established |= ev == Event::Established;
                events.push((tuple, ev));
            }
            if established && conn.accept == AcceptState::AwaitingHandshake {
                conn.accept = AcceptState::Queued;
                self.accept_queues
                    .entry(tuple.local_port)
                    .or_default()
                    .push_back(tuple);
            }
        }

        // Phase 2: build output for the connections still present, and
        // re-arm the active set for any that still need attention.
        //
        // Resolve next hops before consuming output, and cap production
        // by the available local transmit queue space.
        let tx_offload = port.tx_cksum_offload();
        let local_mss = port
            .mtu()
            .min(u32::from(pool.packet_capacity()).saturating_sub(eth::ETH_HDR_LEN as u32))
            .saturating_sub((ipv4::IPV4_HDR_LEN + tcp::TCP_HDR_LEN) as u32)
            .min(u16::MAX as u32) as u16;
        let output_budget = self.output_budget();
        let connections = &mut self.connections;
        let config = &self.config;
        let arp = &mut self.arp;
        for &tuple in &self.processing {
            let Some(conn) = connections.get_mut(&tuple) else {
                continue;
            };
            if !conn.tcb.has_pending_output() {
                if conn.tcb.is_closed() {
                    connections.remove(&tuple);
                }
                continue;
            }
            // Do not consume output until both resolution and bounded
            // local queue space are available. ARP replies are usable this poll.
            let room = MAX_PENDING_TX.saturating_sub(self.tx_batch.len() + self.pending_tx.len());
            #[cfg(feature = "tcp-metrics")]
            if conn.queued_tx != 0 {
                crate::dpdk::metrics::record(|m| m.queued_tx_skips += 1);
            }
            if conn.queued_tx != 0 || room == 0 {
                continue;
            }
            let Some(mac) = arp.resolve(config.next_hop(tuple.remote_ip), now) else {
                let since = match conn.next_hop {
                    NextHop::Resolving { since } => since,
                    NextHop::Resolved => {
                        conn.next_hop = NextHop::Resolving { since: now };
                        now
                    }
                };
                if now.saturating_duration_since(since) >= ARP_TIMEOUT {
                    connections.remove(&tuple);
                    events.push((tuple, Event::Reset));
                }
                continue;
            };
            conn.next_hop = NextHop::Resolved;
            conn.tcb.set_local_mss(local_mss);
            conn.tcb
                .set_tx_payload_limit(port.offloads().tso_max_payload);
            conn.tcb
                .poll_output_queued(now, &mut self.segments, room.min(output_budget));
            #[cfg(feature = "tcp-metrics")]
            crate::dpdk::metrics::record(|m| {
                let n = self.segments.len();
                if n > 0 {
                    m.output_batches[crate::dpdk::metrics::bucket(n)] += 1;
                }
                m.output_packets += n as u64;
                m.output_budget_exhausted +=
                    u64::from(n == room.min(output_budget) && conn.tcb.has_pending_output());
            });
            // A connection that closed is dropped below, so whatever it
            // just produced (a final reset) goes out unowned.
            let owned = !conn.tcb.is_closed();
            for seg in self.segments.drain(..) {
                if owned {
                    conn.queued_tx += 1;
                }
                self.pending_tx.push_back(PendingTcp {
                    tuple,
                    mac,
                    header: conn.tcb.to_header(&seg),
                    tso_mss: if seg.payload.len() > conn.tcb.send_mss() as usize {
                        conn.tcb.send_mss()
                    } else {
                        0
                    },
                    payload: seg.payload,
                    owned,
                });
            }
            if !owned {
                connections.remove(&tuple);
            }
        }

        for (dst_mac, dst_ip) in self.pending_arp_replies.drain(..) {
            if self.tx_batch.len() + self.pending_tx.len() >= MAX_PENDING_TX {
                break;
            }
            if let Some(mbuf) = build_arp_frame(
                pool,
                arp::OP_REPLY,
                self.config.local_mac,
                self.config.local_ip,
                dst_mac,
                dst_ip,
            ) {
                self.tx_batch.push(mbuf);
                self.tx_owners.push(None);
            }
        }
        for dst_ip in self.arp.drain_requests() {
            if self.tx_batch.len() + self.pending_tx.len() >= MAX_PENDING_TX {
                break;
            }
            if let Some(mbuf) = build_arp_frame(
                pool,
                arp::OP_REQUEST,
                self.config.local_mac,
                self.config.local_ip,
                EthAddr::BROADCAST,
                dst_ip,
            ) {
                self.tx_batch.push(mbuf);
                self.tx_owners.push(None);
            }
        }
        for (dst_mac, dst_ip, hdr) in self.pending_raw_resets.drain(..) {
            if self.tx_batch.len() + self.pending_tx.len() >= MAX_PENDING_TX {
                break;
            }
            if let Some(mbuf) = build_ip_tcp_frame(
                pool,
                self.config.local_mac,
                dst_mac,
                self.config.local_ip,
                dst_ip,
                &hdr,
                &Payload::default(),
                tx_offload,
                0,
            ) {
                self.tx_batch.push(mbuf);
                self.tx_owners.push(None);
            }
        }

        self.flush_tx(port, pool, now);
        // NIC acceptance can arm/restart RTO, so schedule only after TX.
        self.reschedule_processed(now);
        #[cfg(feature = "tcp-metrics")]
        crate::dpdk::metrics::record(|m| {
            m.engine_poll_ns += metrics_start.elapsed().as_nanos() as u64
        });
    }

    /// Takes ownership of every packet in `packets`.
    fn handle_gro(&mut self, packets: &mut [*mut crate::dpdk::ffi::rte_mbuf], now: Instant) {
        let count = packets.len();
        if count == 0 {
            return;
        }
        let merged = if count > 1 {
            unsafe { gro::merge(packets, count) }
        } else {
            count
        };
        for raw in &packets[..merged] {
            // SAFETY: GRO returns ownership of each complete output chain exactly once.
            let packet = unsafe { Mbuf::from_raw(*raw) };
            self.handle_frame(packet, true, true, now);
        }
    }

    fn activate_due(&mut self, now: Instant) {
        while let Some(tuple) = self.timers.pop_due(now) {
            self.active.insert(tuple);
        }
    }

    fn reschedule_processed(&mut self, _now: Instant) {
        for &tuple in &self.processing {
            self.active.remove(&tuple);
            let Some(conn) = self.connections.get_mut(&tuple) else {
                self.timers.remove(tuple);
                continue;
            };
            #[cfg(feature = "tcp-metrics")]
            conn.tcb.record_window_limits(_now);
            self.timers.set(tuple, conn.tcb.next_deadline());
            conn.active = conn.tcb.has_pending_output()
                || conn.queued_tx != 0
                || matches!(conn.next_hop, NextHop::Resolving { .. });
            if conn.active {
                self.active.insert(tuple);
            }
        }
        self.processing.clear();
    }

    /// Packets discarded because the port refused them for longer than
    /// [`TX_STALL_TIMEOUT`]. Non-zero means the port stopped accepting
    /// packets for a while or rejects a kind of packet the engine builds.
    pub fn tx_dropped(&self) -> u64 {
        self.tx_dropped
    }

    /// Packets retained locally awaiting pool space or NIC acceptance.
    pub fn pending_tx_len(&self) -> usize {
        self.tx_batch.len() + self.pending_tx.len()
    }

    /// Connections processed during the most recent engine poll.
    pub fn updated_connections(&self) -> &[FourTuple] {
        &self.updated
    }

    fn flush_tx(&mut self, port: &EthPort, pool: &Mempool, now: Instant) {
        #[cfg(feature = "tcp-metrics")]
        crate::dpdk::metrics::record(|m| {
            m.pending_tx_peak = m.pending_tx_peak.max(self.pending_tx_len() as u64)
        });
        while let Some(packet) = self.pending_tx.front() {
            #[cfg(feature = "tcp-metrics")]
            let metrics_start = Instant::now();
            let built = build_ip_tcp_frame_external(
                pool,
                self.config.local_mac,
                packet.mac,
                packet.tuple.local_ip,
                packet.tuple.remote_ip,
                &packet.header,
                &packet.payload,
                port.tx_cksum_offload(),
                packet.tso_mss,
                port.offloads().tx_max_segments,
            );
            #[cfg(feature = "tcp-metrics")]
            crate::dpdk::metrics::record(|m| {
                m.packet_build_calls += 1;
                m.packet_build_failures += u64::from(built.is_none());
                m.packet_build_ns += metrics_start.elapsed().as_nanos() as u64;
            });
            let Some(mbuf) = built else {
                break;
            };
            self.tx_owners.push(
                packet
                    .owned
                    .then(|| (packet.tuple, Seq::new(packet.header.seq))),
            );
            self.tx_batch.push(mbuf);
            self.pending_tx.pop_front();
        }
        let before = self.tx_batch.len();
        if before == 0 {
            return;
        }
        port.tx_burst_in_place(&mut self.tx_batch);
        let sent = before - self.tx_batch.len();
        // A burst is mostly runs of one connection's packets: look the
        // connection up once per run rather than once per packet.
        let mut owners = self.tx_owners.drain(..sent).flatten().peekable();
        while let Some((tuple, seq)) = owners.next() {
            // An owned packet's connection is still tracked: `abort`
            // discards a connection's queued packets along with it.
            let Some(conn) = self.connections.get_mut(&tuple) else {
                continue;
            };
            conn.tcb.mark_transmitted(seq, now);
            conn.queued_tx = conn.queued_tx.saturating_sub(1);
            while let Some((_, seq)) = owners.next_if(|(next, _)| *next == tuple) {
                conn.tcb.mark_transmitted(seq, now);
                conn.queued_tx = conn.queued_tx.saturating_sub(1);
            }
        }
        drop(owners);
        // The unaccepted suffix and its ownership metadata remain for retry.
        if sent > 0 || self.tx_batch.is_empty() {
            self.tx_stalled_since = None;
            return;
        }
        // A full transmit ring clears within a few polls. A port that keeps
        // refusing the same head packet either cannot send at all or
        // rejects that packet in particular (a driver that will not take
        // its offload request, say), and retrying would block every
        // connection behind it forever. Treat the packet as lost on the
        // wire instead: free it and start its retransmission timer, so TCP
        // resends it or, failing that, resets the connection and reports
        // the error. Dropping continues one packet per poll until the port
        // accepts something again.
        let since = *self.tx_stalled_since.get_or_insert(now);
        if now.saturating_duration_since(since) >= TX_STALL_TIMEOUT {
            drop(self.tx_batch.remove(0));
            self.tx_dropped += 1;
            if let Some(owner) = self.tx_owners.remove(0) {
                Self::transmitted(&mut self.connections, owner, now);
            }
        }
    }

    /// A queued packet left the engine, accepted by the port or given up
    /// on: either way its retransmission timer runs from now.
    fn transmitted(
        connections: &mut HashMap<FourTuple, Conn>,
        (tuple, seq): (FourTuple, Seq),
        now: Instant,
    ) {
        // An owned packet's connection is still tracked: `abort`
        // discards a connection's queued packets along with it.
        if let Some(conn) = connections.get_mut(&tuple) {
            conn.tcb.mark_transmitted(seq, now);
            conn.queued_tx = conn.queued_tx.saturating_sub(1);
        }
    }

    /// `ip_ok`/`l4_ok` report that the NIC already verified the IPv4 /
    /// TCP checksum on RX, so software verification can be skipped.
    /// Parse the owned mbuf by borrowing it. Only accepted TCP data is
    /// converted into shared Bytes ownership; control and dropped packets
    /// return directly to the pool without allocating an owner record.
    fn handle_frame(&mut self, mbuf: Mbuf, ip_ok: bool, l4_ok: bool, now: Instant) {
        let frame = mbuf.data();
        let Some(eth_hdr) = eth::EthHeader::parse(frame) else {
            return;
        };
        match eth_hdr.ethertype {
            arp::ETHERTYPE_ARP => self.handle_arp(&frame[eth::ETH_HDR_LEN..], now),
            eth::ETHERTYPE_IPV4 => self.handle_ipv4(mbuf, ip_ok, l4_ok, now),
            _ => {}
        }
    }

    fn handle_arp(&mut self, buf: &[u8], now: Instant) {
        let Some(pkt) = arp::ArpPacket::parse(buf) else {
            return;
        };
        let for_us = pkt.target_ip == self.config.local_ip;
        self.arp.learn(pkt.sender_ip, pkt.sender_mac, for_us, now);
        if pkt.operation == arp::OP_REQUEST && for_us && !pkt.sender_ip.is_unspecified() {
            self.pending_arp_replies
                .push((pkt.sender_mac, pkt.sender_ip));
        }
    }

    fn handle_ipv4(&mut self, mbuf: Mbuf, ip_ok: bool, l4_ok: bool, now: Instant) {
        let buf = &mbuf.data()[eth::ETH_HDR_LEN..];
        let Some(ip_hdr) = ipv4::Ipv4Header::parse(buf, !ip_ok) else {
            return;
        };
        if ip_hdr.protocol != ipv4::PROTO_TCP || ip_hdr.dst != self.config.local_ip {
            return;
        }
        let total_len = ip_hdr.total_length as usize;
        if total_len + eth::ETH_HDR_LEN > mbuf.pkt_len() as usize
            || ip_hdr.flags_fragment_offset & 0x3fff != 0
        {
            return;
        }
        if total_len < ipv4::IPV4_HDR_LEN {
            return;
        }
        let ip_payload = &buf[ipv4::IPV4_HDR_LEN..total_len.min(buf.len())];
        let chained = mbuf.pkt_len() as usize != mbuf.data().len();
        if chained && !l4_ok {
            let seed = super::super::net::checksum::ipv4_pseudo_header_sum(
                ip_hdr.src,
                ip_hdr.dst,
                ipv4::PROTO_TCP,
                (total_len - ipv4::IPV4_HDR_LEN) as u16,
            );
            if super::super::net::checksum::fold(mbuf.checksum_sum(34, total_len - 20, seed)) != 0 {
                return;
            }
        }
        let Some((tcp_hdr, hdr_len)) =
            tcp::TcpHeader::parse(ip_payload, ip_hdr.src, ip_hdr.dst, !l4_ok && !chained)
        else {
            return;
        };
        let payload_len = total_len - ipv4::IPV4_HDR_LEN - hdr_len;

        let tuple = FourTuple {
            local_ip: self.config.local_ip,
            local_port: tcp_hdr.dst_port,
            remote_ip: ip_hdr.src,
            remote_port: tcp_hdr.src_port,
        };

        if let Some(conn) = self.connections.get_mut(&tuple) {
            let start = eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN + hdr_len;
            let end = eth::ETH_HDR_LEN + total_len;
            conn.tcb.on_segment_rx(
                &tcp_hdr,
                payload_len,
                || {
                    let mut skip = start;
                    let mut remaining = end - start;
                    mbuf.into_segments().filter_map(move |segment| {
                        let len = segment.data_len() as usize;
                        if skip >= len {
                            skip -= len;
                            return None;
                        }
                        let n = remaining.min(len - skip);
                        if n == 0 {
                            return None;
                        }
                        let chunk = Chunk::packet(segment, skip, n);
                        skip = 0;
                        remaining -= n;
                        Some(chunk)
                    })
                },
                now,
            );
            // The segment may have produced an ACK/data to send, an event,
            // or a state change -- process it next poll.
            Self::mark_active(&mut self.active, conn, tuple);
            if conn.tcb.is_closed() {
                self.discard_queued(tuple);
            }
            return;
        }

        let is_bare_syn = tcp_hdr.has_flag(tcp::flags::SYN) && !tcp_hdr.has_flag(tcp::flags::ACK);
        if is_bare_syn && self.listeners.contains(&tcp_hdr.dst_port) {
            let peer_mss = tcp_hdr.options.mss.unwrap_or(536);
            let mut tcb = Tcb::new_from_listen(tuple, Seq::new(tcp_hdr.seq), peer_mss);
            tcb.set_peer_scale(tcp_hdr.options.window_scale);
            tcb.set_peer_sack(tcp_hdr.options.sack_permitted);
            // Has a SYN-ACK to send.
            let mut conn = Conn::new(tcb, AcceptState::AwaitingHandshake);
            Self::mark_active(&mut self.active, &mut conn, tuple);
            self.connections.insert(tuple, conn);
            return;
        }

        // RFC 9293 §3.10.7.1: a segment addressed to no listener/connection
        // gets reset, unless it's an RST itself (which would just loop).
        if !tcp_hdr.has_flag(tcp::flags::RST) {
            self.send_reset_for_unknown(&tcp_hdr, payload_len, ip_hdr.src, now);
        }
    }

    fn send_reset_for_unknown(
        &mut self,
        hdr: &tcp::TcpHeader,
        payload_len: usize,
        remote_ip: Ipv4Addr,
        now: Instant,
    ) {
        // A stray RST-worthy segment doesn't own retransmission/ARP
        // queuing machinery the way a Tcb does; if the next hop's MAC isn't
        // known yet, just drop it -- RSTs are best-effort.
        let next_hop = self.config.next_hop(remote_ip);
        let Some(remote_mac) = self.arp.resolve(next_hop, now) else {
            return; // resolution requested; this reset is dropped
        };
        // RFC 9293 §3.10.7.1: if the incoming segment has ACK set, the
        // reset's sequence number is that ACK value with no ACK of its
        // own; otherwise the reset acks the incoming segment's end.
        let (seq, ack, flags) = if hdr.has_flag(tcp::flags::ACK) {
            (hdr.ack, 0u32, tcp::flags::RST)
        } else {
            let seg_len = payload_len as u32
                + if hdr.has_flag(tcp::flags::SYN) || hdr.has_flag(tcp::flags::FIN) {
                    1
                } else {
                    0
                };
            (
                0,
                hdr.seq.wrapping_add(seg_len),
                tcp::flags::RST | tcp::flags::ACK,
            )
        };
        let response_hdr = tcp::TcpHeader {
            src_port: hdr.dst_port,
            dst_port: hdr.src_port,
            seq,
            ack,
            flags,
            window: 0,
            urgent_pointer: 0,
            options: tcp::TcpOptions::default(),
        };
        self.pending_raw_resets
            .push((remote_mac, remote_ip, response_hdr));
    }
}

fn external_segment_count(payload: &Payload, max_segments: usize) -> Option<usize> {
    let mut count = 1; // writable header
    for chunk in payload.chunks() {
        let mut data = &chunk[..];
        while !data.is_empty() {
            let (n, _) = Mbuf::dma_prefix(data)?;
            count += 1;
            if count > max_segments {
                return None;
            }
            data = &data[n..];
        }
    }
    Some(count)
}

#[allow(clippy::too_many_arguments)]
fn build_ip_tcp_frame(
    pool: &Mempool,
    local_mac: EthAddr,
    remote_mac: EthAddr,
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    tcp_hdr: &tcp::TcpHeader,
    payload: &Payload,
    tx_cksum_offload: bool,
    tso_mss: u16,
) -> Option<Mbuf> {
    build_ip_tcp_frame_external(
        pool,
        local_mac,
        remote_mac,
        local_ip,
        remote_ip,
        tcp_hdr,
        payload,
        tx_cksum_offload,
        tso_mss,
        1,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_ip_tcp_frame_external(
    pool: &Mempool,
    local_mac: EthAddr,
    remote_mac: EthAddr,
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    tcp_hdr: &tcp::TcpHeader,
    payload: &Payload,
    tx_cksum_offload: bool,
    tso_mss: u16,
    max_segments: usize,
) -> Option<Mbuf> {
    let tcp_len = tcp_hdr.wire_len();
    let total_len = eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN + tcp_len + payload.len();

    // External attachment is all-or-nothing: unsupported memory or too many
    // DMA ranges uses the established copying path instead of stalling TX.
    if max_segments > 1
        && !payload.is_empty()
        && external_segment_count(payload, max_segments).is_some()
    {
        let mut head = Mbuf::alloc(pool)?;
        let header_len = eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN + tcp_len;
        let buf = head.append(header_len as u16)?;
        eth::EthHeader {
            dst: remote_mac,
            src: local_mac,
            ethertype: eth::ETHERTYPE_IPV4,
        }
        .write(buf);
        ipv4::Ipv4Header {
            dscp_ecn: 0,
            total_length: (total_len - 14) as u16,
            identification: 0,
            flags_fragment_offset: 0x4000,
            ttl: 64,
            protocol: ipv4::PROTO_TCP,
            src: local_ip,
            dst: remote_ip,
        }
        .write(&mut buf[14..34], tx_cksum_offload);
        tcp_hdr.write(&mut buf[34..], &[], local_ip, remote_ip, true);
        let seed = super::super::net::checksum::ipv4_pseudo_header_sum(
            local_ip,
            remote_ip,
            ipv4::PROTO_TCP,
            if tso_mss != 0 {
                0
            } else {
                (tcp_len + payload.len()) as u16
            },
        );
        let csum = if tx_cksum_offload {
            super::super::net::checksum::fold_raw(seed)
        } else {
            buf[50..52].fill(0);
            payload.checksum_sum(super::super::net::checksum::sum16(&buf[34..], seed))
        };
        buf[50..52].copy_from_slice(&csum.to_be_bytes());
        for chunk in payload.chunks() {
            let mut start = 0;
            while start < chunk.len() {
                let (n, _) = Mbuf::dma_prefix(&chunk[start..])?;
                let tail = Mbuf::from_external_bytes(pool, chunk.slice(start..start + n))?;
                head.chain(tail).ok()?;
                start += n;
            }
        }
        if tso_mss != 0 {
            head.set_tx_tso(tcp_len as u16, tso_mss);
        } else if tx_cksum_offload {
            head.set_tx_ipv4_tcp_cksum(14, 20);
        }
        return Some(head);
    }

    if tso_mss != 0 {
        let mut head = Mbuf::alloc(pool)?;
        let header_len = eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN + tcp_len;
        let buf = head.append(header_len as u16)?;
        eth::EthHeader {
            dst: remote_mac,
            src: local_mac,
            ethertype: eth::ETHERTYPE_IPV4,
        }
        .write(buf);
        ipv4::Ipv4Header {
            dscp_ecn: 0,
            total_length: (total_len - eth::ETH_HDR_LEN) as u16,
            identification: 0,
            flags_fragment_offset: 0x4000,
            ttl: 64,
            protocol: ipv4::PROTO_TCP,
            src: local_ip,
            dst: remote_ip,
        }
        .write(&mut buf[14..34], true);
        tcp_hdr.write(&mut buf[34..], &[], local_ip, remote_ip, true);
        // TSO pseudo header excludes length: the device adds each wire segment's length.
        let seed = super::super::net::checksum::ipv4_pseudo_header_sum(
            local_ip,
            remote_ip,
            ipv4::PROTO_TCP,
            0,
        );
        buf[50..52].copy_from_slice(&super::super::net::checksum::fold_raw(seed).to_be_bytes());
        // Fill pool-backed segments once; never flatten the payload into a temporary buffer.
        let mut tail = Mbuf::alloc(pool)?;
        for chunk in payload.chunks() {
            let mut data = &chunk[..];
            while !data.is_empty() {
                if tail.tailroom() == 0 {
                    head.chain(tail).ok()?;
                    tail = Mbuf::alloc(pool)?;
                }
                let n = data.len().min(tail.tailroom() as usize);
                tail.append(n as u16)?.copy_from_slice(&data[..n]);
                data = &data[n..];
            }
        }
        head.chain(tail).ok()?;
        head.set_tx_tso(tcp_len as u16, tso_mss);
        return Some(head);
    }

    let mut mbuf = Mbuf::alloc(pool)?;
    mbuf.reset();
    let buf = mbuf.append(total_len as u16)?;

    let eth_hdr = eth::EthHeader {
        dst: remote_mac,
        src: local_mac,
        ethertype: eth::ETHERTYPE_IPV4,
    };
    eth_hdr.write(&mut buf[..eth::ETH_HDR_LEN]);

    let ip_start = eth::ETH_HDR_LEN;
    let ip_end = ip_start + ipv4::IPV4_HDR_LEN;
    let ip_hdr = ipv4::Ipv4Header {
        dscp_ecn: 0,
        total_length: (ipv4::IPV4_HDR_LEN + tcp_len + payload.len()) as u16,
        identification: 0,
        flags_fragment_offset: 0x4000, // Don't Fragment
        ttl: 64,
        protocol: ipv4::PROTO_TCP,
        src: local_ip,
        dst: remote_ip,
    };

    let tcp_start = ip_end;
    let tcp_end = tcp_start + tcp_len;
    payload.copy_to(&mut buf[tcp_end..tcp_end + payload.len()]);
    {
        let (ip_and_before, rest) = buf.split_at_mut(tcp_start);
        // With TX checksum offload the NIC fills the IPv4 checksum and
        // completes the TCP checksum; we write only the TCP pseudo-header
        // checksum and a zero IPv4 checksum, and tag the mbuf below.
        let (tcp_header, wire_payload) = rest.split_at_mut(tcp_len);
        tcp_hdr.write(
            tcp_header,
            wire_payload,
            local_ip,
            remote_ip,
            tx_cksum_offload,
        );
        ip_hdr.write(&mut ip_and_before[ip_start..ip_end], tx_cksum_offload);
    }

    if tx_cksum_offload {
        mbuf.set_tx_ipv4_tcp_cksum(eth::ETH_HDR_LEN as u16, ipv4::IPV4_HDR_LEN as u16);
    }

    Some(mbuf)
}

fn build_arp_frame(
    pool: &Mempool,
    operation: u16,
    local_mac: EthAddr,
    local_ip: Ipv4Addr,
    dst_mac: EthAddr,
    dst_ip: Ipv4Addr,
) -> Option<Mbuf> {
    let total_len = eth::ETH_HDR_LEN + arp::ARP_HDR_LEN;
    let mut mbuf = Mbuf::alloc(pool)?;
    mbuf.reset();
    let buf = mbuf.append(total_len as u16)?;

    let eth_hdr = eth::EthHeader {
        dst: dst_mac,
        src: local_mac,
        ethertype: arp::ETHERTYPE_ARP,
    };
    eth_hdr.write(&mut buf[..eth::ETH_HDR_LEN]);

    let arp_pkt = arp::ArpPacket {
        operation,
        sender_mac: local_mac,
        sender_ip: local_ip,
        target_mac: if operation == arp::OP_REQUEST {
            EthAddr::ZERO
        } else {
            dst_mac
        },
        target_ip: dst_ip,
    };
    arp_pkt.write(&mut buf[eth::ETH_HDR_LEN..]);

    Some(mbuf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(local: &str, gateway: Option<&str>) -> EngineConfig {
        EngineConfig::from_cli(EthAddr::ZERO, local, gateway).unwrap()
    }

    #[test]
    fn larger_budget_shares_queue_space_and_preserves_unsent_data() {
        let now = Instant::now();
        let mut engine = TcpEngine::new(EngineConfig::default());
        engine.set_tx_budget(std::num::NonZeroU16::new(256).unwrap());
        for port in 1000..1008 {
            let (mut tcb, _) = established_tcb(port, now);
            tcb.set_nodelay(true);
            // Open enough congestion/receive window for a meaningful budget
            // test by acknowledging each warmup flight.
            for _ in 0..20 {
                tcb.send(Bytes::from(vec![0; 4096]));
                let output = tcb.poll_output(now);
                let last = output.last().unwrap();
                let ack = tcp::TcpHeader {
                    src_port: 80,
                    dst_port: port,
                    seq: 101,
                    ack: (last.seq + last.payload.len() as u32).0,
                    flags: tcp::flags::ACK,
                    window: u16::MAX,
                    urgent_pointer: 0,
                    options: tcp::TcpOptions::default(),
                };
                tcb.on_segment(&ack, Bytes::new(), now);
            }
            tcb.send(Bytes::from(vec![0; 100_000]));
            let tuple = tcb.tuple;
            engine
                .connections
                .insert(tuple, Conn::new(tcb, AcceptState::NotApplicable));
            engine.processing.insert(tuple);
        }
        let budget = engine.output_budget();
        let mut total = 0;
        for conn in engine.connections.values_mut() {
            let mut output = Vec::new();
            conn.tcb.poll_output_queued(now, &mut output, budget);
            assert_eq!(output.len(), 32);
            total += output.len();
            assert!(conn.tcb.has_pending_output());
            assert_eq!(conn.tcb.buffered_send_bytes(), 100_000);
        }
        assert_eq!(total, MAX_PENDING_TX);
    }

    fn established_tcb(port: u16, now: Instant) -> (Tcb, tcp::TcpHeader) {
        let tuple = FourTuple {
            local_ip: Ipv4Addr::new(10, 0, 0, 1),
            local_port: port,
            remote_ip: Ipv4Addr::new(10, 0, 0, 2),
            remote_port: 80,
        };
        let mut tcb = Tcb::new_active(tuple);
        let syn = tcb.poll_output(now).remove(0);
        let mut peer = tcp::TcpHeader {
            src_port: 80,
            dst_port: port,
            seq: 100,
            ack: syn.seq.0.wrapping_add(1),
            flags: tcp::flags::SYN | tcp::flags::ACK,
            window: u16::MAX,
            urgent_pointer: 0,
            options: tcp::TcpOptions::default(),
        };
        tcb.on_segment(&peer, Bytes::new(), now);
        tcb.poll_output(now);
        peer.seq += 1;
        peer.flags = tcp::flags::ACK;
        (tcb, peer)
    }

    fn schedule_tcb(engine: &mut TcpEngine, tcb: Tcb) -> FourTuple {
        let tuple = tcb.tuple;
        engine
            .connections
            .insert(tuple, Conn::new(tcb, AcceptState::NotApplicable));
        engine.processing.insert(tuple);
        engine.reschedule_processed(Instant::now());
        tuple
    }

    #[test]
    fn native_chains_tso_and_gro_preserve_payload_and_reclaim_pool() {
        use crate::dpdk::net::checksum;
        use crate::dpdk::{eal, ffi};
        let cpu = unsafe { libc::sched_getcpu() };
        eal::init(&[
            "offload-test",
            "--no-huge",
            "--no-pci",
            "--no-shconf",
            "--no-telemetry",
            "--lcores",
            &format!("0@{cpu}"),
        ])
        .unwrap();
        {
            let pool = Mempool::create("offload-test", 1023, 0, 2176, -1).unwrap();
            let available = || unsafe { ffi::rte_mempool_avail_count(pool.as_raw()) };
            let baseline = available();
            let now = Instant::now();
            let (tcb, peer) = established_tcb(1234, now);
            let mut header = peer.clone();
            header.flags = tcp::flags::ACK;
            // The packet chain must point at the application's original DMA
            // bytes, including odd fragment boundaries, in both normal and TSO TX.
            let mut dma = crate::dpdk::DmaBuffer::new(8193).unwrap();
            for (i, b) in dma.as_mut_slice().iter_mut().enumerate() {
                *b = (i % 251) as u8;
            }
            let dma = dma.freeze();
            let mut queue = super::super::tx_queue::SendBuffer::default();
            queue.push(dma.slice(..1001));
            queue.push(dma.slice(1001..3002));
            queue.push(dma.slice(3002..));
            let external = queue.take(dma.len());
            for tso in [0, 1460] {
                let packet = build_ip_tcp_frame_external(
                    &pool,
                    EthAddr::ZERO,
                    EthAddr::ZERO,
                    tcb.tuple.remote_ip,
                    tcb.tuple.local_ip,
                    &header,
                    &external,
                    tso != 0,
                    tso,
                    32,
                )
                .unwrap();
                let mut offset = 0;
                for segment in packet.segments().skip(1) {
                    assert_eq!(
                        segment.as_ptr(),
                        dma[offset..].as_ptr(),
                        "payload was copied"
                    );
                    offset += segment.len();
                }
                assert_eq!(offset, dma.len());
                let wire: Vec<u8> = packet.segments().flatten().copied().collect();
                assert_eq!(&wire[54..], &dma[..]);
                if tso == 0 {
                    assert!(
                        tcp::TcpHeader::parse(
                            &wire[34..],
                            tcb.tuple.remote_ip,
                            tcb.tuple.local_ip,
                            true
                        )
                        .is_some(),
                        "software checksum must span odd-sized external fragments"
                    );
                }
                drop(packet);
                assert_eq!(available(), baseline);
            }
            assert!(external_segment_count(&external, 1).is_none());
            let fallback = build_ip_tcp_frame_external(
                &pool,
                EthAddr::ZERO,
                EthAddr::ZERO,
                tcb.tuple.remote_ip,
                tcb.tuple.local_ip,
                &header,
                &external,
                true,
                1460,
                1,
            )
            .unwrap();
            assert_ne!(fallback.segments().nth(1).unwrap().as_ptr(), dma.as_ptr());
            drop(fallback);
            drop(external);
            drop(dma);
            assert_eq!(available(), baseline);

            let payload = Payload::from(Bytes::from(vec![42; 8193]));
            let packet = build_ip_tcp_frame(
                &pool,
                EthAddr::ZERO,
                EthAddr::ZERO,
                tcb.tuple.remote_ip,
                tcb.tuple.local_ip,
                &header,
                &payload,
                true,
                1460,
            )
            .unwrap();
            assert_eq!(packet.pkt_len(), 8193 + 54);
            assert!(packet.segments().count() > 1);
            assert!(packet.ol_flags() & ffi::RTE_MBUF_F_TX_TCP_SEG != 0);
            let wire: Vec<u8> = packet.segments().flatten().copied().collect();
            assert_eq!(&wire[54..], vec![42; 8193]);
            assert_eq!(
                u16::from_be_bytes([wire[50], wire[51]]),
                checksum::fold_raw(checksum::ipv4_pseudo_header_sum(
                    tcb.tuple.remote_ip,
                    tcb.tuple.local_ip,
                    ipv4::PROTO_TCP,
                    0
                ))
            );
            // Simulate the device's segmentation and checksum completion.
            for (index, data) in wire[54..].chunks(1460).enumerate() {
                let mut h = header.clone();
                h.seq += (index * 1460) as u32;
                let mut segment = vec![0; 20 + data.len()];
                h.write(
                    &mut segment[..20],
                    data,
                    tcb.tuple.remote_ip,
                    tcb.tuple.local_ip,
                    false,
                );
                segment[20..].copy_from_slice(data);
                assert!(
                    tcp::TcpHeader::parse(&segment, tcb.tuple.remote_ip, tcb.tuple.local_ip, true)
                        .is_some()
                );
            }
            // Early iterator drop must free the unconsumed chain too.
            let mut segments = packet.into_segments();
            drop(segments.next());
            drop(segments);
            assert_eq!(available(), baseline);

            let mut engine = TcpEngine::new(EngineConfig {
                local_ip: tcb.tuple.local_ip,
                local_mac: EthAddr::ZERO,
                gateway: None,
            });
            let tuple = schedule_tcb(&mut engine, tcb);
            let mut raw = [std::ptr::null_mut(); 3];
            for (i, slot) in raw.iter_mut().enumerate() {
                let data = Payload::from(Bytes::from(vec![i as u8; 1001]));
                header.seq = peer.seq + (i * 1001) as u32;
                let mut packet = build_ip_tcp_frame(
                    &pool,
                    EthAddr::ZERO,
                    EthAddr::ZERO,
                    tuple.remote_ip,
                    tuple.local_ip,
                    &header,
                    &data,
                    false,
                    0,
                )
                .unwrap();
                assert!(gro::prepare(&mut packet));
                *slot = packet.into_raw();
            }
            let count = unsafe { gro::merge(&mut raw, 3) };
            assert_eq!(
                count, 1,
                "contiguous packets must merge within the RX burst"
            );
            let packet = unsafe { Mbuf::from_raw(raw[0]) };
            assert_eq!(packet.pkt_len(), 54 + 3003);
            engine.handle_frame(packet, true, true, now);
            use crate::dpdk::tcp::stream::TcpStream;
            use crate::dpdk::tcp::worker::InboundMessage;
            use std::pin::Pin;
            use std::task::{Context, Poll, Waker};
            use tokio::io::{AsyncRead, ReadBuf};

            let (mut stream, _commands, inbound, _) = TcpStream::test_stream();
            engine.recv_each_chunk(tuple, usize::MAX, |chunk| {
                assert!(matches!(chunk, Chunk::Packet { .. }));
                assert!(inbound.push(InboundMessage::Data(chunk)).is_ok());
                true
            });
            let mut cx = Context::from_waker(Waker::noop());
            // Cross a segment boundary and leave a suffix of the second
            // mbuf staged. Borrowed reads must not allocate a Bytes owner.
            let mut storage = [0; 1500];
            let mut buf = ReadBuf::new(&mut storage);
            let (result, allocations) = crate::allocations::count_allocations(|| {
                Pin::new(&mut stream).poll_read(&mut cx, &mut buf)
            });
            assert!(matches!(result, Poll::Ready(Ok(()))));
            assert_eq!(allocations, 0);
            assert_eq!(buf.filled().len(), 1500);
            assert!(buf.filled()[..1001].iter().all(|&byte| byte == 0));
            assert!(buf.filled()[1001..].iter().all(|&byte| byte == 1));
            assert_eq!(available(), baseline - 2);

            // An owned read of the staged suffix makes one Bytes owner.
            let (result, allocations) =
                crate::allocations::count_allocations(|| stream.poll_recv(&mut cx));
            let Poll::Ready(Ok(Some(suffix))) = result else {
                panic!("expected the staged suffix");
            };
            assert_eq!(allocations, 1);
            assert_eq!(suffix.len(), 502);
            assert!(suffix.iter().all(|&byte| byte == 1));
            let slice = suffix.slice(1..);
            drop(suffix);
            assert_eq!(available(), baseline - 2);
            std::thread::spawn(move || drop(slice)).join().unwrap();
            assert_eq!(available(), baseline - 1);

            // Abandoning an unread ring entry returns its mbuf too.
            drop(inbound);
            drop(stream);
            assert_eq!(available(), baseline);

            // Corrupted payloads are never eligible for GRO or accepted by TCP.
            let data = Payload::from(Bytes::from_static(b"corrupt"));
            header.seq = peer.seq + 3003;
            let mut packet = build_ip_tcp_frame(
                &pool,
                EthAddr::ZERO,
                EthAddr::ZERO,
                tuple.remote_ip,
                tuple.local_ip,
                &header,
                &data,
                false,
                0,
            )
            .unwrap();
            packet.data_mut()[54] ^= 1;
            assert!(!gro::prepare(&mut packet));
            engine.handle_frame(packet, false, false, now);
            assert_eq!(engine.readable_len(tuple), 0);
            assert_eq!(available(), baseline);
        }
        eal::cleanup();
    }

    #[test]
    fn three_hundred_time_wait_connections_do_no_work_until_due() {
        let now = Instant::now();
        let mut engine = TcpEngine::new(EngineConfig::default());
        let mut deadline = now;
        for port in 1000..1300 {
            let (mut tcb, mut peer) = established_tcb(port, now);
            tcb.close();
            let fin = tcb.poll_output(now).remove(0);
            peer.ack = fin.seq.0.wrapping_add(1);
            peer.flags |= tcp::flags::FIN;
            tcb.on_segment(&peer, Bytes::new(), now);
            tcb.poll_output(now); // final ACK
            assert_eq!(tcb.state, TcpState::TimeWait);
            deadline = tcb.next_deadline().unwrap();
            schedule_tcb(&mut engine, tcb);
        }
        assert!(engine.active.is_empty());
        for _ in 0..1000 {
            engine.activate_due(deadline - Duration::from_nanos(1));
            assert!(
                engine.active.is_empty(),
                "future timers must not enter either poll phase"
            );
        }
        engine.activate_due(deadline);
        assert_eq!(engine.active.len(), 300);
        for tuple in &engine.active {
            let conn = engine.connections.get_mut(tuple).unwrap();
            conn.tcb.tick(deadline);
            assert!(conn.tcb.is_closed());
        }
    }

    #[test]
    fn retransmitted_fin_moves_time_wait_deadline_without_stale_wakeup() {
        let now = Instant::now();
        let mut engine = TcpEngine::new(EngineConfig::default());
        let (mut tcb, mut peer) = established_tcb(1234, now);
        tcb.close();
        let fin = tcb.poll_output(now).remove(0);
        peer.ack = fin.seq.0.wrapping_add(1);
        peer.flags |= tcp::flags::FIN;
        tcb.on_segment(&peer, Bytes::new(), now);
        tcb.poll_output(now);
        let old_deadline = tcb.next_deadline().unwrap();
        let tuple = schedule_tcb(&mut engine, tcb);
        let later = now + Duration::from_secs(1);
        let conn = engine.connections.get_mut(&tuple).unwrap();
        conn.tcb.on_segment(&peer, Bytes::new(), later);
        conn.tcb.poll_output(later);
        let new_deadline = conn.tcb.next_deadline().unwrap();
        assert!(new_deadline > old_deadline);
        TcpEngine::mark_active(
            &mut engine.active,
            engine.connections.get_mut(&tuple).unwrap(),
            tuple,
        );
        engine.processing.insert(tuple);
        engine.reschedule_processed(Instant::now());
        engine.activate_due(old_deadline);
        assert!(engine.active.is_empty());
        engine.activate_due(new_deadline);
        assert!(engine.active.contains(&tuple));
    }

    #[test]
    fn retransmit_and_persist_sleep_until_their_deadline() {
        let now = Instant::now();
        for persist in [false, true] {
            let mut engine = TcpEngine::new(EngineConfig::default());
            let (mut tcb, mut peer) = established_tcb(1234, now);
            if persist {
                peer.window = 0;
                tcb.on_segment(&peer, Bytes::new(), now);
            }
            tcb.send(Bytes::from_static(b"payload"));
            tcb.poll_output(now);
            let deadline = tcb.next_deadline().unwrap();
            let tuple = schedule_tcb(&mut engine, tcb);
            assert!(engine.active.is_empty());
            engine.activate_due(deadline - Duration::from_nanos(1));
            assert!(engine.active.is_empty());
            engine.activate_due(deadline);
            assert!(engine.active.contains(&tuple));
            let conn = engine.connections.get_mut(&tuple).unwrap();
            conn.tcb.tick(deadline);
            assert!(!conn.tcb.poll_output(deadline).is_empty());
        }
    }

    #[test]
    fn packet_activity_cancels_old_deadline_and_abort_cannot_wake_reused_tuple() {
        let now = Instant::now();
        let mut engine = TcpEngine::new(EngineConfig::default());
        let (mut tcb, mut peer) = established_tcb(1234, now);
        tcb.send(Bytes::from_static(b"payload"));
        let packet = tcb.poll_output(now).remove(0);
        let deadline = tcb.next_deadline().unwrap();
        let tuple = schedule_tcb(&mut engine, tcb);
        peer.ack = (packet.seq + packet.payload.len() as u32).0;
        engine
            .connections
            .get_mut(&tuple)
            .unwrap()
            .tcb
            .on_segment(&peer, Bytes::new(), now);
        TcpEngine::mark_active(
            &mut engine.active,
            engine.connections.get_mut(&tuple).unwrap(),
            tuple,
        );
        engine.processing.insert(tuple);
        engine.reschedule_processed(Instant::now());
        engine.activate_due(deadline);
        assert!(engine.active.is_empty());
        // An aborted timer must not later activate a new connection with the same tuple.
        engine.timers.set(tuple, Some(deadline));
        engine.abort(tuple);
        let (tcb, _) = established_tcb(1234, now);
        schedule_tcb(&mut engine, tcb);
        engine.activate_due(deadline);
        assert!(engine.active.is_empty());
    }

    #[test]
    fn connect_refuses_a_tuple_that_is_already_tracked() {
        let mut engine = TcpEngine::new(EngineConfig {
            local_ip: Ipv4Addr::new(10, 0, 1, 25),
            local_mac: EthAddr::ZERO,
            gateway: None,
        });
        let peer = Ipv4Addr::new(10, 0, 1, 99);
        let tuple = engine.connect(peer, 80, 50000).expect("first connect");
        assert_eq!(engine.connections_opened(), 1);
        assert!(engine.state(tuple).is_some());

        // Same 4-tuple again: refused, existing connection untouched.
        assert_eq!(engine.connect(peer, 80, 50000), None);
        assert_eq!(engine.connections_opened(), 1);
        assert_eq!(engine.state(tuple), Some(TcpState::SynSent));

        // A different local port or remote port is a distinct tuple.
        assert!(engine.connect(peer, 80, 50001).is_some());
        assert!(engine.connect(peer, 81, 50000).is_some());
        assert_eq!(engine.connections_opened(), 3);
    }

    #[test]
    fn no_gateway_is_always_on_link() {
        let c = cfg("10.0.1.25/24", None);
        assert_eq!(c.gateway, None);
        assert_eq!(
            c.next_hop(Ipv4Addr::new(203, 0, 113, 10)),
            Ipv4Addr::new(203, 0, 113, 10)
        );
    }

    #[test]
    fn off_subnet_goes_to_gateway() {
        let c = cfg("10.0.1.25/24", Some("10.0.1.1"));
        assert_eq!(c.local_ip, Ipv4Addr::new(10, 0, 1, 25));
        assert_eq!(
            c.next_hop(Ipv4Addr::new(10, 0, 1, 99)),
            Ipv4Addr::new(10, 0, 1, 99)
        );
        assert_eq!(
            c.next_hop(Ipv4Addr::new(10, 0, 2, 99)),
            Ipv4Addr::new(10, 0, 1, 1)
        );
        assert_eq!(
            c.next_hop(Ipv4Addr::new(203, 0, 113, 10)),
            Ipv4Addr::new(10, 0, 1, 1)
        );
    }

    #[test]
    fn prefix_edges() {
        // No prefix with a gateway means /32: everything via the gateway.
        let c = cfg("10.0.1.25", Some("10.0.1.1"));
        assert_eq!(
            c.next_hop(Ipv4Addr::new(10, 0, 1, 99)),
            Ipv4Addr::new(10, 0, 1, 1)
        );
        assert_eq!(
            c.next_hop(Ipv4Addr::new(10, 0, 1, 25)),
            Ipv4Addr::new(10, 0, 1, 25)
        );
        // /0: everything on-link.
        let c = cfg("10.0.1.25/0", Some("10.0.1.1"));
        assert_eq!(
            c.next_hop(Ipv4Addr::new(203, 0, 113, 10)),
            Ipv4Addr::new(203, 0, 113, 10)
        );
        // Non-octet boundary: 10.0.0.0/20 covers 10.0.0.0-10.0.15.255.
        let c = cfg("10.0.1.25/20", Some("10.0.0.1"));
        assert_eq!(
            c.next_hop(Ipv4Addr::new(10, 0, 15, 255)),
            Ipv4Addr::new(10, 0, 15, 255)
        );
        assert_eq!(
            c.next_hop(Ipv4Addr::new(10, 0, 16, 0)),
            Ipv4Addr::new(10, 0, 0, 1)
        );
    }

    #[test]
    fn from_cli_rejects_bad_input() {
        for (local, gw) in [
            ("10.0.1.25/33", None),
            ("10.0.1.25/x", None),
            ("10.0.1", None),
            ("10.0.1.25/24", Some("gw")),
        ] {
            assert!(
                EngineConfig::from_cli(EthAddr::ZERO, local, gw).is_err(),
                "{local} {gw:?}"
            );
        }
    }
}
