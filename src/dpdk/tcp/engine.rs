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

use super::seq::Seq;
use super::state::TcpState;
use super::tcb::{Event, FourTuple, OutSegment, Tcb};
use super::tx_queue::Payload;

const MAX_RX_BURST: usize = 64;
const MAX_PENDING_TX: usize = 256;
const ARP_TIMEOUT: Duration = Duration::from_secs(30);

struct PendingTcp {
    tuple: FourTuple,
    mac: EthAddr,
    header: tcp::TcpHeader,
    payload: Payload,
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
    config: EngineConfig,
    listeners: HashSet<u16>,
    connections: HashMap<FourTuple, Tcb>,
    connections_opened: u64,
    accept_queues: HashMap<u16, VecDeque<FourTuple>>,
    /// Tuples spawned from a listener's SYN, awaiting their first
    /// `Event::Established` before being handed to `accept()`.
    pending_accept: HashSet<FourTuple>,
    /// Connections that need per-poll attention -- they have pending
    /// output or an armed timer. `poll` processes only these, so idle
    /// connections aren't walked every iteration. Invariant: a connection
    /// *not* in this set has no pending output and no armed timer, so only
    /// an inbound frame or an app call can make it need work -- and both
    /// re-insert it here (see `mark_active`).
    active: HashSet<FourTuple>,
    /// Scratch set for both poll phases; empty between polls. Swapping
    /// with `active` and clearing afterward retains both allocations.
    processing: HashSet<FourTuple>,
    tx_batch: Vec<Mbuf>,
    tx_owners: Vec<Option<(FourTuple, Seq)>>,
    pending_tx: VecDeque<PendingTcp>,
    queued_tx: HashMap<FourTuple, usize>,
    arp_wait: HashMap<FourTuple, Instant>,
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
            config,
            listeners: HashSet::default(),
            connections: HashMap::default(),
            connections_opened: 0,
            accept_queues: HashMap::default(),
            pending_accept: HashSet::default(),
            arp: ArpTable::new(),
            pending_arp_replies: Vec::new(),
            pending_raw_resets: Vec::new(),
            active: HashSet::default(),
            processing: HashSet::default(),
            tx_batch: Vec::new(),
            tx_owners: Vec::new(),
            pending_tx: VecDeque::new(),
            queued_tx: HashMap::default(),
            arp_wait: HashMap::default(),
            updated: Vec::new(),
            segments: Vec::new(),
        }
    }

    /// Marks a connection as needing attention on the next `poll`. Cheap
    /// and idempotent; called from every path that can give a connection
    /// pending output (app ops, inbound segments).
    fn mark_active(&mut self, tuple: FourTuple) {
        self.active.insert(tuple);
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
                v.insert(Tcb::new_active(tuple));
            }
        }
        self.connections_opened += 1;
        self.mark_active(tuple); // has a SYN to send
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

    pub(crate) fn buffered_send_bytes(&self, tuple: FourTuple) -> usize {
        self.connections
            .get(&tuple)
            .map_or(0, Tcb::buffered_send_bytes)
    }

    /// Discards an abandoned connection and all its retained buffers.
    pub(crate) fn abort(&mut self, tuple: FourTuple) {
        self.connections.remove(&tuple);
        self.active.remove(&tuple);
        self.pending_accept.remove(&tuple);
        self.arp_wait.remove(&tuple);
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
        self.queued_tx.remove(&tuple);
    }

    pub fn send(&mut self, tuple: FourTuple, data: Bytes) {
        if let Some(tcb) = self.connections.get_mut(&tuple) {
            tcb.send(data);
            self.mark_active(tuple);
        }
    }

    pub fn recv(&mut self, tuple: FourTuple, max_len: usize) -> Bytes {
        let data = self
            .connections
            .get_mut(&tuple)
            .map(|t| t.recv(max_len))
            .unwrap_or_default();
        if !data.is_empty() {
            self.mark_active(tuple);
        }
        data
    }

    pub fn readable_len(&self, tuple: FourTuple) -> usize {
        self.connections
            .get(&tuple)
            .map(|t| t.readable_len())
            .unwrap_or(0)
    }

    pub fn close(&mut self, tuple: FourTuple) {
        if let Some(tcb) = self.connections.get_mut(&tuple) {
            tcb.close();
            self.mark_active(tuple);
        }
    }

    /// TCP_NODELAY: disable (or re-enable) Nagle's algorithm for one
    /// connection.
    pub fn set_nodelay(&mut self, tuple: FourTuple, nodelay: bool) {
        if let Some(tcb) = self.connections.get_mut(&tuple) {
            tcb.set_nodelay(nodelay);
            // May unblock a Nagle-held tail.
            self.mark_active(tuple);
        }
    }

    /// TCP_CORK-style hold: while set, the trailing sub-MSS segment is
    /// held back until `flush()` (full-MSS segments still flow).
    pub fn set_cork(&mut self, tuple: FourTuple, corked: bool) {
        if let Some(tcb) = self.connections.get_mut(&tuple) {
            tcb.set_cork(corked);
            // Uncorking flushes a held tail.
            self.mark_active(tuple);
        }
    }

    /// Manual trigger releasing a corked connection's held tail segment.
    pub fn flush(&mut self, tuple: FourTuple) {
        if let Some(tcb) = self.connections.get_mut(&tuple) {
            tcb.flush();
            self.mark_active(tuple);
        }
    }

    pub fn state(&self, tuple: FourTuple) -> Option<TcpState> {
        self.connections.get(&tuple).map(|t| t.state)
    }

    /// One iteration of the poll loop: drains received frames, ticks
    /// every connection's timers, and transmits whatever each connection
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
        events.clear();
        self.updated.clear();
        self.arp.expire(now);
        for mbuf in port.rx_packets(MAX_RX_BURST) {
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

        self.flush_tx(port, pool, now);

        // Process only the connections that need attention this poll.
        // Swap into retained scratch storage. Both phases visit the same
        // tuples; phase 2 re-inserts those needing another poll into the
        // now-empty active set. Neither set's allocation is discarded.
        std::mem::swap(&mut self.active, &mut self.processing);

        // Phase 1: tick timers and drain events. Closed connections remain
        // until phase 2 has serialized any final reset.
        for &tuple in &self.processing {
            self.updated.push(tuple);
            let mut established = false;
            {
                let Some(tcb) = self.connections.get_mut(&tuple) else {
                    continue;
                };
                tcb.tick(now);
                for ev in tcb.events.drain(..) {
                    established |= ev == Event::Established;
                    events.push((tuple, ev));
                }
            }
            if established && self.pending_accept.remove(&tuple) {
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
        let connections = &mut self.connections;
        let config = &self.config;
        let arp = &mut self.arp;
        let active_set = &mut self.active;
        for &tuple in &self.processing {
            let Some(tcb) = connections.get_mut(&tuple) else {
                continue;
            };
            // Do not consume output until both resolution and bounded
            // local queue space are available. ARP replies are usable this poll.
            let room = MAX_PENDING_TX.saturating_sub(self.tx_batch.len() + self.pending_tx.len());
            if self.queued_tx.contains_key(&tuple) || room == 0 {
                active_set.insert(tuple);
                continue;
            }
            let Some(mac) = arp.resolve(config.next_hop(tuple.remote_ip), now) else {
                let since = self.arp_wait.entry(tuple).or_insert(now);
                if now.saturating_duration_since(*since) >= ARP_TIMEOUT {
                    connections.remove(&tuple);
                    self.pending_accept.remove(&tuple);
                    self.arp_wait.remove(&tuple);
                    events.push((tuple, Event::Reset));
                } else {
                    active_set.insert(tuple);
                }
                continue;
            };
            self.arp_wait.remove(&tuple);
            tcb.set_local_mss(local_mss);
            tcb.poll_output_limited(now, &mut self.segments, room.min(32));
            for seg in self.segments.drain(..) {
                tcb.mark_transmit_pending(seg.seq);
                self.pending_tx.push_back(PendingTcp {
                    tuple,
                    mac,
                    header: tcb.to_header(&seg),
                    payload: seg.payload,
                });
                *self.queued_tx.entry(tuple).or_default() += 1;
            }
            if tcb.is_closed() {
                connections.remove(&tuple);
                self.pending_accept.remove(&tuple);
            } else if tcb.has_pending_output()
                || tcb.has_armed_timer()
                || self.queued_tx.contains_key(&tuple)
            {
                active_set.insert(tuple);
            }
        }
        self.processing.clear();

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
            ) {
                self.tx_batch.push(mbuf);
                self.tx_owners.push(None);
            }
        }

        self.flush_tx(port, pool, now);
    }

    /// Packets retained locally awaiting pool space or NIC acceptance.
    pub fn pending_tx_len(&self) -> usize {
        self.tx_batch.len() + self.pending_tx.len()
    }

    pub(crate) fn updated_connections(&self) -> &[FourTuple] {
        &self.updated
    }

    fn flush_tx(&mut self, port: &EthPort, pool: &Mempool, now: Instant) {
        while let Some(packet) = self.pending_tx.front() {
            let Some(mbuf) = build_ip_tcp_frame(
                pool,
                self.config.local_mac,
                packet.mac,
                packet.tuple.local_ip,
                packet.tuple.remote_ip,
                &packet.header,
                &packet.payload,
                port.tx_cksum_offload(),
            ) else {
                break;
            };
            self.tx_owners
                .push(Some((packet.tuple, Seq::new(packet.header.seq))));
            self.tx_batch.push(mbuf);
            self.pending_tx.pop_front();
        }
        let before = self.tx_batch.len();
        if before == 0 {
            return;
        }
        port.tx_burst_in_place(&mut self.tx_batch);
        let sent = before - self.tx_batch.len();
        for owner in self.tx_owners.drain(..sent).flatten() {
            let (tuple, seq) = owner;
            if let Some(tcb) = self.connections.get_mut(&tuple) {
                tcb.mark_transmitted(seq, now);
            }
            if let Some(count) = self.queued_tx.get_mut(&tuple) {
                *count -= 1;
                if *count == 0 {
                    self.queued_tx.remove(&tuple);
                }
            }
        }
        // The unaccepted suffix and its ownership metadata remain for retry.
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
        let total_len = (ip_hdr.total_length as usize).min(buf.len());
        if total_len < ipv4::IPV4_HDR_LEN {
            return;
        }
        let ip_payload = &buf[ipv4::IPV4_HDR_LEN..total_len];
        let Some((tcp_hdr, hdr_len)) =
            tcp::TcpHeader::parse(ip_payload, ip_hdr.src, ip_hdr.dst, !l4_ok)
        else {
            return;
        };
        let segment_payload = &ip_payload[hdr_len..];

        let tuple = FourTuple {
            local_ip: self.config.local_ip,
            local_port: tcp_hdr.dst_port,
            remote_ip: ip_hdr.src,
            remote_port: tcp_hdr.src_port,
        };

        if let Some(tcb) = self.connections.get_mut(&tuple) {
            let start = eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN + hdr_len;
            let end = eth::ETH_HDR_LEN + total_len;
            tcb.on_segment_with(
                &tcp_hdr,
                segment_payload.len(),
                || mbuf.into_bytes().slice(start..end),
                now,
            );
            if tcb.is_closed() {
                self.discard_queued(tuple);
            }
            // The segment may have produced an ACK/data to send, an event,
            // or a state change -- process it next poll.
            self.mark_active(tuple);
            return;
        }

        let is_bare_syn = tcp_hdr.has_flag(tcp::flags::SYN) && !tcp_hdr.has_flag(tcp::flags::ACK);
        if is_bare_syn && self.listeners.contains(&tcp_hdr.dst_port) {
            let peer_mss = tcp_hdr.options.mss.unwrap_or(536);
            let tcb = Tcb::new_from_listen(tuple, Seq::new(tcp_hdr.seq), peer_mss);
            self.connections.insert(tuple, tcb);
            self.pending_accept.insert(tuple);
            self.mark_active(tuple); // has a SYN-ACK to send
            return;
        }

        // RFC 9293 §3.10.7.1: a segment addressed to no listener/connection
        // gets reset, unless it's an RST itself (which would just loop).
        if !tcp_hdr.has_flag(tcp::flags::RST) {
            self.send_reset_for_unknown(&tcp_hdr, segment_payload.len(), ip_hdr.src, now);
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
) -> Option<Mbuf> {
    let tcp_len = tcp_hdr.wire_len();
    let total_len = eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN + tcp_len + payload.len();

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
