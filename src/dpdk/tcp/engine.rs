//! Wires the DPDK port to the per-connection TCP state machines: demuxes
//! received frames to the right `Tcb` (or spawns one for a SYN on a
//! listened port), drives timers, and serializes each `Tcb`'s pending
//! output back onto the wire.
//!
//! Addressing is intentionally simple: no routing table or default
//! gateway -- every peer is assumed directly reachable on the local
//! Ethernet segment, resolved via a minimal built-in ARP responder/
//! resolver. That's the right fit for a back-to-back or single-subnet
//! DPDK test setup; a real deployment behind a gateway would need a route
//! table this stack doesn't have.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::core::hashmap::HashMap;
use crate::core::hashset::HashSet;
use crate::dpdk::net::{arp, eth, ipv4, tcp};
use crate::dpdk::{EthPort, Mbuf, Mempool};

use super::seq::Seq;
use super::state::TcpState;
use super::tcb::{Event, FourTuple, OutSegment, Tcb};

const ARP_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const MAX_RX_BURST: usize = 64;

pub struct EngineConfig {
    pub local_mac: [u8; 6],
    pub local_ip: [u8; 4],
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

    arp_table: HashMap<[u8; 4], [u8; 6]>,
    arp_last_request: HashMap<[u8; 4], Instant>,
    pending_arp_replies: Vec<([u8; 6], [u8; 4])>,
    pending_arp_requests: Vec<[u8; 4]>,
    /// RSTs sent to a peer with no matching connection/listener. Built
    /// eagerly (mac already resolved) rather than routed through a Tcb,
    /// since there is no Tcb for an unknown 4-tuple.
    pending_raw_resets: Vec<([u8; 6], [u8; 4], tcp::TcpHeader)>,
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
            arp_table: HashMap::default(),
            arp_last_request: HashMap::default(),
            pending_arp_replies: Vec::new(),
            pending_arp_requests: Vec::new(),
            pending_raw_resets: Vec::new(),
            active: HashSet::default(),
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

    pub fn connect(&mut self, remote_ip: [u8; 4], remote_port: u16, local_port: u16) -> FourTuple {
        let tuple = FourTuple {
            local_ip: self.config.local_ip,
            local_port,
            remote_ip,
            remote_port,
        };
        self.connections.insert(tuple, Tcb::new_active(tuple));
        self.connections_opened += 1;
        self.mark_active(tuple); // has a SYN to send
        tuple
    }

    /// Total active opens since the engine was created (never decremented;
    /// a connection-reuse observability counter, not a live-count).
    pub fn connections_opened(&self) -> u64 {
        self.connections_opened
    }

    pub fn accept(&mut self, port: u16) -> Option<FourTuple> {
        self.accept_queues.get_mut(&port)?.pop_front()
    }

    pub fn send(&mut self, tuple: FourTuple, data: Bytes) {
        if let Some(tcb) = self.connections.get_mut(&tuple) {
            tcb.send(data);
            self.mark_active(tuple);
        }
    }

    pub fn recv(&mut self, tuple: FourTuple, max_len: usize) -> Bytes {
        self.connections
            .get_mut(&tuple)
            .map(|t| t.recv(max_len))
            .unwrap_or_default()
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
    /// the socket layer may care about.
    pub fn poll(
        &mut self,
        port: &EthPort,
        pool: &Mempool,
        now: Instant,
    ) -> Vec<(FourTuple, Event)> {
        for mbuf in port.rx_burst(MAX_RX_BURST) {
            // RX checksum offload: if the NIC checked a checksum and it was
            // wrong, drop the frame; if it verified one as good, skip the
            // corresponding software check. When RX offload is off the
            // flags read UNKNOWN, so both fall back to software verify.
            if mbuf.rx_ip_cksum_bad() || mbuf.rx_l4_cksum_bad() {
                continue;
            }
            let ip_ok = mbuf.rx_ip_cksum_good();
            let l4_ok = mbuf.rx_l4_cksum_good();
            // Zero-copy RX: the frame becomes a `Bytes` that owns the mbuf,
            // so a data segment's payload is delivered to the application as
            // a refcounted slice of it -- never copied. The mbuf is freed
            // when the last reference (possibly on the app thread) drops.
            let frame = mbuf.into_bytes();
            self.handle_frame(&frame, ip_ok, l4_ok, now);
        }

        let mut events = Vec::new();
        let mut out_mbufs = Vec::new();

        // Process only the connections that need attention this poll.
        // `drain` empties the set; each connection re-inserts itself in
        // phase 2 if it still has pending output or an armed timer, so an
        // idle connection is dropped from the set and not walked again
        // until an inbound frame / app call re-adds it.
        let active: Vec<FourTuple> = self.active.drain().collect();

        // Phase 1: tick timers, drain events, reap fully-closed
        // connections. The `tcb` borrow is scoped so the accept-queue /
        // reap steps can touch other engine fields afterward.
        for &tuple in &active {
            let mut established = false;
            let closed;
            {
                let Some(tcb) = self.connections.get_mut(&tuple) else {
                    continue;
                };
                tcb.tick(now);
                for ev in tcb.events.drain(..) {
                    established |= ev == Event::Established;
                    events.push((tuple, ev));
                }
                closed = tcb.is_closed();
            }
            if established && self.pending_accept.remove(&tuple) {
                self.accept_queues
                    .entry(tuple.local_port)
                    .or_default()
                    .push_back(tuple);
            }
            // Keep TIME_WAIT (not `is_closed`) around; drop only fully
            // closed connections.
            if closed {
                self.connections.remove(&tuple);
                self.pending_accept.remove(&tuple);
            }
        }

        // Phase 2: build output for the connections still present, and
        // re-arm the active set for any that still need attention.
        //
        // Disjoint field borrows: `connections` is borrowed for the loop
        // while `arp_table`/`arp_last_request`/`pending_arp_requests` are
        // borrowed separately by `build_tcp_frame` (a free function, so
        // the borrow checker sees the borrows don't overlap), and `active`
        // is a third disjoint field.
        let tx_offload = port.tx_cksum_offload();
        let connections = &mut self.connections;
        let config = &self.config;
        let arp_table = &self.arp_table;
        let arp_last_request = &mut self.arp_last_request;
        let pending_arp_requests = &mut self.pending_arp_requests;
        let active_set = &mut self.active;
        for &tuple in &active {
            let Some(tcb) = connections.get_mut(&tuple) else {
                continue; // reaped in phase 1
            };
            for seg in tcb.poll_output(now) {
                if let Some(mbuf) = build_tcp_frame(
                    pool,
                    config,
                    arp_table,
                    arp_last_request,
                    pending_arp_requests,
                    &tuple,
                    tcb,
                    &seg,
                    tx_offload,
                ) {
                    out_mbufs.push(mbuf);
                }
            }
            if tcb.has_pending_output() || tcb.has_armed_timer() {
                active_set.insert(tuple);
            }
        }
        for (dst_mac, dst_ip) in self.pending_arp_replies.drain(..) {
            if let Some(mbuf) = build_arp_frame(
                pool,
                arp::OP_REPLY,
                self.config.local_mac,
                self.config.local_ip,
                dst_mac,
                dst_ip,
            ) {
                out_mbufs.push(mbuf);
            }
        }
        for dst_ip in self.pending_arp_requests.drain(..) {
            if let Some(mbuf) = build_arp_frame(
                pool,
                arp::OP_REQUEST,
                self.config.local_mac,
                self.config.local_ip,
                [0xff; 6],
                dst_ip,
            ) {
                out_mbufs.push(mbuf);
            }
        }
        for (dst_mac, dst_ip, hdr) in self.pending_raw_resets.drain(..) {
            if let Some(mbuf) = build_ip_tcp_frame(
                pool,
                self.config.local_mac,
                dst_mac,
                self.config.local_ip,
                dst_ip,
                &hdr,
                &[],
                tx_offload,
            ) {
                out_mbufs.push(mbuf);
            }
        }

        if !out_mbufs.is_empty() {
            port.tx_burst(out_mbufs);
        }

        events
    }

    /// `ip_ok`/`l4_ok` report that the NIC already verified the IPv4 /
    /// TCP checksum on RX, so software verification can be skipped.
    /// `frame` is the received Ethernet frame as an mbuf-owning `Bytes`
    /// (see [`Mbuf::into_bytes`]); parsing borrows it as a slice, and only a
    /// TCP data payload is sliced out of it (by refcount, zero-copy).
    fn handle_frame(&mut self, frame: &Bytes, ip_ok: bool, l4_ok: bool, now: Instant) {
        let Some(eth_hdr) = eth::EthHeader::parse(frame) else {
            return;
        };
        match eth_hdr.ethertype {
            arp::ETHERTYPE_ARP => self.handle_arp(&frame[eth::ETH_HDR_LEN..]),
            eth::ETHERTYPE_IPV4 => self.handle_ipv4(frame, ip_ok, l4_ok, now),
            _ => {}
        }
    }

    fn handle_arp(&mut self, buf: &[u8]) {
        let Some(pkt) = arp::ArpPacket::parse(buf) else {
            return;
        };
        if pkt.sender_ip != [0, 0, 0, 0] {
            self.arp_table.insert(pkt.sender_ip, pkt.sender_mac);
        }
        if pkt.operation == arp::OP_REQUEST && pkt.target_ip == self.config.local_ip {
            self.pending_arp_replies
                .push((pkt.sender_mac, pkt.sender_ip));
        }
    }

    fn handle_ipv4(&mut self, frame: &Bytes, ip_ok: bool, l4_ok: bool, now: Instant) {
        let buf = &frame[eth::ETH_HDR_LEN..];
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
            // Zero-copy: the payload is a refcounted slice of the mbuf-owning
            // frame `Bytes` (empty payloads resolve to `Bytes::new()`, which
            // pins nothing).
            tcb.on_segment(&tcp_hdr, frame.slice_ref(segment_payload), now);
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
            self.send_reset_for_unknown(&tcp_hdr, segment_payload.len(), ip_hdr.src);
        }
    }

    fn send_reset_for_unknown(
        &mut self,
        hdr: &tcp::TcpHeader,
        payload_len: usize,
        remote_ip: [u8; 4],
    ) {
        // A stray RST-worthy segment doesn't own retransmission/ARP
        // queuing machinery the way a Tcb does; if the peer's MAC isn't
        // known yet, just drop it -- RSTs are best-effort.
        let Some(&remote_mac) = self.arp_table.get(&remote_ip) else {
            self.request_arp(remote_ip);
            return;
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

    fn request_arp(&mut self, ip: [u8; 4]) {
        request_arp(
            &mut self.arp_last_request,
            &mut self.pending_arp_requests,
            ip,
        );
    }
}

/// Rate-limited ARP request trigger, shared by the `&mut self` call site
/// (`send_reset_for_unknown`) and the free-function `build_tcp_frame`
/// call site (used where only disjoint fields, not the whole `TcpEngine`,
/// can be borrowed -- see the comment in `poll`).
fn request_arp(
    arp_last_request: &mut HashMap<[u8; 4], Instant>,
    pending_arp_requests: &mut Vec<[u8; 4]>,
    ip: [u8; 4],
) {
    let due = match arp_last_request.get(&ip) {
        Some(&t) => t.elapsed() >= ARP_RETRY_INTERVAL,
        None => true,
    };
    if due {
        arp_last_request.insert(ip, Instant::now());
        pending_arp_requests.push(ip);
    }
}

#[allow(clippy::too_many_arguments)]
fn build_tcp_frame(
    pool: &Mempool,
    config: &EngineConfig,
    arp_table: &HashMap<[u8; 4], [u8; 6]>,
    arp_last_request: &mut HashMap<[u8; 4], Instant>,
    pending_arp_requests: &mut Vec<[u8; 4]>,
    tuple: &FourTuple,
    tcb: &Tcb,
    seg: &OutSegment,
    tx_cksum_offload: bool,
) -> Option<Mbuf> {
    let Some(&remote_mac) = arp_table.get(&tuple.remote_ip) else {
        request_arp(arp_last_request, pending_arp_requests, tuple.remote_ip);
        return None;
    };
    let hdr = tcb.to_header(seg);
    build_ip_tcp_frame(
        pool,
        config.local_mac,
        remote_mac,
        config.local_ip,
        tuple.remote_ip,
        &hdr,
        &seg.payload,
        tx_cksum_offload,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_ip_tcp_frame(
    pool: &Mempool,
    local_mac: [u8; 6],
    remote_mac: [u8; 6],
    local_ip: [u8; 4],
    remote_ip: [u8; 4],
    tcp_hdr: &tcp::TcpHeader,
    payload: &[u8],
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
    buf[tcp_end..tcp_end + payload.len()].copy_from_slice(payload);
    {
        let (ip_and_before, rest) = buf.split_at_mut(tcp_start);
        // With TX checksum offload the NIC fills the IPv4 checksum and
        // completes the TCP checksum; we write only the TCP pseudo-header
        // checksum and a zero IPv4 checksum, and tag the mbuf below.
        tcp_hdr.write(
            &mut rest[..tcp_len],
            payload,
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
    local_mac: [u8; 6],
    local_ip: [u8; 4],
    dst_mac: [u8; 6],
    dst_ip: [u8; 4],
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
            [0; 6]
        } else {
            dst_mac
        },
        target_ip: dst_ip,
    };
    arp_pkt.write(&mut buf[eth::ETH_HDR_LEN..]);

    Some(mbuf)
}
