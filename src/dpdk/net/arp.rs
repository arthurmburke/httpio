//! Minimal ARP (RFC 826) for IPv4-over-Ethernet: just enough to resolve a
//! next-hop MAC address and answer requests for our own IP, since without
//! it there is no way to actually address an Ethernet frame to a real
//! peer/gateway.

//!
//! [`ArpTable`] is the resolver's state: learned `IPv4 -> MAC` mappings
//! that expire, plus the bookkeeping for the requests that fill it.

use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use gxhash::HashMap;

use crate::dpdk::net::eth::EthAddr;

pub const ARP_HDR_LEN: usize = 28;
pub const ETHERTYPE_ARP: u16 = 0x0806;

const HTYPE_ETHERNET: u16 = 1;
const PTYPE_IPV4: u16 = 0x0800;
const HLEN_ETHERNET: u8 = 6;
const PLEN_IPV4: u8 = 4;

pub const OP_REQUEST: u16 = 1;
pub const OP_REPLY: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub operation: u16,
    pub sender_mac: EthAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: EthAddr,
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < ARP_HDR_LEN {
            return None;
        }
        let htype = u16::from_be_bytes([buf[0], buf[1]]);
        let ptype = u16::from_be_bytes([buf[2], buf[3]]);
        if htype != HTYPE_ETHERNET
            || ptype != PTYPE_IPV4
            || buf[4] != HLEN_ETHERNET
            || buf[5] != PLEN_IPV4
        {
            return None;
        }
        let mac = |at: usize| EthAddr::new(buf[at..at + 6].try_into().unwrap());
        let ip = |at: usize| Ipv4Addr::from(<[u8; 4]>::try_from(&buf[at..at + 4]).unwrap());
        Some(Self {
            operation: u16::from_be_bytes([buf[6], buf[7]]),
            sender_mac: mac(8),
            sender_ip: ip(14),
            target_mac: mac(18),
            target_ip: ip(24),
        })
    }

    pub fn write(&self, out: &mut [u8]) {
        out[0..2].copy_from_slice(&HTYPE_ETHERNET.to_be_bytes());
        out[2..4].copy_from_slice(&PTYPE_IPV4.to_be_bytes());
        out[4] = HLEN_ETHERNET;
        out[5] = PLEN_IPV4;
        out[6..8].copy_from_slice(&self.operation.to_be_bytes());
        out[8..14].copy_from_slice(self.sender_mac.as_ref());
        out[14..18].copy_from_slice(&self.sender_ip.octets());
        out[18..24].copy_from_slice(self.target_mac.as_ref());
        out[24..28].copy_from_slice(&self.target_ip.octets());
    }
}

/// How long a learned mapping is trusted before it must be re-resolved.
pub const ENTRY_TTL: Duration = Duration::from_secs(60);
/// Age past which a still-valid entry is re-requested when used, so a
/// mapping in active use is refreshed before it expires instead of
/// stalling traffic for a resolution round trip.
pub const REFRESH_AFTER: Duration = Duration::from_secs(45);
/// Minimum spacing between requests for the same address.
pub const REQUEST_INTERVAL: Duration = Duration::from_secs(1);
/// Upper bound on learned mappings; the oldest is evicted to make room.
pub const MAX_ENTRIES: usize = 1024;
/// How often [`ArpTable::expire`] actually walks the table.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpEntry {
    pub mac: EthAddr,
    pub updated: Instant,
}

/// The IPv4 -> Ethernet neighbour cache and the request state that fills it.
///
/// All methods take the caller's clock (`now`), so behaviour is
/// deterministic and testable with a synthetic one.
pub struct ArpTable {
    entries: HashMap<Ipv4Addr, ArpEntry>,
    /// When each address was last requested: rate-limits requests and marks
    /// the addresses this host is actively trying to resolve.
    last_request: HashMap<Ipv4Addr, Instant>,
    /// Requests [`resolve`](Self::resolve) decided to send, awaiting
    /// [`drain_requests`](Self::drain_requests).
    pending_requests: Vec<Ipv4Addr>,
    next_sweep: Option<Instant>,
}

impl Default for ArpTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::default(),
            last_request: HashMap::default(),
            pending_requests: Vec::new(),
            next_sweep: None,
        }
    }

    /// The MAC address for `ip`, if a mapping is known and has not expired.
    /// Pure lookup: never queues a request.
    pub fn lookup(&self, ip: Ipv4Addr, now: Instant) -> Option<EthAddr> {
        self.entries
            .get(&ip)
            .filter(|entry| age(entry.updated, now) < ENTRY_TTL)
            .map(|entry| entry.mac)
    }

    /// Looks `ip` up for transmission. A missing or expired mapping queues a
    /// (rate-limited) request and returns `None`; a valid one nearing expiry
    /// is returned and also re-requested so it is refreshed while in use.
    pub fn resolve(&mut self, ip: Ipv4Addr, now: Instant) -> Option<EthAddr> {
        match self.entries.get(&ip) {
            Some(entry) if age(entry.updated, now) < ENTRY_TTL => {
                let mac = entry.mac;
                if age(entry.updated, now) >= REFRESH_AFTER {
                    self.request(ip, now);
                }
                Some(mac)
            }
            _ => {
                self.request(ip, now);
                None
            }
        }
    }

    /// Queues a request for `ip` unless one was sent within
    /// [`REQUEST_INTERVAL`]. Returns whether one was queued.
    pub fn request(&mut self, ip: Ipv4Addr, now: Instant) -> bool {
        let due = self
            .last_request
            .get(&ip)
            .is_none_or(|&sent| age(sent, now) >= REQUEST_INTERVAL);
        if due {
            self.last_request.insert(ip, now);
            self.pending_requests.push(ip);
        }
        due
    }

    /// The addresses to send ARP requests for now. Draining keeps the
    /// vector's allocation.
    pub fn drain_requests(&mut self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.pending_requests.drain(..)
    }

    /// Records the sender mapping of a received ARP packet, following RFC
    /// 826's merge rule: an address already in the table -- or one this host
    /// is currently requesting -- is always updated; a new one is added only
    /// when the packet was `addressed_to_us` (its target IP is ours).
    /// Everything else overheard on the segment is ignored, so the table is
    /// bounded by this host's own conversations rather than by the segment's
    /// traffic. Returns whether the mapping was stored.
    pub fn learn(
        &mut self,
        ip: Ipv4Addr,
        mac: EthAddr,
        addressed_to_us: bool,
        now: Instant,
    ) -> bool {
        if ip.is_unspecified() {
            return false; // an ARP probe's sender; not a mapping
        }
        let wanted = self.last_request.remove(&ip).is_some();
        if let Some(entry) = self.entries.get_mut(&ip) {
            *entry = ArpEntry { mac, updated: now };
            return true;
        }
        if !(wanted || addressed_to_us) {
            return false;
        }
        if self.entries.len() >= MAX_ENTRIES {
            self.evict_oldest();
        }
        self.entries.insert(ip, ArpEntry { mac, updated: now });
        true
    }

    /// Drops expired mappings and forgotten request records. Cheap to call
    /// on every poll: the table is only walked once per [`SWEEP_INTERVAL`].
    pub fn expire(&mut self, now: Instant) {
        if self.next_sweep.is_some_and(|at| now < at) {
            return;
        }
        self.next_sweep = Some(now + SWEEP_INTERVAL);
        self.entries
            .retain(|_, entry| age(entry.updated, now) < ENTRY_TTL);
        // An unanswered request older than the entry lifetime is for an
        // address nothing has needed since; a later use starts afresh.
        self.last_request
            .retain(|_, &mut sent| age(sent, now) < ENTRY_TTL);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.updated)
            .map(|(&ip, _)| ip)
        {
            self.entries.remove(&oldest);
        }
    }
}

/// Time since `then`, zero if the clock reads earlier than it.
fn age(then: Instant, now: Instant) -> Duration {
    now.saturating_duration_since(then)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const OTHER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
    const MAC_A: EthAddr = EthAddr::new([2, 0, 0, 0, 0, 0xa]);
    const MAC_B: EthAddr = EthAddr::new([2, 0, 0, 0, 0, 0xb]);

    #[test]
    fn packet_round_trips() {
        let pkt = ArpPacket {
            operation: OP_REPLY,
            sender_mac: MAC_A,
            sender_ip: PEER,
            target_mac: MAC_B,
            target_ip: OTHER,
        };
        let mut buf = [0u8; ARP_HDR_LEN];
        pkt.write(&mut buf);
        assert_eq!(ArpPacket::parse(&buf), Some(pkt));
        assert_eq!(ArpPacket::parse(&buf[..ARP_HDR_LEN - 1]), None);
    }

    #[test]
    fn resolve_requests_then_answers_once_learned() {
        let now = Instant::now();
        let mut table = ArpTable::new();
        assert_eq!(table.resolve(PEER, now), None);
        assert_eq!(table.drain_requests().collect::<Vec<_>>(), [PEER]);

        // The reply is accepted because we asked, even if not addressed to us.
        assert!(table.learn(PEER, MAC_A, false, now));
        assert_eq!(table.resolve(PEER, now), Some(MAC_A));
        assert_eq!(table.drain_requests().count(), 0);
    }

    #[test]
    fn requests_are_rate_limited_per_address() {
        let now = Instant::now();
        let mut table = ArpTable::new();
        for _ in 0..5 {
            assert_eq!(table.resolve(PEER, now), None);
        }
        assert_eq!(table.resolve(OTHER, now), None);
        assert_eq!(table.drain_requests().collect::<Vec<_>>(), [PEER, OTHER]);

        let just_before = now + REQUEST_INTERVAL - Duration::from_millis(1);
        assert_eq!(table.resolve(PEER, just_before), None);
        assert_eq!(table.drain_requests().count(), 0);

        assert_eq!(table.resolve(PEER, now + REQUEST_INTERVAL), None);
        assert_eq!(table.drain_requests().collect::<Vec<_>>(), [PEER]);
    }

    #[test]
    fn entries_expire_and_are_re_requested() {
        let now = Instant::now();
        let mut table = ArpTable::new();
        table.learn(PEER, MAC_A, true, now);

        let last_valid = now + ENTRY_TTL - Duration::from_millis(1);
        assert_eq!(table.lookup(PEER, last_valid), Some(MAC_A));

        // Expired by the clock alone, before any sweep has run.
        let expired = now + ENTRY_TTL;
        assert_eq!(table.lookup(PEER, expired), None);
        assert_eq!(table.resolve(PEER, expired), None);
        assert_eq!(table.drain_requests().collect::<Vec<_>>(), [PEER]);

        table.expire(expired);
        assert!(table.is_empty());
    }

    #[test]
    fn an_entry_in_use_is_refreshed_before_it_expires() {
        let now = Instant::now();
        let mut table = ArpTable::new();
        table.learn(PEER, MAC_A, true, now);

        let fresh = now + REFRESH_AFTER - Duration::from_millis(1);
        assert_eq!(table.resolve(PEER, fresh), Some(MAC_A));
        assert_eq!(table.drain_requests().count(), 0);

        let ageing = now + REFRESH_AFTER;
        assert_eq!(table.resolve(PEER, ageing), Some(MAC_A));
        assert_eq!(table.drain_requests().collect::<Vec<_>>(), [PEER]);

        // The reply restarts the lifetime (and may carry a new MAC).
        table.learn(PEER, MAC_B, true, ageing);
        assert_eq!(table.lookup(PEER, now + ENTRY_TTL), Some(MAC_B));
        assert_eq!(table.lookup(PEER, ageing + ENTRY_TTL), None);
    }

    #[test]
    fn overheard_traffic_is_not_learned() {
        let now = Instant::now();
        let mut table = ArpTable::new();
        assert!(!table.learn(OTHER, MAC_B, false, now));
        assert!(table.is_empty());
        assert!(!table.learn(Ipv4Addr::UNSPECIFIED, MAC_B, true, now));
        assert!(table.is_empty());

        // Addressed to us: the sender is about to talk to us.
        assert!(table.learn(OTHER, MAC_B, true, now));
        // Known address: updated from any packet.
        assert!(table.learn(OTHER, MAC_A, false, now));
        assert_eq!(table.lookup(OTHER, now), Some(MAC_A));
    }

    #[test]
    fn sweep_drops_expired_entries_and_stale_requests() {
        let now = Instant::now();
        let mut table = ArpTable::new();
        table.learn(PEER, MAC_A, true, now);
        table.resolve(OTHER, now); // never answered
        table.drain_requests().count();
        table.expire(now);

        let later = now + ENTRY_TTL;
        table.learn(Ipv4Addr::new(10, 0, 0, 9), MAC_B, true, later);
        table.expire(later);
        assert_eq!(table.len(), 1);
        assert!(table.last_request.is_empty());
        // A reply for a request that was forgotten is no longer solicited.
        assert!(!table.learn(OTHER, MAC_B, false, later));
    }

    #[test]
    fn a_full_table_evicts_its_oldest_entry() {
        let start = Instant::now();
        let mut table = ArpTable::new();
        let ip = |i: usize| Ipv4Addr::from(0x0a00_0000 + i as u32);
        for i in 0..MAX_ENTRIES {
            table.learn(ip(i), MAC_A, true, start + Duration::from_micros(i as u64));
        }
        let now = start + Duration::from_secs(1);
        table.learn(ip(MAX_ENTRIES), MAC_B, true, now);
        assert_eq!(table.len(), MAX_ENTRIES);
        assert_eq!(table.lookup(ip(0), now), None);
        assert_eq!(table.lookup(ip(1), now), Some(MAC_A));
        assert_eq!(table.lookup(ip(MAX_ENTRIES), now), Some(MAC_B));
    }
}
