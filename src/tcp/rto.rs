//! Retransmission timeout estimation (RFC 6298, the Jacobson/Karels
//! algorithm) and the per-connection retransmit queue.

use std::time::{Duration, Instant};

use bytes::Bytes;

use super::seq::Seq;

pub const MIN_RTO: Duration = Duration::from_millis(200);
pub const MAX_RTO: Duration = Duration::from_secs(60);
/// RFC 6298 clock granularity term added to every RTO computation.
const CLOCK_GRANULARITY: Duration = Duration::from_millis(100);
/// RFC 9293 §3.8.3 recommendation (R2): give up after this many
/// retransmissions of the same segment.
pub const MAX_RETRANSMITS: u32 = 12;

pub struct RtoEstimator {
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
}

impl Default for RtoEstimator {
    fn default() -> Self {
        Self {
            srtt: None,
            rttvar: Duration::ZERO,
            // RFC 6298 §2.1: until the first RTT sample, use 1s.
            rto: Duration::from_secs(1),
        }
    }
}

impl RtoEstimator {
    /// Feeds a fresh round-trip-time sample. Callers must apply Karn's
    /// algorithm themselves: never call this for a segment that was
    /// retransmitted before being acked, since the sample would be
    /// ambiguous about which transmission was actually acked.
    pub fn sample(&mut self, rtt: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                let delta = rtt.abs_diff(srtt);
                self.rttvar = self.rttvar * 3 / 4 + delta / 4;
                self.srtt = Some(srtt * 7 / 8 + rtt / 8);
            }
        }
        let srtt = self.srtt.unwrap();
        let candidate = srtt + std::cmp::max(CLOCK_GRANULARITY, self.rttvar * 4);
        self.rto = candidate.clamp(MIN_RTO, MAX_RTO);
    }

    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// RFC 6298 §5.5: exponential backoff on timeout, applied to the
    /// timer directly (not fed back into the SRTT/RTTVAR estimate).
    pub fn backoff(&mut self) {
        self.rto = (self.rto * 2).min(MAX_RTO);
    }
}

/// One outstanding (sent, not yet acked) byte range in the retransmit
/// queue. `data` is kept so the segment can be resent verbatim; it shares
/// the same underlying buffer as the segment on the wire (a refcounted
/// `Bytes`), so retaining it for retransmission costs no copy.
pub struct UnackedSegment {
    pub seq: Seq,
    pub data: Bytes,
    pub syn: bool,
    pub fin: bool,
    pub first_sent_at: Instant,
    pub last_sent_at: Instant,
    /// Karn's algorithm: a segment retransmitted at least once must not
    /// generate an RTT sample when it's finally acked.
    pub retransmitted: bool,
    pub retransmit_count: u32,
}

impl UnackedSegment {
    /// Sequence number one past the end of this segment. SYN and FIN each
    /// consume one sequence number per RFC 9293 §3.4, same as a data byte.
    pub fn end_seq(&self) -> Seq {
        self.seq
            + self.data.len() as u32
            + if self.syn { 1 } else { 0 }
            + if self.fin { 1 } else { 0 }
    }
}

#[derive(Default)]
pub struct RetransmitQueue {
    pub segments: std::collections::VecDeque<UnackedSegment>,
}

impl RetransmitQueue {
    /// Enqueues a sent-but-unacked segment so it can be resent verbatim
    /// if `on_rto` fires before it's acked. `syn`/`fin` mark control
    /// segments (the handshake SYN/SYN-ACK and the closing FIN) so they
    /// get retried through the same mechanism as data instead of being
    /// silently dropped if the first transmission is lost (e.g. to an
    /// unresolved ARP entry).
    pub fn push(&mut self, seq: Seq, data: Bytes, syn: bool, fin: bool, now: Instant) {
        self.segments.push_back(UnackedSegment {
            seq,
            data,
            syn,
            fin,
            first_sent_at: now,
            last_sent_at: now,
            retransmitted: false,
            retransmit_count: 0,
        });
    }

    /// Drops fully-acked segments given the peer's cumulative ACK
    /// (`snd_una`). Returns an RTT sample from the oldest segment removed
    /// this call, if it qualifies under Karn's algorithm.
    pub fn ack_up_to(&mut self, snd_una: Seq, now: Instant) -> Option<Duration> {
        let mut sample = None;
        while let Some(front) = self.segments.front() {
            if front.end_seq().leq(snd_una) {
                let seg = self.segments.pop_front().unwrap();
                if !seg.retransmitted && sample.is_none() {
                    sample = now.checked_duration_since(seg.first_sent_at);
                }
            } else {
                break;
            }
        }
        sample
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn oldest_deadline(&self, rto: Duration) -> Option<Instant> {
        self.segments.front().map(|s| s.last_sent_at + rto)
    }
}
