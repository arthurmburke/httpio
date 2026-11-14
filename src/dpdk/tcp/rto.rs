//! Retransmission timeout estimation (RFC 6298, the Jacobson/Karels
//! algorithm) and the per-connection retransmit queue.

use std::time::{Duration, Instant};

use super::tx_queue::Payload;

use super::seq::Seq;

pub const MIN_RTO: Duration = Duration::from_millis(200);
pub const MAX_RTO: Duration = Duration::from_secs(60);
/// RFC 6298 clock granularity term added to every RTO computation.
const CLOCK_GRANULARITY: Duration = Duration::from_millis(100);
/// RFC 9293 §3.8.3 recommendation (R2): give up after this many
/// retransmissions of the same segment.
pub const MAX_RETRANSMITS: u32 = 12;

/// The smoothed round-trip estimate (RFC 6298 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RttEstimate {
    /// No sample yet: the RTO is the initial 1s (§2.1).
    Unmeasured,
    /// At least one sample has been folded in (§2.2, §2.3).
    Measured { srtt: Duration, rttvar: Duration },
}

pub struct RtoEstimator {
    estimate: RttEstimate,
    rto: Duration,
}

impl Default for RtoEstimator {
    fn default() -> Self {
        Self {
            estimate: RttEstimate::Unmeasured,
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
        let (srtt, rttvar) = match self.estimate {
            RttEstimate::Unmeasured => (rtt, rtt / 2),
            RttEstimate::Measured { srtt, rttvar } => {
                let delta = rtt.abs_diff(srtt);
                (srtt * 7 / 8 + rtt / 8, rttvar * 3 / 4 + delta / 4)
            }
        };
        self.estimate = RttEstimate::Measured { srtt, rttvar };
        let candidate = srtt + std::cmp::max(CLOCK_GRANULARITY, rttvar * 4);
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
/// payload slices), so retaining it for retransmission costs no data copy.
pub struct UnackedSegment {
    pub seq: Seq,
    pub data: Payload,
    pub syn: bool,
    pub fin: bool,
    pub first_sent_at: Instant,
    pub last_sent_at: Instant,
    /// Karn's algorithm: a segment retransmitted at least once must not
    /// generate an RTT sample when it's finally acked.
    pub retransmitted: bool,
    pub retransmit_count: u32,
    /// The peer reported holding this range (RFC 2018). Not an
    /// acknowledgment: the range stays queued until cumulatively acked.
    pub sacked: bool,
    /// Considered lost: it no longer counts as in flight, and is resent
    /// as soon as the congestion window allows.
    pub lost: bool,
    /// Resent since it was marked lost; that copy counts as in flight.
    pub rexmit_out: bool,
    pending_transmit: bool,
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
    payload_bytes: usize,
    /// New segments start out waiting for the port to accept them; see
    /// [`RetransmitQueue::hold_until_transmitted`].
    hold: bool,
    /// Some segment is marked SACKed or lost.
    scoreboard: bool,
    /// How many segments at the back of the queue are still waiting.
    /// They are confirmed oldest first, so the next confirmation is
    /// normally for the first of them and needs no search.
    untransmitted: usize,
    pub segments: std::collections::VecDeque<UnackedSegment>,
}

impl RetransmitQueue {
    /// Enqueues a sent-but-unacked segment so it can be resent verbatim
    /// if `on_rto` fires before it's acked. `syn`/`fin` mark control
    /// segments (the handshake SYN/SYN-ACK and the closing FIN) so they
    /// get retried through the same mechanism as data. The engine marks
    /// locally queued output pending until NIC acceptance, so local
    /// backpressure does not start a network retransmission timer.
    pub fn push(&mut self, seq: Seq, data: impl Into<Payload>, syn: bool, fin: bool, now: Instant) {
        let data = data.into();
        self.payload_bytes += data.len();
        self.untransmitted += usize::from(self.hold);
        self.segments.push_back(UnackedSegment {
            seq,
            data,
            syn,
            fin,
            first_sent_at: now,
            last_sent_at: now,
            retransmitted: false,
            retransmit_count: 0,
            sacked: false,
            lost: false,
            rexmit_out: false,
            pending_transmit: self.hold,
        });
    }

    /// Whether any segment is marked SACKed or lost. While none is, what
    /// is in flight is simply everything unacknowledged.
    pub fn scoreboard(&self) -> bool {
        self.scoreboard
    }

    /// Makes `seq` a segment boundary, splitting the data segment it
    /// falls inside (a SACK block or one MSS can end mid-segment: a
    /// segment here may be a whole TSO packet).
    fn split_at(&mut self, seq: Seq) {
        let index = self.segments.partition_point(|s| s.end_seq().leq(seq));
        let len = self.segments.len();
        let Some(seg) = self.segments.get_mut(index) else {
            return;
        };
        if !seg.seq.lt(seq) {
            return;
        }
        let n = seq.distance(seg.seq) as usize;
        if n >= seg.data.len() {
            return;
        }
        let right = UnackedSegment {
            seq,
            data: seg.data.slice(n, seg.data.len() - n),
            syn: false,
            fin: false,
            first_sent_at: seg.first_sent_at,
            last_sent_at: seg.last_sent_at,
            retransmitted: seg.retransmitted,
            retransmit_count: seg.retransmit_count,
            sacked: seg.sacked,
            lost: seg.lost,
            rexmit_out: seg.rexmit_out,
            pending_transmit: seg.pending_transmit,
        };
        seg.data = seg.data.slice(0, n);
        // One more segment among those still waiting for the port.
        if right.pending_transmit && index >= len - self.untransmitted.min(len) {
            self.untransmitted += 1;
        }
        self.segments.insert(index + 1, right);
    }

    /// Limits the oldest segment to `mss` bytes, so that resending it
    /// resends all of it.
    pub fn split_front(&mut self, mss: usize) {
        if let Some(front) = self.segments.front()
            && front.data.len() > mss
        {
            self.split_at(front.seq + mss as u32);
        }
    }

    /// Records the peer's SACK blocks. Blocks outside `(snd_una, snd_nxt]`
    /// (stale, duplicate-SACK, or invalid) are ignored.
    pub fn apply_sack(&mut self, blocks: &[(u32, u32)], snd_una: Seq, snd_nxt: Seq) {
        for &(left, right) in blocks {
            let (mut left, right) = (Seq::new(left), Seq::new(right));
            if !left.lt(right) || right.leq(snd_una) || right.gt(snd_nxt) {
                continue;
            }
            if left.lt(snd_una) {
                left = snd_una;
            }
            self.split_at(left);
            self.split_at(right);
            let start = self.segments.partition_point(|s| s.seq.lt(left));
            for seg in self.segments.range_mut(start..) {
                if seg.end_seq().gt(right) {
                    break;
                }
                seg.sacked = true;
                self.scoreboard = true;
            }
        }
    }

    /// RFC 6675 `IsLost`: an unSACKed segment is lost once the peer holds
    /// three segments, or more than two MSS of data, sent after it.
    /// Returns whether any segment was newly marked.
    pub fn detect_lost(&mut self, mss: u32) -> bool {
        let (mut bytes_above, mut segments_above) = (0u32, 0u32);
        let mut any = false;
        for seg in self.segments.iter_mut().rev() {
            if seg.sacked {
                bytes_above = bytes_above.saturating_add(seg.data.len() as u32);
                segments_above += 1;
            } else if (segments_above >= 3 || bytes_above > 2 * mss) && !seg.lost && !seg.syn {
                seg.lost = true;
                seg.rexmit_out = false;
                any = true;
            }
        }
        any
    }

    /// The oldest segment is known lost (third duplicate ACK, or a
    /// partial ACK during recovery) unless a resent copy is still out.
    pub fn mark_front_lost(&mut self) {
        if let Some(front) = self.segments.front_mut()
            && !front.sacked
            && !front.rexmit_out
        {
            front.lost = true;
            self.scoreboard = true;
        }
    }

    /// Retransmission timeout: everything the peer has not reported
    /// holding is presumed lost and is resent as the window reopens.
    pub fn mark_all_lost(&mut self) {
        // The oldest segment cannot both be held by the peer and remain
        // unacknowledged: the peer discarded data it had SACKed (RFC 2018
        // §8), so none of its reports can be trusted.
        if self.segments.front().is_some_and(|s| s.sacked) {
            for seg in &mut self.segments {
                seg.sacked = false;
            }
        }
        for seg in &mut self.segments {
            if !seg.sacked && !seg.pending_transmit {
                seg.lost = true;
                seg.rexmit_out = false;
                self.scoreboard = true;
            }
        }
    }

    /// RFC 6675 `SetPipe`: sequence space believed to be in the network.
    /// SACKed data has left it and lost data never arrived; a resent copy
    /// of lost data is in it.
    pub fn pipe(&self) -> u32 {
        let mut pipe = 0u32;
        for seg in &self.segments {
            if seg.sacked {
                continue;
            }
            let len = seg.end_seq().distance(seg.seq) as u32;
            if !seg.lost || seg.rexmit_out {
                pipe = pipe.saturating_add(len);
            }
        }
        pipe
    }

    fn awaits_resend(seg: &UnackedSegment) -> bool {
        seg.lost && !seg.sacked && !seg.rexmit_out && !seg.syn
    }

    pub fn has_lost_to_send(&self) -> bool {
        self.scoreboard && self.segments.iter().any(Self::awaits_resend)
    }

    /// Takes the oldest lost segment for resending, at most `mss` bytes
    /// of it: its sequence number, data, and whether it is the FIN.
    pub fn take_lost(&mut self, mss: usize, now: Instant) -> Option<(Seq, Payload, bool)> {
        let index = self.segments.iter().position(Self::awaits_resend)?;
        if self.segments[index].data.len() > mss {
            let boundary = self.segments[index].seq + mss as u32;
            self.split_at(boundary);
        }
        let hold = self.hold;
        let seg = &mut self.segments[index];
        seg.rexmit_out = true;
        // Karn: its eventual ACK is ambiguous.
        seg.retransmitted = true;
        seg.last_sent_at = now;
        if hold {
            seg.pending_transmit = true;
        }
        Some((seg.seq, seg.data.clone(), seg.fin))
    }

    /// Chooses whether segments queued from now on wait for
    /// [`RetransmitQueue::mark_transmitted`] before their retransmission
    /// timer runs. A caller that queues output locally ahead of the port
    /// holds them, so local backpressure is not mistaken for loss.
    pub fn hold_until_transmitted(&mut self, hold: bool) {
        self.hold = hold;
    }

    /// The oldest segment is about to be resent: under a hold its timer
    /// waits for the port again.
    pub fn front_resent(&mut self) {
        let hold = self.hold;
        if let Some(front) = self.segments.front_mut() {
            front.rexmit_out = front.lost;
            if hold {
                front.pending_transmit = true;
            }
        }
    }

    /// The port accepted the segment starting at `seq`: its timer runs
    /// from `now`. Unknown sequence numbers (pure ACKs, segments already
    /// acknowledged) are ignored.
    pub fn mark_transmitted(&mut self, seq: Seq, now: Instant) {
        let len = self.segments.len();
        let oldest_waiting = len - self.untransmitted.min(len);
        // A resent segment is the front; anything else is normally the
        // oldest segment still waiting. Fall back to a search otherwise.
        let index = if self.segments.front().is_some_and(|s| s.seq == seq) {
            0
        } else if self
            .segments
            .get(oldest_waiting)
            .is_some_and(|s| s.seq == seq)
        {
            oldest_waiting
        } else if let Ok(index) = self.segments.binary_search_by_key(&seq, |s| s.seq) {
            index
        } else {
            return;
        };
        let seg = &mut self.segments[index];
        if seg.pending_transmit && index == oldest_waiting {
            self.untransmitted = self.untransmitted.saturating_sub(1);
        }
        seg.pending_transmit = false;
        seg.last_sent_at = now;
        if !seg.retransmitted {
            seg.first_sent_at = now;
        }
    }

    /// Drops fully-acked segments given the peer's cumulative ACK
    /// (`snd_una`). Returns an RTT sample from the oldest segment removed
    /// this call, if it qualifies under Karn's algorithm.
    pub fn ack_up_to(&mut self, snd_una: Seq, now: Instant) -> Option<Duration> {
        let mut sample = None;
        while let Some(front) = self.segments.front() {
            if front.end_seq().leq(snd_una) {
                let seg = self.segments.pop_front().unwrap();
                self.payload_bytes -= seg.data.len();
                if !seg.retransmitted && sample.is_none() {
                    sample = now.checked_duration_since(seg.first_sent_at);
                }
            } else {
                // Large TSO ranges can be cumulatively ACKed a segment at a time.
                let front = self.segments.front_mut().unwrap();
                if !front.syn && front.seq.lt(snd_una) {
                    let n = snd_una.distance(front.seq) as usize;
                    if n <= front.data.len() {
                        front.data = front.data.slice(n, front.data.len() - n);
                        front.seq = snd_una;
                        self.payload_bytes -= n;
                    }
                }
                break;
            }
        }
        self.untransmitted = self.untransmitted.min(self.segments.len());
        // RFC 6298 §5.3: an ACK of new data restarts the timer for what
        // is still outstanding. Otherwise a segment sent long ago and
        // lost along with the one just acknowledged would time out the
        // moment it reached the front, before it could be resent.
        if let Some(front) = self.segments.front_mut()
            && !front.pending_transmit
            && front.last_sent_at < now
        {
            front.last_sent_at = now;
        }
        if self.scoreboard {
            self.scoreboard = self.segments.iter().any(|s| s.sacked || s.lost);
        }
        sample
    }

    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn oldest_deadline(&self, rto: Duration) -> Option<Instant> {
        self.segments
            .front()
            .filter(|s| !s.pending_transmit)
            .map(|s| s.last_sent_at + rto)
    }
}
