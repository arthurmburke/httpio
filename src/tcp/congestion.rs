//! Reno-style congestion control: slow start, congestion avoidance, fast
//! retransmit, and fast recovery (RFC 5681).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    SlowStart,
    CongestionAvoidance,
    /// Holds the `snd_una` value at the moment fast recovery was entered,
    /// so we can tell a "new ack" (recovery over) from a within-recovery
    /// partial/duplicate ack.
    FastRecovery {
        recovery_point: u32,
    },
}

pub struct CongestionControl {
    mss: u32,
    cwnd: u32,
    ssthresh: u32,
    phase: Phase,
    dup_ack_count: u32,
}

impl CongestionControl {
    pub fn new(mss: u16) -> Self {
        let mss = mss as u32;
        Self {
            mss,
            // RFC 5681 §3.1 initial window (conservative IW = 2*MSS here;
            // real stacks vary the initial window with MSS, capped ~4
            // segments).
            cwnd: 2 * mss,
            ssthresh: u32::MAX,
            phase: Phase::SlowStart,
            dup_ack_count: 0,
        }
    }

    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// Call when a new (previously unacked) byte range is cumulatively
    /// acked; `newly_acked` is how many bytes advanced `snd_una`.
    pub fn on_new_ack(&mut self, newly_acked: u32, snd_una_after: u32) {
        self.dup_ack_count = 0;
        match self.phase {
            Phase::SlowStart => {
                self.cwnd += newly_acked.min(self.mss);
                if self.cwnd >= self.ssthresh {
                    self.phase = Phase::CongestionAvoidance;
                }
            }
            Phase::CongestionAvoidance => {
                // Additive increase: +MSS per RTT, approximated as
                // +MSS*MSS/cwnd per ACK.
                let inc = ((self.mss as u64 * self.mss as u64) / self.cwnd as u64).max(1) as u32;
                self.cwnd += inc;
            }
            Phase::FastRecovery { recovery_point } => {
                if snd_una_after.wrapping_sub(recovery_point) as i32 >= 0 {
                    // The retransmitted segment (and everything before
                    // recovery) is now acked: recovery is over.
                    self.cwnd = self.ssthresh;
                    self.phase = Phase::CongestionAvoidance;
                } else {
                    // Partial ack: a further segment was lost. Deflate
                    // cwnd by the amount acked (NewReno-lite) and stay in
                    // recovery so the next lost segment gets retransmitted
                    // too.
                    self.cwnd = self.cwnd.saturating_sub(newly_acked).max(self.mss);
                }
            }
        }
    }

    /// Call on every duplicate ACK (one that does not advance `snd_una`).
    /// Returns `true` exactly once recovery should trigger a fast
    /// retransmit (the 3rd duplicate).
    pub fn on_duplicate_ack(&mut self, snd_una: u32) -> bool {
        if matches!(self.phase, Phase::FastRecovery { .. }) {
            // Already in recovery: RFC 5681's "artificial inflation" --
            // each further dup ack means another segment left the
            // network, so cwnd can grow by one MSS.
            self.cwnd += self.mss;
            return false;
        }
        self.dup_ack_count += 1;
        if self.dup_ack_count == 3 {
            self.ssthresh = (self.cwnd / 2).max(2 * self.mss);
            self.cwnd = self.ssthresh + 3 * self.mss;
            self.phase = Phase::FastRecovery {
                recovery_point: snd_una,
            };
            true
        } else {
            false
        }
    }

    /// Call when the retransmission timer fires (RFC 5681 §3.1 / RFC
    /// 6298 §5): a timeout is a stronger loss signal than dup ACKs, so
    /// congestion control resets to slow start regardless of phase.
    pub fn on_rto_timeout(&mut self, flight_size: u32) {
        self.ssthresh = (flight_size / 2).max(2 * self.mss);
        self.cwnd = self.mss;
        self.phase = Phase::SlowStart;
        self.dup_ack_count = 0;
    }

    pub fn in_fast_recovery(&self) -> bool {
        matches!(self.phase, Phase::FastRecovery { .. })
    }
}
