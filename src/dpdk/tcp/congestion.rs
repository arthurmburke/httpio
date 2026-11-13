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
        Self::with_initial_window(mss, 10)
    }

    pub(crate) fn with_initial_window(mss: u16, segments: u16) -> Self {
        assert!(segments > 0);
        let mss = mss as u32;
        Self {
            mss,
            // RFC 6928 initial window: ten segments, bounded in bytes for
            // large MSS values. This is what Linux uses.
            cwnd: if segments == 10 {
                (10 * mss).min((2 * mss).max(14_600))
            } else {
                u32::from(segments) * mss
            },
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
                // RFC 3465 byte counting with L = 2: a receiver that ACKs
                // every other segment (or a whole burst at once) still
                // lets the window double each round trip.
                self.cwnd = self.cwnd.saturating_add(newly_acked.min(2 * self.mss));
                if self.cwnd >= self.ssthresh {
                    self.phase = Phase::CongestionAvoidance;
                }
            }
            Phase::CongestionAvoidance => {
                // Additive increase: +MSS per RTT, approximated as
                // +MSS*MSS/cwnd per ACK.
                let inc = ((self.mss as u64 * self.mss as u64) / self.cwnd as u64).max(1) as u32;
                self.cwnd = self.cwnd.saturating_add(inc);
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
    pub fn on_duplicate_ack(&mut self, recovery_point: u32) -> bool {
        if matches!(self.phase, Phase::FastRecovery { .. }) {
            // Already in recovery: RFC 5681's "artificial inflation" --
            // each further dup ack means another segment left the
            // network, so cwnd can grow by one MSS.
            self.cwnd = self.cwnd.saturating_add(self.mss);
            return false;
        }
        self.dup_ack_count += 1;
        if self.dup_ack_count == 3 {
            self.ssthresh = (self.cwnd / 2).max(self.mss.saturating_mul(2));
            self.cwnd = self.ssthresh.saturating_add(self.mss.saturating_mul(3));
            self.phase = Phase::FastRecovery { recovery_point };
            true
        } else {
            false
        }
    }

    /// Call when the retransmission timer fires (RFC 5681 §3.1 / RFC
    /// 6298 §5): a timeout is a stronger loss signal than dup ACKs, so
    /// congestion control resets to slow start regardless of phase.
    pub fn on_rto_timeout(&mut self, flight_size: u32) {
        self.ssthresh = (flight_size / 2).max(self.mss.saturating_mul(2));
        self.cwnd = self.mss;
        self.phase = Phase::SlowStart;
        self.dup_ack_count = 0;
    }

    pub fn in_fast_recovery(&self) -> bool {
        matches!(self.phase, Phase::FastRecovery { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_window_still_reacts_to_loss() {
        let mut cc = CongestionControl::with_initial_window(1460, 64);
        assert_eq!(cc.cwnd(), 64 * 1460);
        for _ in 0..3 {
            cc.on_duplicate_ack(100);
        }
        cc.on_new_ack(1460, 101);
        assert_eq!(cc.cwnd(), 32 * 1460);
        cc.on_rto_timeout(cc.cwnd());
        assert_eq!(cc.cwnd(), 1460);
    }

    #[test]
    fn slow_start_saturates() {
        let mut cc = CongestionControl::new(1460);
        cc.cwnd = u32::MAX - 10;
        cc.on_new_ack(1460, 1000);
        assert_eq!(cc.cwnd(), u32::MAX);
        cc.on_new_ack(1460, 2000);
        assert_eq!(cc.cwnd(), u32::MAX);
    }

    #[test]
    fn congestion_avoidance_saturates() {
        let mut cc = CongestionControl::new(1460);
        cc.phase = Phase::CongestionAvoidance;
        cc.cwnd = u32::MAX;
        cc.on_new_ack(1460, 1000);
        assert_eq!(cc.cwnd(), u32::MAX);
        cc.cwnd = u32::MAX - 1;
        cc.on_new_ack(1460, 2000);
        assert_eq!(cc.cwnd(), u32::MAX);
    }

    #[test]
    fn fast_recovery_saturates() {
        let mut cc = CongestionControl::new(1460);
        cc.cwnd = u32::MAX;
        assert!(!cc.on_duplicate_ack(500));
        assert!(!cc.on_duplicate_ack(500));
        assert!(cc.on_duplicate_ack(500));
        assert!(cc.in_fast_recovery());
        assert_eq!(cc.ssthresh, u32::MAX / 2);
        cc.cwnd = u32::MAX - 5;
        assert!(!cc.on_duplicate_ack(500));
        assert_eq!(cc.cwnd(), u32::MAX);
        // Exiting recovery is fine too.
        cc.on_new_ack(1460, 600);
        assert_eq!(cc.cwnd(), u32::MAX / 2);
    }

    #[test]
    fn ssthresh_plus_inflation_saturates() {
        let mut cc = CongestionControl::new(1460);
        cc.cwnd = u32::MAX;
        cc.ssthresh = u32::MAX;
        for _ in 0..3 {
            cc.on_duplicate_ack(0);
        }
        // ssthresh = MAX/2, + 3*mss: no overflow.
        assert_eq!(cc.cwnd(), u32::MAX / 2 + 3 * 1460);
    }

    #[test]
    fn rto_resets() {
        let mut cc = CongestionControl::new(1460);
        cc.on_rto_timeout(u32::MAX);
        assert_eq!(cc.cwnd(), 1460);
    }
}
