//! The TCP state machine (RFC 9293 §3.3.2).
//!
//! The connection-teardown half of the diagram lives here as pure
//! transition functions ([`TcpState::on_fin_sent`],
//! [`TcpState::on_fin_received`], [`TcpState::on_fin_acked`]) so the table
//! can be read -- and tested -- in one place. The handshake half depends on
//! sequence-number checks and stays with the segment processing in
//! [`Tcb`](super::tcb::Tcb).
//!
//! ```text
//!                  on_fin_sent            on_fin_acked
//!   Established ----------------> FinWait1 -----------> FinWait2
//!        |                           |                     |
//!        | on_fin_received           | on_fin_received     | on_fin_received
//!        v                           v                     v
//!    CloseWait ---> LastAck       Closing -----------> TimeWait --(2MSL)--> Closed
//!           on_fin_sent  |               on_fin_acked
//!                        +--> Closed
//!                    on_fin_acked
//! ```
//!
//! This stack moves `Closing` straight to `Closed` when its FIN is acked
//! rather than lingering in `TimeWait`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl TcpState {
    /// Data has been exchanged and sequence numbers are meaningful (past
    /// the handshake, not yet torn down enough to stop accepting data).
    pub fn is_synchronized(self) -> bool {
        !matches!(
            self,
            TcpState::Closed | TcpState::Listen | TcpState::SynSent
        )
    }

    /// The local side may still originate new data.
    pub fn can_send(self) -> bool {
        matches!(self, TcpState::Established | TcpState::CloseWait)
    }

    /// The local side may still accept incoming data.
    pub fn can_receive(self) -> bool {
        matches!(
            self,
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
        )
    }

    pub fn is_closed(self) -> bool {
        matches!(self, TcpState::Closed)
    }

    /// The state after this side's FIN goes out. States that cannot send a
    /// FIN are returned unchanged.
    #[must_use]
    pub fn on_fin_sent(self) -> Self {
        match self {
            TcpState::Established => TcpState::FinWait1,
            TcpState::CloseWait => TcpState::LastAck,
            other => other,
        }
    }

    /// The state after the peer's FIN is accepted in order. States in which
    /// a FIN changes nothing are returned unchanged.
    #[must_use]
    pub fn on_fin_received(self) -> Self {
        match self {
            TcpState::Established => TcpState::CloseWait,
            TcpState::FinWait1 => TcpState::Closing,
            TcpState::FinWait2 => TcpState::TimeWait,
            other => other,
        }
    }

    /// The state after the peer acknowledges this side's FIN. States with
    /// no FIN outstanding are returned unchanged.
    #[must_use]
    pub fn on_fin_acked(self) -> Self {
        match self {
            TcpState::FinWait1 => TcpState::FinWait2,
            TcpState::Closing | TcpState::LastAck => TcpState::Closed,
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TcpState::{self, *};

    const ALL: [TcpState; 11] = [
        Closed,
        Listen,
        SynSent,
        SynReceived,
        Established,
        FinWait1,
        FinWait2,
        CloseWait,
        Closing,
        LastAck,
        TimeWait,
    ];

    #[test]
    fn teardown_paths_reach_closed_or_time_wait() {
        // Active close.
        let s = Established.on_fin_sent();
        assert_eq!(s, FinWait1);
        assert_eq!(s.on_fin_acked(), FinWait2);
        assert_eq!(s.on_fin_acked().on_fin_received(), TimeWait);
        // Simultaneous close.
        assert_eq!(s.on_fin_received(), Closing);
        assert_eq!(s.on_fin_received().on_fin_acked(), Closed);
        // Passive close.
        let s = Established.on_fin_received();
        assert_eq!(s, CloseWait);
        assert_eq!(s.on_fin_sent(), LastAck);
        assert_eq!(s.on_fin_sent().on_fin_acked(), Closed);
    }

    #[test]
    fn transitions_leave_unrelated_states_alone() {
        for s in ALL {
            if !matches!(s, Established | CloseWait) {
                assert_eq!(s.on_fin_sent(), s);
            }
            if !matches!(s, Established | FinWait1 | FinWait2) {
                assert_eq!(s.on_fin_received(), s);
            }
            if !matches!(s, FinWait1 | Closing | LastAck) {
                assert_eq!(s.on_fin_acked(), s);
            }
        }
    }
}
