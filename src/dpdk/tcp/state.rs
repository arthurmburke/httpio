//! The TCP state machine (RFC 9293 §3.3.2).

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
}
