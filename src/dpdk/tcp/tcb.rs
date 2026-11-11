//! The Transmission Control Block: all per-connection state, and the RFC
//! 9293 §3.10 segment-processing state machine.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::dpdk::net::tcp::{TcpHeader, TcpOptions, flags};

use super::congestion::CongestionControl;
use super::rto::{MAX_RETRANSMITS, MAX_RTO, RetransmitQueue, RtoEstimator};
use super::rx_queue::ReassemblyBuffer;
use super::seq::Seq;
use super::state::TcpState;
use super::tx_queue::{Payload, SendBuffer};

pub const DEFAULT_MSS: u16 = 1460;
/// RFC 9293 §3.7.1: the default MSS to assume for a peer that didn't send
/// an MSS option.
const FALLBACK_PEER_MSS: u16 = 536;
/// Local receive-window ceiling: without window scaling this stack is
/// capped at 65535 like RFC 9293 §3.1 requires.
const RECV_BUFFER_CAPACITY: u32 = 64 * 1024;
/// RFC 9293 §3.10.7.4 / RFC 6191: 2*MSL time-wait duration; shortened well
/// below the traditional 4 minutes for a lab/demo-scale stack.
pub const TIME_WAIT_DURATION: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FourTuple {
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
}

/// A segment the engine should serialize onto the wire.
pub struct OutSegment {
    pub seq: Seq,
    pub ack: Seq,
    pub flags: u8,
    pub window: u16,
    pub payload: Payload,
    pub mss: Option<u16>,
}

/// Notable state transitions the engine/socket layer needs to react to
/// (e.g. wake up a blocked `accept`/`connect`/`recv` caller).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Established,
    PeerClosed,
    Closed,
    Reset,
}

pub struct Tcb {
    pub tuple: FourTuple,
    pub state: TcpState,

    // Send sequence variables (RFC 9293 §3.3.1).
    iss: Seq,
    snd_una: Seq,
    snd_nxt: Seq,
    snd_wnd: u32,
    snd_wl1: Seq,
    snd_wl2: Seq,

    // Receive sequence variables.
    irs: Seq,
    rcv_nxt: Seq,

    peer_mss: u16,
    local_mss: u16,

    retransmit: RetransmitQueue,
    rto: RtoEstimator,
    congestion: CongestionControl,
    send_buffer: SendBuffer,
    recv_buffer: ReassemblyBuffer,

    ack_pending: bool,
    want_syn: bool,
    want_synack: bool,
    want_fin: bool,
    fin_sent: bool,
    want_rst: bool,
    close_requested: bool,
    retransmit_now: bool,
    /// SEG.ACK of an unacceptable handshake ACK: RFC 9293 §3.10.7.3 /
    /// §3.10.7.4 require the answering RST to use it as its sequence number
    /// (`<SEQ=SEG.ACK><CTL=RST>`). `None` means the RST uses `snd_nxt`.
    rst_seq: Option<Seq>,

    /// Zero-window probe timer (RFC 9293 §3.8.6.1): armed while data is
    /// buffered, nothing is in flight, and the peer's window is zero.
    persist_deadline: Option<Instant>,
    /// Interval to use for the next persist arming; doubles per probe up to
    /// `MAX_RTO` and resets once the window opens or the buffer empties.
    persist_backoff: Option<Duration>,
    /// The persist timer fired: the next output poll sends a 1-byte probe.
    persist_probe_now: bool,
    /// A window probe is unacknowledged. A peer that answers it (even with
    /// a zero window) is alive, so such answers reset its retransmit count.
    probe_outstanding: bool,

    /// TCP_NODELAY: when set, Nagle's algorithm (RFC 9293 §3.7.4) is
    /// disabled and sub-MSS segments are sent immediately instead of
    /// waiting for in-flight data to be acked.
    nodelay: bool,
    /// TCP_CORK-style hold: full-MSS segments still flow, but a trailing
    /// sub-MSS segment is held back until `flush()` releases it (or the
    /// connection is closed, which flushes implicitly).
    corked: bool,
    /// One-shot release for `corked`: set by `flush()`, cleared once the
    /// send buffer has fully drained to the wire.
    flush_requested: bool,

    time_wait_deadline: Option<Instant>,

    pub events: Vec<Event>,
}

fn random_iss() -> Seq {
    use std::time::{SystemTime, UNIX_EPOCH};
    // RFC 9293 §3.4.1 just requires an unpredictable-ish, roughly
    // time-driven ISS; a full PRNG isn't in scope here.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u32;
    Seq::new(nanos)
}

impl Tcb {
    fn new(tuple: FourTuple, state: TcpState) -> Self {
        let iss = random_iss();
        Self {
            tuple,
            state,
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 0,
            snd_wl1: Seq::new(0),
            snd_wl2: Seq::new(0),
            irs: Seq::new(0),
            rcv_nxt: Seq::new(0),
            peer_mss: FALLBACK_PEER_MSS,
            local_mss: DEFAULT_MSS,
            retransmit: RetransmitQueue::default(),
            rto: RtoEstimator::default(),
            congestion: CongestionControl::new(DEFAULT_MSS),
            send_buffer: SendBuffer::default(),
            recv_buffer: ReassemblyBuffer::default(),
            ack_pending: false,
            want_syn: false,
            want_synack: false,
            want_fin: false,
            fin_sent: false,
            want_rst: false,
            close_requested: false,
            retransmit_now: false,
            rst_seq: None,
            persist_deadline: None,
            persist_backoff: None,
            persist_probe_now: false,
            probe_outstanding: false,
            nodelay: false,
            corked: false,
            flush_requested: false,
            time_wait_deadline: None,
            events: Vec::new(),
        }
    }

    /// Active open: RFC 9293 §3.10.1.
    pub fn new_active(tuple: FourTuple) -> Self {
        let mut tcb = Self::new(tuple, TcpState::SynSent);
        tcb.snd_nxt = tcb.iss + 1;
        tcb.want_syn = true;
        tcb
    }

    /// Passive open, spawned once a SYN lands on a listening port: RFC
    /// 9293 §3.10.7.2.
    pub fn new_from_listen(tuple: FourTuple, peer_iss: Seq, peer_mss: u16) -> Self {
        let mut tcb = Self::new(tuple, TcpState::SynReceived);
        tcb.irs = peer_iss;
        tcb.rcv_nxt = peer_iss + 1;
        tcb.peer_mss = peer_mss.clamp(1, DEFAULT_MSS);
        tcb.congestion = CongestionControl::new(tcb.peer_mss);
        tcb.snd_nxt = tcb.iss + 1;
        tcb.want_synack = true;
        tcb
    }

    pub fn is_closed(&self) -> bool {
        self.state.is_closed()
    }

    pub fn in_time_wait(&self) -> bool {
        matches!(self.state, TcpState::TimeWait)
    }

    // ---- application-facing operations ---------------------------------

    pub fn send(&mut self, data: Bytes) {
        self.send_buffer.push(data);
    }

    /// Bound segmentation by the local link and single-mbuf capacity.
    /// The engine applies this before the first SYN and every output poll.
    pub(crate) fn set_local_mss(&mut self, mss: u16) {
        self.local_mss = mss.min(DEFAULT_MSS);
    }

    /// TCP_NODELAY. `true` disables Nagle's algorithm: sub-MSS segments
    /// go out immediately rather than waiting for outstanding data to be
    /// acked. Has no effect while corked -- the cork gate is stricter and
    /// checked first.
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
    }

    /// TCP_CORK-style hold. While corked, full-MSS segments still flow
    /// but a trailing partial segment is held back until `flush()`.
    /// Uncorking releases anything currently held.
    pub fn set_cork(&mut self, corked: bool) {
        self.corked = corked;
        if !corked {
            self.flush_requested = true;
        }
    }

    /// Manual trigger: release the held tail segment (one-shot; the cork
    /// stays in place for data buffered after this flush completes).
    pub fn flush(&mut self) {
        self.flush_requested = true;
    }

    pub fn recv(&mut self, max_len: usize) -> Bytes {
        let data = self.recv_buffer.read(max_len);
        if !data.is_empty() && self.state.can_receive() {
            // Advertise the newly available space without waiting for
            // another peer packet (especially when its window is zero).
            self.ack_pending = true;
        }
        data
    }

    pub fn readable_len(&self) -> usize {
        self.recv_buffer.readable_len()
    }

    /// Application-initiated close: RFC 9293 §3.10.4. The FIN is deferred
    /// until any buffered data has actually been sent.
    pub fn close(&mut self) {
        self.close_requested = true;
        // Implicit flush: the FIN is only sent once the send buffer has
        // drained, so a corked/Nagle-held tail must be released or the
        // close would deadlock waiting on a trigger that never comes.
        self.flush_requested = true;
    }

    fn flight_size(&self) -> u32 {
        self.snd_nxt.distance(self.snd_una).max(0) as u32
    }

    // ---- inbound segment processing ------------------------------------

    /// RFC 9293 §3.10.7: processes one incoming segment against the
    /// current state.
    ///
    /// `payload` is an owned, refcounted slice of the RX mbuf (see
    /// [`Mbuf::into_bytes`](crate::dpdk::Mbuf::into_bytes)); if accepted it
    /// moves into the reassembly buffer without being copied.
    pub fn on_segment(&mut self, hdr: &TcpHeader, payload: Bytes, now: Instant) {
        self.on_segment_with(hdr, payload.len(), || payload, now);
    }

    /// Materialize payload ownership only after TCP accepts the segment.
    pub(crate) fn on_segment_with(
        &mut self,
        hdr: &TcpHeader,
        payload_len: usize,
        payload: impl FnOnce() -> Bytes,
        now: Instant,
    ) {
        if hdr.has_flag(flags::RST) {
            if self.reset_is_acceptable(hdr) {
                self.on_reset();
            }
            return;
        }

        match self.state {
            TcpState::SynSent => self.on_segment_syn_sent(hdr, now),
            _ => self.on_segment_general(hdr, payload_len as u32, payload, now),
        }
    }

    fn on_reset(&mut self) {
        self.state = TcpState::Closed;
        self.events.push(Event::Reset);
    }

    /// Validates an incoming reset before allowing it to tear down the
    /// connection. In SYN-SENT, RFC 9293 requires an acceptable ACK. In
    /// synchronized states, RFC 5961 §3 accepts an exact RCV.NXT match and
    /// sends a challenge ACK for another sequence number inside the window.
    fn reset_is_acceptable(&mut self, hdr: &TcpHeader) -> bool {
        match self.state {
            TcpState::SynSent => {
                if !hdr.has_flag(flags::ACK) {
                    return false;
                }
                let ack = Seq::new(hdr.ack);
                ack.gt(self.iss) && ack.leq(self.snd_nxt)
            }
            TcpState::TimeWait => false,
            state if state.is_synchronized() => {
                let seq = Seq::new(hdr.seq);
                if seq == self.rcv_nxt {
                    return true;
                }

                let rcv_wnd = RECV_BUFFER_CAPACITY
                    .saturating_sub(self.recv_buffer.readable_len() as u32)
                    .max(1);
                if seq.in_range(self.rcv_nxt, self.rcv_nxt + rcv_wnd) {
                    self.ack_pending = true;
                }
                false
            }
            _ => false,
        }
    }

    fn on_segment_syn_sent(&mut self, hdr: &TcpHeader, now: Instant) {
        if hdr.has_flag(flags::ACK) {
            // Must ack our SYN, not something old/future (RFC 9293
            // §3.10.7.3 step 1).
            let ack = Seq::new(hdr.ack);
            if ack.leq(self.iss) || ack.gt(self.snd_nxt) {
                self.want_rst = true;
                self.rst_seq = Some(ack);
                return;
            }
        }
        if !hdr.has_flag(flags::SYN) {
            return;
        }
        self.irs = Seq::new(hdr.seq);
        self.rcv_nxt = self.irs + 1;
        self.peer_mss = hdr
            .options
            .mss
            .unwrap_or(FALLBACK_PEER_MSS)
            .clamp(1, DEFAULT_MSS);
        self.congestion = CongestionControl::new(self.peer_mss);

        if hdr.has_flag(flags::ACK) {
            self.snd_una = Seq::new(hdr.ack);
            if let Some(rtt) = self.retransmit.ack_up_to(self.snd_una, now) {
                self.rto.sample(rtt);
            }
            self.state = TcpState::Established;
            self.snd_wnd = hdr.window as u32;
            self.snd_wl1 = self.irs;
            self.snd_wl2 = self.snd_una;
            self.ack_pending = true;
            self.events.push(Event::Established);
        } else {
            // Simultaneous open (RFC 9293 §3.10.7.3 step 2): both sides
            // sent SYN before either ACK arrived.
            self.state = TcpState::SynReceived;
            self.want_synack = true;
        }
    }

    fn on_segment_general(
        &mut self,
        hdr: &TcpHeader,
        payload_len: u32,
        payload: impl FnOnce() -> Bytes,
        now: Instant,
    ) {
        // A lost SYN-ACK causes the peer to repeat its original SYN.
        // Reuse the outstanding SYN-ACK rather than enqueueing another
        // retransmit entry or resetting an otherwise valid handshake.
        if self.state == TcpState::SynReceived
            && hdr.has_flag(flags::SYN)
            && !hdr.has_flag(flags::ACK | flags::FIN)
            && Seq::new(hdr.seq) == self.irs
            && payload_len == 0
        {
            if let Some(seg) = self.retransmit.segments.front_mut() {
                seg.retransmitted = true;
                seg.last_sent_at = now;
                self.retransmit_now = true;
            }
            return;
        }
        // RFC 9293 §3.10.7.4 step 1: drop segments outside the receive
        // window entirely (for SynReceived/Listen-derived TCBs the window
        // isn't open yet, so any incoming SYN retransmit / stray segment
        // is checked once rcv_nxt is meaningful).
        if self.state.is_synchronized() && !hdr.has_flag(flags::SYN) {
            // RFC 9293 §3.10.7.4 step 1 (simplified): the segment must
            // overlap the currently advertised receive window.
            let seq = Seq::new(hdr.seq);
            let seg_len = payload_len + if hdr.has_flag(flags::FIN) { 1 } else { 0 };
            let rcv_wnd = RECV_BUFFER_CAPACITY
                .saturating_sub(self.recv_buffer.readable_len() as u32)
                .max(1);
            let window_end = self.rcv_nxt + rcv_wnd;
            let overlaps_window = seq.lt(window_end) && (seq + seg_len.max(1)).gt(self.rcv_nxt);
            if !overlaps_window {
                self.ack_pending = true; // stray segment: re-ACK our state
                // RFC 9293 §3.10.7.4 (TIME-WAIT): a retransmitted FIN means
                // our ACK was lost; re-ACK it and restart the 2MSL timer.
                if self.state == TcpState::TimeWait
                    && hdr.has_flag(flags::FIN)
                    && seq + payload_len + 1 == self.rcv_nxt
                {
                    self.time_wait_deadline = Some(now + TIME_WAIT_DURATION);
                }
                return;
            }
        }

        if hdr.has_flag(flags::SYN) && self.state.is_synchronized() {
            // RFC 9293 §3.10.7.4 step 4: SYN in the window after the
            // connection is synchronized is an error -> reset.
            self.want_rst = true;
            self.rst_seq = None;
            self.state = TcpState::Closed;
            self.events.push(Event::Reset);
            return;
        }

        if hdr.has_flag(flags::ACK) {
            self.process_ack(hdr, payload_len, now);
            if self.state.is_closed() {
                return;
            }
        } else {
            return; // RFC 9293 §3.10.7.4 step 5: no ACK -> drop.
        }

        if self.state.can_receive() && payload_len != 0 {
            // Enforce the advertised window [rcv_nxt, rcv_nxt + rcv_wnd):
            // in-order and out-of-order data alike is truncated at the right
            // edge, and a segment wholly beyond it (or any data while the
            // window is zero) is dropped. A truncated segment's FIN is not
            // consumed because `on_fin` compares against the original length.
            let seq = Seq::new(hdr.seq);
            let rcv_wnd =
                RECV_BUFFER_CAPACITY.saturating_sub(self.recv_buffer.readable_len() as u32);
            let right_edge = self.rcv_nxt + rcv_wnd;
            let keep = if seq.geq(right_edge) {
                0
            } else {
                payload_len.min(right_edge.distance(seq) as u32)
            };
            if keep != 0 {
                let mut data = payload();
                if (keep as usize) < data.len() {
                    data.truncate(keep as usize);
                }
                let new_rcv_nxt = self.recv_buffer.insert(seq, data, self.rcv_nxt);
                if new_rcv_nxt != self.rcv_nxt {
                    self.rcv_nxt = new_rcv_nxt;
                }
            }
            self.ack_pending = true;
        }

        if hdr.has_flag(flags::FIN) && self.state.is_synchronized() {
            self.on_fin(hdr, payload_len, now);
        }
    }

    fn process_ack(&mut self, hdr: &TcpHeader, payload_len: u32, now: Instant) {
        let ack = Seq::new(hdr.ack);

        match self.state {
            TcpState::SynReceived => {
                if ack.leq(self.snd_una) || ack.gt(self.snd_nxt) {
                    self.want_rst = true;
                    self.rst_seq = Some(ack);
                    return;
                }
                self.snd_una = ack;
                if let Some(rtt) = self.retransmit.ack_up_to(self.snd_una, now) {
                    self.rto.sample(rtt);
                }
                self.state = TcpState::Established;
                self.snd_wnd = hdr.window as u32;
                self.snd_wl1 = Seq::new(hdr.seq);
                self.snd_wl2 = ack;
                self.events.push(Event::Established);
                return;
            }
            TcpState::LastAck => {
                if ack.geq(self.snd_nxt) {
                    self.state = TcpState::Closed;
                    self.events.push(Event::Closed);
                }
                return;
            }
            _ => {}
        }

        if ack.gt(self.snd_nxt) {
            self.ack_pending = true; // acks something not yet sent
            return;
        }

        if ack.gt(self.snd_una) {
            let newly_acked = ack.distance(self.snd_una) as u32;
            self.snd_una = ack;
            if let Some(rtt) = self.retransmit.ack_up_to(self.snd_una, now) {
                self.rto.sample(rtt);
            }
            let was_in_recovery = self.congestion.in_fast_recovery();
            self.congestion.on_new_ack(newly_acked, ack.0);
            if was_in_recovery && self.congestion.in_fast_recovery() {
                // Partial ACK (RFC 6582 §3.2): the next unacked segment was
                // lost too; retransmit it now instead of waiting for an RTO.
                // Karn: the retransmission makes its eventual ACK ambiguous.
                if let Some(seg) = self.retransmit.segments.front_mut() {
                    seg.retransmitted = true;
                    seg.last_sent_at = now;
                    self.retransmit_now = true;
                }
            }
            self.update_send_window(hdr, ack);
        } else if ack == self.snd_una {
            // RFC 5681 §2: a duplicate ACK carries no data and doesn't
            // move the window; with nothing in flight it's just a normal
            // keepalive-style ACK, not a loss signal.
            let is_dup_candidate =
                payload_len == 0 && !hdr.has_flag(flags::SYN) && !hdr.has_flag(flags::FIN);
            if is_dup_candidate
                && !self.probe_outstanding
                && self.flight_size() > 0
                && self.congestion.on_duplicate_ack(self.snd_nxt.0)
            {
                // Karn's algorithm: an ACK after this retransmission is
                // ambiguous and must not produce an RTT sample. Restart
                // the oldest segment's timer from this transmission.
                if let Some(seg) = self.retransmit.segments.front_mut() {
                    seg.retransmitted = true;
                    seg.last_sent_at = now;
                }
                self.retransmit_now = true;
            }
            self.update_send_window(hdr, ack);
        }

        if self.probe_outstanding {
            if self.flight_size() == 0 || self.snd_wnd > 0 {
                self.probe_outstanding = false;
            } else if hdr.window == 0
                && let Some(seg) = self.retransmit.segments.front_mut()
            {
                // The peer answered the probe (still advertising zero):
                // it is alive, so keep probing indefinitely rather than
                // counting this toward retransmission exhaustion.
                seg.retransmit_count = 0;
            }
        }

        match self.state {
            TcpState::FinWait1 if self.fin_sent && ack.geq(self.snd_nxt) => {
                self.state = TcpState::FinWait2;
            }
            TcpState::Closing if ack.geq(self.snd_nxt) => {
                self.state = TcpState::Closed;
                self.events.push(Event::Closed);
            }
            _ => {}
        }
    }

    fn update_send_window(&mut self, hdr: &TcpHeader, ack: Seq) {
        let seq = Seq::new(hdr.seq);
        if self.snd_wl1.lt(seq) || (self.snd_wl1 == seq && self.snd_wl2.leq(ack)) {
            self.snd_wnd = hdr.window as u32;
            self.snd_wl1 = seq;
            self.snd_wl2 = ack;
        }
    }

    fn on_fin(&mut self, hdr: &TcpHeader, payload_len: u32, now: Instant) {
        // The FIN consumes the sequence number immediately after any data
        // carried in the same segment. Only advance for an in-order FIN;
        // an out-of-order one is simply not acked yet, and the peer will
        // retransmit once the gap ahead of it closes.
        let fin_seq = Seq::new(hdr.seq) + payload_len;
        if fin_seq != self.rcv_nxt {
            return;
        }
        self.rcv_nxt = self.rcv_nxt + 1;
        self.ack_pending = true;
        self.events.push(Event::PeerClosed);

        self.state = match self.state {
            TcpState::Established => TcpState::CloseWait,
            TcpState::FinWait1 => TcpState::Closing,
            TcpState::FinWait2 => {
                self.time_wait_deadline = Some(now + TIME_WAIT_DURATION);
                TcpState::TimeWait
            }
            other => other,
        };
    }

    // ---- timers ----------------------------------------------------------

    /// Drives retransmission timeouts and TIME_WAIT expiry. Call
    /// periodically (e.g. every main-loop iteration).
    pub fn tick(&mut self, now: Instant) {
        if self.is_closed() {
            return;
        }
        self.update_persist(now);
        if let Some(deadline) = self.persist_deadline
            && now >= deadline
        {
            self.persist_deadline = None;
            self.persist_probe_now = true;
        }
        if let Some(deadline) = self.time_wait_deadline
            && now >= deadline
        {
            self.state = TcpState::Closed;
            self.events.push(Event::Closed);
            return;
        }

        if let Some(deadline) = self.retransmit.oldest_deadline(self.rto.rto())
            && now >= deadline
        {
            self.on_rto(now);
        }
    }

    /// RFC 9293 §3.8.6.1: data is buffered, nothing is in flight to elicit
    /// an ACK, and the peer's window is zero, so only a probe can learn
    /// that the window reopened.
    fn persist_needed(&self) -> bool {
        self.state.can_send()
            && !self.send_buffer.is_empty()
            && self.snd_wnd == 0
            && self.flight_size() == 0
    }

    /// Arms or disarms the persist timer to match `persist_needed`. The
    /// backoff survives while a probe is in flight and is reset once the
    /// window opens or the buffer empties.
    fn update_persist(&mut self, now: Instant) {
        if self.persist_needed() {
            if self.persist_deadline.is_none() && !self.persist_probe_now {
                let interval = self.persist_backoff.unwrap_or_else(|| self.rto.rto());
                self.persist_deadline = Some(now + interval);
                self.persist_backoff = Some((interval * 2).min(MAX_RTO));
            }
        } else {
            self.persist_deadline = None;
            self.persist_probe_now = false;
            if self.snd_wnd > 0 || self.send_buffer.is_empty() {
                self.persist_backoff = None;
            }
        }
    }

    fn on_rto(&mut self, now: Instant) {
        self.congestion.on_rto_timeout(self.flight_size());
        self.rto.backoff();
        if let Some(seg) = self.retransmit.segments.front_mut() {
            seg.retransmitted = true;
            seg.retransmit_count += 1;
            seg.last_sent_at = now;
            if seg.retransmit_count > MAX_RETRANSMITS {
                self.want_rst = true;
                self.rst_seq = None;
                self.state = TcpState::Closed;
                // An aborted connection must reach the worker's error
                // path, including after the handshake has completed.
                self.events.push(Event::Reset);
                return;
            }
            self.retransmit_now = true;
        }
    }

    // ---- outbound segment construction -----------------------------------

    /// Gathers every segment that should go out right now: handshake
    /// control segments, retransmits, new data (bounded by cwnd/rwnd),
    /// FIN, and standalone ACKs. Use `poll_output_into` to reuse storage.
    pub fn poll_output(&mut self, now: Instant) -> Vec<OutSegment> {
        let mut out = Vec::new();
        self.poll_output_into(now, &mut out);
        out
    }

    /// Writes into reusable caller storage, retaining its capacity.
    pub fn poll_output_into(&mut self, now: Instant, out: &mut Vec<OutSegment>) {
        out.clear();

        if self.want_rst {
            self.want_rst = false;
            let seq = self.rst_seq.take().unwrap_or(self.snd_nxt);
            out.push(self.make_segment(seq, flags::RST, Bytes::new(), None));
            return;
        }

        if self.is_closed() {
            return;
        }

        if self.want_syn {
            self.want_syn = false;
            self.retransmit
                .push(self.iss, Bytes::new(), true, false, now);
            out.push(self.make_segment(self.iss, flags::SYN, Bytes::new(), Some(self.local_mss)));
            return;
        }

        if self.want_synack {
            self.want_synack = false;
            self.retransmit
                .push(self.iss, Bytes::new(), true, false, now);
            out.push(self.make_segment(
                self.iss,
                flags::SYN | flags::ACK,
                Bytes::new(),
                Some(self.local_mss),
            ));
            return;
        }

        // Retransmit: `on_rto` (called from `tick`) sets this when the
        // oldest unacked segment's timer has just expired. A SYN retransmit
        // only ever happens while still in SynSent (a bare SYN, no ACK); a
        // SYN-ACK retransmit only while still in SynReceived -- so "carry
        // ACK unless we're in SynSent" correctly distinguishes the two.
        if self.retransmit_now {
            self.retransmit_now = false;
            if let Some(seg) = self.retransmit.segments.front() {
                let seq = seg.seq;
                let data = seg.data.clone();
                let mut seg_flags = 0u8;
                if seg.syn {
                    seg_flags |= flags::SYN;
                }
                if seg.fin {
                    seg_flags |= flags::FIN;
                }
                if !matches!(self.state, TcpState::SynSent) {
                    seg_flags |= flags::ACK;
                }
                let mss = seg.syn.then_some(self.local_mss);
                out.push(self.make_segment(seq, seg_flags, data, mss));
            }
        }

        if self.state.can_send() {
            self.send_new_data(now, out);
        }

        if self.close_requested
            && !self.want_fin
            && !self.fin_sent
            && self.send_buffer.is_empty()
            && self.retransmit.is_empty()
            && matches!(self.state, TcpState::Established | TcpState::CloseWait)
        {
            self.want_fin = true;
        }

        if self.want_fin {
            self.want_fin = false;
            self.fin_sent = true;
            let seq = self.snd_nxt;
            self.snd_nxt = self.snd_nxt + 1;
            self.retransmit.push(seq, Bytes::new(), false, true, now);
            self.state = match self.state {
                TcpState::Established => TcpState::FinWait1,
                TcpState::CloseWait => TcpState::LastAck,
                other => other,
            };
            out.push(self.make_segment(seq, flags::FIN | flags::ACK, Bytes::new(), None));
        } else if self.ack_pending && out.is_empty() {
            self.ack_pending = false;
            out.push(self.make_segment(self.snd_nxt, flags::ACK, Bytes::new(), None));
        }
    }

    fn send_new_data(&mut self, now: Instant, out: &mut Vec<OutSegment>) {
        // Zero-window probe: one byte as an ordinary data segment, so the
        // retransmit queue and ACK processing handle it like any other.
        if self.persist_probe_now {
            self.persist_probe_now = false;
            if self.persist_needed() {
                let data = self.send_buffer.take(1);
                let seq = self.snd_nxt;
                self.snd_nxt = self.snd_nxt + data.len() as u32;
                self.retransmit.push(seq, data.clone(), false, false, now);
                self.probe_outstanding = true;
                out.push(self.make_segment(seq, flags::ACK | flags::PSH, data, None));
                self.ack_pending = false;
            }
        }

        loop {
            let usable_window = self.snd_wnd.min(self.congestion.cwnd());
            let flight = self.flight_size();
            let available = usable_window.saturating_sub(flight);
            if available == 0 || self.send_buffer.is_empty() {
                break;
            }
            let mss = self.peer_mss.min(self.local_mss) as usize;
            let chunk_len = (available as usize).min(mss).min(self.send_buffer.len());
            if chunk_len == 0 {
                break;
            }

            // Tail gating. Only the *true* tail is gated: a segment that
            // is sub-MSS because the send buffer has run down, not one
            // clamped short by the window (holding window-clamped data
            // would interact badly with a zero-window-ish peer).
            let is_partial_tail =
                self.send_buffer.len() < mss && available as usize >= self.send_buffer.len();
            if is_partial_tail && !self.flush_requested {
                // TCP_CORK: hold the tail until an explicit flush().
                if self.corked {
                    break;
                }
                // Nagle (RFC 9293 §3.7.4): with older data still in
                // flight, buffer the tail until that data is acked --
                // unless TCP_NODELAY turned this off.
                if !self.nodelay && flight > 0 {
                    break;
                }
            }

            let data = self.send_buffer.take(chunk_len);
            let seq = self.snd_nxt;
            self.snd_nxt = self.snd_nxt + data.len() as u32;
            self.retransmit.push(seq, data.clone(), false, false, now);
            out.push(self.make_segment(seq, flags::ACK | flags::PSH, data, None));
            self.ack_pending = false;
        }

        // A flush is one-shot: once everything buffered at flush time has
        // hit the wire, re-arm the cork for whatever comes next. If the
        // window stopped us short, keep it pending so the remainder
        // (including the tail) drains as the window reopens.
        if self.send_buffer.is_empty() {
            self.flush_requested = false;
        }

        self.update_persist(now);
    }

    fn make_segment(
        &self,
        seq: Seq,
        flags: u8,
        payload: impl Into<Payload>,
        mss: Option<u16>,
    ) -> OutSegment {
        let window = RECV_BUFFER_CAPACITY
            .saturating_sub(self.recv_buffer.readable_len() as u32)
            .min(u16::MAX as u32) as u16;
        OutSegment {
            seq,
            ack: self.rcv_nxt,
            flags,
            window,
            payload: payload.into(),
            mss,
        }
    }

    pub fn to_header(&self, seg: &OutSegment) -> TcpHeader {
        TcpHeader {
            src_port: self.tuple.local_port,
            dst_port: self.tuple.remote_port,
            seq: seg.seq.0,
            ack: seg.ack.0,
            flags: seg.flags,
            window: seg.window,
            urgent_pointer: 0,
            options: TcpOptions { mss: seg.mss },
        }
    }

    /// Whether there is anything worth waking the poll loop up early for
    /// (as opposed to waiting for the next timer tick).
    pub fn has_pending_output(&self) -> bool {
        // A corked tail (or a Nagle-held one waiting on an ACK) is not
        // "pending" -- nothing will go out until flush()/an ACK arrives,
        // so don't make a wakeup-hint-driven caller spin on it.
        // Likewise data blocked only by a zero send window: the persist
        // timer (see `has_armed_timer`) drives the probe, not a busy poll.
        let sendable_data = self.state.can_send()
            && !self.send_buffer.is_empty()
            && self.snd_wnd > 0
            && (self.send_buffer.len() >= self.peer_mss.min(self.local_mss) as usize
                || self.flush_requested
                || (!self.corked && self.nodelay)
                || (!self.corked && self.flight_size() == 0));
        self.want_syn
            || self.want_synack
            || self.want_rst
            || self.ack_pending
            || self.retransmit_now
            || self.persist_probe_now
            || sendable_data
            // A FIN still waiting to be sent (close requested, buffer
            // drained, not yet sent).
            || (self.close_requested && !self.fin_sent && self.send_buffer.is_empty())
    }

    /// Whether a retransmission, persist or TIME_WAIT timer is armed, i.e. the
    /// connection needs `tick`ing on future polls even with no pending
    /// output. Together with `has_pending_output`, this is what keeps a
    /// connection in the engine's active set; a connection with neither is
    /// fully idle and can be skipped until an inbound frame or app call.
    pub fn has_armed_timer(&self) -> bool {
        !self.retransmit.is_empty()
            || self.time_wait_deadline.is_some()
            // Reported as soon as the persist condition holds (before the
            // deadline is armed by the next tick/poll) so the engine ticks it.
            || self.persist_deadline.is_some()
            || self.persist_needed()
    }
}

#[cfg(test)]
mod tests {
    use super::super::rto::MAX_RTO;
    use super::*;

    fn tuple() -> FourTuple {
        FourTuple {
            local_ip: Ipv4Addr::new(10, 0, 0, 1),
            local_port: 49152,
            remote_ip: Ipv4Addr::new(10, 0, 0, 2),
            remote_port: 80,
        }
    }

    fn header(seq: Seq, ack: Seq, flags: u8, window: u16) -> TcpHeader {
        TcpHeader {
            src_port: 80,
            dst_port: 49152,
            seq: seq.0,
            ack: ack.0,
            flags,
            window,
            urgent_pointer: 0,
            options: TcpOptions::default(),
        }
    }

    fn establish(now: Instant) -> Tcb {
        let mut tcb = Tcb::new_active(tuple());
        let _syn = tcb.poll_output(now);
        let syn_ack = header(
            Seq::new(1000),
            tcb.snd_nxt,
            flags::SYN | flags::ACK,
            u16::MAX,
        );
        tcb.on_segment(&syn_ack, Bytes::new(), now);
        let _ack = tcb.poll_output(now);
        assert_eq!(tcb.state, TcpState::Established);
        tcb
    }

    #[test]
    fn segmentation_respects_peer_and_local_limits() {
        let now = Instant::now();
        for peer_mss in [0, 536, 1460, 9000, u16::MAX] {
            for local_mss in [512, 1460] {
                for passive in [false, true] {
                    let mut tcb = if passive {
                        Tcb::new_from_listen(tuple(), Seq::new(1000), peer_mss)
                    } else {
                        Tcb::new_active(tuple())
                    };
                    tcb.set_local_mss(local_mss);
                    assert_eq!(tcb.poll_output(now)[0].mss, Some(local_mss));
                    let mut reply = header(
                        Seq::new(if passive { 1001 } else { 1000 }),
                        tcb.snd_nxt,
                        if passive {
                            flags::ACK
                        } else {
                            flags::SYN | flags::ACK
                        },
                        u16::MAX,
                    );
                    reply.options.mss = Some(peer_mss);
                    tcb.on_segment(&reply, Bytes::new(), now);
                    tcb.poll_output(now);
                    tcb.set_nodelay(true);
                    tcb.send(Bytes::from(vec![42; 9000]));
                    let mut sent = 0;
                    while sent < 9000 {
                        let segments = tcb.poll_output(now);
                        assert!(!segments.is_empty(), "sender stalled at {sent}");
                        for seg in &segments {
                            assert!(!seg.payload.is_empty());
                            assert!(seg.payload.len() <= peer_mss.max(1).min(local_mss) as usize);
                            sent += seg.payload.len();
                        }
                        let ack = header(tcb.rcv_nxt, tcb.snd_nxt, flags::ACK, u16::MAX);
                        tcb.on_segment(&ack, Bytes::new(), now);
                    }
                    assert_eq!(sent, 9000);
                }
            }
        }
    }

    #[test]
    fn reading_reopens_a_zero_window_without_a_peer_probe() {
        let now = Instant::now();
        let mut tcb = establish(now);
        for _ in 0..64 {
            let hdr = header(tcb.rcv_nxt, tcb.snd_una, flags::ACK, u16::MAX);
            tcb.on_segment(&hdr, Bytes::from(vec![42; 1024]), now);
            tcb.poll_output(now);
        }
        assert_eq!(
            tcb.make_segment(tcb.snd_nxt, flags::ACK, Bytes::new(), None)
                .window,
            0
        );
        assert!(!tcb.has_pending_output());
        assert!(tcb.recv(0).is_empty());
        assert!(!tcb.has_pending_output());
        assert_eq!(tcb.recv(1024).len(), 1024);
        let update = tcb.poll_output(now);
        assert_eq!(update.len(), 1);
        assert_eq!(update[0].flags, flags::ACK);
        assert_eq!(update[0].window, 1024);
        assert!(update[0].payload.is_empty());
    }

    #[test]
    fn repeated_syn_retransmits_synack_and_can_complete_handshake() {
        let now = Instant::now();
        let mut tcb = Tcb::new_from_listen(tuple(), Seq::new(1000), 1460);
        let original = tcb.poll_output(now).remove(0);
        let mut syn = header(Seq::new(1000), Seq::new(0), flags::SYN, u16::MAX);
        for extra_flags in [0, flags::ECE | flags::CWR, 0] {
            syn.flags = flags::SYN | extra_flags;
            tcb.on_segment(&syn, Bytes::new(), now);
            assert_eq!(tcb.state, TcpState::SynReceived);
            let resent = tcb.poll_output(now);
            assert_eq!(resent.len(), 1);
            assert_eq!(resent[0].flags, flags::SYN | flags::ACK);
            assert_eq!(resent[0].seq, original.seq);
            assert_eq!(resent[0].ack, original.ack);
            assert_eq!(tcb.retransmit.segments.len(), 1);
            assert!(tcb.events.is_empty());
        }
        let ack = header(Seq::new(1001), tcb.snd_nxt, flags::ACK, u16::MAX);
        tcb.on_segment(&ack, Bytes::new(), now);
        assert_eq!(tcb.state, TcpState::Established);
        assert!(tcb.retransmit.is_empty());
        assert_eq!(tcb.events, [Event::Established]);
    }

    #[test]
    fn retransmission_exhaustion_reports_an_abort() {
        for established in [false, true] {
            let mut now = Instant::now();
            let mut tcb = if established {
                establish(now)
            } else {
                Tcb::new_active(tuple())
            };
            tcb.events.clear();
            if established {
                tcb.send(Bytes::from_static(b"unacknowledged"));
            }
            tcb.poll_output(now);
            for _ in 0..=MAX_RETRANSMITS {
                now += super::super::rto::MAX_RTO + Duration::from_secs(1);
                tcb.tick(now);
                tcb.poll_output(now);
            }
            assert_eq!(tcb.state, TcpState::Closed);
            assert_eq!(tcb.events, [Event::Reset]);
        }
    }

    #[test]
    fn syn_sent_ignores_reset_without_an_acceptable_ack() {
        let now = Instant::now();
        let mut tcb = Tcb::new_active(tuple());
        let rst = header(Seq::new(0), Seq::new(0), flags::RST, 0);

        tcb.on_segment(&rst, Bytes::new(), now);

        assert_eq!(tcb.state, TcpState::SynSent);
        assert!(tcb.events.is_empty());
    }

    #[test]
    fn established_ignores_out_of_window_reset() {
        let now = Instant::now();
        let mut tcb = establish(now);
        let rst = header(
            tcb.rcv_nxt + RECV_BUFFER_CAPACITY + 1,
            tcb.snd_una,
            flags::RST,
            0,
        );

        tcb.on_segment(&rst, Bytes::new(), now);

        assert_eq!(tcb.state, TcpState::Established);
        assert!(!tcb.events.contains(&Event::Reset));
    }

    #[test]
    fn third_duplicate_ack_schedules_fast_retransmit() {
        let now = Instant::now();
        let mut tcb = establish(now);
        tcb.send(Bytes::from_static(b"payload"));
        let sent = tcb.poll_output(now);
        assert_eq!(sent.len(), 1);
        let ack = header(tcb.rcv_nxt, tcb.snd_una, flags::ACK, u16::MAX);

        for _ in 0..3 {
            tcb.on_segment(&ack, Bytes::new(), now);
        }
        let retransmitted = tcb.poll_output(now);

        assert!(
            retransmitted
                .iter()
                .any(|seg| seg.payload == b"payload"[..])
        );
    }

    #[test]
    fn zero_window_persist_timer_probes_and_resumes() {
        let mut now = Instant::now();
        let mut tcb = establish(now);
        let zero = header(tcb.rcv_nxt, tcb.snd_una, flags::ACK, 0);
        tcb.on_segment(&zero, Bytes::new(), now);
        tcb.poll_output(now);
        tcb.send(Bytes::from_static(b"0123456789"));
        assert!(tcb.poll_output(now).is_empty());
        assert!(!tcb.has_pending_output());
        assert!(tcb.has_armed_timer());

        // Probe once the persist deadline passes.
        now += Duration::from_secs(2);
        tcb.tick(now);
        let probe = tcb.poll_output(now);
        assert_eq!(probe.len(), 1);
        assert!(probe[0].payload == b"0"[..]);
        assert_eq!(tcb.flight_size(), 1);

        // The peer keeps answering with a zero window (not acking the
        // byte): it is alive, so the connection must survive far more than
        // MAX_RETRANSMITS probe retransmissions.
        for _ in 0..(MAX_RETRANSMITS * 2) {
            now += MAX_RTO + Duration::from_secs(1);
            tcb.tick(now);
            tcb.poll_output(now);
            let ans = header(tcb.rcv_nxt, tcb.snd_una, flags::ACK, 0);
            tcb.on_segment(&ans, Bytes::new(), now);
        }
        assert_eq!(tcb.state, TcpState::Established);
        assert!(tcb.events.iter().all(|e| *e != Event::Reset));

        // Window opens: the probe is acked and the rest flows.
        let open = header(tcb.rcv_nxt, tcb.snd_nxt, flags::ACK, 1000);
        tcb.on_segment(&open, Bytes::new(), now);
        let rest = tcb.poll_output(now);
        assert_eq!(rest.len(), 1);
        assert!(rest[0].payload == b"123456789"[..]);
        assert!(tcb.persist_deadline.is_none());
    }

    #[test]
    fn data_beyond_a_full_receive_window_is_not_buffered() {
        let now = Instant::now();
        let mut tcb = establish(now);
        for _ in 0..64 {
            let hdr = header(tcb.rcv_nxt, tcb.snd_una, flags::ACK, u16::MAX);
            tcb.on_segment(&hdr, Bytes::from(vec![1; 1024]), now);
            tcb.poll_output(now);
        }
        let rcv_nxt = tcb.rcv_nxt;
        let hdr = header(rcv_nxt, tcb.snd_una, flags::ACK, u16::MAX);
        tcb.on_segment(&hdr, Bytes::from(vec![2; 100]), now);
        assert_eq!(tcb.readable_len(), 64 * 1024);
        assert_eq!(tcb.rcv_nxt, rcv_nxt);
        assert!(tcb.ack_pending);
        // Out-of-order data beyond the right edge is dropped too.
        let hdr = header(rcv_nxt + 10, tcb.snd_una, flags::ACK, u16::MAX);
        tcb.on_segment(&hdr, Bytes::from(vec![2; 100]), now);
        assert!(!tcb.recv_buffer.has_out_of_order());
    }

    #[test]
    fn segment_straddling_the_window_edge_is_truncated_without_its_fin() {
        let now = Instant::now();
        let mut tcb = establish(now);
        for _ in 0..63 {
            let hdr = header(tcb.rcv_nxt, tcb.snd_una, flags::ACK, u16::MAX);
            tcb.on_segment(&hdr, Bytes::from(vec![1; 1024]), now);
        }
        let rcv_nxt = tcb.rcv_nxt;
        let hdr = header(rcv_nxt, tcb.snd_una, flags::ACK | flags::FIN, u16::MAX);
        tcb.on_segment(&hdr, Bytes::from(vec![2; 1500]), now);
        assert_eq!(tcb.readable_len(), 64 * 1024);
        assert_eq!(tcb.rcv_nxt, rcv_nxt + 1024);
        assert_eq!(tcb.state, TcpState::Established);
        assert!(!tcb.events.contains(&Event::PeerClosed));
    }

    #[test]
    fn syn_sent_bad_ack_reset_uses_the_offending_ack_as_sequence() {
        let now = Instant::now();
        let mut tcb = Tcb::new_active(tuple());
        tcb.poll_output(now);
        let bad_ack = tcb.snd_nxt + 5;
        let hdr = header(Seq::new(1000), bad_ack, flags::SYN | flags::ACK, 100);
        tcb.on_segment(&hdr, Bytes::new(), now);
        let out = tcb.poll_output(now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].flags, flags::RST);
        assert_eq!(out[0].seq, bad_ack);
    }

    #[test]
    fn syn_received_bad_ack_reset_uses_the_offending_ack_as_sequence() {
        let now = Instant::now();
        let mut tcb = Tcb::new_from_listen(tuple(), Seq::new(1000), 1460);
        tcb.poll_output(now);
        let bad_ack = tcb.snd_nxt + 10;
        let hdr = header(Seq::new(1001), bad_ack, flags::ACK, 100);
        tcb.on_segment(&hdr, Bytes::new(), now);
        let out = tcb.poll_output(now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].flags, flags::RST);
        assert_eq!(out[0].seq, bad_ack);
        // Other resets still use snd_nxt.
        let mut est = establish(now);
        let syn = header(est.rcv_nxt, est.snd_una, flags::SYN | flags::ACK, 100);
        est.on_segment(&syn, Bytes::new(), now);
        let out = est.poll_output(now);
        assert_eq!(out[0].flags, flags::RST);
        assert_eq!(out[0].seq, est.snd_nxt);
    }

    fn into_time_wait(now: Instant) -> Tcb {
        let mut tcb = establish(now);
        tcb.close();
        tcb.poll_output(now);
        assert_eq!(tcb.state, TcpState::FinWait1);
        let ack = header(tcb.rcv_nxt, tcb.snd_nxt, flags::ACK, u16::MAX);
        tcb.on_segment(&ack, Bytes::new(), now);
        assert_eq!(tcb.state, TcpState::FinWait2);
        let fin = header(tcb.rcv_nxt, tcb.snd_nxt, flags::FIN | flags::ACK, u16::MAX);
        tcb.on_segment(&fin, Bytes::new(), now);
        assert_eq!(tcb.state, TcpState::TimeWait);
        tcb
    }

    #[test]
    fn time_wait_expires_relative_to_the_supplied_clock() {
        let t = Instant::now();
        let mut tcb = into_time_wait(t);
        tcb.tick(t + TIME_WAIT_DURATION - Duration::from_millis(1));
        assert_eq!(tcb.state, TcpState::TimeWait);
        tcb.tick(t + TIME_WAIT_DURATION);
        assert_eq!(tcb.state, TcpState::Closed);
    }

    #[test]
    fn retransmitted_fin_in_time_wait_is_reacked_and_restarts_the_timer() {
        let t = Instant::now();
        let mut tcb = into_time_wait(t);
        tcb.poll_output(t);
        let t2 = t + Duration::from_secs(10);
        let fin = header(
            tcb.rcv_nxt - 1,
            tcb.snd_nxt,
            flags::FIN | flags::ACK,
            u16::MAX,
        );
        tcb.on_segment(&fin, Bytes::new(), t2);
        let out = tcb.poll_output(t2);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].flags, flags::ACK);
        tcb.tick(t + TIME_WAIT_DURATION + Duration::from_secs(1));
        assert_eq!(tcb.state, TcpState::TimeWait);
        tcb.tick(t2 + TIME_WAIT_DURATION);
        assert_eq!(tcb.state, TcpState::Closed);
    }

    #[test]
    fn partial_ack_in_fast_recovery_retransmits_the_next_segment() {
        let now = Instant::now();
        let mut tcb = establish(now);
        tcb.set_nodelay(true);
        for chunk in [&b"aaaa"[..], b"bbbb", b"cccc", b"dddd"] {
            tcb.send(Bytes::copy_from_slice(chunk));
            assert_eq!(tcb.poll_output(now).len(), 1);
        }
        let dup = header(tcb.rcv_nxt, tcb.snd_una, flags::ACK, u16::MAX);
        for _ in 0..3 {
            tcb.on_segment(&dup, Bytes::new(), now);
        }
        assert!(tcb.congestion.in_fast_recovery());
        let first = tcb.poll_output(now);
        assert!(first.iter().any(|s| s.payload == b"aaaa"[..]));

        // Ack only "aaaa": a partial ack, "bbbb" is lost as well.
        let partial = header(tcb.rcv_nxt, tcb.snd_una + 4, flags::ACK, u16::MAX);
        tcb.on_segment(&partial, Bytes::new(), now);
        assert!(tcb.congestion.in_fast_recovery());
        assert!(tcb.retransmit_now);
        let second = tcb.poll_output(now);
        assert!(second.iter().any(|s| s.payload == b"bbbb"[..]));
    }

    #[test]
    fn passive_open_sizes_congestion_window_from_the_peer_mss() {
        let tcb = Tcb::new_from_listen(tuple(), Seq::new(1000), 536);
        assert_eq!(tcb.congestion.cwnd(), 2 * 536);
    }
}
