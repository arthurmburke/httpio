//! The Transmission Control Block: all per-connection state, and the RFC
//! 9293 §3.10 segment-processing state machine.

use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::dpdk::net::tcp::{TcpHeader, TcpOptions, flags};

use super::congestion::CongestionControl;
use super::rto::{MAX_RETRANSMITS, RetransmitQueue, RtoEstimator};
use super::rx_queue::ReassemblyBuffer;
use super::seq::Seq;
use super::state::TcpState;
use super::tx_queue::SendBuffer;

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
    pub local_ip: [u8; 4],
    pub local_port: u16,
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
}

/// A segment the engine should serialize onto the wire.
pub struct OutSegment {
    pub seq: Seq,
    pub ack: Seq,
    pub flags: u8,
    pub window: u16,
    pub payload: Bytes,
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
        tcb.peer_mss = peer_mss;
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
        self.recv_buffer.read(max_len)
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
        if hdr.has_flag(flags::RST) {
            if self.reset_is_acceptable(hdr) {
                self.on_reset();
            }
            return;
        }

        match self.state {
            TcpState::SynSent => self.on_segment_syn_sent(hdr, now),
            _ => self.on_segment_general(hdr, payload, now),
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
                return;
            }
        }
        if !hdr.has_flag(flags::SYN) {
            return;
        }
        self.irs = Seq::new(hdr.seq);
        self.rcv_nxt = self.irs + 1;
        self.peer_mss = hdr.options.mss.unwrap_or(FALLBACK_PEER_MSS);
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

    fn on_segment_general(&mut self, hdr: &TcpHeader, payload: Bytes, now: Instant) {
        // The payload moves into the reassembly buffer below; keep its
        // length for the checks that need it afterward.
        let payload_len = payload.len() as u32;
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
                return;
            }
        }

        if hdr.has_flag(flags::SYN) && self.state.is_synchronized() {
            // RFC 9293 §3.10.7.4 step 4: SYN in the window after the
            // connection is synchronized is an error -> reset.
            self.want_rst = true;
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

        if self.state.can_receive() && !payload.is_empty() {
            let seq = Seq::new(hdr.seq);
            let new_rcv_nxt = self.recv_buffer.insert(seq, payload, self.rcv_nxt);
            if new_rcv_nxt != self.rcv_nxt {
                self.rcv_nxt = new_rcv_nxt;
            }
            self.ack_pending = true;
        }

        if hdr.has_flag(flags::FIN) && self.state.is_synchronized() {
            self.on_fin(hdr, payload_len);
        }
    }

    fn process_ack(&mut self, hdr: &TcpHeader, payload_len: u32, now: Instant) {
        let ack = Seq::new(hdr.ack);

        match self.state {
            TcpState::SynReceived => {
                if ack.leq(self.snd_una) || ack.gt(self.snd_nxt) {
                    self.want_rst = true;
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
            self.congestion.on_new_ack(newly_acked, ack.0);
            self.update_send_window(hdr, ack);
        } else if ack == self.snd_una {
            // RFC 5681 §2: a duplicate ACK carries no data and doesn't
            // move the window; with nothing in flight it's just a normal
            // keepalive-style ACK, not a loss signal.
            let is_dup_candidate =
                payload_len == 0 && !hdr.has_flag(flags::SYN) && !hdr.has_flag(flags::FIN);
            if is_dup_candidate
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

    fn on_fin(&mut self, hdr: &TcpHeader, payload_len: u32) {
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
                self.time_wait_deadline = Some(Instant::now() + TIME_WAIT_DURATION);
                TcpState::TimeWait
            }
            other => other,
        };
    }

    // ---- timers ----------------------------------------------------------

    /// Drives retransmission timeouts and TIME_WAIT expiry. Call
    /// periodically (e.g. every main-loop iteration).
    pub fn tick(&mut self, now: Instant) {
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

    fn on_rto(&mut self, now: Instant) {
        self.congestion.on_rto_timeout(self.flight_size());
        self.rto.backoff();
        if let Some(seg) = self.retransmit.segments.front_mut() {
            seg.retransmitted = true;
            seg.retransmit_count += 1;
            seg.last_sent_at = now;
            if seg.retransmit_count > MAX_RETRANSMITS {
                self.want_rst = true;
                self.state = TcpState::Closed;
                self.events.push(Event::Closed);
                return;
            }
            self.retransmit_now = true;
        }
    }

    // ---- outbound segment construction -----------------------------------

    /// Gathers every segment that should go out right now: handshake
    /// control segments, retransmits, new data (bounded by cwnd/rwnd),
    /// FIN, and standalone ACKs.
    pub fn poll_output(&mut self, now: Instant) -> Vec<OutSegment> {
        let mut out = Vec::new();

        if self.want_rst {
            self.want_rst = false;
            out.push(self.make_segment(self.snd_nxt, flags::RST, Bytes::new(), None));
            return out;
        }

        if self.want_syn {
            self.want_syn = false;
            self.retransmit
                .push(self.iss, Bytes::new(), true, false, now);
            out.push(self.make_segment(self.iss, flags::SYN, Bytes::new(), Some(DEFAULT_MSS)));
            return out;
        }

        if self.want_synack {
            self.want_synack = false;
            self.retransmit
                .push(self.iss, Bytes::new(), true, false, now);
            out.push(self.make_segment(
                self.iss,
                flags::SYN | flags::ACK,
                Bytes::new(),
                Some(DEFAULT_MSS),
            ));
            return out;
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
                let mss = seg.syn.then_some(DEFAULT_MSS);
                out.push(self.make_segment(seq, seg_flags, data, mss));
            }
        }

        if self.state.can_send() {
            self.send_new_data(now, &mut out);
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

        out
    }

    fn send_new_data(&mut self, now: Instant, out: &mut Vec<OutSegment>) {
        loop {
            let usable_window = self.snd_wnd.min(self.congestion.cwnd());
            let flight = self.flight_size();
            let available = usable_window.saturating_sub(flight);
            if available == 0 || self.send_buffer.is_empty() {
                break;
            }
            let mss = self.peer_mss as usize;
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
    }

    fn make_segment(&self, seq: Seq, flags: u8, payload: Bytes, mss: Option<u16>) -> OutSegment {
        let window = RECV_BUFFER_CAPACITY
            .saturating_sub(self.recv_buffer.readable_len() as u32)
            .min(u16::MAX as u32) as u16;
        OutSegment {
            seq,
            ack: self.rcv_nxt,
            flags,
            window,
            payload,
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
        let sendable_data = self.state.can_send()
            && !self.send_buffer.is_empty()
            && (self.send_buffer.len() >= self.peer_mss as usize
                || self.flush_requested
                || (!self.corked && self.nodelay)
                || (!self.corked && self.flight_size() == 0));
        self.want_syn
            || self.want_synack
            || self.want_rst
            || self.ack_pending
            || self.retransmit_now
            || sendable_data
            // A FIN still waiting to be sent (close requested, buffer
            // drained, not yet sent).
            || (self.close_requested && !self.fin_sent && self.send_buffer.is_empty())
    }

    /// Whether a retransmission or TIME_WAIT timer is armed, i.e. the
    /// connection needs `tick`ing on future polls even with no pending
    /// output. Together with `has_pending_output`, this is what keeps a
    /// connection in the engine's active set; a connection with neither is
    /// fully idle and can be skipped until an inbound frame or app call.
    pub fn has_armed_timer(&self) -> bool {
        !self.retransmit.is_empty() || self.time_wait_deadline.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple() -> FourTuple {
        FourTuple {
            local_ip: [10, 0, 0, 1],
            local_port: 49152,
            remote_ip: [10, 0, 0, 2],
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
}
