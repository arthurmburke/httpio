//! The Transmission Control Block: all per-connection state, and the RFC
//! 9293 §3.10 segment-processing state machine.

use std::cell::Cell;
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
const SCALED_RECV_CAPACITY: u32 = 1024 * 1024;
const LOCAL_WINDOW_SCALE: u8 = 4;
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

/// The handshake control segment waiting to be emitted. A SYN-ACK
/// supersedes a SYN that has not gone out yet (simultaneous open), since
/// it carries the same SYN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeOut {
    Syn,
    SynAck,
}

/// The sequence number of a reset waiting to be emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResetOut {
    /// `<SEQ=SND.NXT><CTL=RST>`: aborting a synchronized connection.
    AtSndNxt,
    /// `<SEQ=SEG.ACK><CTL=RST>`: answering an unacceptable handshake ACK
    /// (RFC 9293 §3.10.7.3 / §3.10.7.4).
    At(Seq),
}

/// Progress of the application's close (RFC 9293 §3.10.4). Advances only
/// forward: `Open -> Requested -> FinQueued -> FinSent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalClose {
    /// The application has not closed its sending side.
    Open,
    /// `close()` was called; the FIN waits for buffered and in-flight data
    /// to drain (and for the handshake to finish).
    Requested,
    /// Everything drained; the FIN goes out as soon as an output poll has
    /// room for it.
    FinQueued,
    /// The FIN is on the retransmit queue (sent, possibly not yet acked).
    FinSent,
}

/// The zero-window probe cycle (RFC 9293 §3.8.6.1):
///
/// ```text
/// Idle -> Armed -> ProbeDue -> ProbeOutstanding -> Idle | Armed
/// ```
///
/// `Armed` and `ProbeDue` exist only while the persist condition holds
/// (data buffered, nothing in flight, peer window zero); they fall back to
/// `Idle` the moment it stops holding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Persist {
    Idle,
    /// The timer is running; a probe becomes due at the deadline.
    Armed(Instant),
    /// The timer fired: the next output poll sends a 1-byte probe.
    ProbeDue,
    /// A probe is unacknowledged. A peer that answers it (even with a zero
    /// window) is alive, so such answers reset its retransmit count.
    ProbeOutstanding,
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
    tx_payload_limit: usize,
    peer_scale: Option<u8>,

    retransmit: RetransmitQueue,
    rto: RtoEstimator,
    congestion: CongestionControl,
    send_buffer: SendBuffer,
    recv_buffer: ReassemblyBuffer,

    ack_pending: bool,
    /// Right edge of the receive window last advertised to the peer.
    /// Written when a segment is built, read to decide whether a read by
    /// the application opened enough window to be worth announcing.
    rcv_advertised: Cell<Seq>,
    retransmit_now: bool,
    /// SYN / SYN-ACK waiting to be emitted.
    handshake_out: Option<HandshakeOut>,
    /// RST waiting to be emitted.
    reset_out: Option<ResetOut>,
    local_close: LocalClose,

    /// Where the zero-window probe cycle stands.
    persist: Persist,
    /// Interval to use for the next persist arming; doubles per probe up to
    /// `MAX_RTO` and resets once the window opens or the buffer empties.
    persist_backoff: Option<Duration>,

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
            tx_payload_limit: 0,
            peer_scale: None,
            retransmit: RetransmitQueue::default(),
            rto: RtoEstimator::default(),
            congestion: CongestionControl::new(DEFAULT_MSS),
            send_buffer: SendBuffer::default(),
            recv_buffer: ReassemblyBuffer::default(),
            ack_pending: false,
            rcv_advertised: Cell::new(Seq::new(0)),
            retransmit_now: false,
            handshake_out: None,
            reset_out: None,
            local_close: LocalClose::Open,
            persist: Persist::Idle,
            persist_backoff: None,
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
        tcb.handshake_out = Some(HandshakeOut::Syn);
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
        tcb.handshake_out = Some(HandshakeOut::SynAck);
        tcb
    }

    pub(crate) fn set_peer_scale(&mut self, scale: Option<u8>) {
        self.peer_scale = scale.map(|v| v.min(14));
    }
    fn receive_capacity(&self) -> u32 {
        if self.peer_scale.is_some() {
            SCALED_RECV_CAPACITY
        } else {
            RECV_BUFFER_CAPACITY
        }
    }
    fn peer_window(&self, hdr: &TcpHeader) -> u32 {
        (hdr.window as u32)
            << if hdr.has_flag(flags::SYN) {
                0
            } else {
                self.peer_scale.unwrap_or(0)
            }
    }
    pub(crate) fn send_mss(&self) -> u16 {
        self.peer_mss.min(self.local_mss)
    }
    pub(crate) fn set_tx_payload_limit(&mut self, limit: usize) {
        self.tx_payload_limit = limit;
    }

    pub fn is_closed(&self) -> bool {
        self.state.is_closed()
    }

    pub fn in_time_wait(&self) -> bool {
        matches!(self.state, TcpState::TimeWait)
    }

    // ---- application-facing operations ---------------------------------

    pub(crate) fn buffered_send_bytes(&self) -> usize {
        self.send_buffer.len() + self.retransmit.payload_bytes()
    }

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
            // Announce newly freed space without waiting for another peer
            // packet, but only when the peer needs it: its window is shut,
            // or it holds at most half the buffer and the read doubled
            // what it may send. Otherwise every read costs a pure ACK that
            // the next data ACK would have carried anyway.
            let capacity = self.receive_capacity();
            let free = capacity.saturating_sub(self.recv_buffer.readable_len() as u32);
            let advertised = self.rcv_advertised.get().distance(self.rcv_nxt).max(0) as u32;
            if advertised == 0 || (advertised <= capacity / 2 && free >= 2 * advertised) {
                self.ack_pending = true;
            }
        }
        data
    }

    pub fn readable_len(&self) -> usize {
        self.recv_buffer.readable_len()
    }

    /// Application-initiated close: RFC 9293 §3.10.4. The FIN follows the
    /// last buffered byte onto the wire; it does not wait for that data
    /// to be acknowledged.
    pub fn close(&mut self) {
        if self.local_close == LocalClose::Open {
            self.local_close = LocalClose::Requested;
        }
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
        self.on_segment_chunks_with(hdr, payload_len, || std::iter::once(payload()), now);
    }

    pub(crate) fn on_segment_chunks_with<I: IntoIterator<Item = Bytes>>(
        &mut self,
        hdr: &TcpHeader,
        payload_len: usize,
        payload: impl FnOnce() -> I,
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

                let rcv_wnd = self
                    .receive_capacity()
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
                self.reset_out = Some(ResetOut::At(ack));
                return;
            }
        }
        if !hdr.has_flag(flags::SYN) {
            return;
        }
        self.set_peer_scale(hdr.options.window_scale);
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
            self.snd_wnd = self.peer_window(hdr);
            self.snd_wl1 = self.irs;
            self.snd_wl2 = self.snd_una;
            self.ack_pending = true;
            self.events.push(Event::Established);
        } else {
            // Simultaneous open (RFC 9293 §3.10.7.3 step 2): both sides
            // sent SYN before either ACK arrived.
            self.state = TcpState::SynReceived;
            self.handshake_out = Some(HandshakeOut::SynAck);
        }
    }

    fn on_segment_general<I: IntoIterator<Item = Bytes>>(
        &mut self,
        hdr: &TcpHeader,
        payload_len: u32,
        payload: impl FnOnce() -> I,
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
            let rcv_wnd = self
                .receive_capacity()
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
            self.reset_out = Some(ResetOut::AtSndNxt);
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
            let rcv_wnd = self
                .receive_capacity()
                .saturating_sub(self.recv_buffer.readable_len() as u32);
            let right_edge = self.rcv_nxt + rcv_wnd;
            let keep = if seq.geq(right_edge) {
                0
            } else {
                payload_len.min(right_edge.distance(seq) as u32)
            };
            if keep != 0 {
                let mut remaining = keep as usize;
                let mut chunk_seq = seq;
                for mut data in payload() {
                    if remaining == 0 {
                        break;
                    }
                    data.truncate(remaining.min(data.len()));
                    remaining -= data.len();
                    let end = chunk_seq + data.len() as u32;
                    self.rcv_nxt = self.recv_buffer.insert(chunk_seq, data, self.rcv_nxt);
                    chunk_seq = end;
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
                    self.reset_out = Some(ResetOut::At(ack));
                    return;
                }
                self.snd_una = ack;
                if let Some(rtt) = self.retransmit.ack_up_to(self.snd_una, now) {
                    self.rto.sample(rtt);
                }
                self.state = TcpState::Established;
                self.snd_wnd = self.peer_window(hdr);
                self.snd_wl1 = Seq::new(hdr.seq);
                self.snd_wl2 = ack;
                self.events.push(Event::Established);
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
            let is_dup_candidate = payload_len == 0
                && self.peer_window(hdr) == self.snd_wnd
                && !hdr.has_flag(flags::SYN)
                && !hdr.has_flag(flags::FIN);
            if is_dup_candidate
                && self.persist != Persist::ProbeOutstanding
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

        if self.persist == Persist::ProbeOutstanding {
            if self.flight_size() == 0 || self.snd_wnd > 0 {
                self.persist = Persist::Idle;
            } else if hdr.window == 0
                && let Some(seg) = self.retransmit.segments.front_mut()
            {
                // The peer answered the probe (still advertising zero):
                // it is alive, so keep probing indefinitely rather than
                // counting this toward retransmission exhaustion.
                seg.retransmit_count = 0;
            }
        }

        // Data can still be outstanding ahead of our FIN, so every closing
        // state takes the ordinary ACK processing above and finishes only
        // once the FIN itself is covered.
        if matches!(
            self.state,
            TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
        ) && ack.geq(self.snd_nxt)
        {
            self.fin_acked();
        }
    }

    /// Our FIN was acknowledged: advance the teardown (see
    /// [`TcpState::on_fin_acked`]), reporting the close if that finished it.
    fn fin_acked(&mut self) {
        self.state = self.state.on_fin_acked();
        if self.state.is_closed() {
            self.events.push(Event::Closed);
        }
    }

    fn update_send_window(&mut self, hdr: &TcpHeader, ack: Seq) {
        let seq = Seq::new(hdr.seq);
        if self.snd_wl1.lt(seq) || (self.snd_wl1 == seq && self.snd_wl2.leq(ack)) {
            self.snd_wnd = self.peer_window(hdr);
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

        let next = self.state.on_fin_received();
        if next == TcpState::TimeWait && self.state != TcpState::TimeWait {
            self.time_wait_deadline = Some(now + TIME_WAIT_DURATION);
        }
        self.state = next;
    }

    // ---- timers ----------------------------------------------------------

    /// Drives retransmission timeouts and TIME_WAIT expiry. Call
    /// periodically (e.g. every main-loop iteration).
    pub fn tick(&mut self, now: Instant) {
        if self.is_closed() {
            return;
        }
        self.update_persist(now);
        if let Persist::Armed(deadline) = self.persist
            && now >= deadline
        {
            self.persist = Persist::ProbeDue;
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
            if matches!(self.persist, Persist::Idle | Persist::ProbeOutstanding) {
                let interval = self.persist_backoff.unwrap_or_else(|| self.rto.rto());
                self.persist = Persist::Armed(now + interval);
                self.persist_backoff = Some((interval * 2).min(MAX_RTO));
            }
        } else {
            if matches!(self.persist, Persist::Armed(_) | Persist::ProbeDue) {
                self.persist = Persist::Idle;
            }
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
                self.reset_out = Some(ResetOut::AtSndNxt);
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
        self.retransmit.hold_until_transmitted(false);
        self.poll_output_limited(now, out, usize::MAX);
    }

    /// The port accepted the segment starting at `seq`, which
    /// [`Tcb::poll_output_queued`] produced: its retransmission timer
    /// starts now.
    pub(crate) fn mark_transmitted(&mut self, seq: Seq, now: Instant) {
        self.retransmit.mark_transmitted(seq, now);
    }

    /// Like [`Tcb::poll_output_into`], for a caller that queues the
    /// segments ahead of the port: at most `limit` segments, and each
    /// one's retransmission timer waits for [`Tcb::mark_transmitted`].
    pub(crate) fn poll_output_queued(
        &mut self,
        now: Instant,
        out: &mut Vec<OutSegment>,
        limit: usize,
    ) {
        self.retransmit.hold_until_transmitted(true);
        self.poll_output_limited(now, out, limit);
    }

    fn poll_output_limited(&mut self, now: Instant, out: &mut Vec<OutSegment>, limit: usize) {
        out.clear();
        if limit == 0 {
            return;
        }

        if let Some(reset) = self.reset_out.take() {
            let seq = match reset {
                ResetOut::AtSndNxt => self.snd_nxt,
                ResetOut::At(seq) => seq,
            };
            out.push(self.make_segment(seq, flags::RST, Bytes::new(), None));
            return;
        }

        if self.is_closed() {
            return;
        }

        if let Some(handshake) = self.handshake_out.take() {
            let seg_flags = match handshake {
                HandshakeOut::Syn => flags::SYN,
                HandshakeOut::SynAck => flags::SYN | flags::ACK,
            };
            self.retransmit
                .push(self.iss, Bytes::new(), true, false, now);
            out.push(self.make_segment(self.iss, seg_flags, Bytes::new(), Some(self.local_mss)));
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
                let data = seg.data.slice(
                    0,
                    seg.data
                        .len()
                        .min(self.peer_mss.min(self.local_mss) as usize),
                );
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
                self.retransmit.front_resent();
            }
        }

        if self.state.can_send() {
            self.send_new_data(now, out, limit);
        }

        // The FIN goes out as soon as the last buffered byte has been
        // segmented, right behind it, rather than a round trip later once
        // that data is acknowledged. It queues behind the data for
        // retransmission and takes the sequence number after it.
        if self.local_close == LocalClose::Requested
            && self.send_buffer.is_empty()
            && self.state.can_send()
        {
            self.local_close = LocalClose::FinQueued;
        }

        if self.local_close == LocalClose::FinQueued && out.len() < limit {
            self.local_close = LocalClose::FinSent;
            let seq = self.snd_nxt;
            self.snd_nxt = self.snd_nxt + 1;
            self.retransmit.push(seq, Bytes::new(), false, true, now);
            self.state = self.state.on_fin_sent();
            out.push(self.make_segment(seq, flags::FIN | flags::ACK, Bytes::new(), None));
        } else if self.ack_pending && out.is_empty() {
            self.ack_pending = false;
            out.push(self.make_segment(self.snd_nxt, flags::ACK, Bytes::new(), None));
        }
    }

    fn send_new_data(&mut self, now: Instant, out: &mut Vec<OutSegment>, limit: usize) {
        if out.len() == limit {
            return;
        }
        // Zero-window probe: one byte as an ordinary data segment, so the
        // retransmit queue and ACK processing handle it like any other.
        if self.persist == Persist::ProbeDue {
            self.persist = Persist::Idle;
            if self.persist_needed() {
                let data = self.send_buffer.take(1);
                let seq = self.snd_nxt;
                self.snd_nxt = self.snd_nxt + data.len() as u32;
                self.retransmit.push(seq, data.clone(), false, false, now);
                self.persist = Persist::ProbeOutstanding;
                out.push(self.make_segment(seq, flags::ACK | flags::PSH, data, None));
                self.ack_pending = false;
            }
        }

        while out.len() < limit {
            let usable_window = self.snd_wnd.min(self.congestion.cwnd());
            let flight = self.flight_size();
            let available = usable_window.saturating_sub(flight);
            if available == 0 || self.send_buffer.is_empty() {
                break;
            }
            let mss = self.peer_mss.min(self.local_mss) as usize;
            let max_payload = self.tx_payload_limit.max(mss);
            let chunk_len = (available as usize)
                .min(max_payload)
                .min(self.send_buffer.len());
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
        let free = self
            .receive_capacity()
            .saturating_sub(self.recv_buffer.readable_len() as u32);
        let scale = if flags & flags::SYN == 0 && self.peer_scale.is_some() {
            LOCAL_WINDOW_SCALE
        } else {
            0
        };
        let window = (free >> scale).min(u16::MAX as u32) as u16;
        self.rcv_advertised
            .set(self.rcv_nxt + (u32::from(window) << scale));
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
            options: TcpOptions {
                mss: seg.mss,
                window_scale: (seg.flags & flags::SYN != 0
                    && (self.state == TcpState::SynSent || self.peer_scale.is_some()))
                .then_some(LOCAL_WINDOW_SCALE),
            },
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
        let flight = self.flight_size();
        let available = self
            .snd_wnd
            .min(self.congestion.cwnd())
            .saturating_sub(flight);
        let mss = self.peer_mss.min(self.local_mss) as usize;
        // Match send_new_data: only a true sub-MSS tail is cork/Nagle held;
        // a window-clamped prefix may still be sent.
        let partial_tail =
            self.send_buffer.len() < mss && available as usize >= self.send_buffer.len();
        let sendable_data = self.state.can_send()
            && !self.send_buffer.is_empty()
            && available > 0
            && mss > 0
            && (!partial_tail
                || self.flush_requested
                || (!self.corked && (self.nodelay || flight == 0)));
        self.handshake_out.is_some()
            || self.reset_out.is_some()
            || self.ack_pending
            || self.retransmit_now
            || self.persist == Persist::ProbeDue
            || sendable_data
            // A FIN still waiting to be sent (close requested, buffer
            // drained, not yet sent).
            || self.local_close == LocalClose::FinQueued
            || (self.local_close == LocalClose::Requested
                && self.state.can_send()
                && self.send_buffer.is_empty())
    }

    /// Earliest armed timer. Locally queued transmissions have no RTO
    /// until NIC acceptance; the engine retries those through its ready set.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        if self.is_closed() {
            return None;
        }
        [
            self.time_wait_deadline,
            self.retransmit.oldest_deadline(self.rto.rto()),
            match self.persist {
                Persist::Armed(at) => Some(at),
                _ => None,
            },
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Whether a retransmission, persist or TIME_WAIT timer is armed, i.e. the
    /// connection needs `tick`ing on future polls even with no pending
    /// output. The engine schedules the actual deadline separately from
    /// immediately runnable output.
    pub fn has_armed_timer(&self) -> bool {
        !self.retransmit.is_empty()
            || self.time_wait_deadline.is_some()
            // Reported as soon as the persist condition holds (before the
            // deadline is armed by the next tick/poll) so the engine ticks it.
            || matches!(self.persist, Persist::Armed(_))
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
    fn window_scaling_is_negotiated_and_syn_window_is_unscaled() {
        let now = Instant::now();
        let mut tcb = Tcb::new_active(tuple());
        let syn = tcb.poll_output(now).remove(0);
        let offer = tcb.to_header(&syn);
        assert_eq!(offer.options.window_scale, Some(4));
        let mut reply = header(Seq::new(1000), tcb.snd_nxt, flags::SYN | flags::ACK, 1000);
        reply.options.window_scale = Some(7);
        tcb.on_segment(&reply, Bytes::new(), now);
        assert_eq!(tcb.snd_wnd, 1000, "SYN windows are never scaled");
        assert_eq!(tcb.poll_output(now)[0].window, 65535);
        reply.flags = flags::ACK;
        reply.seq += 1;
        reply.window = 2000;
        tcb.on_segment(&reply, Bytes::new(), now);
        assert_eq!(tcb.snd_wnd, 2000 << 7);
        assert_eq!(tcb.receive_capacity(), 1024 * 1024);
        assert_eq!(establish(now).receive_capacity(), RECV_BUFFER_CAPACITY);
    }

    #[test]
    fn passive_scaling_requires_peer_offer_and_scales_third_handshake_ack() {
        let now = Instant::now();
        for scale in [None, Some(7)] {
            let mut tcb = Tcb::new_from_listen(tuple(), Seq::new(1000), 1460);
            tcb.set_peer_scale(scale);
            let synack = tcb.poll_output(now).remove(0);
            assert_eq!(
                tcb.to_header(&synack).options.window_scale,
                scale.map(|_| 4)
            );
            let ack = header(Seq::new(1001), tcb.snd_nxt, flags::ACK, 1000);
            tcb.on_segment(&ack, Bytes::new(), now);
            assert_eq!(tcb.snd_wnd, 1000 << scale.unwrap_or(0));
        }
    }

    #[test]
    fn tso_ranges_retransmit_only_the_first_unacknowledged_mss() {
        let now = Instant::now();
        let mut tcb = establish(now);
        tcb.set_tx_payload_limit(32768);
        let original: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        tcb.send(Bytes::from(original.clone()));
        let sent = tcb.poll_output(now);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].payload.len() > tcb.send_mss() as usize);
        let ack_seq = sent[0].seq + 777;
        let ack = header(tcb.rcv_nxt, ack_seq, flags::ACK, u16::MAX);
        tcb.on_segment(&ack, Bytes::new(), now);
        assert_eq!(tcb.retransmit.segments.front().unwrap().seq, ack_seq);
        for _ in 0..3 {
            tcb.on_segment(&ack, Bytes::new(), now);
        }
        let retry = tcb.poll_output(now);
        assert_eq!(retry[0].seq, ack_seq);
        assert!(retry[0].payload.len() <= tcb.send_mss() as usize);
        let mut bytes = vec![0; retry[0].payload.len()];
        retry[0].payload.copy_to(&mut bytes);
        assert_eq!(bytes, original[777..777 + bytes.len()]);
    }

    #[test]
    fn send_credit_counts_buffered_and_unacknowledged_payload() {
        let now = Instant::now();
        let mut tcb = establish(now);
        tcb.send(Bytes::from(vec![0; 4096]));
        assert_eq!(tcb.buffered_send_bytes(), 4096);
        let output = tcb.poll_output(now);
        assert!(!output.is_empty());
        assert_eq!(tcb.buffered_send_bytes(), 4096);
        // Partial ACKs release logical byte credit and trim retransmit ranges.
        let first = &output[0];
        let partial = header(tcb.rcv_nxt, first.seq + 1, flags::ACK, u16::MAX);
        tcb.on_segment(&partial, Bytes::new(), now);
        assert_eq!(tcb.buffered_send_bytes(), 4095);
        let ack = header(
            tcb.rcv_nxt,
            first.seq + first.payload.len() as u32,
            flags::ACK,
            u16::MAX,
        );
        tcb.on_segment(&ack, Bytes::new(), now);
        assert_eq!(tcb.buffered_send_bytes(), 4096 - first.payload.len());
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
    fn locally_queued_segments_do_not_expire_before_transmission() {
        let now = Instant::now();
        let mut tcb = establish(now);
        tcb.send(Bytes::from_static(b"payload"));
        let mut output = Vec::new();
        tcb.poll_output_queued(now, &mut output, usize::MAX);
        let later = now + Duration::from_secs(60);
        tcb.tick(later);
        assert!(!tcb.retransmit_now);
        assert_eq!(tcb.retransmit.segments.front().unwrap().retransmit_count, 0);
        tcb.mark_transmitted(output[0].seq, later);
        tcb.tick(later);
        assert!(!tcb.retransmit_now);
        tcb.tick(later + tcb.rto.rto());
        assert!(tcb.retransmit_now);
    }

    #[test]
    fn pending_hint_allows_window_clamped_data_on_a_corked_connection() {
        let now = Instant::now();
        let mut tcb = establish(now);
        let update = header(tcb.rcv_nxt, tcb.snd_una, flags::ACK, 4);
        tcb.on_segment(&update, Bytes::new(), now);
        tcb.set_cork(true);
        tcb.send(Bytes::from_static(b"abcdefgh"));
        assert!(tcb.has_pending_output());
        let output = tcb.poll_output(now);
        assert_eq!(output[0].payload.len(), 4);
        assert!(!tcb.has_pending_output());
    }

    #[test]
    fn congestion_blocked_data_and_close_wait_for_ack_or_timer() {
        let now = Instant::now();
        let mut tcb = establish(now);
        tcb.send(Bytes::from(vec![0; 65536]));
        tcb.poll_output(now);
        assert!(!tcb.send_buffer.is_empty());
        assert!(!tcb.has_pending_output());
        assert!(tcb.next_deadline().is_some());

        // Data blocked behind the congestion window holds the FIN back:
        // it may only follow the last byte.
        tcb.close();
        assert!(!tcb.has_pending_output());
        assert_eq!(tcb.state, TcpState::Established);
    }

    #[test]
    fn fin_follows_unacknowledged_data_and_is_retransmitted_after_it() {
        let now = Instant::now();
        let mut tcb = establish(now);
        tcb.send(Bytes::from_static(b"payload"));
        let packet = tcb.poll_output(now).remove(0);
        let data_end = packet.seq + packet.payload.len() as u32;
        tcb.close();
        assert!(tcb.has_pending_output(), "FIN must not wait for the ACK");
        let fin = tcb.poll_output(now).remove(0);
        assert_eq!(fin.flags, flags::FIN | flags::ACK);
        assert_eq!(fin.seq, data_end);
        assert_eq!(tcb.state, TcpState::FinWait1);

        // An ACK for the data alone leaves the FIN outstanding.
        let ack = header(tcb.rcv_nxt, data_end, flags::ACK, u16::MAX);
        tcb.on_segment(&ack, Bytes::new(), now);
        assert_eq!(tcb.state, TcpState::FinWait1);
        assert_eq!(tcb.retransmit.segments.len(), 1);

        // The lost FIN is what the retransmission timer resends.
        let later = now + tcb.rto.rto();
        tcb.tick(later);
        let resent = tcb.poll_output(later).remove(0);
        assert_eq!(resent.flags, flags::FIN | flags::ACK);
        assert_eq!(resent.seq, data_end);

        let ack = header(tcb.rcv_nxt, data_end + 1, flags::ACK, u16::MAX);
        tcb.on_segment(&ack, Bytes::new(), later);
        assert_eq!(tcb.state, TcpState::FinWait2);
    }

    #[test]
    fn passive_close_acknowledges_data_sent_ahead_of_its_fin() {
        let now = Instant::now();
        let mut tcb = establish(now);
        let peer_fin = header(tcb.rcv_nxt, tcb.snd_una, flags::FIN | flags::ACK, u16::MAX);
        tcb.on_segment(&peer_fin, Bytes::new(), now);
        tcb.poll_output(now);
        tcb.send(Bytes::from_static(b"payload"));
        tcb.close();
        let out = tcb.poll_output(now);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].flags, flags::FIN | flags::ACK);
        assert_eq!(tcb.state, TcpState::LastAck);
        let data_end = out[0].seq + out[0].payload.len() as u32;

        // The data ACK must be consumed in LAST-ACK, or a lost FIN could
        // never reach the front of the retransmission queue.
        let ack = header(tcb.rcv_nxt, data_end, flags::ACK, u16::MAX);
        tcb.on_segment(&ack, Bytes::new(), now);
        assert_eq!(tcb.state, TcpState::LastAck);
        assert_eq!(tcb.snd_una, data_end);
        assert_eq!(tcb.retransmit.segments.len(), 1);

        let ack = header(tcb.rcv_nxt, data_end + 1, flags::ACK, u16::MAX);
        tcb.on_segment(&ack, Bytes::new(), now);
        assert!(tcb.is_closed());
    }

    #[test]
    fn output_budget_leaves_unsent_data_in_the_send_buffer() {
        let now = Instant::now();
        let mut tcb = establish(now);
        tcb.send(Bytes::from(vec![0; 4096]));
        let mut output = Vec::new();
        tcb.poll_output_limited(now, &mut output, 0);
        assert!(output.is_empty());
        assert_eq!(tcb.send_buffer.len(), 4096);
        tcb.poll_output_limited(now, &mut output, 1);
        assert_eq!(output.len(), 1);
        assert_eq!(tcb.send_buffer.len(), 4096 - output[0].payload.len());
    }

    #[test]
    fn window_updates_do_not_trigger_fast_retransmit() {
        let now = Instant::now();
        let mut tcb = establish(now);
        tcb.send(Bytes::from_static(b"payload"));
        tcb.poll_output(now);
        let cwnd = tcb.congestion.cwnd();
        for window in [40000, 45000, 50000, 55000] {
            let ack = header(tcb.rcv_nxt, tcb.snd_una, flags::ACK, window);
            tcb.on_segment(&ack, Bytes::new(), now);
            assert!(tcb.poll_output(now).is_empty());
            assert_eq!(tcb.congestion.cwnd(), cwnd);
            assert!(!tcb.congestion.in_fast_recovery());
        }
        // Genuine duplicates still trigger recovery after three ACKs.
        let ack = header(tcb.rcv_nxt, tcb.snd_una, flags::ACK, 55000);
        for _ in 0..3 {
            tcb.on_segment(&ack, Bytes::new(), now);
        }
        assert_eq!(tcb.poll_output(now).len(), 1);
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
        assert!(!matches!(tcb.persist, Persist::Armed(_)));
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
        assert_eq!(tcb.congestion.cwnd(), 10 * 536);
    }
}
