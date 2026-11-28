//! Turbo-Tunnel Live Session Engine (`src/session_resume.rs`).
//!
//! Decouples end-to-end TCP/Stream session state and destination socket ownership from volatile
//! underlying carriers (`TCP`, `TCP+Camo`, `UDP/ARQ`, `QUIC-like`, `KCP-FEC`, `WS/H2`).
//!
//! Cryptographic & Protocol guarantees:
//!   * 128-bit CSPRNG `session_id` + 256-bit CSPRNG `resume_token` bound to peer Noise static key
//!     via HMAC-SHA256 proof (`HMAC-SHA256(resume_token, peer_pub || session_id || epoch)`).
//!   * Monotonic `ResumeEpoch` lease (Generation Lease) prevents split-brain / zombie carrier takeover.
//!   * Strict `ReplayLedger` rejects replayed or stale `(epoch, seq)` / resume proofs.
//!   * Bounded per-session & global ring-buffer (`ResumeDataPlane`) stores unacknowledged outbound
//!     chunks so carrier death triggers seamless reattachment and zero-loss retransmission without
//!     resetting the destination TCP socket on Exit or client TCP socket on Entry.

use crate::stats;
use crate::util::{ct_eq, rand_bytes};
use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify};

pub const SESSION_ID_LEN: usize = 16;
pub const RESUME_TOKEN_LEN: usize = 32;
pub const RESUME_PROOF_LEN: usize = 32;
pub const MAX_UNACKED_BYTES_PER_SESSION: usize = 512 * 1024;
pub const MAX_GLOBAL_RESUME_BUFFER_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RESUMABLE_SESSIONS: usize = 4096;
pub const DEFAULT_SESSION_DETACH_TTL: Duration = Duration::from_secs(45);
/// Max selective-ACK blocks per frame (TCP-style; keeps wire small).
pub const MAX_SACK_BLOCKS: usize = 4;
/// RFC 6675-style duplicate threshold for declaring a segment lost via SACK.
pub const DUP_THRESH: usize = 3;
/// Cap recovery retransmits per retransmit-loop tick to avoid carrier bursts.
const MAX_LOST_RETX_PER_TICK: usize = 8;
/// Upper bound on handing one live frame to a carrier channel before treating it as wedged.
const LIVE_CARRIER_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bound on replaying unacknowledged segments after carrier reattachment.
const REPLAY_TIMEOUT: Duration = Duration::from_secs(15);

pub type SessionId = [u8; SESSION_ID_LEN];
pub type ResumeToken = [u8; RESUME_TOKEN_LEN];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResumeFrame {
    /// Entry -> Exit: attach or reattach a detached SessionOwner onto a live carrier.
    AttachReq {
        session_id: SessionId,
        epoch: u32,
        last_ack_seq: u64,
        target_addr: Vec<u8>,
        proof: [u8; RESUME_PROOF_LEN],
        /// Entry-generated resume token (inside Noise channel). Exit stores it and verifies proofs.
        token: ResumeToken,
    },
    /// Exit -> Entry: session attached/resumed; peer should retransmit from `peer_ack_seq + 1`.
    AttachAck {
        session_id: SessionId,
        epoch: u32,
        peer_ack_seq: u64,
        accepted: bool,
    },
    /// Sequenced reliable stream payload.
    SeqData {
        session_id: SessionId,
        epoch: u32,
        seq: u64,
        ack: u64,
        payload: Vec<u8>,
    },
    /// Explicit cumulative ACK.
    SeqAck {
        session_id: SessionId,
        epoch: u32,
        ack: u64,
    },
    /// Cumulative ACK plus selective blocks for out-of-order holes.
    /// Each range is half-open `[left, right)` in sequence-number space.
    SeqSack {
        session_id: SessionId,
        epoch: u32,
        ack: u64,
        ranges: Vec<(u64, u64)>,
    },
    /// Graceful EOF with final sequence number.
    SeqFin {
        session_id: SessionId,
        epoch: u32,
        seq: u64,
    },
}

impl ResumeFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            ResumeFrame::AttachReq {
                session_id,
                epoch,
                last_ack_seq,
                target_addr,
                proof,
                token,
            } => {
                out.push(0x10);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(&last_ack_seq.to_be_bytes());
                out.extend_from_slice(&(target_addr.len() as u16).to_be_bytes());
                out.extend_from_slice(target_addr);
                out.extend_from_slice(proof);
                out.extend_from_slice(token);
            }
            ResumeFrame::AttachAck {
                session_id,
                epoch,
                peer_ack_seq,
                accepted,
            } => {
                out.push(0x11);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(&peer_ack_seq.to_be_bytes());
                out.push(u8::from(*accepted));
            }
            ResumeFrame::SeqData {
                session_id,
                epoch,
                seq,
                ack,
                payload,
            } => {
                out.push(0x12);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(&ack.to_be_bytes());
                out.extend_from_slice(payload);
            }
            ResumeFrame::SeqAck {
                session_id,
                epoch,
                ack,
            } => {
                out.push(0x13);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(&ack.to_be_bytes());
            }
            ResumeFrame::SeqSack {
                session_id,
                epoch,
                ack,
                ranges,
            } => {
                out.push(0x15);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(&ack.to_be_bytes());
                let n = ranges.len().min(MAX_SACK_BLOCKS) as u8;
                out.push(n);
                for &(left, right) in ranges.iter().take(n as usize) {
                    out.extend_from_slice(&left.to_be_bytes());
                    out.extend_from_slice(&right.to_be_bytes());
                }
            }
            ResumeFrame::SeqFin {
                session_id,
                epoch,
                seq,
            } => {
                out.push(0x14);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(&seq.to_be_bytes());
            }
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 1 + SESSION_ID_LEN + 4 {
            bail!("resume frame too short");
        }
        let tag = buf[0];
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&buf[1..17]);
        let epoch = u32::from_be_bytes(buf[17..21].try_into()?);
        match tag {
            0x10 => {
                if buf.len() < 21 + 8 + 2 + RESUME_PROOF_LEN + RESUME_TOKEN_LEN {
                    bail!("AttachReq truncated");
                }
                let last_ack_seq = u64::from_be_bytes(buf[21..29].try_into()?);
                let tlen = u16::from_be_bytes(buf[29..31].try_into()?) as usize;
                if tlen > 512 {
                    bail!("AttachReq target too long");
                }
                if buf.len() != 31 + tlen + RESUME_PROOF_LEN + RESUME_TOKEN_LEN {
                    bail!("AttachReq length mismatch");
                }
                let target_addr = buf[31..31 + tlen].to_vec();
                let mut proof = [0u8; RESUME_PROOF_LEN];
                proof.copy_from_slice(&buf[31 + tlen..31 + tlen + RESUME_PROOF_LEN]);
                let mut token = [0u8; RESUME_TOKEN_LEN];
                token.copy_from_slice(&buf[31 + tlen + RESUME_PROOF_LEN..]);
                Ok(ResumeFrame::AttachReq {
                    session_id,
                    epoch,
                    last_ack_seq,
                    target_addr,
                    proof,
                    token,
                })
            }
            0x11 => {
                if buf.len() != 30 {
                    bail!("AttachAck length mismatch");
                }
                let peer_ack_seq = u64::from_be_bytes(buf[21..29].try_into()?);
                let accepted = buf[29] == 1;
                Ok(ResumeFrame::AttachAck {
                    session_id,
                    epoch,
                    peer_ack_seq,
                    accepted,
                })
            }
            0x12 => {
                if buf.len() < 37 {
                    bail!("SeqData truncated");
                }
                let seq = u64::from_be_bytes(buf[21..29].try_into()?);
                let ack = u64::from_be_bytes(buf[29..37].try_into()?);
                Ok(ResumeFrame::SeqData {
                    session_id,
                    epoch,
                    seq,
                    ack,
                    payload: buf[37..].to_vec(),
                })
            }
            0x13 => {
                if buf.len() != 29 {
                    bail!("SeqAck length mismatch");
                }
                let ack = u64::from_be_bytes(buf[21..29].try_into()?);
                Ok(ResumeFrame::SeqAck {
                    session_id,
                    epoch,
                    ack,
                })
            }
            0x15 => {
                if buf.len() < 30 {
                    bail!("SeqSack truncated");
                }
                let ack = u64::from_be_bytes(buf[21..29].try_into()?);
                let n = buf[29] as usize;
                if n > MAX_SACK_BLOCKS {
                    bail!("SeqSack too many blocks");
                }
                if buf.len() != 30 + n * 16 {
                    bail!("SeqSack length mismatch");
                }
                let mut ranges = Vec::with_capacity(n);
                let mut off = 30;
                for _ in 0..n {
                    let left = u64::from_be_bytes(buf[off..off + 8].try_into()?);
                    let right = u64::from_be_bytes(buf[off + 8..off + 16].try_into()?);
                    if right <= left {
                        bail!("SeqSack empty/inverted range");
                    }
                    ranges.push((left, right));
                    off += 16;
                }
                Ok(ResumeFrame::SeqSack {
                    session_id,
                    epoch,
                    ack,
                    ranges,
                })
            }
            0x14 => {
                if buf.len() != 29 {
                    bail!("SeqFin length mismatch");
                }
                let seq = u64::from_be_bytes(buf[21..29].try_into()?);
                Ok(ResumeFrame::SeqFin {
                    session_id,
                    epoch,
                    seq,
                })
            }
            _ => bail!("unknown resume frame tag 0x{tag:02x}"),
        }
    }
}

/// Cryptographic proof binding a `ResumeToken` to the authenticated Noise static key,
/// `session_id`, and strictly monotonic `epoch`.
pub fn compute_resume_proof(
    token: &ResumeToken,
    peer_noise_pub: &[u8],
    session_id: &SessionId,
    epoch: u32,
) -> [u8; RESUME_PROOF_LEN] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(token).expect("hmac accepts 32B key");
    mac.update(b"khaymali/resume-proof/v1");
    mac.update(peer_noise_pub);
    mac.update(session_id);
    mac.update(&epoch.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let mut proof = [0u8; RESUME_PROOF_LEN];
    proof.copy_from_slice(&out);
    proof
}

pub fn verify_resume_proof(
    token: &ResumeToken,
    peer_noise_pub: &[u8],
    session_id: &SessionId,
    epoch: u32,
    proof: &[u8; RESUME_PROOF_LEN],
) -> bool {
    let expected = compute_resume_proof(token, peer_noise_pub, session_id, epoch);
    ct_eq(&expected, proof)
}

/// Authorize an AttachReq before touching the replay ledger.
///
/// `proof_binding` is the key mixed into the HMAC (on the wire path this is the Exit static
/// public key — the same value the Entry stores as `SessionOwner.peer_noise_pub`).
/// `noise_peer` is the authenticated Noise remote static key of the carrier (Entry identity).
///
/// Returns `Ok(false)` for a new session and `Ok(true)` to resume. Forged proofs, empty peers,
/// zero tokens, or binding mismatches are rejected without burning the victim's epoch.
pub fn authorize_attach(
    proof_binding: &[u8],
    noise_peer: &[u8],
    token: &ResumeToken,
    session_id: &SessionId,
    epoch: u32,
    proof: &[u8; RESUME_PROOF_LEN],
    existing: Option<(&[u8], &[u8], bool)>,
) -> Result<bool> {
    if noise_peer.is_empty() || proof_binding.is_empty() {
        bail!("resume rejected: missing peer identity");
    }
    if token.iter().all(|b| *b == 0) {
        bail!("resume rejected: empty token");
    }
    if !verify_resume_proof(token, proof_binding, session_id, epoch, proof) {
        bail!("resume rejected: invalid proof");
    }
    if let Some((stored_token, stored_peer, closed)) = existing {
        if closed
            || stored_peer.is_empty()
            || !ct_eq(stored_peer, noise_peer)
            || !ct_eq(stored_token, token)
        {
            bail!("resume rejected: session binding mismatch");
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Replay & Generation-Lease ledger preventing replay of old resume handshakes or stale epochs.
struct LedgerState {
    seen: HashSet<[u8; RESUME_PROOF_LEN]>,
    order: VecDeque<[u8; RESUME_PROOF_LEN]>,
    highest_epoch: HashMap<SessionId, u32>,
}

pub struct ReplayLedger {
    inner: Mutex<LedgerState>,
}

impl Default for ReplayLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayLedger {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(LedgerState {
                seen: HashSet::new(),
                order: VecDeque::new(),
                highest_epoch: HashMap::new(),
            }),
        }
    }

    pub fn validate_and_record(
        &self,
        session_id: &SessionId,
        epoch: u32,
        proof: &[u8; RESUME_PROOF_LEN],
    ) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if g.seen.contains(proof) {
            bail!("replayed resume proof rejected");
        }
        if let Some(&prev) = g.highest_epoch.get(session_id) {
            if epoch <= prev {
                bail!("stale resume epoch {epoch} <= {prev}");
            }
        }
        const CAP: usize = MAX_RESUMABLE_SESSIONS * 8;
        while g.order.len() >= CAP {
            if let Some(old) = g.order.pop_front() {
                g.seen.remove(&old);
            } else {
                break;
            }
        }
        g.seen.insert(*proof);
        g.order.push_back(*proof);
        g.highest_epoch.insert(*session_id, epoch);
        Ok(())
    }
}

/// One staged outbound chunk. `last_sent == None` means it has not been handed to a carrier yet,
/// so the retransmit loop must not race the original send.
struct OutSeg {
    seq: u64,
    data: Vec<u8>,
    last_sent: Option<Instant>,
    sends: u32,
    /// Peer reported this seq via SACK; skip RTO until cumulative ACK advances (TCP-style).
    sacked: bool,
    /// Declared lost by IsLost (SACK scoreboard); may still be in flight after one recovery retx.
    lost: bool,
    /// One-shot: recovery path should retransmit this segment once after it was declared lost.
    lost_retx_pending: bool,
}

/// Jacobson/Karels RTT estimator (RFC 6298-style constants).
/// Samples only from segments sent once (Karn's algorithm).
struct RttEstimator {
    srtt: Option<Duration>,
    rttvar: Duration,
}

impl RttEstimator {
    fn new() -> Self {
        Self {
            srtt: None,
            // Conservative initial variance until the first sample arrives.
            rttvar: Duration::from_millis(250),
        }
    }

    fn update(&mut self, m: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(m);
                self.rttvar = (m / 2).max(Duration::from_millis(1));
            }
            Some(s) => {
                let err = if m > s { m - s } else { s - m };
                // RTTVAR ← (1 - β)·RTTVAR + β·|SRTT - m|  with β = 1/4
                self.rttvar = (self.rttvar.saturating_mul(3) + err) / 4;
                // SRTT ← (1 - α)·SRTT + α·m  with α = 1/8
                self.srtt = Some((s.saturating_mul(7) + m) / 8);
            }
        }
    }

    /// RTO = SRTT + 4·RTTVAR, clamped to [200ms, 3s].
    fn base_rto(&self) -> Duration {
        const MIN_RTO: Duration = Duration::from_millis(200);
        const MAX_RTO: Duration = Duration::from_secs(3);
        let srtt = self.srtt.unwrap_or(Duration::from_millis(500));
        let rto = srtt.saturating_add(self.rttvar.saturating_mul(4));
        if rto < MIN_RTO {
            MIN_RTO
        } else if rto > MAX_RTO {
            MAX_RTO
        } else {
            rto
        }
    }

    /// After carrier reattach the path may have changed; inflate variance so we do not
    /// under-estimate RTO on the new carrier.
    fn inflate_after_reattach(&mut self) {
        if let Some(s) = self.srtt {
            let floor = (s / 2).max(Duration::from_millis(50));
            self.rttvar = self.rttvar.max(floor);
            if self.rttvar > Duration::from_secs(1) {
                self.rttvar = Duration::from_secs(1);
            }
        } else {
            self.rttvar = Duration::from_millis(500);
        }
    }
}

/// Per-segment timeout: exponential backoff on top of the adaptive base RTO.
fn rto_after(sends: u32, base: Duration) -> Duration {
    let exp = sends.saturating_sub(1).min(4);
    let base_ms = base.as_millis() as u64;
    let ms = base_ms.saturating_mul(1u64 << exp).min(3000);
    Duration::from_millis(ms.max(1)).min(Duration::from_secs(3))
}

/// Reliable in-order sequenced data-plane buffer (`ResumeDataPlane`) with ACK trimming,
/// out-of-order reassembly, duplicate suppression, and memory ceiling enforcement.
pub struct ResumeDataPlane {
    next_send_seq: u64,
    peer_acked_seq: u64,
    unacked: VecDeque<OutSeg>,
    unacked_bytes: usize,
    next_recv_seq: u64,
    ooo_recv: BTreeMap<u64, Vec<u8>>,
    ooo_bytes: usize,
    max_buffer_bytes: usize,
    rtt: RttEstimator,
    /// RFC 6675 RecoveryPoint: highest sequence number sent when entering SACK recovery.
    recovery_point: Option<u64>,
}

impl ResumeDataPlane {
    pub fn new(max_buffer_bytes: usize) -> Self {
        Self {
            next_send_seq: 1,
            peer_acked_seq: 0,
            unacked: VecDeque::new(),
            unacked_bytes: 0,
            next_recv_seq: 1,
            ooo_recv: BTreeMap::new(),
            ooo_bytes: 0,
            max_buffer_bytes: max_buffer_bytes.max(4096),
            rtt: RttEstimator::new(),
            recovery_point: None,
        }
    }

    pub fn has_unacked(&self) -> bool {
        !self.unacked.is_empty()
    }

    pub fn in_recovery(&self) -> bool {
        self.recovery_point.is_some()
    }

    pub fn recovery_point(&self) -> Option<u64> {
        self.recovery_point
    }

    pub fn current_ack(&self) -> u64 {
        self.next_recv_seq.saturating_sub(1)
    }

    pub fn unacked_bytes(&self) -> usize {
        self.unacked_bytes
    }

    pub fn peer_acked(&self) -> u64 {
        self.peer_acked_seq
    }

    pub fn stage_outbound(&mut self, payload: Vec<u8>) -> Result<u64> {
        if self.unacked_bytes + payload.len() > self.max_buffer_bytes {
            bail!("session unacked buffer full ({} bytes)", self.unacked_bytes);
        }
        let seq = self.next_send_seq;
        self.next_send_seq += 1;
        self.unacked_bytes += payload.len();
        self.unacked.push_back(OutSeg {
            seq,
            data: payload,
            last_sent: None,
            sends: 0,
            sacked: false,
            lost: false,
            lost_retx_pending: false,
        });
        Ok(seq)
    }

    pub fn mark_sent(&mut self, seq: u64, now: Instant) {
        if let Some(seg) = self.unacked.iter_mut().find(|s| s.seq == seq) {
            seg.last_sent = Some(now);
            if seg.sends == 0 {
                seg.sends = 1;
            }
        }
    }

    /// Segments whose last transmission is older than the current RTO.
    pub fn base_rto(&self) -> Duration {
        self.rtt.base_rto()
    }

    pub fn srtt(&self) -> Option<Duration> {
        self.rtt.srtt
    }

    pub fn due_retransmits(&mut self, now: Instant) -> Vec<(u64, Vec<u8>)> {
        let base = self.rtt.base_rto();
        let mut out = Vec::new();
        // 1) Recovery retransmits for segments newly declared lost (IsLost / left-edge).
        for seg in self.unacked.iter_mut() {
            if out.len() >= MAX_LOST_RETX_PER_TICK {
                break;
            }
            if seg.sacked || !seg.lost_retx_pending {
                continue;
            }
            if seg.last_sent.is_none() {
                continue;
            }
            seg.lost_retx_pending = false;
            seg.last_sent = Some(now);
            seg.sends = seg.sends.saturating_add(1);
            out.push((seg.seq, seg.data.clone()));
        }
        // 2) RTO path for anything still missing (including lost segments after recovery retx).
        for seg in self.unacked.iter_mut() {
            if seg.sacked {
                continue;
            }
            if out.iter().any(|(s, _)| *s == seg.seq) {
                continue;
            }
            let Some(sent) = seg.last_sent else { continue };
            if now.saturating_duration_since(sent) < rto_after(seg.sends.max(1), base) {
                continue;
            }
            seg.last_sent = Some(now);
            seg.sends = seg.sends.saturating_add(1);
            out.push((seg.seq, seg.data.clone()));
        }
        out
    }

    /// Fast retransmit of the oldest hole after duplicate ACKs.
    pub fn force_oldest_retransmit(&mut self, now: Instant) -> Vec<(u64, Vec<u8>)> {
        // Prefer a pending IsLost recovery retx if any.
        if let Some(seg) = self
            .unacked
            .iter_mut()
            .find(|s| s.lost_retx_pending && !s.sacked && s.last_sent.is_some())
        {
            seg.lost_retx_pending = false;
            seg.last_sent = Some(now);
            seg.sends = seg.sends.saturating_add(1);
            return vec![(seg.seq, seg.data.clone())];
        }
        let Some(seg) = self.unacked.iter_mut().find(|s| !s.sacked && s.last_sent.is_some()) else {
            return Vec::new();
        };
        seg.last_sent = Some(now);
        seg.sends = seg.sends.saturating_add(1);
        vec![(seg.seq, seg.data.clone())]
    }

    /// Test helper: pretend every in-flight segment was sent `by` ago so the RTO fires at once.
    pub fn test_backdate_unacked(&mut self, by: Duration) {
        let sent_at = Instant::now().checked_sub(by).unwrap_or_else(Instant::now);
        for seg in self.unacked.iter_mut() {
            seg.last_sent = Some(sent_at);
            if seg.sends == 0 {
                seg.sends = 1;
            }
        }
    }

    pub fn process_ack(&mut self, ack: u64) {
        self.process_ack_ex(ack, true);
    }

    /// `sample_rtt`: when false (e.g. resume trim), do not feed Karn samples — the
    /// send timestamp may span a dead carrier and would poison SRTT.
    fn process_ack_ex(&mut self, ack: u64, sample_rtt: bool) {
        if ack <= self.peer_acked_seq {
            return;
        }
        self.peer_acked_seq = ack;
        let now = Instant::now();
        while let Some(seg) = self.unacked.front() {
            if seg.seq > ack {
                break;
            }
            if sample_rtt && seg.sends == 1 {
                // Karn: ignore retransmitted segments (ambiguous which flight was ACKed).
                if let Some(sent) = seg.last_sent {
                    let m = now.saturating_duration_since(sent);
                    if m >= Duration::from_millis(1) && m <= Duration::from_secs(10) {
                        self.rtt.update(m);
                    }
                }
            }
            self.unacked_bytes = self.unacked_bytes.saturating_sub(seg.data.len());
            self.unacked.pop_front();
        }
        if let Some(rp) = self.recovery_point {
            if self.peer_acked_seq >= rp || self.unacked.is_empty() {
                self.recovery_point = None;
            }
        }
    }

    pub fn inflate_rtt_after_reattach(&mut self) {
        self.rtt.inflate_after_reattach();
    }

    /// Mark unacked segments covered by selective ACK ranges so RTO skips them.
    pub fn mark_sacked(&mut self, ranges: &[(u64, u64)]) {
        if ranges.is_empty() {
            return;
        }
        for seg in self.unacked.iter_mut() {
            if seg.sacked || seg.seq <= self.peer_acked_seq {
                continue;
            }
            for &(left, right) in ranges {
                if seg.seq >= left && seg.seq < right {
                    seg.sacked = true;
                    seg.lost = false;
                    seg.lost_retx_pending = false;
                    break;
                }
            }
        }
        self.update_is_lost();
    }

    /// RFC 6675-inspired IsLost on a segment scoreboard.
    ///
    /// A non-SACKed, already-sent segment above the cumulative ACK is declared lost when
    /// at least `DUP_THRESH` later segments are SACKed. The left edge of the scoreboard
    /// is also marked lost whenever any SACK block exists (fast recovery of the first hole
    /// even before DupThresh SACKs accumulate above it).
    pub fn update_is_lost(&mut self) {
        let sacked_after: Vec<u64> = self
            .unacked
            .iter()
            .filter(|s| s.sacked)
            .map(|s| s.seq)
            .collect();
        let has_sack = !sacked_after.is_empty();
        let mut newly_pending = false;
        let peer_acked = self.peer_acked_seq;
        for seg in self.unacked.iter_mut() {
            if seg.sacked || seg.last_sent.is_none() || seg.seq <= peer_acked {
                seg.lost = false;
                seg.lost_retx_pending = false;
                continue;
            }
            let above = sacked_after.iter().filter(|&&s| s > seg.seq).count();
            let is_lost = above >= DUP_THRESH;
            if is_lost {
                if !seg.lost {
                    seg.lost = true;
                    seg.lost_retx_pending = true;
                    newly_pending = true;
                }
            } else {
                // Reorder path: not enough evidence anymore.
                if seg.lost && !seg.lost_retx_pending {
                    seg.lost = false;
                } else if !seg.lost {
                    seg.lost_retx_pending = false;
                }
            }
        }
        // Left-edge assist: any SACK implies the oldest hole is worth one recovery retx.
        if has_sack {
            if let Some(front) = self.unacked.front_mut() {
                if !front.sacked
                    && front.last_sent.is_some()
                    && front.seq > peer_acked
                    && !front.lost_retx_pending
                {
                    if !front.lost {
                        front.lost = true;
                        front.lost_retx_pending = true;
                        newly_pending = true;
                    } else if front.sends <= 1 {
                        // Declared lost earlier but recovery retx not yet queued.
                        front.lost_retx_pending = true;
                        newly_pending = true;
                    }
                }
            }
        }
        if newly_pending && self.recovery_point.is_none() {
            let high_data = self.next_send_seq.saturating_sub(1);
            if high_data > peer_acked {
                self.recovery_point = Some(high_data);
            }
        } else if self.unacked.is_empty() {
            self.recovery_point = None;
        }
    }

    /// True when at least one segment awaits a recovery retransmission.
    pub fn has_lost_retx_pending(&self) -> bool {
        self.unacked.iter().any(|s| s.lost_retx_pending)
    }

    /// Test helper: number of segments currently marked lost.
    pub fn lost_count(&self) -> usize {
        self.unacked.iter().filter(|s| s.lost).count()
    }

    /// Build up to `MAX_SACK_BLOCKS` contiguous ranges from the out-of-order map.
    pub fn sack_blocks(&self) -> Vec<(u64, u64)> {
        let mut blocks = Vec::new();
        let mut iter = self.ooo_recv.keys();
        let Some(&first) = iter.next() else {
            return blocks;
        };
        let mut left = first;
        let mut right = first + 1;
        for &seq in iter {
            if seq == right {
                right = seq + 1;
                continue;
            }
            blocks.push((left, right));
            if blocks.len() >= MAX_SACK_BLOCKS {
                return blocks;
            }
            left = seq;
            right = seq + 1;
        }
        blocks.push((left, right));
        blocks
    }

    pub fn replay_from(&mut self, peer_ack_seq: u64) -> Vec<(u64, Vec<u8>)> {
        // Trim with peer's cumulative ACK but do not sample RTT across the old carrier.
        self.process_ack_ex(peer_ack_seq, false);
        self.rtt.inflate_after_reattach();
        self.recovery_point = None;
        let now = Instant::now();
        for seg in self.unacked.iter_mut() {
            seg.last_sent = Some(now);
            if seg.sends == 0 {
                seg.sends = 1;
            }
            // Replay is a new flight on a new carrier; allow a fresh Karn sample later.
            if seg.sends > 1 {
                seg.sends = 1;
            }
            seg.sacked = false;
            seg.lost = false;
            seg.lost_retx_pending = false;
        }
        self.unacked
            .iter()
            .map(|seg| (seg.seq, seg.data.clone()))
            .collect()
    }

    pub fn ingest_inbound(&mut self, seq: u64, payload: Vec<u8>) -> Result<Vec<Vec<u8>>> {
        if seq < self.next_recv_seq {
            return Ok(Vec::new());
        }
        if seq == self.next_recv_seq {
            let mut ready = vec![payload];
            self.next_recv_seq += 1;
            while let Some(next_chunk) = self.ooo_recv.remove(&self.next_recv_seq) {
                self.ooo_bytes = self.ooo_bytes.saturating_sub(next_chunk.len());
                ready.push(next_chunk);
                self.next_recv_seq += 1;
            }
            return Ok(ready);
        }
        if !self.ooo_recv.contains_key(&seq) {
            if self.ooo_bytes + payload.len() > self.max_buffer_bytes {
                bail!("session out-of-order buffer limit exceeded");
            }
            self.ooo_bytes += payload.len();
            self.ooo_recv.insert(seq, payload);
        }
        Ok(Vec::new())
    }
}

/// Carrier attachment channel for a live `SessionOwner`.
/// When a carrier dies, `carrier_tx` is swapped atomically to `None` while the `SessionOwner`
/// task keeps the underlying TCP socket alive and waits for `reattach_carrier(...)`.
pub struct SessionOwner {
    pub session_id: SessionId,
    pub resume_token: ResumeToken,
    pub peer_noise_pub: Vec<u8>,
    pub target_addr: Vec<u8>,
    pub epoch: AtomicU32,
    pub closed: AtomicBool,
    pub last_activity: Mutex<Instant>,
    pub dataplane: Mutex<ResumeDataPlane>,
    carrier_tx: Mutex<Option<mpsc::Sender<ResumeFrame>>>,
    reattached_notify: Notify,
    /// Woken when an ACK frees space in the un-ACKed send window.
    pub window_notify: Notify,
    /// Woken immediately when `close()` is invoked so blocked readers/writers exit cleanly.
    close_notify: Notify,
    /// Ordered inbound chunks already reassembled by `ResumeDataPlane`, drained by one FIFO task.
    inbound_queue: Mutex<VecDeque<Vec<u8>>>,
    inbound_notify: Notify,
    drainer_started: AtomicBool,
    /// Set when three duplicate ACKs or IsLost recovery say segments should go again now.
    fast_retx: AtomicBool,
    dup_acks: AtomicU32,
    /// Consecutive explicit `AttachAck(accepted=false)` rejections observed by supervisor.
    reattach_rejects: AtomicU32,
    /// Serializes reassembly + forwarding for `deliver_from_carrier`.
    deliver_lock: tokio::sync::Mutex<()>,
    /// Option so `close()` drops the sender immediately and breaks any blocked `to_socket_rx.recv()`.
    to_socket_tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
}

impl SessionOwner {
    pub fn new(
        peer_noise_pub: Vec<u8>,
        target_addr: Vec<u8>,
        to_socket_tx: mpsc::Sender<Vec<u8>>,
    ) -> Arc<Self> {
        Self::with_id_and_token(
            rand_bytes::<SESSION_ID_LEN>(),
            rand_bytes::<RESUME_TOKEN_LEN>(),
            peer_noise_pub,
            target_addr,
            to_socket_tx,
        )
    }

    pub fn with_id_and_token(
        session_id: SessionId,
        resume_token: ResumeToken,
        peer_noise_pub: Vec<u8>,
        target_addr: Vec<u8>,
        to_socket_tx: mpsc::Sender<Vec<u8>>,
    ) -> Arc<Self> {
        let owner = Arc::new(Self {
            session_id,
            resume_token,
            peer_noise_pub,
            target_addr,
            epoch: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            last_activity: Mutex::new(Instant::now()),
            dataplane: Mutex::new(ResumeDataPlane::new(MAX_UNACKED_BYTES_PER_SESSION)),
            carrier_tx: Mutex::new(None),
            reattached_notify: Notify::new(),
            window_notify: Notify::new(),
            close_notify: Notify::new(),
            inbound_queue: Mutex::new(VecDeque::new()),
            inbound_notify: Notify::new(),
            drainer_started: AtomicBool::new(false),
            fast_retx: AtomicBool::new(false),
            dup_acks: AtomicU32::new(0),
            reattach_rejects: AtomicU32::new(0),
            deliver_lock: tokio::sync::Mutex::new(()),
            to_socket_tx: Mutex::new(Some(to_socket_tx)),
        });
        // Weak so the task dies with the session even if a caller forgets `close()`.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let weak = Arc::downgrade(&owner);
            handle.spawn(async move { SessionOwner::retransmit_loop(weak).await });
        }
        owner
    }

    pub fn current_epoch(&self) -> u32 {
        self.epoch.load(Relaxed)
    }

    pub fn bump_epoch(&self) -> u32 {
        self.epoch.fetch_add(1, Relaxed) + 1
    }

    pub fn is_detached(&self) -> bool {
        let g = self.carrier_tx.lock().unwrap();
        match g.as_ref() {
            None => true,
            Some(tx) => tx.is_closed(),
        }
    }

    pub fn has_unacked(&self) -> bool {
        self.dataplane.lock().unwrap().has_unacked()
    }

    pub fn note_reattach_reject(&self) -> u32 {
        self.reattach_rejects.fetch_add(1, Relaxed) + 1
    }

    pub fn reset_reattach_rejects(&self) {
        self.reattach_rejects.store(0, Relaxed);
    }

    /// Resolves immediately once `close()` has been called on this session.
    pub async fn wait_closed(&self) {
        loop {
            let n = self.close_notify.notified();
            tokio::pin!(n);
            n.as_mut().enable();
            if self.closed.load(Relaxed) {
                return;
            }
            n.await;
        }
    }

    /// Wait up to `max_wait` for all outbound chunks (including in-band FIN) to be ACKed,
    /// returning early if the session is closed.
    pub async fn wait_drained(&self, max_wait: Duration) {
        let deadline = Instant::now() + max_wait;
        loop {
            let wn = self.window_notify.notified();
            tokio::pin!(wn);
            wn.as_mut().enable();
            if self.closed.load(Relaxed) || !self.has_unacked() {
                return;
            }
            let rem = deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                return;
            }
            tokio::select! {
                _ = tokio::time::timeout(rem.min(Duration::from_millis(200)), wn) => {}
                _ = self.wait_closed() => return,
            }
        }
    }

    pub fn detach_carrier(&self) {
        *self.carrier_tx.lock().unwrap() = None;
    }

    /// Drop the carrier only when `tx` is still the live one. A forwarder from a previous
    /// attach must not clear the sender installed by a newer reattach.
    pub fn detach_if_same_sender(&self, tx: &mpsc::Sender<ResumeFrame>) {
        let mut slot = self.carrier_tx.lock().unwrap();
        if slot.as_ref().is_some_and(|cur| cur.same_channel(tx)) {
            *slot = None;
        }
    }

    /// Session-level retransmission for frames lost to a dead forwarder / map race / peer drop.
    async fn retransmit_loop(weak: std::sync::Weak<SessionOwner>) {
        loop {
            tokio::time::sleep(Duration::from_millis(80)).await;
            let Some(this) = weak.upgrade() else { return };
            if this.closed.load(Relaxed) {
                return;
            }
            let force = this.fast_retx.swap(false, Relaxed);
            let due = {
                let mut dp = this.dataplane.lock().unwrap();
                let now = Instant::now();
                // `due_retransmits` already drains IsLost pending (up to MAX_LOST_RETX_PER_TICK)
                // and RTO-expired segments. On force, also ensure at least the oldest hole moves
                // if the scoreboard has not marked anything yet (pure dup-ACK path).
                let mut due = dp.due_retransmits(now);
                if force && due.is_empty() {
                    due = dp.force_oldest_retransmit(now);
                }
                due
            };
            if due.is_empty() {
                continue;
            }
            let tx = this.carrier_tx.lock().unwrap().clone();
            let Some(tx) = tx else { continue };
            if tx.is_closed() {
                this.detach_if_same_sender(&tx);
                continue;
            }
            let epoch = this.epoch.load(Relaxed);
            let ack = this.dataplane.lock().unwrap().current_ack();
            for (seq, payload) in due {
                if this.closed.load(Relaxed) {
                    return;
                }
                let frame = ResumeFrame::SeqData {
                    session_id: this.session_id,
                    epoch,
                    seq,
                    ack,
                    payload,
                };
                let sent = tokio::select! {
                    r = tokio::time::timeout(LIVE_CARRIER_SEND_TIMEOUT, tx.send(frame)) => {
                        matches!(r, Ok(Ok(())))
                    }
                    _ = this.wait_closed() => return,
                };
                if !sent {
                    this.detach_if_same_sender(&tx);
                    break;
                }
                stats::SESSION_RETRANSMITS.fetch_add(1, Relaxed);
            }
        }
    }

    pub async fn reattach_carrier(
        &self,
        new_epoch: u32,
        peer_ack_seq: u64,
        tx: mpsc::Sender<ResumeFrame>,
    ) -> Result<usize> {
        if self.closed.load(Relaxed) {
            bail!("cannot reattach closed session");
        }
        self.epoch.store(new_epoch, Relaxed);
        self.reset_reattach_rejects();
        let (replay_list, ack_now, sack_ranges) = {
            let mut dp = self.dataplane.lock().unwrap();
            let list = dp.replay_from(peer_ack_seq);
            let ack = dp.current_ack();
            let ranges = dp.sack_blocks();
            (list, ack, ranges)
        };
        let replayed = replay_list.len();
        let replay_deadline = Instant::now() + REPLAY_TIMEOUT;
        for (seq, payload) in replay_list {
            let rem = replay_deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                bail!("replacement carrier replay timeout exceeded");
            }
            let frame = ResumeFrame::SeqData {
                session_id: self.session_id,
                epoch: new_epoch,
                seq,
                ack: ack_now,
                payload,
            };
            tokio::select! {
                r = tokio::time::timeout(rem, tx.send(frame)) => {
                    match r {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => bail!("replacement carrier closed during replay"),
                        Err(_) => bail!("replacement carrier replay timeout exceeded"),
                    }
                }
                _ = self.wait_closed() => bail!("session closed during replay"),
            }
        }
        if replayed == 0 && (ack_now > 0 || !sack_ranges.is_empty()) {
            let ack_frame = if sack_ranges.is_empty() {
                ResumeFrame::SeqAck {
                    session_id: self.session_id,
                    epoch: new_epoch,
                    ack: ack_now,
                }
            } else {
                ResumeFrame::SeqSack {
                    session_id: self.session_id,
                    epoch: new_epoch,
                    ack: ack_now,
                    ranges: sack_ranges,
                }
            };
            let _ = tokio::time::timeout(LIVE_CARRIER_SEND_TIMEOUT, tx.send(ack_frame)).await;
        }
        *self.carrier_tx.lock().unwrap() = Some(tx);
        *self.last_activity.lock().unwrap() = Instant::now();
        self.reattached_notify.notify_waiters();
        self.window_notify.notify_waiters();
        stats::SESSIONS_RESUMED.fetch_add(1, Relaxed);
        Ok(replayed)
    }

    pub async fn send_from_socket(&self, payload: Vec<u8>, wait_budget: Duration) -> Result<()> {
        if self.closed.load(Relaxed) {
            bail!("session closed");
        }
        let deadline = Instant::now() + wait_budget;
        // Flow control: wait (bounded by `wait_budget`) for the peer to ACK enough data instead of
        // failing as soon as the 512 KiB un-ACKed window is full.
        let seq = loop {
            let win_notified = self.window_notify.notified();
            tokio::pin!(win_notified);
            win_notified.as_mut().enable();
            if self.closed.load(Relaxed) {
                bail!("session closed");
            }
            let staged = {
                let mut dp = self.dataplane.lock().unwrap();
                if dp.unacked_bytes() + payload.len() <= MAX_UNACKED_BYTES_PER_SESSION {
                    Some(dp.stage_outbound(payload.clone())?)
                } else {
                    None
                }
            };
            if let Some(seq) = staged {
                break seq;
            }
            let rem = deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                bail!("send window stayed full: peer stopped acknowledging");
            }
            tokio::select! {
                _ = tokio::time::timeout(rem.min(Duration::from_millis(200)), win_notified) => {}
                _ = self.wait_closed() => bail!("session closed while waiting for send window"),
            }
        };
        loop {
            let re_notified = self.reattached_notify.notified();
            tokio::pin!(re_notified);
            re_notified.as_mut().enable();
            if self.closed.load(Relaxed) {
                bail!("session closed while waiting for carrier");
            }
            let maybe_tx = self.carrier_tx.lock().unwrap().clone();
            if let Some(tx) = maybe_tx {
                let epoch = self.epoch.load(Relaxed);
                let ack = self.dataplane.lock().unwrap().current_ack();
                let frame = ResumeFrame::SeqData {
                    session_id: self.session_id,
                    epoch,
                    seq,
                    ack,
                    payload: payload.clone(),
                };
                let sent = tokio::select! {
                    r = tokio::time::timeout(LIVE_CARRIER_SEND_TIMEOUT, tx.send(frame)) => {
                        matches!(r, Ok(Ok(())))
                    }
                    _ = self.wait_closed() => bail!("session closed while sending"),
                };
                if sent {
                    let now = Instant::now();
                    *self.last_activity.lock().unwrap() = now;
                    self.dataplane.lock().unwrap().mark_sent(seq, now);
                    return Ok(());
                }
                self.detach_if_same_sender(&tx);
            }
            let rem = deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                bail!("carrier reattach timeout exceeded");
            }
            tokio::select! {
                _ = tokio::time::timeout(rem.min(Duration::from_millis(250)), re_notified) => {}
                _ = self.wait_closed() => bail!("session closed while waiting for carrier"),
            }
        }
    }

    /// End-of-stream marker: an empty chunk staged like any other, so it keeps its place in the
    /// sequence (never overtakes data) and is replayed after a carrier switch. The receiving side
    /// treats an empty chunk as EOF and half-closes its socket.
    pub async fn send_fin(&self, budget: Duration) -> Result<()> {
        self.send_from_socket(Vec::new(), budget).await
    }

    /// Apply a cumulative ACK from the peer and wake senders waiting for window space.
    /// Three identical ACKs trigger fast retransmit of the oldest unacked segment.
    pub fn apply_ack(&self, ack: u64) {
        self.apply_sack(ack, &[]);
    }

    /// Cumulative ACK plus optional selective ranges. Updates the SACK scoreboard and
    /// IsLost flags; pending recovery retransmissions arm `fast_retx`.
    pub fn apply_sack(&self, ack: u64, ranges: &[(u64, u64)]) {
        let (advanced, need_retx) = {
            let mut dp = self.dataplane.lock().unwrap();
            let prev = dp.peer_acked();
            dp.process_ack(ack);
            if ranges.is_empty() {
                // Cumulative-only path still refreshes left-edge state.
                dp.update_is_lost();
            } else {
                dp.mark_sacked(ranges);
            }
            (ack > prev, dp.has_lost_retx_pending())
        };
        if advanced {
            self.dup_acks.store(0, Relaxed);
            self.window_notify.notify_waiters();
        } else if ack > 0 && ranges.is_empty() {
            let n = self.dup_acks.fetch_add(1, Relaxed) + 1;
            if n >= DUP_THRESH as u32 {
                self.dup_acks.store(0, Relaxed);
                self.fast_retx.store(true, Relaxed);
            }
        }
        if need_retx {
            self.fast_retx.store(true, Relaxed);
        }
    }

    /// Cumulative ack and current SACK blocks for building `SeqAck` / `SeqSack`.
    pub fn ack_state(&self) -> (u64, Vec<(u64, u64)>) {
        let dp = self.dataplane.lock().unwrap();
        (dp.current_ack(), dp.sack_blocks())
    }

    /// Prefer `SeqSack` when the peer has holes; otherwise plain `SeqAck`.
    pub fn make_ack_frame(&self, epoch: u32) -> ResumeFrame {
        let (ack, ranges) = self.ack_state();
        if ranges.is_empty() {
            ResumeFrame::SeqAck {
                session_id: self.session_id,
                epoch,
                ack,
            }
        } else {
            ResumeFrame::SeqSack {
                session_id: self.session_id,
                epoch,
                ack,
                ranges,
            }
        }
    }

    fn ensure_drainer_running(self: &Arc<Self>) {
        if self.drainer_started.swap(true, Relaxed) {
            return;
        }
        let ow = self.clone();
        tokio::spawn(async move {
            loop {
                let notified = ow.inbound_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                let mut sent_any = false;
                loop {
                    let next_chunk = ow.inbound_queue.lock().unwrap().pop_front();
                    let Some(chunk) = next_chunk else { break };
                    let maybe_tx = ow.to_socket_tx.lock().unwrap().clone();
                    let Some(tx) = maybe_tx else {
                        ow.close();
                        return;
                    };
                    let send_res = tokio::select! {
                        r = tx.send(chunk) => r,
                        _ = ow.wait_closed() => return,
                    };
                    if send_res.is_err() {
                        ow.close();
                        return;
                    }
                    sent_any = true;
                }

                if sent_any {
                    let maybe_carrier = ow.carrier_tx.lock().unwrap().clone();
                    if let Some(c_tx) = maybe_carrier {
                        let epoch = ow.epoch.load(Relaxed);
                        let ack_f = ow.make_ack_frame(epoch);
                        let ack_res = tokio::select! {
                            r = tokio::time::timeout(Duration::from_secs(2), c_tx.send(ack_f)) => r,
                            _ = ow.wait_closed() => return,
                        };
                        if matches!(ack_res, Ok(Err(_))) {
                            ow.detach_if_same_sender(&c_tx);
                        }
                    }
                }

                if ow.closed.load(Relaxed) {
                    return;
                }
                tokio::select! {
                    _ = notified => {}
                    _ = ow.wait_closed() => return,
                }
            }
        });
    }

    /// Synchronously ingest an inbound `SeqData` frame on the carrier reader in exact wire order,
    /// eliminating per-frame `tokio::spawn` LIFO reordering on multi-core hosts.
    /// Returns `Ok(Some(ack_frame))` immediately for out-of-order / duplicate frames (so SACK
    /// reaches the peer without waiting), or `Ok(None)` when the per-session FIFO drainer will
    /// emit a coalesced `SeqAck`/`SeqSack` after delivering chunks to the socket.
    pub fn enqueue_from_carrier(
        self: &Arc<Self>,
        epoch: u32,
        seq: u64,
        ack: u64,
        payload: Vec<u8>,
    ) -> Result<Option<ResumeFrame>> {
        if self.closed.load(Relaxed) {
            bail!("session closed");
        }
        if epoch < self.epoch.load(Relaxed) {
            bail!("stale epoch frame dropped");
        }
        let (chunks, ack_now, ranges, ack_advanced) = {
            let mut dp = self.dataplane.lock().unwrap();
            let prev = dp.peer_acked();
            dp.process_ack(ack);
            let chunks = dp.ingest_inbound(seq, payload)?;
            let cur_ack = dp.current_ack();
            let ranges = dp.sack_blocks();
            (chunks, cur_ack, ranges, ack > prev)
        };
        if ack_advanced {
            self.dup_acks.store(0, Relaxed);
            self.window_notify.notify_waiters();
        }
        *self.last_activity.lock().unwrap() = Instant::now();
        if chunks.is_empty() {
            let frame = if ranges.is_empty() {
                ResumeFrame::SeqAck {
                    session_id: self.session_id,
                    epoch,
                    ack: ack_now,
                }
            } else {
                ResumeFrame::SeqSack {
                    session_id: self.session_id,
                    epoch,
                    ack: ack_now,
                    ranges,
                }
            };
            return Ok(Some(frame));
        }
        {
            let mut q = self.inbound_queue.lock().unwrap();
            q.extend(chunks);
        }
        self.ensure_drainer_running();
        self.inbound_notify.notify_one();
        Ok(None)
    }

    pub async fn deliver_from_carrier(
        &self,
        epoch: u32,
        seq: u64,
        ack: u64,
        payload: Vec<u8>,
    ) -> Result<u64> {
        if epoch < self.epoch.load(Relaxed) {
            bail!("stale epoch frame dropped");
        }
        // Order guarantee: concurrent deliveries for this session are serialized from
        // reassembly until their chunks are queued to the socket.
        let _ordered = self.deliver_lock.lock().await;
        let chunks = {
            let mut dp = self.dataplane.lock().unwrap();
            dp.process_ack(ack);
            dp.ingest_inbound(seq, payload)?
        };
        self.window_notify.notify_waiters();
        *self.last_activity.lock().unwrap() = Instant::now();
        let maybe_tx = self.to_socket_tx.lock().unwrap().clone();
        let Some(tx) = maybe_tx else {
            self.close();
            bail!("local socket closed");
        };
        for c in chunks {
            if tx.send(c).await.is_err() {
                self.close();
                bail!("local socket closed");
            }
        }
        Ok(self.dataplane.lock().unwrap().current_ack())
    }

    pub fn close(&self) {
        self.closed.store(true, Relaxed);
        self.detach_carrier();
        *self.to_socket_tx.lock().unwrap() = None;
        self.inbound_queue.lock().unwrap().clear();
        self.close_notify.notify_waiters();
        self.inbound_notify.notify_waiters();
        self.reattached_notify.notify_waiters();
        self.window_notify.notify_waiters();
    }
}

pub struct SessionRegistry {
    sessions: Mutex<HashMap<SessionId, Arc<SessionOwner>>>,
    ledger: ReplayLedger,
    global_bytes: AtomicU64,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            ledger: ReplayLedger::new(),
            global_bytes: AtomicU64::new(0),
        }
    }

    pub fn insert(&self, owner: Arc<SessionOwner>) -> Result<()> {
        let mut map = self.sessions.lock().unwrap();
        if map.contains_key(&owner.session_id) {
            bail!("session id already registered");
        }
        if map.len() >= MAX_RESUMABLE_SESSIONS {
            bail!("max resumable sessions reached ({MAX_RESUMABLE_SESSIONS})");
        }
        map.insert(owner.session_id, owner);
        stats::RESUMABLE_SESSIONS_ACTIVE.store(map.len() as i64, Relaxed);
        Ok(())
    }

    pub fn get(&self, id: &SessionId) -> Option<Arc<SessionOwner>> {
        self.sessions.lock().unwrap().get(id).cloned()
    }

    pub fn remove(&self, id: &SessionId) -> Option<Arc<SessionOwner>> {
        let mut map = self.sessions.lock().unwrap();
        let out = map.remove(id);
        stats::RESUMABLE_SESSIONS_ACTIVE.store(map.len() as i64, Relaxed);
        out
    }

    pub fn active_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    pub fn detached_sessions(&self) -> Vec<Arc<SessionOwner>> {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| !s.closed.load(Relaxed) && s.is_detached())
            .cloned()
            .collect()
    }

    pub fn ledger(&self) -> &ReplayLedger {
        &self.ledger
    }

    pub fn global_buffered_bytes(&self) -> u64 {
        self.global_bytes.load(Relaxed)
    }

    pub fn sweep_expired(&self, ttl: Duration) -> usize {
        let mut map = self.sessions.lock().unwrap();
        let before = map.len();
        map.retain(|_, s| {
            let idle = s.last_activity.lock().unwrap().elapsed();
            let detached = s.is_detached();
            if s.closed.load(Relaxed) || (detached && idle > ttl) {
                s.close();
                false
            } else {
                true
            }
        });
        stats::RESUMABLE_SESSIONS_ACTIVE.store(map.len() as i64, Relaxed);
        before - map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn resume_frame_roundtrip_and_replay_ledger() {
        let sid = [7u8; 16];
        let tok = [9u8; 32];
        let pubk = [3u8; 32];
        let proof = compute_resume_proof(&tok, &pubk, &sid, 2);
        assert!(verify_resume_proof(&tok, &pubk, &sid, 2, &proof));
        assert!(!verify_resume_proof(&tok, &pubk, &sid, 3, &proof));

        let frame = ResumeFrame::AttachReq {
            session_id: sid,
            epoch: 2,
            last_ack_seq: 42,
            target_addr: vec![1, 1, 1, 1, 1, 0, 80],
            proof,
            token: tok,
        };
        let dec = ResumeFrame::decode(&frame.encode()).unwrap();
        assert_eq!(dec, frame);

        let ledger = ReplayLedger::new();
        ledger.validate_and_record(&sid, 2, &proof).unwrap();
        assert!(ledger.validate_and_record(&sid, 2, &proof).is_err());
        let proof_old = compute_resume_proof(&tok, &pubk, &sid, 1);
        assert!(ledger.validate_and_record(&sid, 1, &proof_old).is_err());
    }

    #[test]
    fn forged_attach_cannot_steal_session_or_burn_epoch() {
        let sid = [4u8; 16];
        let token = [8u8; 32];
        let exit_pub = [5u8; 32];
        let entry_pub = [3u8; 32];
        let other_entry = [6u8; 32];
        let attacker_token = [7u8; 32];

        let proof = compute_resume_proof(&token, &exit_pub, &sid, 1);
        assert_eq!(
            authorize_attach(&exit_pub, &entry_pub, &token, &sid, 1, &proof, None).unwrap(),
            false
        );

        let existing = Some((token.as_slice(), entry_pub.as_slice(), false));
        let resume = compute_resume_proof(&token, &exit_pub, &sid, 2);
        assert!(authorize_attach(&exit_pub, &entry_pub, &token, &sid, 2, &resume, existing).unwrap());

        let forged = compute_resume_proof(&attacker_token, &exit_pub, &sid, 3);
        assert!(authorize_attach(
            &exit_pub,
            &entry_pub,
            &attacker_token,
            &sid,
            3,
            &forged,
            existing
        )
        .is_err());

        let stolen = compute_resume_proof(&token, &exit_pub, &sid, 3);
        assert!(authorize_attach(
            &exit_pub,
            &other_entry,
            &token,
            &sid,
            3,
            &stolen,
            existing
        )
        .is_err());

        assert!(authorize_attach(&exit_pub, &[], &token, &sid, 3, &proof, None).is_err());
        let zero = [0u8; 32];
        let zp = compute_resume_proof(&zero, &exit_pub, &sid, 1);
        assert!(authorize_attach(&exit_pub, &entry_pub, &zero, &sid, 1, &zp, None).is_err());
    }

    #[test]
    fn dataplane_dedup_reorders_and_replays() {
        let mut dp = ResumeDataPlane::new(64 * 1024);
        assert_eq!(dp.stage_outbound(b"chunk-1".to_vec()).unwrap(), 1);
        assert_eq!(dp.stage_outbound(b"chunk-2".to_vec()).unwrap(), 2);
        assert_eq!(dp.stage_outbound(b"chunk-3".to_vec()).unwrap(), 3);

        let replay = dp.replay_from(1);
        assert_eq!(replay.len(), 2);
        assert_eq!(replay[0].0, 2);
        assert_eq!(replay[1].0, 3);

        assert!(dp.ingest_inbound(3, b"C".to_vec()).unwrap().is_empty());
        assert!(dp.ingest_inbound(2, b"B".to_vec()).unwrap().is_empty());
        let out = dp.ingest_inbound(1, b"A".to_vec()).unwrap();
        assert_eq!(out, vec![b"A".to_vec(), b"B".to_vec(), b"C".to_vec()]);
        assert!(dp.ingest_inbound(2, b"B".to_vec()).unwrap().is_empty());
        assert_eq!(dp.current_ack(), 3);
    }

    #[test]
    fn jacobson_rtt_converges_and_karn_ignores_retx() {
        let mut dp = ResumeDataPlane::new(64 * 1024);
        // No samples → default base around 500ms + 4*250ms = 1.5s, clamped logic.
        let initial = dp.base_rto();
        assert!(initial >= Duration::from_millis(200));
        assert!(initial <= Duration::from_secs(3));

        // Stage + mark as sent once, then ACK after ~100ms of artificial age.
        let seq = dp.stage_outbound(b"x".to_vec()).unwrap();
        let sent_at = Instant::now() - Duration::from_millis(100);
        if let Some(seg) = dp.unacked.iter_mut().find(|s| s.seq == seq) {
            seg.last_sent = Some(sent_at);
            seg.sends = 1;
        }
        dp.process_ack(seq);
        let srtt1 = dp.srtt().expect("first sample");
        assert!(srtt1 >= Duration::from_millis(80) && srtt1 <= Duration::from_millis(150));
        let rto1 = dp.base_rto();
        assert!(rto1 >= Duration::from_millis(200));

        // Retransmitted segment must not move SRTT (Karn).
        let seq2 = dp.stage_outbound(b"y".to_vec()).unwrap();
        let sent_at2 = Instant::now() - Duration::from_millis(50);
        if let Some(seg) = dp.unacked.iter_mut().find(|s| s.seq == seq2) {
            seg.last_sent = Some(sent_at2);
            seg.sends = 3; // retransmitted
        }
        let before = dp.srtt();
        dp.process_ack(seq2);
        assert_eq!(dp.srtt(), before, "Karn must ignore retx samples");

        // Several clean 100ms samples should keep RTO in a sane band.
        for _ in 0..8 {
            let s = dp.stage_outbound(b"z".to_vec()).unwrap();
            let at = Instant::now() - Duration::from_millis(100);
            if let Some(seg) = dp.unacked.iter_mut().find(|se| se.seq == s) {
                seg.last_sent = Some(at);
                seg.sends = 1;
            }
            dp.process_ack(s);
        }
        let srtt_n = dp.srtt().unwrap();
        assert!(
            srtt_n >= Duration::from_millis(70) && srtt_n <= Duration::from_millis(140),
            "srtt={srtt_n:?}"
        );
        let rto_n = dp.base_rto();
        assert!(rto_n >= Duration::from_millis(200) && rto_n <= Duration::from_secs(3));
    }

    #[test]
    fn rto_backoff_uses_adaptive_base() {
        let mut dp = ResumeDataPlane::new(64 * 1024);
        // Force a small SRTT via direct samples.
        for _ in 0..5 {
            let s = dp.stage_outbound(b"a".to_vec()).unwrap();
            let at = Instant::now() - Duration::from_millis(40);
            if let Some(seg) = dp.unacked.iter_mut().find(|se| se.seq == s) {
                seg.last_sent = Some(at);
                seg.sends = 1;
            }
            dp.process_ack(s);
        }
        let base = dp.base_rto();
        assert!(base >= Duration::from_millis(200)); // floor
        // With sends=1, due threshold is base; age just below base → not due.
        let s = dp.stage_outbound(b"b".to_vec()).unwrap();
        let almost = base.saturating_sub(Duration::from_millis(30));
        if let Some(seg) = dp.unacked.iter_mut().find(|se| se.seq == s) {
            seg.last_sent = Some(Instant::now() - almost);
            seg.sends = 1;
        }
        let due = dp.due_retransmits(Instant::now());
        assert!(due.is_empty(), "should not fire before base RTO");
        // Age past base → due.
        if let Some(seg) = dp.unacked.iter_mut().find(|se| se.seq == s) {
            seg.last_sent = Some(Instant::now() - base - Duration::from_millis(20));
            seg.sends = 1;
        }
        let due2 = dp.due_retransmits(Instant::now());
        assert_eq!(due2.len(), 1);
        assert_eq!(due2[0].0, s);
    }

    #[test]
    fn is_lost_dup_thresh_and_left_edge() {
        let mut dp = ResumeDataPlane::new(64 * 1024);
        // Stage seq 1..=5, all "sent".
        for i in 0..5 {
            let s = dp.stage_outbound(vec![i as u8]).unwrap();
            dp.mark_sent(s, Instant::now());
        }
        // SACK 3,4,5 (three above hole at 1 and 2) with cum ack 0.
        dp.mark_sacked(&[(3, 6)]);
        assert!(dp.lost_count() >= 2, "holes 1 and 2 should be IsLost");
        assert!(dp.has_lost_retx_pending());
        let due = dp.due_retransmits(Instant::now());
        let seqs: Vec<u64> = due.iter().map(|(s, _)| *s).collect();
        assert!(seqs.contains(&1), "seq1 recovery retx: {seqs:?}");
        assert!(seqs.contains(&2), "seq2 recovery retx: {seqs:?}");
        // SACKed segments must not be retransmitted.
        assert!(!seqs.contains(&3));
        assert!(!seqs.contains(&4));
    }

    #[test]
    fn is_lost_single_hole_left_edge_with_two_sacks() {
        let mut dp = ResumeDataPlane::new(64 * 1024);
        for _ in 0..3 {
            let s = dp.stage_outbound(b"x".to_vec()).unwrap();
            dp.mark_sent(s, Instant::now());
        }
        // Only two SACKs above — below DupThresh, but left-edge assist must still fire for seq1.
        dp.mark_sacked(&[(2, 4)]);
        assert!(dp.has_lost_retx_pending());
        let due = dp.due_retransmits(Instant::now());
        assert_eq!(due[0].0, 1);
    }

    #[test]
    fn seqsack_wire_roundtrip_and_blocks_from_ooo() {
        let sid = [9u8; SESSION_ID_LEN];
        let frame = ResumeFrame::SeqSack {
            session_id: sid,
            epoch: 3,
            ack: 4,
            ranges: vec![(6, 8), (10, 12)],
        };
        let enc = frame.encode();
        assert_eq!(enc[0], 0x15);
        let dec = ResumeFrame::decode(&enc).unwrap();
        assert_eq!(dec, frame);

        let mut dp = ResumeDataPlane::new(64 * 1024);
        // Deliver 1, skip 2, deliver 3-4, skip 5, deliver 6
        assert!(dp.ingest_inbound(1, b"a".to_vec()).unwrap().len() == 1);
        assert!(dp.ingest_inbound(3, b"c".to_vec()).unwrap().is_empty());
        assert!(dp.ingest_inbound(4, b"d".to_vec()).unwrap().is_empty());
        assert!(dp.ingest_inbound(6, b"f".to_vec()).unwrap().is_empty());
        // next_recv still 2; ooo has 3,4,6
        let blocks = dp.sack_blocks();
        assert_eq!(blocks, vec![(3, 5), (6, 7)]);
        assert_eq!(dp.current_ack(), 1);
    }

    #[tokio::test]
    async fn sack_skips_rto_for_selectively_acked_and_retx_hole() {
        let (a_up, _a_up_rx) = mpsc::channel::<Vec<u8>>(4);
        let (b_up, mut b_up_rx) = mpsc::channel::<Vec<u8>>(8);
        let sender = SessionOwner::new(vec![1u8; 32], vec![], a_up);
        let receiver = SessionOwner::new(vec![2u8; 32], vec![], b_up);
        let (carrier_tx, mut carrier_rx) = mpsc::channel::<ResumeFrame>(16);
        sender.reattach_carrier(1, 0, carrier_tx).await.unwrap();

        // Three segments; drop the first on the wire, deliver 2 and 3 to receiver.
        for payload in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            sender
                .send_from_socket(payload.to_vec(), Duration::from_secs(2))
                .await
                .unwrap();
        }
        let mut frames = Vec::new();
        for _ in 0..3 {
            frames.push(
                tokio::time::timeout(Duration::from_secs(2), carrier_rx.recv())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        // Deliver only seq 2 and 3 to create a hole at 1.
        for f in frames.iter().skip(1) {
            if let ResumeFrame::SeqData {
                epoch,
                seq,
                ack,
                payload,
                ..
            } = f
            {
                receiver
                    .deliver_from_carrier(*epoch, *seq, *ack, payload.clone())
                    .await
                    .unwrap();
            }
        }
        let ack_f = receiver.make_ack_frame(1);
        match &ack_f {
            ResumeFrame::SeqSack { ack, ranges, .. } => {
                assert_eq!(*ack, 0);
                assert!(!ranges.is_empty());
            }
            other => panic!("expected SeqSack after hole, got {other:?}"),
        }
        if let ResumeFrame::SeqSack { ack, ranges, .. } = ack_f {
            sender.apply_sack(ack, &ranges);
        }
        // Hole must be retransmitted promptly via fast_retx.
        let retx = tokio::time::timeout(Duration::from_secs(3), carrier_rx.recv())
            .await
            .expect("hole was not retransmitted")
            .expect("carrier closed");
        match retx {
            ResumeFrame::SeqData { seq, payload, .. } => {
                assert_eq!(seq, 1);
                assert_eq!(payload, b"one");
                receiver
                    .deliver_from_carrier(1, seq, 0, payload)
                    .await
                    .unwrap();
            }
            other => panic!("expected hole SeqData, got {other:?}"),
        }
        // In-order delivery should now flush one/two/three.
        let mut got = Vec::new();
        for _ in 0..3 {
            got.push(
                tokio::time::timeout(Duration::from_secs(2), b_up_rx.recv())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        assert_eq!(got, vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]);
        sender.close();
        receiver.close();
    }

    #[tokio::test]
    async fn retransmit_recovers_a_dropped_segment_without_changing_carrier() {
        let (a_up, _a_up_rx) = mpsc::channel::<Vec<u8>>(4);
        let (b_up, mut b_up_rx) = mpsc::channel::<Vec<u8>>(4);
        let sender = SessionOwner::new(vec![1u8; 32], vec![], a_up);
        let receiver = SessionOwner::new(vec![2u8; 32], vec![], b_up);
        let (carrier_tx, mut carrier_rx) = mpsc::channel::<ResumeFrame>(8);
        sender.reattach_carrier(1, 0, carrier_tx).await.unwrap();

        sender
            .send_from_socket(b"hello-loss".to_vec(), Duration::from_secs(2))
            .await
            .unwrap();
        let before = stats::SESSION_RETRANSMITS.load(Relaxed);
        let dropped = tokio::time::timeout(Duration::from_secs(2), carrier_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match dropped {
            ResumeFrame::SeqData { payload, .. } => assert_eq!(payload, b"hello-loss"),
            other => panic!("expected SeqData, got {other:?}"),
        }
        // Frame never reached the peer. Age it so the RTO fires on the next tick.
        sender.dataplane.lock().unwrap().test_backdate_unacked(Duration::from_secs(5));

        let again = tokio::time::timeout(Duration::from_secs(3), carrier_rx.recv())
            .await
            .expect("retransmit did not fire")
            .expect("carrier closed");
        match again {
            ResumeFrame::SeqData {
                epoch,
                seq,
                ack,
                payload,
                ..
            } => {
                assert_eq!(payload, b"hello-loss");
                receiver
                    .deliver_from_carrier(epoch, seq, ack, payload)
                    .await
                    .unwrap();
            }
            other => panic!("expected retransmitted SeqData, got {other:?}"),
        }
        let got = tokio::time::timeout(Duration::from_secs(2), b_up_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, b"hello-loss");
        assert!(stats::SESSION_RETRANSMITS.load(Relaxed) > before);
        sender.close();
        receiver.close();
    }

    #[tokio::test]
    async fn live_tcp_session_survives_carrier_kill_and_reattach() {
        let srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = srv.local_addr().unwrap();
        let echo_srv = tokio::spawn(async move {
            let (mut s, _) = srv.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => s.write_all(&buf[..n]).await.unwrap(),
                }
            }
        });

        let mut dest_sock = TcpStream::connect(addr).await.unwrap();
        let (to_sock_tx, mut to_sock_rx) = mpsc::channel::<Vec<u8>>(32);
        let owner = SessionOwner::new(vec![1u8; 32], vec![], to_sock_tx);

        let owner_sock = owner.clone();
        let sock_task = tokio::spawn(async move {
            let (mut rd, mut wr) = dest_sock.split();
            let up = async {
                while let Some(data) = to_sock_rx.recv().await {
                    wr.write_all(&data).await?;
                }
                Ok::<(), anyhow::Error>(())
            };
            let down = async {
                let mut buf = [0u8; 1024];
                loop {
                    let n = rd.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    owner_sock
                        .send_from_socket(buf[..n].to_vec(), Duration::from_secs(5))
                        .await?;
                }
                Ok::<(), anyhow::Error>(())
            };
            let _ = tokio::join!(up, down);
        });

        let (c_a_tx, mut c_a_rx) = mpsc::channel::<ResumeFrame>(32);
        owner.reattach_carrier(1, 0, c_a_tx).await.unwrap();
        owner.deliver_from_carrier(1, 1, 0, b"before-cut-".to_vec()).await.unwrap();
        let f1 = c_a_rx.recv().await.unwrap();
        if let ResumeFrame::SeqData { payload, .. } = f1 {
            assert_eq!(payload, b"before-cut-");
        } else {
            panic!("expected SeqData");
        }

        owner.detach_carrier();
        drop(c_a_rx);

        owner.deliver_from_carrier(1, 2, 1, b"after-reattach".to_vec()).await.unwrap();
        // Echo is async: wait until the reply is staged on the detached session.
        for _ in 0..50 {
            if owner.has_unacked() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(owner.has_unacked(), "echo reply should be staged while detached");

        let (c_b_tx, mut c_b_rx) = mpsc::channel::<ResumeFrame>(32);
        owner.reattach_carrier(2, 1, c_b_tx).await.unwrap();
        let f2 = tokio::time::timeout(Duration::from_secs(2), c_b_rx.recv())
            .await
            .expect("timeout waiting for replay")
            .expect("channel closed");
        if let ResumeFrame::SeqData { payload, epoch, .. } = f2 {
            assert_eq!(epoch, 2);
            assert_eq!(payload, b"after-reattach");
        } else {
            panic!("expected replayed SeqData on Carrier B, got {f2:?}");
        }

        owner.close();
        drop(sock_task);
        echo_srv.abort();
    }

    #[test]
    fn recovery_episode_multi_hole_and_exit_at_recovery_point() {
        let mut dp = ResumeDataPlane::new(64 * 1024);
        let now = Instant::now();
        for i in 1..=8u64 {
            let s = dp.stage_outbound(vec![i as u8; 64]).unwrap();
            dp.mark_sent(s, now);
        }
        assert!(!dp.in_recovery());
        // Holes at 1 and 3; SACK blocks [2,3) and [4,9) -> 5 sacked above 3 (>= DUP_THRESH)
        dp.mark_sacked(&[(2, 3), (4, 9)]);
        assert!(dp.in_recovery());
        assert_eq!(dp.recovery_point(), Some(8));
        assert!(dp.lost_count() >= 2);
        let retx = dp.due_retransmits(now);
        let retx_seqs: Vec<u64> = retx.into_iter().map(|(s, _)| s).collect();
        assert_eq!(retx_seqs, vec![1, 3]);
        // Partial ACK (covers 1..=2) keeps recovery active
        dp.process_ack(2);
        assert!(dp.in_recovery());
        // Full ACK reaching RecoveryPoint (8) exits recovery
        dp.process_ack(8);
        assert!(!dp.in_recovery());
        assert!(!dp.has_unacked());
    }

    #[tokio::test]
    async fn burst_enqueue_preserves_order_and_close_unblocks_receiver() {
        let (to_sock_tx, mut to_sock_rx) = mpsc::channel::<Vec<u8>>(16);
        let owner = SessionOwner::new(vec![2u8; 32], vec![], to_sock_tx);
        let (c_tx, mut c_rx) = mpsc::channel::<ResumeFrame>(64);
        owner.reattach_carrier(1, 0, c_tx).await.unwrap();

        for seq in 1..=80u64 {
            let mut chunk = vec![(seq & 0xff) as u8; 12 * 1024];
            chunk[0..8].copy_from_slice(&seq.to_be_bytes());
            assert!(owner.enqueue_from_carrier(1, seq, 0, chunk).unwrap().is_none());
        }
        for seq in 1..=80u64 {
            let got = tokio::time::timeout(Duration::from_secs(2), to_sock_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&got[0..8], &seq.to_be_bytes());
        }
        let mut max_ack = 0u64;
        while let Ok(f) = c_rx.try_recv() {
            if let ResumeFrame::SeqAck { ack, .. } | ResumeFrame::SeqSack { ack, .. } = f {
                max_ack = max_ack.max(ack);
            }
        }
        assert!(max_ack > 0);

        // Dropping carrier receiver immediately marks session detached
        drop(c_rx);
        assert!(owner.is_detached());

        // Calling close() while owner is still held immediately yields None on to_sock_rx
        owner.close();
        let closed_res = tokio::time::timeout(Duration::from_secs(1), to_sock_rx.recv())
            .await
            .unwrap();
        assert!(closed_res.is_none());
    }
}
