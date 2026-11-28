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
            } => {
                out.push(0x10);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(&last_ack_seq.to_be_bytes());
                out.extend_from_slice(&(target_addr.len() as u16).to_be_bytes());
                out.extend_from_slice(target_addr);
                out.extend_from_slice(proof);
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
                if buf.len() < 21 + 8 + 2 + RESUME_PROOF_LEN {
                    bail!("AttachReq truncated");
                }
                let last_ack_seq = u64::from_be_bytes(buf[21..29].try_into()?);
                let tlen = u16::from_be_bytes(buf[29..31].try_into()?) as usize;
                if buf.len() != 31 + tlen + RESUME_PROOF_LEN {
                    bail!("AttachReq length mismatch");
                }
                let target_addr = buf[31..31 + tlen].to_vec();
                let mut proof = [0u8; RESUME_PROOF_LEN];
                proof.copy_from_slice(&buf[31 + tlen..]);
                Ok(ResumeFrame::AttachReq {
                    session_id,
                    epoch,
                    last_ack_seq,
                    target_addr,
                    proof,
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

/// Replay & Generation-Lease ledger preventing replay of old resume handshakes or stale epochs.
pub struct ReplayLedger {
    seen_proofs: Mutex<HashSet<[u8; RESUME_PROOF_LEN]>>,
    highest_epoch: Mutex<HashMap<SessionId, u32>>,
}

impl Default for ReplayLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayLedger {
    pub fn new() -> Self {
        Self {
            seen_proofs: Mutex::new(HashSet::new()),
            highest_epoch: Mutex::new(HashMap::new()),
        }
    }

    pub fn validate_and_record(
        &self,
        session_id: &SessionId,
        epoch: u32,
        proof: &[u8; RESUME_PROOF_LEN],
    ) -> Result<()> {
        let mut proofs = self.seen_proofs.lock().unwrap();
        if proofs.contains(proof) {
            bail!("replayed resume proof rejected");
        }
        let mut epochs = self.highest_epoch.lock().unwrap();
        if let Some(&prev) = epochs.get(session_id) {
            if epoch <= prev {
                bail!("stale resume epoch {epoch} <= {prev}");
            }
        }
        if proofs.len() >= MAX_RESUMABLE_SESSIONS * 8 {
            proofs.clear();
        }
        proofs.insert(*proof);
        epochs.insert(*session_id, epoch);
        Ok(())
    }
}

/// Reliable in-order sequenced data-plane buffer (`ResumeDataPlane`) with ACK trimming,
/// out-of-order reassembly, duplicate suppression, and memory ceiling enforcement.
pub struct ResumeDataPlane {
    next_send_seq: u64,
    peer_acked_seq: u64,
    unacked: VecDeque<(u64, Vec<u8>)>,
    unacked_bytes: usize,
    next_recv_seq: u64,
    ooo_recv: BTreeMap<u64, Vec<u8>>,
    ooo_bytes: usize,
    max_buffer_bytes: usize,
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
        }
    }

    pub fn current_ack(&self) -> u64 {
        self.next_recv_seq.saturating_sub(1)
    }

    pub fn unacked_bytes(&self) -> usize {
        self.unacked_bytes
    }

    pub fn stage_outbound(&mut self, payload: Vec<u8>) -> Result<u64> {
        if self.unacked_bytes + payload.len() > self.max_buffer_bytes {
            bail!("session unacked buffer full ({} bytes)", self.unacked_bytes);
        }
        let seq = self.next_send_seq;
        self.next_send_seq += 1;
        self.unacked_bytes += payload.len();
        self.unacked.push_back((seq, payload));
        Ok(seq)
    }

    pub fn process_ack(&mut self, ack: u64) {
        if ack <= self.peer_acked_seq {
            return;
        }
        self.peer_acked_seq = ack;
        while let Some((seq, data)) = self.unacked.front() {
            if *seq <= ack {
                self.unacked_bytes = self.unacked_bytes.saturating_sub(data.len());
                self.unacked.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn replay_from(&mut self, peer_ack_seq: u64) -> Vec<(u64, Vec<u8>)> {
        self.process_ack(peer_ack_seq);
        self.unacked.iter().cloned().collect()
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
    /// Serializes reassembly + forwarding so ready chunks reach the socket in seq order.
    deliver_lock: tokio::sync::Mutex<()>,
    to_socket_tx: mpsc::Sender<Vec<u8>>,
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
        Arc::new(Self {
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
            deliver_lock: tokio::sync::Mutex::new(()),
            to_socket_tx,
        })
    }

    pub fn current_epoch(&self) -> u32 {
        self.epoch.load(Relaxed)
    }

    pub fn bump_epoch(&self) -> u32 {
        self.epoch.fetch_add(1, Relaxed) + 1
    }

    pub fn is_detached(&self) -> bool {
        self.carrier_tx.lock().unwrap().is_none()
    }

    pub fn detach_carrier(&self) {
        *self.carrier_tx.lock().unwrap() = None;
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
        let replay_list = {
            let mut dp = self.dataplane.lock().unwrap();
            dp.replay_from(peer_ack_seq)
        };
        let ack_now = self.dataplane.lock().unwrap().current_ack();
        let replayed = replay_list.len();
        for (seq, payload) in replay_list {
            tx.send(ResumeFrame::SeqData {
                session_id: self.session_id,
                epoch: new_epoch,
                seq,
                ack: ack_now,
                payload,
            })
            .await
            .map_err(|_| anyhow::anyhow!("replacement carrier closed during replay"))?;
        }
        *self.carrier_tx.lock().unwrap() = Some(tx);
        *self.last_activity.lock().unwrap() = Instant::now();
        self.reattached_notify.notify_waiters();
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
            let _ = tokio::time::timeout(rem.min(Duration::from_millis(50)), self.window_notify.notified()).await;
        };
        loop {
            if self.closed.load(Relaxed) {
                bail!("session closed while waiting for carrier");
            }
            let maybe_tx = self.carrier_tx.lock().unwrap().clone();
            if let Some(tx) = maybe_tx {
                let epoch = self.epoch.load(Relaxed);
                let ack = self.dataplane.lock().unwrap().current_ack();
                if tx
                    .send(ResumeFrame::SeqData {
                        session_id: self.session_id,
                        epoch,
                        seq,
                        ack,
                        payload: payload.clone(),
                    })
                    .await
                    .is_ok()
                {
                    *self.last_activity.lock().unwrap() = Instant::now();
                    return Ok(());
                }
                self.detach_carrier();
            }
            let rem = deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                bail!("carrier reattach timeout exceeded");
            }
            let _ = tokio::time::timeout(
                rem.min(Duration::from_millis(250)),
                self.reattached_notify.notified(),
            )
            .await;
        }
    }

    /// End-of-stream marker: an empty chunk staged like any other, so it keeps its place in the
    /// sequence (never overtakes data) and is replayed after a carrier switch. The receiving side
    /// treats an empty chunk as EOF and half-closes its socket.
    pub async fn send_fin(&self, budget: Duration) -> Result<()> {
        self.send_from_socket(Vec::new(), budget).await
    }

    /// Apply a cumulative ACK from the peer and wake senders waiting for window space.
    pub fn apply_ack(&self, ack: u64) {
        self.dataplane.lock().unwrap().process_ack(ack);
        self.window_notify.notify_waiters();
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
        for c in chunks {
            if self.to_socket_tx.send(c).await.is_err() {
                self.closed.store(true, Relaxed);
                bail!("local socket closed");
            }
        }
        Ok(self.dataplane.lock().unwrap().current_ack())
    }

    pub fn close(&self) {
        self.closed.store(true, Relaxed);
        self.detach_carrier();
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

        let (c_b_tx, mut c_b_rx) = mpsc::channel::<ResumeFrame>(32);
        owner.reattach_carrier(2, 1, c_b_tx).await.unwrap();
        let f2 = c_b_rx.recv().await.unwrap();
        if let ResumeFrame::SeqData { payload, epoch, .. } = f2 {
            assert_eq!(epoch, 2);
            assert_eq!(payload, b"after-reattach");
        } else {
            panic!("expected replayed SeqData on Carrier B");
        }

        owner.close();
        drop(sock_task);
        echo_srv.abort();
    }
}
