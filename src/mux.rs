//! Lightweight Stream Multiplexer over Noise `Link` with carrier-level keepalive,
//! automatic coordinated Noise session rotation (Rekeying), and Turbo-Tunnel Live Session
//! Resumption (`CMD_RESUME = 10`) decoupling TCP socket ownership from carrier lifetime.
//!
//! Wire framing inside each encrypted Noise message (5-byte header):
//!   `[cmd: u8][stream_id: u32 BE][payload...]`
//!   - `1` (SYN):      Entry -> Exit, payload = SOCKS5-style target address (`[atyp, addr, port]`)
//!   - `2` (SYN_OK):   Exit -> Entry, target connected
//!   - `3` (SYN_ERR):  Exit -> Entry, target refused/unreachable
//!   - `4` (DATA):     Bidirectional stream data (up to `MUX_MAX_PAYLOAD` bytes)
//!   - `5` (FIN):      Bidirectional graceful half-close (EOF)
//!   - `6` (RST):      Bidirectional immediate stream abort
//!   - `7` (PING):     Carrier keepalive request
//!   - `8` (PONG):     Carrier keepalive response
//!   - `9` (REKEY):    Graceful carrier drain & rotation request (fresh Noise_IK DH handshake)
//!   - `10` (RESUME):  Turbo-Tunnel SessionOwner framing (`AttachReq`, `AttachAck`, `SeqData`, `SeqAck`, `SeqFin`)

use crate::link::{self, Link, CHUNK};
use crate::recovery::{AdaptiveRuntime, TransportEvent};
use crate::session_resume::{
    authorize_attach, compute_resume_proof, ResumeFrame, SessionId, SessionOwner, SessionRegistry,
    DEFAULT_SESSION_DETACH_TTL,
};
use crate::stats;
use crate::util::{parse_addr, resolve_validated};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{sleep, timeout};

pub const MUX_HDR_LEN: usize = 5;
pub const MUX_MAX_PAYLOAD: usize = CHUNK - MUX_HDR_LEN;
pub const MUX_MAX_STREAMS_PER_CARRIER: usize = 128;
/// Rotate carrier to a fresh Noise_IK DH session after 512 MiB or 15 minutes (Forward Secrecy).
pub const REKEY_MAX_BYTES: u64 = 512 * 1024 * 1024;
pub const REKEY_MAX_AGE: Duration = Duration::from_secs(15 * 60);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const STREAM_CHAN_CAP: usize = 128;
const CARRIER_TX_CAP: usize = 512;
const EXIT_CARRIER_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const CARRIER_WRITE_TIMEOUT: Duration = Duration::from_secs(20);

const CMD_SYN: u8 = 1;
const CMD_SYN_OK: u8 = 2;
const CMD_SYN_ERR: u8 = 3;
const CMD_DATA: u8 = 4;
const CMD_FIN: u8 = 5;
const CMD_RST: u8 = 6;
const CMD_PING: u8 = 7;
const CMD_PONG: u8 = 8;
const CMD_REKEY: u8 = 9;
pub const CMD_RESUME: u8 = 10;

#[inline]
fn encode_frame(cmd: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(MUX_HDR_LEN + payload.len());
    v.push(cmd);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

#[inline]
fn decode_header(buf: &[u8]) -> Option<(u8, u32, &[u8])> {
    if buf.len() < MUX_HDR_LEN {
        return None;
    }
    let cmd = buf[0];
    let sid = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    Some((cmd, sid, &buf[MUX_HDR_LEN..]))
}

/// After one direction of a resumable stream has finished (EOF), the other direction gets this
/// long to finish before the session is torn down.
const HALF_CLOSE_GRACE: Duration = Duration::from_secs(60);

/// Run both directions of a stream. Finishes when both are done, when either fails, or when one
/// direction has been done for `HALF_CLOSE_GRACE` and the other still has not finished.
async fn join_half_closed<A, B>(up: A, down: B) -> Result<()>
where
    A: std::future::Future<Output = Result<()>>,
    B: std::future::Future<Output = Result<()>>,
{
    tokio::pin!(up);
    tokio::pin!(down);
    let (mut up_done, mut down_done) = (false, false);
    loop {
        tokio::select! {
            r = &mut up, if !up_done => { r?; up_done = true; }
            r = &mut down, if !down_done => { r?; down_done = true; }
            _ = sleep(HALF_CLOSE_GRACE), if up_done != down_done => return Ok(()),
        }
        if up_done && down_done {
            return Ok(());
        }
    }
}

enum StreamRx {
    Data(Vec<u8>),
    Fin,
    Rst,
}

pub enum MuxOpenResult {
    Opened(MuxStream),
    Refused,
    CarrierDead,
}

pub enum ResumableOpenResult {
    Opened(ResumableMuxStream),
    Refused,
    CarrierDead,
}

/// Resumable Entry-side TCP stream backed by a carrier-independent `SessionOwner`.
/// Survives carrier death/rekeying without resetting the local client TCP socket.
pub struct ResumableMuxStream {
    pub owner: Arc<SessionOwner>,
    to_socket_rx: mpsc::Receiver<Vec<u8>>,
    registry: Arc<SessionRegistry>,
}

impl Drop for ResumableMuxStream {
    fn drop(&mut self) {
        self.owner.close();
        self.registry.remove(&self.owner.session_id);
    }
}

impl ResumableMuxStream {
    pub async fn send_data(&self, data: &[u8]) -> Result<()> {
        for chunk in data.chunks(MUX_MAX_PAYLOAD.saturating_sub(64)) {
            self.owner
                .send_from_socket(chunk.to_vec(), DEFAULT_SESSION_DETACH_TTL)
                .await?;
        }
        Ok(())
    }

    pub async fn recv_chunk(&mut self) -> Option<Vec<u8>> {
        self.to_socket_rx.recv().await
    }

    pub async fn pipe_tcp(
        mut self,
        tcp: TcpStream,
        adaptive: Option<Arc<AdaptiveRuntime>>,
    ) -> Result<()> {
        stats::STREAMS_TOTAL.fetch_add(1, Relaxed);
        stats::STREAMS_ACTIVE.fetch_add(1, Relaxed);
        let r = self.pipe_tcp_inner(tcp, adaptive.as_deref()).await;
        stats::STREAMS_ACTIVE.fetch_sub(1, Relaxed);
        r
    }

    async fn pipe_tcp_inner(
        &mut self,
        tcp: TcpStream,
        adaptive: Option<&AdaptiveRuntime>,
    ) -> Result<()> {
        let (mut tr, mut tw) = tcp.into_split();
        let owner_up = self.owner.clone();
        let transferred = AtomicU64::new(0);
        let max_chunk = MUX_MAX_PAYLOAD.saturating_sub(64);

        let up = async {
            let mut buf = vec![0u8; max_chunk];
            loop {
                let lim = adaptive
                    .map(|a| a.current_chunk_size().min(max_chunk))
                    .unwrap_or(max_chunk);
                let n = tr.read(&mut buf[..lim]).await?;
                if n == 0 {
                    // client finished sending: tell the exit (in order, after the data) and keep
                    // the session open so the response can still arrive
                    let _ = owner_up.send_fin(DEFAULT_SESSION_DETACH_TTL).await;
                    return Ok::<(), anyhow::Error>(());
                }
                stats::BYTES_UP.fetch_add(n as u64, Relaxed);
                transferred.fetch_add(n as u64, Relaxed);
                owner_up
                    .send_from_socket(buf[..n].to_vec(), DEFAULT_SESSION_DETACH_TTL)
                    .await?;
                if let Some(a) = adaptive {
                    let p_us = a.current_pacing_us();
                    if p_us > 0 {
                        sleep(Duration::from_micros(p_us)).await;
                    }
                }
            }
        };

        let down = async {
            let mut got_eof = false;
            while let Some(chunk) = self.to_socket_rx.recv().await {
                if chunk.is_empty() {
                    got_eof = true;
                    break; // in-band EOF from the exit: the target closed
                }
                stats::BYTES_DOWN.fetch_add(chunk.len() as u64, Relaxed);
                transferred.fetch_add(chunk.len() as u64, Relaxed);
                tw.write_all(&chunk).await?;
            }
            let _ = tw.shutdown().await;
            if !got_eof {
                bail!("resumable session closed before EOF");
            }
            Ok::<(), anyhow::Error>(())
        };

        let res = join_half_closed(up, down).await;
        if res.is_ok() {
            if let Some(a) = adaptive {
                a.record(
                    TransportEvent::StreamOk {
                        bytes: transferred.load(Relaxed),
                    },
                    0,
                );
            }
        }
        res?;
        Ok(())
    }
}

/// Client-side (Entry) multiplexed stream handle over a shared `MuxCarrier`.
pub struct MuxStream {
    id: u32,
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<StreamRx>,
    carrier: Arc<MuxCarrier>,
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        self.carrier.remove_stream(self.id);
    }
}

impl MuxStream {
    pub async fn send_data(&self, data: &[u8]) -> Result<()> {
        for chunk in data.chunks(MUX_MAX_PAYLOAD) {
            self.tx
                .send(encode_frame(CMD_DATA, self.id, chunk))
                .await
                .map_err(|_| anyhow::anyhow!("mux carrier closed"))?;
        }
        Ok(())
    }

    pub async fn send_fin(&self) -> Result<()> {
        let _ = self.tx.send(encode_frame(CMD_FIN, self.id, &[])).await;
        Ok(())
    }

    pub async fn recv_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        match self.rx.recv().await {
            Some(StreamRx::Data(b)) => Ok(Some(b)),
            Some(StreamRx::Fin) | None => Ok(None),
            Some(StreamRx::Rst) => bail!("mux stream reset by peer"),
        }
    }

    /// Pipe a local TCP stream through this multiplexed stream with adaptive chunking & pacing.
    pub async fn pipe_tcp(
        mut self,
        tcp: TcpStream,
        adaptive: Option<Arc<AdaptiveRuntime>>,
    ) -> Result<()> {
        stats::STREAMS_TOTAL.fetch_add(1, Relaxed);
        stats::STREAMS_ACTIVE.fetch_add(1, Relaxed);
        let r = self.pipe_tcp_inner(tcp, adaptive.as_deref()).await;
        stats::STREAMS_ACTIVE.fetch_sub(1, Relaxed);
        r
    }

    async fn pipe_tcp_inner(
        &mut self,
        tcp: TcpStream,
        adaptive: Option<&AdaptiveRuntime>,
    ) -> Result<()> {
        let (mut tr, mut tw) = tcp.into_split();
        let tx = self.tx.clone();
        let sid = self.id;
        let transferred = AtomicU64::new(0);

        let up = async {
            let mut buf = vec![0u8; MUX_MAX_PAYLOAD];
            loop {
                let lim = adaptive
                    .map(|a| a.current_chunk_size().min(MUX_MAX_PAYLOAD))
                    .unwrap_or(MUX_MAX_PAYLOAD);
                let n = tr.read(&mut buf[..lim]).await?;
                if n == 0 {
                    let _ = tx.send(encode_frame(CMD_FIN, sid, &[])).await;
                    return Ok::<(), anyhow::Error>(());
                }
                stats::BYTES_UP.fetch_add(n as u64, Relaxed);
                transferred.fetch_add(n as u64, Relaxed);
                tx.send(encode_frame(CMD_DATA, sid, &buf[..n]))
                    .await
                    .map_err(|_| anyhow::anyhow!("mux carrier closed"))?;
                if let Some(a) = adaptive {
                    let p_us = a.current_pacing_us();
                    if p_us > 0 {
                        sleep(Duration::from_micros(p_us)).await;
                    }
                }
            }
        };

        let down = async {
            loop {
                match self.rx.recv().await {
                    Some(StreamRx::Data(b)) => {
                        stats::BYTES_DOWN.fetch_add(b.len() as u64, Relaxed);
                        transferred.fetch_add(b.len() as u64, Relaxed);
                        tw.write_all(&b).await?;
                    }
                    Some(StreamRx::Fin) | None => {
                        let _ = tw.shutdown().await;
                        return Ok::<(), anyhow::Error>(());
                    }
                    Some(StreamRx::Rst) => {
                        let _ = tw.shutdown().await;
                        if let Some(a) = adaptive {
                            a.record(
                                TransportEvent::EarlyReset {
                                    bytes_transferred: transferred.load(Relaxed),
                                },
                                0,
                            );
                        }
                        bail!("mux stream reset");
                    }
                }
            }
        };

        let res = tokio::try_join!(up, down);
        if res.is_err() {
            let _ = self.tx.try_send(encode_frame(CMD_RST, sid, &[]));
        } else if let Some(a) = adaptive {
            a.record(
                TransportEvent::StreamOk {
                    bytes: transferred.load(Relaxed),
                },
                0,
            );
        }
        res?;
        Ok(())
    }
}

struct CarrierState {
    pending_syn: HashMap<u32, oneshot::Sender<bool>>,
    pending_attach: HashMap<SessionId, oneshot::Sender<(bool, u64)>>,
    streams: HashMap<u32, mpsc::Sender<StreamRx>>,
    resumable_owners: HashMap<SessionId, Arc<SessionOwner>>,
}

/// Entry-side multiplexed carrier running over a single authenticated Noise `Link`.
/// A carrier with work in flight that has not received a single frame for this long is treated as
/// frozen (silent black hole, middlebox stall) and replaced; resumable sessions move to another
/// carrier. Before this, a frozen carrier stayed "alive" forever and swallowed every stream on it.
const CARRIER_STALL: Duration = Duration::from_secs(25);
/// With work in flight, probe a quiet carrier after this long (any reply, even a PONG, proves life).
const CARRIER_PING_AFTER: Duration = Duration::from_secs(4);
/// An idle carrier is pinged every 15 s by its writer; no frame at all for this long means dead.
const CARRIER_IDLE_DEAD: Duration = Duration::from_secs(75);

pub struct MuxCarrier {
    tx: mpsc::Sender<Vec<u8>>,
    next_id: AtomicU32,
    active_streams: AtomicUsize,
    bytes_total: AtomicU64,
    alive: AtomicBool,
    draining: AtomicBool,
    created: Instant,
    /// Milliseconds since `created` at which the last frame arrived (stall detection).
    last_rx_ms: AtomicU64,
    /// Milliseconds since `created` at which the carrier became busy (0 = idle).
    busy_since_ms: AtomicU64,
    /// Prefer a flag over try_send so a full data queue does not drop keepalives.
    ping_pending: AtomicBool,
    max_age: Duration,
    peer_pub: Vec<u8>,
    state: StdMutex<CarrierState>,
}

impl MuxCarrier {
    pub fn spawn(link: Link, max_age: Duration) -> Arc<Self> {
        let peer_pub = link.peer_pub().unwrap_or_default().to_vec();
        let (mut lr, mut lw) = link.split();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CARRIER_TX_CAP);
        let effective_max_age = max_age.min(REKEY_MAX_AGE).max(Duration::from_secs(5));
        let carrier = Arc::new(Self {
            tx,
            next_id: AtomicU32::new(1),
            active_streams: AtomicUsize::new(0),
            bytes_total: AtomicU64::new(0),
            alive: AtomicBool::new(true),
            draining: AtomicBool::new(false),
            created: Instant::now(),
            last_rx_ms: AtomicU64::new(0),
            busy_since_ms: AtomicU64::new(0),
            ping_pending: AtomicBool::new(false),
            max_age: effective_max_age,
            peer_pub,
            state: StdMutex::new(CarrierState {
                pending_syn: HashMap::new(),
                pending_attach: HashMap::new(),
                streams: HashMap::new(),
                resumable_owners: HashMap::new(),
            }),
        });
        stats::MUX_CARRIERS_ACTIVE.fetch_add(1, Relaxed);
        let (closed_tx, mut closed_rx) = watch::channel(false);

        // Writer task + idle CMD_PING keepalive
        let c_wr = carrier.clone();
        let closed_wr = closed_tx.clone();
        let closed_mon = closed_tx.clone();
        tokio::spawn(async move {
            let mut sent_rekey = false;
            loop {
                if !c_wr.alive.load(Relaxed) {
                    break;
                }
                if c_wr.ping_pending.swap(false, Relaxed)
                    && !matches!(
                        timeout(CARRIER_WRITE_TIMEOUT, lw.send(&encode_frame(CMD_PING, 0, &[]))).await,
                        Ok(Ok(()))
                    )
                {
                    break;
                }
                let frame = match timeout(Duration::from_secs(15), rx.recv()).await {
                    Ok(Some(f)) => f,
                    Ok(None) => break,
                    Err(_) => {
                        if !matches!(
                            timeout(CARRIER_WRITE_TIMEOUT, lw.send(&encode_frame(CMD_PING, 0, &[]))).await,
                            Ok(Ok(()))
                        ) {
                            break;
                        }
                        continue;
                    }
                };
                let flen = frame.len() as u64;
                if !matches!(timeout(CARRIER_WRITE_TIMEOUT, lw.send(&frame)).await, Ok(Ok(()))) {
                    break;
                }
                let tot = c_wr.bytes_total.fetch_add(flen, Relaxed) + flen;
                if !sent_rekey && (tot >= REKEY_MAX_BYTES || c_wr.created.elapsed() >= c_wr.max_age) {
                    sent_rekey = true;
                    c_wr.draining.store(true, Relaxed);
                    stats::REKEY_ROTATIONS.fetch_add(1, Relaxed);
                    let _ = lw.send(&encode_frame(CMD_REKEY, 0, &[])).await;
                }
            }
            c_wr.mark_dead();
            let _ = closed_wr.send(true);
        });

        // Reader demux task (non-blocking per-stream dispatch so 1 slow stream never stalls carrier)
        let c_rd = carrier.clone();
        let closed_rd = closed_tx;
        tokio::spawn(async move {
            let mut plain = vec![0u8; CHUNK + 64];
            loop {
                let n = tokio::select! {
                    _ = closed_rd_wait(&mut closed_rx) => break,
                    r = lr.recv_into(&mut plain) => match r {
                        Ok(n) if n >= MUX_HDR_LEN => n,
                        _ => break,
                    }
                };
                c_rd.bytes_total.fetch_add(n as u64, Relaxed);
                c_rd.last_rx_ms.store(c_rd.created.elapsed().as_millis() as u64, Relaxed);
                let Some((cmd, sid, payload)) = decode_header(&plain[..n]) else {
                    continue;
                };
                match cmd {
                    CMD_SYN_OK | CMD_SYN_ERR => {
                        let waiter = c_rd.state.lock().unwrap().pending_syn.remove(&sid);
                        if let Some(w) = waiter {
                            let _ = w.send(cmd == CMD_SYN_OK);
                        }
                    }
                    CMD_DATA => {
                        let tx_s = c_rd.state.lock().unwrap().streams.get(&sid).cloned();
                        if let Some(tx_s) = tx_s {
                            match tx_s.try_send(StreamRx::Data(payload.to_vec())) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(item)) => {
                                    if !matches!(
                                        tokio::time::timeout(Duration::from_secs(2), tx_s.send(item)).await,
                                        Ok(Ok(()))
                                    ) {
                                        c_rd.remove_stream(sid);
                                        let _ = c_rd.tx.try_send(encode_frame(CMD_RST, sid, &[]));
                                    }
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    c_rd.remove_stream(sid);
                                }
                            }
                        }
                    }
                    CMD_FIN => {
                        let tx_s = c_rd.state.lock().unwrap().streams.remove(&sid);
                        if let Some(tx_s) = tx_s {
                            let _ = tx_s.try_send(StreamRx::Fin);
                        }
                    }
                    CMD_RST => {
                        let tx_s = c_rd.state.lock().unwrap().streams.remove(&sid);
                        if let Some(tx_s) = tx_s {
                            let _ = tx_s.try_send(StreamRx::Rst);
                        }
                    }
                    CMD_PING => {
                        let _ = c_rd.tx.try_send(encode_frame(CMD_PONG, 0, &[]));
                    }
                    CMD_PONG => {}
                    CMD_REKEY => {
                        c_rd.draining.store(true, Relaxed);
                        stats::REKEY_ROTATIONS.fetch_add(1, Relaxed);
                    }
                    CMD_RESUME => {
                        if let Ok(rframe) = ResumeFrame::decode(payload) {
                            match rframe {
                                ResumeFrame::AttachAck {
                                    session_id,
                                    peer_ack_seq,
                                    accepted,
                                    ..
                                } => {
                                    let waiter =
                                        c_rd.state.lock().unwrap().pending_attach.remove(&session_id);
                                    if let Some(w) = waiter {
                                        let _ = w.send((accepted, peer_ack_seq));
                                    }
                                }
                                ResumeFrame::SeqData {
                                    session_id,
                                    epoch,
                                    seq,
                                    ack,
                                    payload,
                                } => {
                                    let owner = c_rd
                                        .state
                                        .lock()
                                        .unwrap()
                                        .resumable_owners
                                        .get(&session_id)
                                        .cloned();
                                    if let Some(ow) = owner {
                                        if let Ok(Some(ack_f)) =
                                            ow.enqueue_from_carrier(epoch, seq, ack, payload)
                                        {
                                            let _ = c_rd.tx.try_send(encode_frame(
                                                CMD_RESUME,
                                                0,
                                                &ack_f.encode(),
                                            ));
                                        }
                                    }
                                }
                                ResumeFrame::SeqAck {
                                    session_id, ack, ..
                                } => {
                                    if let Some(ow) =
                                        c_rd.state.lock().unwrap().resumable_owners.get(&session_id)
                                    {
                                        ow.apply_ack(ack);
                                    }
                                }
                                ResumeFrame::SeqSack {
                                    session_id,
                                    ack,
                                    ranges,
                                    ..
                                } => {
                                    if let Some(ow) =
                                        c_rd.state.lock().unwrap().resumable_owners.get(&session_id)
                                    {
                                        ow.apply_sack(ack, &ranges);
                                    }
                                }
                                ResumeFrame::SeqFin { session_id, .. } => {
                                    if let Some(ow) =
                                        c_rd.state.lock().unwrap().resumable_owners.remove(&session_id)
                                    {
                                        ow.close();
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            c_rd.mark_dead();
            let _ = closed_rd.send(true);
            stats::MUX_CARRIERS_ACTIVE.fetch_sub(1, Relaxed);
        });

        // Stall monitor: a frozen carrier never errors, so only silence can reveal it.
        let c_mon = carrier.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(2)).await;
                if !c_mon.alive.load(Relaxed) {
                    break;
                }
                let busy = {
                    let st = c_mon.state.lock().unwrap();
                    !st.streams.is_empty()
                        || !st.pending_syn.is_empty()
                        || !st.pending_attach.is_empty()
                        || !st.resumable_owners.is_empty()
                };
                let now_ms = c_mon.created.elapsed().as_millis() as u64;
                let last_rx = c_mon.last_rx_ms.load(Relaxed);
                let quiet = if busy {
                    let bs = match c_mon.busy_since_ms.compare_exchange(
                        0,
                        now_ms.max(1),
                        Relaxed,
                        Relaxed,
                    ) {
                        Ok(_) => now_ms.max(1),
                        Err(prev) => prev,
                    };
                    Duration::from_millis(now_ms.saturating_sub(last_rx.max(bs)))
                } else {
                    c_mon.busy_since_ms.store(0, Relaxed);
                    Duration::from_millis(now_ms.saturating_sub(last_rx))
                };
                if busy && quiet >= CARRIER_PING_AFTER {
                    c_mon.ping_pending.store(true, Relaxed);
                }
                let limit = if busy { CARRIER_STALL } else { CARRIER_IDLE_DEAD };
                if quiet >= limit {
                    stats::log_err_rl(&format!(
                        "[mux] carrier silent for {}s with {} work in flight: replacing it",
                        quiet.as_secs(),
                        if busy { "streams" } else { "no" }
                    ));
                    c_mon.mark_dead();
                    let _ = closed_mon.send(true);
                    break;
                }
            }
        });

        carrier
    }

    fn mark_dead(&self) {
        self.alive.store(false, Relaxed);
        self.draining.store(true, Relaxed);
        let mut st = self.state.lock().unwrap();
        st.pending_syn.clear();
        st.pending_attach.clear();
        for (_, owner) in st.resumable_owners.drain() {
            owner.detach_carrier();
        }
        st.streams.clear();
        self.active_streams.store(0, Relaxed);
    }

    pub fn attach_resumable_owner(&self, owner: Arc<SessionOwner>) {
        let mut st = self.state.lock().unwrap();
        st.resumable_owners.retain(|_, o| !o.closed.load(Relaxed));
        st.resumable_owners.insert(owner.session_id, owner);
    }

    fn remove_stream(&self, sid: u32) {
        let mut st = self.state.lock().unwrap();
        if st.streams.remove(&sid).is_some() {
            self.active_streams.store(st.streams.len(), Relaxed);
        }
        st.pending_syn.remove(&sid);
    }

    pub fn is_usable(&self) -> bool {
        self.alive.load(Relaxed)
            && !self.draining.load(Relaxed)
            && self.created.elapsed() < self.max_age
            && self.bytes_total.load(Relaxed) < REKEY_MAX_BYTES
            && self.active_streams.load(Relaxed) < MUX_MAX_STREAMS_PER_CARRIER
    }

    /// Streams currently riding this carrier. Resumable sessions (the default) are not in
    /// `streams`, so they are counted from `resumable_owners`; before, they counted as zero and
    /// every new stream picked the same "least loaded" carrier, so one carrier (and one throttled
    /// TCP connection) carried everything while the others sat idle.
    pub fn load(&self) -> usize {
        let st = self.state.lock().unwrap();
        st.streams.len() + st.resumable_owners.values().filter(|o| !o.closed.load(Relaxed)).count()
    }

    /// Attach or reattach a `SessionOwner` onto this live `MuxCarrier` using `CMD_RESUME`.
    pub async fn attach_session(
        self: &Arc<Self>,
        owner: &Arc<SessionOwner>,
        epoch: u32,
        include_target: bool,
    ) -> Result<bool> {
        if !self.is_usable() {
            bail!("mux carrier not usable");
        }
        let (ack_tx, ack_rx) = oneshot::channel();
        {
            let mut st = self.state.lock().unwrap();
            if !self.alive.load(Relaxed) {
                bail!("mux carrier closed");
            }
            st.pending_attach.insert(owner.session_id, ack_tx);
            st.resumable_owners.retain(|_, o| !o.closed.load(Relaxed));
            st.resumable_owners.insert(owner.session_id, owner.clone());
        }

        let last_ack_seq = owner.dataplane.lock().unwrap().current_ack();
        let proof = compute_resume_proof(
            &owner.resume_token,
            &owner.peer_noise_pub,
            &owner.session_id,
            epoch,
        );
        let req = ResumeFrame::AttachReq {
            session_id: owner.session_id,
            epoch,
            last_ack_seq,
            target_addr: if include_target {
                owner.target_addr.clone()
            } else {
                Vec::new()
            },
            proof,
            token: owner.resume_token,
        };
        if self
            .tx
            .send(encode_frame(CMD_RESUME, 0, &req.encode()))
            .await
            .is_err()
        {
            {
                let mut st = self.state.lock().unwrap();
                st.pending_attach.remove(&owner.session_id);
                st.resumable_owners.remove(&owner.session_id);
            }
            self.mark_dead();
            bail!("failed to send AttachReq");
        }

        match timeout(Duration::from_secs(20), ack_rx).await {
            Ok(Ok((true, peer_ack_seq))) => {
                let (r_tx, mut r_rx) = mpsc::channel::<ResumeFrame>(STREAM_CHAN_CAP);
                let tx_fwd = self.tx.clone();
                let owner_fwd = owner.clone();
                let tx_id = r_tx.clone();
                tokio::spawn(async move {
                    while let Some(rf) = r_rx.recv().await {
                        if tx_fwd
                            .send(encode_frame(CMD_RESUME, 0, &rf.encode()))
                            .await
                            .is_err()
                        {
                            // Must not remove the session from resumable_owners: this task
                            // also exits when a newer attach replaces r_tx, and deleting
                            // the owner then black-holed SeqData after resume (bulk = 0 bytes).
                            owner_fwd.detach_if_same_sender(&tx_id);
                            break;
                        }
                    }
                });
                owner.reattach_carrier(epoch, peer_ack_seq, r_tx).await?;
                Ok(true)
            }
            Ok(Ok((false, _))) => {
                let mut st = self.state.lock().unwrap();
                st.pending_attach.remove(&owner.session_id);
                st.resumable_owners.remove(&owner.session_id);
                Ok(false)
            }
            _ => {
                let mut st = self.state.lock().unwrap();
                st.pending_attach.remove(&owner.session_id);
                st.resumable_owners.remove(&owner.session_id);
                bail!("AttachReq timeout or carrier closed")
            }
        }
    }

    /// Open a new Turbo-Tunnel resumable TCP stream backed by `SessionOwner` and `SessionRegistry`.
    pub async fn open_resumable_stream(
        self: &Arc<Self>,
        target_addr: &[u8],
        registry: &Arc<SessionRegistry>,
    ) -> ResumableOpenResult {
        if !self.is_usable() {
            return ResumableOpenResult::CarrierDead;
        }
        let (to_sock_tx, to_sock_rx) = mpsc::channel::<Vec<u8>>(STREAM_CHAN_CAP);
        let owner = SessionOwner::new(
            self.peer_pub.clone(),
            target_addr.to_vec(),
            to_sock_tx,
        );
        if registry.insert(owner.clone()).is_err() {
            return ResumableOpenResult::CarrierDead;
        }
        match self.attach_session(&owner, 1, true).await {
            Ok(true) => {
                stats::MUX_STREAMS_OPENED.fetch_add(1, Relaxed);
                ResumableOpenResult::Opened(ResumableMuxStream {
                    owner,
                    to_socket_rx: to_sock_rx,
                    registry: registry.clone(),
                })
            }
            Ok(false) => {
                owner.close();
                registry.remove(&owner.session_id);
                ResumableOpenResult::Refused
            }
            Err(_) => {
                owner.close();
                registry.remove(&owner.session_id);
                ResumableOpenResult::CarrierDead
            }
        }
    }

    pub async fn open_stream(self: &Arc<Self>, target_addr: &[u8]) -> MuxOpenResult {
        if !self.is_usable() {
            return MuxOpenResult::CarrierDead;
        }
        let sid = self.next_id.fetch_add(1, Relaxed);
        let (syn_tx, syn_rx) = oneshot::channel();
        let (rx_tx, rx_rx) = mpsc::channel(STREAM_CHAN_CAP);
        {
            let mut st = self.state.lock().unwrap();
            if !self.alive.load(Relaxed) {
                return MuxOpenResult::CarrierDead;
            }
            st.pending_syn.insert(sid, syn_tx);
            st.streams.insert(sid, rx_tx);
            self.active_streams.store(st.streams.len(), Relaxed);
        }
        if self.tx.send(encode_frame(CMD_SYN, sid, target_addr)).await.is_err() {
            self.remove_stream(sid);
            self.mark_dead();
            return MuxOpenResult::CarrierDead;
        }
        match timeout(Duration::from_secs(10), syn_rx).await {
            Ok(Ok(true)) => {
                stats::MUX_STREAMS_OPENED.fetch_add(1, Relaxed);
                MuxOpenResult::Opened(MuxStream {
                    id: sid,
                    tx: self.tx.clone(),
                    rx: rx_rx,
                    carrier: self.clone(),
                })
            }
            Ok(Ok(false)) => {
                self.remove_stream(sid);
                MuxOpenResult::Refused
            }
            _ => {
                // One slow SYN must not kill every resumable session on this carrier.
                self.remove_stream(sid);
                let _ = self.tx.try_send(encode_frame(CMD_RST, sid, &[]));
                MuxOpenResult::CarrierDead
            }
        }
    }
}

async fn closed_rd_wait(rx: &mut watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Exit-side multiplexed carrier server: accepts `CMD_SYN` streams and `CMD_RESUME`
/// Turbo-Tunnel `SessionOwner` streams, enforcing anti-SSRF destination validation.
pub async fn serve_exit(link: Link, allow_private: bool) -> Result<()> {
    let reg = Arc::new(SessionRegistry::new());
    // No local static public available: resume AttachReq will be rejected (proof_binding empty).
    serve_exit_with_registry(link, allow_private, reg, Vec::new()).await
}

pub async fn serve_exit_with_registry(
    link: Link,
    allow_private: bool,
    session_reg: Arc<SessionRegistry>,
    local_static_pub: Vec<u8>,
) -> Result<()> {
    let peer_pub = link.peer_pub().unwrap_or_default().to_vec();
    let (mut lr, mut lw) = link.split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CARRIER_TX_CAP);
    let streams: Arc<StdMutex<HashMap<u32, mpsc::Sender<StreamRx>>>> =
        Arc::new(StdMutex::new(HashMap::new()));
    let bytes_total = Arc::new(AtomicU64::new(0));
    let started = Instant::now();

    let b_wr = bytes_total.clone();
    let writer = tokio::spawn(async move {
        let mut sent_rekey = false;
        while let Some(frame) = rx.recv().await {
            let flen = frame.len() as u64;
            if !matches!(timeout(CARRIER_WRITE_TIMEOUT, lw.send(&frame)).await, Ok(Ok(()))) {
                break;
            }
            let tot = b_wr.fetch_add(flen, Relaxed) + flen;
            if !sent_rekey && (tot >= REKEY_MAX_BYTES || started.elapsed() >= REKEY_MAX_AGE) {
                sent_rekey = true;
                stats::REKEY_ROTATIONS.fetch_add(1, Relaxed);
                let _ = timeout(
                    CARRIER_WRITE_TIMEOUT,
                    lw.send(&encode_frame(CMD_REKEY, 0, &[])),
                )
                .await;
            }
        }
    });

    let mut plain = vec![0u8; CHUNK + 64];
    loop {
        let n = match timeout(EXIT_CARRIER_IDLE_TIMEOUT, lr.recv_into(&mut plain)).await {
            Ok(Ok(n)) if n >= MUX_HDR_LEN => n,
            _ => break,
        };
        bytes_total.fetch_add(n as u64, Relaxed);
        let Some((cmd, sid, payload)) = decode_header(&plain[..n]) else {
            continue;
        };
        match cmd {
            CMD_SYN => {
                if streams.lock().unwrap().len() >= MUX_MAX_STREAMS_PER_CARRIER {
                    let _ = tx.try_send(encode_frame(CMD_SYN_ERR, sid, &[]));
                    continue;
                }
                let (s_tx, s_rx) = mpsc::channel::<StreamRx>(STREAM_CHAN_CAP);
                streams.lock().unwrap().insert(sid, s_tx);
                let addr_bytes = payload.to_vec();
                let tx_c = tx.clone();
                let streams_c = streams.clone();
                tokio::spawn(async move {
                    run_exit_stream(sid, addr_bytes, allow_private, tx_c, s_rx).await;
                    streams_c.lock().unwrap().remove(&sid);
                });
            }
            CMD_DATA => {
                let s_tx = streams.lock().unwrap().get(&sid).cloned();
                if let Some(s_tx) = s_tx {
                    match s_tx.try_send(StreamRx::Data(payload.to_vec())) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(item)) => {
                            if !matches!(
                                tokio::time::timeout(Duration::from_secs(2), s_tx.send(item)).await,
                                Ok(Ok(()))
                            ) {
                                streams.lock().unwrap().remove(&sid);
                                let _ = tx.try_send(encode_frame(CMD_RST, sid, &[]));
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            streams.lock().unwrap().remove(&sid);
                        }
                    }
                }
            }
            CMD_FIN => {
                let s_tx = streams.lock().unwrap().remove(&sid);
                if let Some(s_tx) = s_tx {
                    let _ = s_tx.try_send(StreamRx::Fin);
                }
            }
            CMD_RST => {
                let s_tx = streams.lock().unwrap().remove(&sid);
                if let Some(s_tx) = s_tx {
                    let _ = s_tx.try_send(StreamRx::Rst);
                }
            }
            CMD_PING => {
                let _ = tx.try_send(encode_frame(CMD_PONG, 0, &[]));
            }
            CMD_PONG | CMD_REKEY => {}
            CMD_RESUME => {
                if let Ok(rframe) = ResumeFrame::decode(payload) {
                    match rframe {
                        ResumeFrame::AttachReq {
                            session_id,
                            epoch,
                            last_ack_seq,
                            target_addr,
                            proof,
                            token,
                        } => {
                            let existing = session_reg.get(&session_id);
                            let binding = existing.as_ref().map(|e| {
                                (
                                    e.resume_token,
                                    e.peer_noise_pub.clone(),
                                    e.closed.load(Relaxed),
                                )
                            });
                            // proof_binding = Exit static public (same key Entry mixed into HMAC).
                            // noise_peer = authenticated Entry static public on this carrier.
                            let authorized = authorize_attach(
                                &local_static_pub,
                                &peer_pub,
                                &token,
                                &session_id,
                                epoch,
                                &proof,
                                binding.as_ref().map(|(t, p, c)| (t.as_slice(), p.as_slice(), *c)),
                            );
                            if authorized.is_err() {
                                let rej = ResumeFrame::AttachAck {
                                    session_id,
                                    epoch,
                                    peer_ack_seq: 0,
                                    accepted: false,
                                };
                                let _ = tx.try_send(encode_frame(CMD_RESUME, 0, &rej.encode()));
                                continue;
                            }
                            let ledger_ok = session_reg
                                .ledger()
                                .validate_and_record(&session_id, epoch, &proof)
                                .is_ok();
                            if !ledger_ok {
                                let rej = ResumeFrame::AttachAck {
                                    session_id,
                                    epoch,
                                    peer_ack_seq: 0,
                                    accepted: false,
                                };
                                let _ = tx.try_send(encode_frame(CMD_RESUME, 0, &rej.encode()));
                                continue;
                            }
                            if authorized.unwrap() {
                                let Some(existing) = existing else {
                                    continue;
                                };
                                let tx_re = tx.clone();
                                tokio::spawn(async move {
                                    let (r_tx, mut r_rx) =
                                        mpsc::channel::<ResumeFrame>(STREAM_CHAN_CAP);
                                    let tx_fwd = tx_re.clone();
                                    let owner_fwd = existing.clone();
                                    let tx_id = r_tx.clone();
                                    tokio::spawn(async move {
                                        while let Some(rf) = r_rx.recv().await {
                                            if tx_fwd
                                                .send(encode_frame(CMD_RESUME, 0, &rf.encode()))
                                                .await
                                                .is_err()
                                            {
                                                owner_fwd.detach_if_same_sender(&tx_id);
                                                break;
                                            }
                                        }
                                    });
                                    let peer_ack =
                                        existing.dataplane.lock().unwrap().current_ack();
                                    let ack_msg = ResumeFrame::AttachAck {
                                        session_id,
                                        epoch,
                                        peer_ack_seq: peer_ack,
                                        accepted: true,
                                    };
                                    if matches!(
                                        timeout(
                                            Duration::from_secs(5),
                                            tx_re.send(encode_frame(
                                                CMD_RESUME,
                                                0,
                                                &ack_msg.encode(),
                                            )),
                                        )
                                        .await,
                                        Ok(Ok(()))
                                    ) {
                                        let _ = existing
                                            .reattach_carrier(epoch, last_ack_seq, r_tx)
                                            .await;
                                    }
                                });
                            } else {
                                let tx_init = tx.clone();
                                let reg_c = session_reg.clone();
                                let peer_pub_c = peer_pub.clone();
                                let token_c = token;
                                tokio::spawn(async move {
                                    let target = match timeout(Duration::from_secs(12), async {
                                        let (host, port, _) = parse_addr(&target_addr)?;
                                        let addrs =
                                            resolve_validated(&host, port, allow_private, DNS_TIMEOUT)
                                                .await?;
                                        for sa in addrs {
                                            if let Ok(s) = TcpStream::connect(sa).await {
                                                return Ok::<TcpStream, anyhow::Error>(s);
                                            }
                                        }
                                        anyhow::bail!("unreachable")
                                    })
                                    .await
                                    {
                                        Ok(Ok(t)) => t,
                                        _ => {
                                            let rej = ResumeFrame::AttachAck {
                                                session_id,
                                                epoch,
                                                peer_ack_seq: 0,
                                                accepted: false,
                                            };
                                            let _ = tx_init
                                                .send(encode_frame(CMD_RESUME, 0, &rej.encode()))
                                                .await;
                                            return;
                                        }
                                    };
                                    link::tune(&target);
                                    let (to_sock_tx, mut to_sock_rx) =
                                        mpsc::channel::<Vec<u8>>(STREAM_CHAN_CAP);
                                    let owner = SessionOwner::with_id_and_token(
                                        session_id,
                                        token_c,
                                        peer_pub_c,
                                        target_addr,
                                        to_sock_tx,
                                    );
                                    if reg_c.insert(owner.clone()).is_err() {
                                        return;
                                    }
                                    let (r_tx, mut r_rx) = mpsc::channel::<ResumeFrame>(STREAM_CHAN_CAP);
                                    let tx_fwd = tx_init.clone();
                                    let owner_fwd = owner.clone();
                                    let tx_id = r_tx.clone();
                                    tokio::spawn(async move {
                                        while let Some(rf) = r_rx.recv().await {
                                            if tx_fwd
                                                .send(encode_frame(CMD_RESUME, 0, &rf.encode()))
                                                .await
                                                .is_err()
                                            {
                                                owner_fwd.detach_if_same_sender(&tx_id);
                                                break;
                                            }
                                        }
                                    });
                                    let _ = owner.reattach_carrier(epoch, last_ack_seq, r_tx).await;
                                    let ack_msg = ResumeFrame::AttachAck {
                                        session_id,
                                        epoch,
                                        peer_ack_seq: 0,
                                        accepted: true,
                                    };
                                    let _ = tx_init
                                        .send(encode_frame(CMD_RESUME, 0, &ack_msg.encode()))
                                        .await;
                                    let owner_sock = owner.clone();
                                    let (mut tr, mut tw) = target.into_split();
                                    let up = async {
                                        while let Some(chunk) = to_sock_rx.recv().await {
                                            if chunk.is_empty() {
                                                // in-band EOF: the client finished sending
                                                let _ = tw.shutdown().await;
                                                break;
                                            }
                                            if tw.write_all(&chunk).await.is_err() {
                                                break;
                                            }
                                        }
                                        Ok::<(), anyhow::Error>(())
                                    };
                                    let down = async {
                                        let mut buf = vec![0u8; MUX_MAX_PAYLOAD.saturating_sub(64)];
                                        loop {
                                            match tr.read(&mut buf).await {
                                                Ok(0) | Err(_) => break,
                                                Ok(n) => {
                                                    if owner_sock
                                                        .send_from_socket(
                                                            buf[..n].to_vec(),
                                                            DEFAULT_SESSION_DETACH_TTL,
                                                        )
                                                        .await
                                                        .is_err()
                                                    {
                                                        return Ok::<(), anyhow::Error>(());
                                                    }
                                                }
                                            }
                                        }
                                        // target closed: pass EOF on to the entry's client
                                        let _ = owner_sock.send_fin(DEFAULT_SESSION_DETACH_TTL).await;
                                        Ok::<(), anyhow::Error>(())
                                    };
                                    let _ = join_half_closed(up, down).await;
                                    // Keep session alive until final data + in-band FIN are ACKed
                                    // (bounded by DEFAULT_SESSION_DETACH_TTL) so carrier loss at
                                    // tail of a response can still resume and deliver EOF cleanly.
                                    owner.wait_drained(DEFAULT_SESSION_DETACH_TTL).await;
                                    owner.close();
                                    reg_c.remove(&session_id);
                                });
                            }
                        }
                        ResumeFrame::SeqData {
                            session_id,
                            epoch,
                            seq,
                            ack,
                            payload,
                        } => {
                            if let Some(ow) = session_reg.get(&session_id) {
                                if let Ok(Some(ack_f)) =
                                    ow.enqueue_from_carrier(epoch, seq, ack, payload)
                                {
                                    let _ = tx.try_send(encode_frame(
                                        CMD_RESUME,
                                        0,
                                        &ack_f.encode(),
                                    ));
                                }
                            }
                        }
                        ResumeFrame::SeqAck {
                            session_id, ack, ..
                        } => {
                            if let Some(ow) = session_reg.get(&session_id) {
                                ow.apply_ack(ack);
                            }
                        }
                        ResumeFrame::SeqSack {
                            session_id,
                            ack,
                            ranges,
                            ..
                        } => {
                            if let Some(ow) = session_reg.get(&session_id) {
                                ow.apply_sack(ack, &ranges);
                            }
                        }
                        ResumeFrame::SeqFin { session_id, .. } => {
                            if let Some(ow) = session_reg.remove(&session_id) {
                                ow.close();
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    streams.lock().unwrap().clear();
    drop(tx);
    writer.abort();
    let _ = writer.await;
    Ok(())
}

async fn run_exit_stream(
    sid: u32,
    addr: Vec<u8>,
    allow_private: bool,
    tx: mpsc::Sender<Vec<u8>>,
    mut rx: mpsc::Receiver<StreamRx>,
) {
    let target = match timeout(Duration::from_secs(10), async {
        let (host, port, _) = parse_addr(&addr)?;
        let addrs = resolve_validated(&host, port, allow_private, DNS_TIMEOUT).await?;
        let mut last = None;
        for sa in addrs {
            match TcpStream::connect(sa).await {
                Ok(s) => return Ok::<TcpStream, anyhow::Error>(s),
                Err(e) => last = Some(e.into()),
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("no addresses reachable")))
    })
    .await
    {
        Ok(Ok(t)) => t,
        _ => {
            let _ = tx.send(encode_frame(CMD_SYN_ERR, sid, &[])).await;
            return;
        }
    };

    link::tune(&target);
    if tx.send(encode_frame(CMD_SYN_OK, sid, &[])).await.is_err() {
        return;
    }

    stats::STREAMS_TOTAL.fetch_add(1, Relaxed);
    stats::STREAMS_ACTIVE.fetch_add(1, Relaxed);

    let (mut tr, mut tw) = target.into_split();
    let tx_dn = tx.clone();
    let down = async {
        let mut buf = vec![0u8; MUX_MAX_PAYLOAD];
        loop {
            let lim = stats::ADAPTIVE_CHUNK_BYTES
                .load(Relaxed)
                .clamp(1200, MUX_MAX_PAYLOAD);
            match tr.read(&mut buf[..lim]).await {
                Ok(0) => {
                    let _ = tx_dn.send(encode_frame(CMD_FIN, sid, &[])).await;
                    break;
                }
                Ok(n) => {
                    stats::BYTES_DOWN.fetch_add(n as u64, Relaxed);
                    if tx_dn.send(encode_frame(CMD_DATA, sid, &buf[..n])).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = tx_dn.send(encode_frame(CMD_RST, sid, &[])).await;
                    break;
                }
            }
        }
    };

    let up = async {
        loop {
            match rx.recv().await {
                Some(StreamRx::Data(b)) => {
                    stats::BYTES_UP.fetch_add(b.len() as u64, Relaxed);
                    if tw.write_all(&b).await.is_err() {
                        let _ = tx.send(encode_frame(CMD_RST, sid, &[])).await;
                        break;
                    }
                }
                Some(StreamRx::Fin) | None => {
                    let _ = tw.shutdown().await;
                    break;
                }
                Some(StreamRx::Rst) => {
                    let _ = tw.shutdown().await;
                    break;
                }
            }
        }
    };

    tokio::join!(up, down);
    stats::STREAMS_ACTIVE.fetch_sub(1, Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::encode_sockaddr;
    use tokio::io::duplex;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn mux_multiple_concurrent_streams_over_single_noise_link() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = echo.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        let (esk, epk) = link::keygen().unwrap();
        let (xsk, xpk) = link::keygen().unwrap();
        let (a, b) = duplex(1 << 18);
        let allowed = vec![epk];

        let exit_task = tokio::spawn(async move {
            let lk = link::respond(Box::new(b), &xsk, &allowed).await.unwrap();
            let _ = serve_exit(lk, true).await;
        });

        let entry_lk = link::initiate(Box::new(a), &esk, &xpk).await.unwrap();
        let carrier = MuxCarrier::spawn(entry_lk, Duration::from_secs(60));
        let target_bytes = encode_sockaddr(echo_addr);

        let mut handles = Vec::new();
        for i in 0..16u32 {
            let c = carrier.clone();
            let tb = target_bytes.clone();
            handles.push(tokio::spawn(async move {
                let MuxOpenResult::Opened(mut st) = c.open_stream(&tb).await else {
                    panic!("expected stream open");
                };
                let msg = format!("hello-mux-stream-{i}");
                st.send_data(msg.as_bytes()).await.unwrap();
                st.send_fin().await.unwrap();
                let mut got = Vec::new();
                while let Some(chunk) = st.recv_chunk().await.unwrap() {
                    got.extend_from_slice(&chunk);
                }
                assert_eq!(got, msg.as_bytes());
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        drop(carrier);
        let _ = timeout(Duration::from_secs(2), exit_task).await;
    }
}
