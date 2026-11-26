//! Link layer: bounded length-prefixed frames carrying Noise_IK transport messages (SPEC §2.1).
//!
//! Security & Performance guarantees:
//!   * Pre-allocation frame length ceilings (`MAX_HANDSHAKE_FRAME = 2048`, `MAX_LINK_FRAME = 32768`).
//!   * Frame size alignment: `CHUNK = 14336` bytes so `2 + CHUNK + 16 = 14354` fits inside a single
//!     Camo TLS record (`DATA_CHUNK = 15360`) and Channel-Bound frame (`16384`) without splitting.
//!   * Post-auth Bridge Anti-Replay order: decrypt m1 -> allowlist -> ±120s timestamp -> replay cache.
//!   * Encrypted READY v2 carries a 32-byte CSPRNG `cb_secret` for secret-bound Channel Binding.
//!   * Application-level idle pool keepalive (`ping`) and adaptive chunk/pacing relay (`pipe_adaptive`).

use crate::adapt::TunnelSide;
use crate::recovery::{AdaptiveRuntime, TransportEvent};
use crate::stats;
use crate::util::{ct_eq, now_unix, rand_bytes, BoxRw};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use snow::{Builder, StatelessTransportState};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{
    split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf,
};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{sleep, timeout};

pub const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE_LINK: &[u8] = b"khaymali/link/1";
pub const PROLOGUE_BRIDGE: &[u8] = b"khaymali/bridge/1";
/// Aligned plaintext chunk: `2 + CHUNK + 16 = 14354` bytes fits in 1 Camo record (15360) and 1 Bound frame (16384).
pub const CHUNK: usize = 14 * 1024;
const TAG: usize = 16;

pub const MAX_HANDSHAKE_FRAME: usize = 2048;
pub const MAX_LINK_FRAME: usize = 32 * 1024;
pub const BRIDGE_MAX_SKEW_SECS: u64 = 120;
const BRIDGE_REPLAY_CAP: usize = 4096;
pub const BRIDGE_READY_V1: &[u8] = b"khaymali-bridge-ok";
const BRIDGE_READY_V2: &[u8] = b"khaymali-bridge-v2";

pub fn keygen() -> Result<(Vec<u8>, Vec<u8>)> {
    let kp = Builder::new(PATTERN.parse()?).generate_keypair()?;
    Ok((kp.private, kp.public))
}

pub fn tune(s: &TcpStream) {
    let _ = s.set_nodelay(true);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    let _ = socket2::SockRef::from(s).set_tcp_keepalive(&ka);
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > MAX_LINK_FRAME {
        bail!("frame too large ({} > {})", data.len(), MAX_LINK_FRAME);
    }
    let mut buf = Vec::with_capacity(2 + data.len());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    w.write_all(&buf).await?;
    Ok(())
}

/// Reads a 2-byte length-prefixed frame, validating `len <= max_len` BEFORE allocating.
pub async fn read_frame_bounded<R: AsyncRead + Unpin>(r: &mut R, max_len: usize) -> Result<Vec<u8>> {
    let mut l = [0u8; 2];
    r.read_exact(&mut l).await?;
    let len = u16::from_be_bytes(l) as usize;
    if len > max_len {
        bail!("frame length {len} exceeds maximum {max_len}");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn read_frame_into<R: AsyncRead + Unpin>(
    r: &mut R,
    max_len: usize,
    buf: &mut Vec<u8>,
) -> Result<usize> {
    let mut l = [0u8; 2];
    r.read_exact(&mut l).await?;
    let len = u16::from_be_bytes(l) as usize;
    if len > max_len {
        bail!("frame length {len} exceeds maximum {max_len}");
    }
    if buf.len() < len {
        buf.resize(len, 0);
    }
    r.read_exact(&mut buf[..len]).await?;
    Ok(len)
}

/// Bounded anti-replay cache for authenticated Bridge `m1` messages (SPEC §2.1).
pub struct BridgeReplayCache {
    seen: Mutex<HashMap<[u8; 32], Instant>>,
    cap: usize,
    ttl: Duration,
}

impl BridgeReplayCache {
    pub fn new() -> Self {
        Self::with_limits(BRIDGE_REPLAY_CAP, Duration::from_secs(BRIDGE_MAX_SKEW_SECS * 2))
    }

    pub fn with_limits(cap: usize, ttl: Duration) -> Self {
        Self {
            seen: Mutex::new(HashMap::with_capacity(cap.min(256))),
            cap: cap.max(1),
            ttl,
        }
    }

    pub fn check_and_insert(&self, m1: &[u8]) -> bool {
        let key: [u8; 32] = Sha256::digest(m1).into();
        let now = Instant::now();
        let mut m = self.seen.lock().unwrap();
        if m.contains_key(&key) {
            return false;
        }
        if m.len() >= self.cap {
            let ttl = self.ttl;
            m.retain(|_, t| now.saturating_duration_since(*t) < ttl);
            if m.len() >= self.cap {
                if let Some(oldest_k) = m.iter().min_by_key(|(_, &t)| t).map(|(&k, _)| k) {
                    m.remove(&oldest_k);
                }
            }
        }
        m.insert(key, now);
        true
    }

    pub fn len(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

pub struct LinkReader {
    s: ReadHalf<BoxRw>,
    ts: Arc<StatelessTransportState>,
    n: u64,
    frame_buf: Vec<u8>,
    _permit: Option<Arc<OwnedSemaphorePermit>>,
}

pub struct LinkWriter {
    s: WriteHalf<BoxRw>,
    ts: Arc<StatelessTransportState>,
    n: u64,
    wire_buf: Vec<u8>,
}

pub struct Link {
    rd: LinkReader,
    wr: LinkWriter,
    created: Instant,
    last_checked: Instant,
    peer_pub: Option<Vec<u8>>,
}

impl LinkWriter {
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        let max_ct = data.len() + TAG;
        if max_ct > MAX_LINK_FRAME {
            bail!("plaintext chunk too large for Noise frame");
        }
        if self.wire_buf.len() < 2 + max_ct {
            self.wire_buf.resize(2 + max_ct, 0);
        }
        let n = self.ts.write_message(self.n, data, &mut self.wire_buf[2..])?;
        self.n = self.n.checked_add(1).context("Noise nonce overflow")?;
        let len_be = (n as u16).to_be_bytes();
        self.wire_buf[0] = len_be[0];
        self.wire_buf[1] = len_be[1];
        self.s.write_all(&self.wire_buf[..2 + n]).await?;
        Ok(())
    }
}

impl LinkReader {
    /// Decrypt next Noise frame directly into reusable `plain` buffer (zero per-packet alloc).
    pub async fn recv_into(&mut self, plain: &mut Vec<u8>) -> Result<usize> {
        let flen = read_frame_into(&mut self.s, MAX_LINK_FRAME, &mut self.frame_buf).await?;
        if plain.len() < flen {
            plain.resize(flen, 0);
        }
        let n = self.ts.read_message(self.n, &self.frame_buf[..flen], plain)?;
        self.n = self.n.checked_add(1).context("Noise nonce overflow")?;
        Ok(n)
    }

    /// An empty vector is the in-band end-of-stream marker.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let n = self.recv_into(&mut out).await?;
        out.truncate(n);
        Ok(out)
    }
}

fn is_reset_err(err: &anyhow::Error) -> bool {
    for c in err.chain() {
        if let Some(ioe) = c.downcast_ref::<std::io::Error>() {
            if matches!(
                ioe.kind(),
                ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::BrokenPipe
                    | ErrorKind::UnexpectedEof
            ) {
                return true;
            }
        }
    }
    false
}

impl Link {
    fn new(s: BoxRw, ts: StatelessTransportState, peer_pub: Option<Vec<u8>>) -> Link {
        let (r, w) = split(s);
        let ts = Arc::new(ts);
        let now = Instant::now();
        Link {
            rd: LinkReader {
                s: r,
                ts: ts.clone(),
                n: 0,
                frame_buf: vec![0u8; CHUNK + TAG],
                _permit: None,
            },
            wr: LinkWriter {
                s: w,
                ts,
                n: 0,
                wire_buf: vec![0u8; 2 + CHUNK + TAG],
            },
            created: now,
            last_checked: now,
            peer_pub,
        }
    }

    pub fn with_permit(mut self, permit: OwnedSemaphorePermit) -> Self {
        self.rd._permit = Some(Arc::new(permit));
        self
    }

    pub fn age(&self) -> Duration {
        self.created.elapsed()
    }

    pub fn idle_since_check(&self) -> Duration {
        self.last_checked.elapsed()
    }

    pub fn peer_pub(&self) -> Option<&[u8]> {
        self.peer_pub.as_deref()
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.wr.send(data).await
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        self.rd.recv().await
    }

    /// Application-level keepalive probe (`[0]` -> `[0]`) for pooled idle links.
    /// Catches silently dropped NAT/DPI connections before handing them to a client.
    pub async fn ping(&mut self, wait: Duration) -> bool {
        let ok = match timeout(wait, async {
            self.wr.send(&[0]).await?;
            let resp = self.rd.recv().await?;
            Ok::<bool, anyhow::Error>(resp == [0])
        })
        .await
        {
            Ok(Ok(true)) => true,
            _ => false,
        };
        if ok {
            self.last_checked = Instant::now();
        }
        ok
    }

    pub fn split(self) -> (LinkReader, LinkWriter) {
        (self.rd, self.wr)
    }

    pub async fn pipe(self, tcp: TcpStream) -> Result<()> {
        self.pipe_adaptive(tcp, None).await
    }

    pub async fn pipe_adaptive(
        self,
        tcp: TcpStream,
        adaptive: Option<Arc<AdaptiveRuntime>>,
    ) -> Result<()> {
        stats::STREAMS_TOTAL.fetch_add(1, Relaxed);
        stats::STREAMS_ACTIVE.fetch_add(1, Relaxed);
        let r = self.pipe_inner(tcp, adaptive.as_deref()).await;
        stats::STREAMS_ACTIVE.fetch_sub(1, Relaxed);
        r
    }

    async fn pipe_inner(
        self,
        tcp: TcpStream,
        adaptive: Option<&AdaptiveRuntime>,
    ) -> Result<()> {
        let (mut tr, mut tw) = tcp.into_split();
        let (mut lr, mut lw) = (self.rd, self.wr);
        let transferred = std::sync::atomic::AtomicU64::new(0);

        let up = async {
            let mut buf = vec![0u8; CHUNK];
            loop {
                let lim = adaptive
                    .map(|a| a.current_chunk_size().min(CHUNK))
                    .unwrap_or(CHUNK);
                let n = tr.read(&mut buf[..lim]).await?;
                if n == 0 {
                    lw.send(&[]).await.context(TunnelSide)?;
                    return Ok::<(), anyhow::Error>(());
                }
                stats::BYTES_UP.fetch_add(n as u64, Relaxed);
                transferred.fetch_add(n as u64, Relaxed);
                if let Err(e) = lw.send(&buf[..n]).await {
                    if let Some(a) = adaptive {
                        let bytes = transferred.load(Relaxed);
                        if is_reset_err(&e) {
                            a.record(TransportEvent::EarlyReset { bytes_transferred: bytes }, 0);
                        } else {
                            a.record(
                                TransportEvent::MidStreamStall {
                                    bytes_transferred: bytes,
                                    frame_size: lim,
                                },
                                0,
                            );
                        }
                    }
                    return Err(e.context(TunnelSide));
                }
                if let Some(a) = adaptive {
                    let p_us = a.current_pacing_us();
                    if p_us > 0 {
                        sleep(Duration::from_micros(p_us)).await;
                    }
                }
            }
        };
        let down = async {
            let mut plain = vec![0u8; CHUNK + TAG];
            loop {
                let n = match lr.recv_into(&mut plain).await {
                    Ok(n) => n,
                    Err(e) => {
                        if let Some(a) = adaptive {
                            let bytes = transferred.load(Relaxed);
                            let lim = a.current_chunk_size();
                            if is_reset_err(&e) {
                                a.record(TransportEvent::EarlyReset { bytes_transferred: bytes }, 0);
                            } else {
                                a.record(
                                    TransportEvent::MidStreamStall {
                                        bytes_transferred: bytes,
                                        frame_size: lim,
                                    },
                                    0,
                                );
                            }
                        }
                        return Err(e.context(TunnelSide));
                    }
                };
                if n == 0 {
                    let _ = tw.shutdown().await;
                    return Ok::<(), anyhow::Error>(());
                }
                stats::BYTES_DOWN.fetch_add(n as u64, Relaxed);
                transferred.fetch_add(n as u64, Relaxed);
                tw.write_all(&plain[..n]).await?;
            }
        };
        let res = tokio::try_join!(up, down);
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

pub async fn initiate(mut s: BoxRw, local_priv: &[u8], remote_pub: &[u8]) -> Result<Link> {
    let mut hs = Builder::new(PATTERN.parse()?)
        .prologue(PROLOGUE_LINK)
        .local_private_key(local_priv)
        .remote_public_key(remote_pub)
        .build_initiator()?;
    let mut buf = vec![0u8; MAX_HANDSHAKE_FRAME];
    let n = hs.write_message(&[], &mut buf)?;
    write_frame(&mut s, &buf[..n]).await?;
    let m2 = read_frame_bounded(&mut s, MAX_HANDSHAKE_FRAME).await?;
    hs.read_message(&m2, &mut buf)?;
    Ok(Link::new(s, hs.into_stateless_transport_mode()?, Some(remote_pub.to_vec())))
}

pub async fn respond(mut s: BoxRw, local_priv: &[u8], allowed: &[Vec<u8>]) -> Result<Link> {
    let mut hs = Builder::new(PATTERN.parse()?)
        .prologue(PROLOGUE_LINK)
        .local_private_key(local_priv)
        .build_responder()?;
    let m1 = read_frame_bounded(&mut s, MAX_HANDSHAKE_FRAME).await?;
    let mut buf = vec![0u8; MAX_HANDSHAKE_FRAME];
    hs.read_message(&m1, &mut buf)?;
    let remote = hs.get_remote_static().context("no remote static key")?.to_vec();
    if !allowed.iter().any(|k| ct_eq(k, &remote)) {
        bail!("initiator key not in allowlist");
    }
    let n = hs.write_message(&[], &mut buf)?;
    write_frame(&mut s, &buf[..n]).await?;
    Ok(Link::new(s, hs.into_stateless_transport_mode()?, Some(remote)))
}

/// Bridge side of bridge authentication (SPEC §2.1, §2.2).
/// Sends timestamp inside m1 and 32-byte random `cb_secret` inside encrypted READY v2.
/// Returns `(handshake_hash, cb_secret)` for secret-bound HKDF Channel Binding.
pub async fn auth_initiate<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    bridge_priv: &[u8],
    entry_pub: &[u8],
) -> Result<([u8; 32], [u8; 32])> {
    auth_initiate_at(s, bridge_priv, entry_pub, now_unix()).await
}

pub async fn auth_initiate_at<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    bridge_priv: &[u8],
    entry_pub: &[u8],
    ts: u64,
) -> Result<([u8; 32], [u8; 32])> {
    let mut hs = Builder::new(PATTERN.parse()?)
        .prologue(PROLOGUE_BRIDGE)
        .local_private_key(bridge_priv)
        .remote_public_key(entry_pub)
        .build_initiator()?;
    let mut buf = vec![0u8; MAX_HANDSHAKE_FRAME];
    let n = hs.write_message(&ts.to_be_bytes(), &mut buf)?;
    write_frame(s, &buf[..n]).await?;
    let m2 = read_frame_bounded(s, MAX_HANDSHAKE_FRAME).await?;
    hs.read_message(&m2, &mut buf)?;
    let mut hs_hash = [0u8; 32];
    let h = hs.get_handshake_hash();
    if h.len() != 32 {
        bail!("unexpected handshake hash length");
    }
    hs_hash.copy_from_slice(h);
    let ts_state = hs.into_stateless_transport_mode()?;

    let cb_secret: [u8; 32] = rand_bytes();
    let mut ready_plain = Vec::with_capacity(BRIDGE_READY_V2.len() + 32);
    ready_plain.extend_from_slice(BRIDGE_READY_V2);
    ready_plain.extend_from_slice(&cb_secret);
    let n = ts_state.write_message(0, &ready_plain, &mut buf)?;
    write_frame(s, &buf[..n]).await?;
    Ok((hs_hash, cb_secret))
}

/// Entry side (SPEC §2.1): STRICT post-auth replay cache order:
/// 1) bounded read m1  2) Noise decrypt  3) allowlist ct_eq  4) ±120s timestamp  5) replay cache
/// 6) send m2 & verify encrypted READY (extracting 32-byte `cb_secret` if v2).
pub async fn auth_respond<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    entry_priv: &[u8],
    allowed: &[Vec<u8>],
    replay: &BridgeReplayCache,
    require_channel_binding: bool,
) -> Result<(Vec<u8>, [u8; 32], Option<[u8; 32]>)> {
    let mut hs = Builder::new(PATTERN.parse()?)
        .prologue(PROLOGUE_BRIDGE)
        .local_private_key(entry_priv)
        .build_responder()?;
    // 1. Bounded read
    let m1 = read_frame_bounded(s, MAX_HANDSHAKE_FRAME).await?;
    let mut buf = vec![0u8; MAX_HANDSHAKE_FRAME];
    // 2. Noise decrypt
    let plen = hs.read_message(&m1, &mut buf)?;
    // 3. Allowlist check BEFORE touching replay cache (prevents cache poisoning)
    let remote = hs.get_remote_static().context("no remote static key")?.to_vec();
    if !allowed.iter().any(|k| ct_eq(k, &remote)) {
        bail!("bridge key not in allowlist");
    }
    // 4. Timestamp window check BEFORE touching replay cache
    if plen != 8 {
        bail!("bridge m1 missing timestamp payload");
    }
    let ts = u64::from_be_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
    let skew = ts.abs_diff(now_unix());
    if skew > BRIDGE_MAX_SKEW_SECS {
        stats::BRIDGE_REPLAY_DROPPED.fetch_add(1, Relaxed);
        stats::CLOCK_SKEW_DROPPED.fetch_add(1, Relaxed);
        bail!("bridge m1 timestamp skew {skew}s outside ±{}s window (check NTP sync)", BRIDGE_MAX_SKEW_SECS);
    }
    // 5. Post-auth replay cache insert (silent close on duplicate: no m2 written)
    if !replay.check_and_insert(&m1) {
        stats::BRIDGE_REPLAY_DROPPED.fetch_add(1, Relaxed);
        bail!("bridge m1 replay detected");
    }

    // 6. Complete handshake & verify encrypted READY
    let n = hs.write_message(&[], &mut buf)?;
    write_frame(s, &buf[..n]).await?;
    let mut hs_hash = [0u8; 32];
    let h = hs.get_handshake_hash();
    if h.len() != 32 {
        bail!("unexpected handshake hash length");
    }
    hs_hash.copy_from_slice(h);
    let ts_state = hs.into_stateless_transport_mode()?;

    let confirm = read_frame_bounded(s, MAX_HANDSHAKE_FRAME).await?;
    let mut out = vec![0u8; confirm.len()];
    let n = ts_state.read_message(0, &confirm, &mut out)?;
    let cb_secret = if n == BRIDGE_READY_V2.len() + 32
        && ct_eq(&out[..BRIDGE_READY_V2.len()], BRIDGE_READY_V2)
    {
        let mut sec = [0u8; 32];
        sec.copy_from_slice(&out[BRIDGE_READY_V2.len()..n]);
        Some(sec)
    } else if ct_eq(&out[..n], BRIDGE_READY_V1) {
        if require_channel_binding {
            bail!("bridge attempted legacy READY v1 while --require-channel-binding is enabled");
        }
        None
    } else {
        bail!("bad bridge READY confirmation");
    };
    Ok((remote, hs_hash, cb_secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};

    fn boxed(s: tokio::io::DuplexStream) -> BoxRw {
        Box::new(s)
    }

    #[tokio::test]
    async fn noise_link_roundtrip_and_allowlist() {
        let (esk, epk) = keygen().unwrap();
        let (xsk, xpk) = keygen().unwrap();
        let (a, b) = duplex(1 << 16);
        let allowed = vec![epk.clone()];
        let srv = tokio::spawn(async move {
            let mut l = respond(boxed(b), &xsk, &allowed).await.unwrap();
            let m = l.recv().await.unwrap();
            l.send(&m).await.unwrap();
        });
        let mut l = initiate(boxed(a), &esk, &xpk).await.unwrap();
        l.send(b"hello").await.unwrap();
        assert_eq!(l.recv().await.unwrap(), b"hello");
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn link_ping_keepalive_roundtrip() {
        let (esk, epk) = keygen().unwrap();
        let (xsk, xpk) = keygen().unwrap();
        let (a, b) = duplex(1 << 16);
        let allowed = vec![epk.clone()];
        let srv = tokio::spawn(async move {
            let mut l = respond(boxed(b), &xsk, &allowed).await.unwrap();
            let req = l.recv().await.unwrap();
            assert_eq!(req, [0]);
            l.send(&[0]).await.unwrap();
        });
        let mut l = initiate(boxed(a), &esk, &xpk).await.unwrap();
        assert!(l.ping(Duration::from_secs(2)).await);
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn bridge_auth_exchanges_hash_and_secret() {
        let (esk, epk) = keygen().unwrap();
        let (bsk, bpk) = keygen().unwrap();
        let (mut a, mut b) = duplex(1 << 16);
        let allowed = vec![bpk.clone()];
        let replay = Arc::new(BridgeReplayCache::new());
        let r2 = replay.clone();
        let srv = tokio::spawn(async move { auth_respond(&mut b, &esk, &allowed, &r2, true).await });
        let (h_cli, sec_cli) = auth_initiate(&mut a, &bsk, &epk).await.unwrap();
        let (got_pk, h_srv, sec_srv) = srv.await.unwrap().unwrap();
        assert_eq!(got_pk, bpk);
        assert_eq!(h_cli, h_srv);
        assert_eq!(sec_srv, Some(sec_cli));
    }

    #[tokio::test]
    async fn neg_bridge_replay_and_cache_poisoning() {
        let (esk, epk) = keygen().unwrap();
        let (bsk, bpk) = keygen().unwrap();
        let (evil_sk, _) = keygen().unwrap();
        let allowed = vec![bpk];
        let replay = Arc::new(BridgeReplayCache::with_limits(8, Duration::from_secs(240)));

        let mut hs = Builder::new(PATTERN.parse().unwrap())
            .prologue(PROLOGUE_BRIDGE)
            .local_private_key(&bsk)
            .remote_public_key(&epk)
            .build_initiator()
            .unwrap();
        let mut m1_buf = vec![0u8; MAX_HANDSHAKE_FRAME];
        let m1_len = hs.write_message(&now_unix().to_be_bytes(), &mut m1_buf).unwrap();
        let captured_m1 = m1_buf[..m1_len].to_vec();

        let (mut c1, mut s1) = duplex(4096);
        let (esk1, al1, r1) = (esk.clone(), allowed.clone(), replay.clone());
        let srv1 = tokio::spawn(async move { auth_respond(&mut s1, &esk1, &al1, &r1, false).await });
        write_frame(&mut c1, &captured_m1).await.unwrap();
        drop(c1);
        assert!(srv1.await.unwrap().is_err());
        assert_eq!(replay.len(), 1);

        for _ in 0..32 {
            let mut ehs = Builder::new(PATTERN.parse().unwrap())
                .prologue(PROLOGUE_BRIDGE)
                .local_private_key(&evil_sk)
                .remote_public_key(&epk)
                .build_initiator()
                .unwrap();
            let mut eb = vec![0u8; MAX_HANDSHAKE_FRAME];
            let elen = ehs.write_message(&now_unix().to_be_bytes(), &mut eb).unwrap();
            let (mut ce, mut se) = duplex(4096);
            let (eske, ale, re) = (esk.clone(), allowed.clone(), replay.clone());
            let srve = tokio::spawn(async move { auth_respond(&mut se, &eske, &ale, &re, false).await });
            write_frame(&mut ce, &eb[..elen]).await.unwrap();
            drop(ce);
            assert!(srve.await.unwrap().is_err());
        }
        assert_eq!(replay.len(), 1, "unallowed flood must not pollute replay cache");

        let (mut c2, mut s2) = duplex(4096);
        let (esk2, al2, r2) = (esk.clone(), allowed.clone(), replay.clone());
        let srv2 = tokio::spawn(async move { auth_respond(&mut s2, &esk2, &al2, &r2, false).await });
        write_frame(&mut c2, &captured_m1).await.unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(c2.read(&mut byte).await.unwrap(), 0, "replay must get silent close");
        assert!(srv2.await.unwrap().is_err());

        let (mut c3, mut s3) = duplex(4096);
        let (esk3, al3, r3) = (esk.clone(), allowed.clone(), replay.clone());
        let srv3 = tokio::spawn(async move { auth_respond(&mut s3, &esk3, &al3, &r3, false).await });
        let _ = auth_initiate_at(&mut c3, &bsk, &epk, now_unix().saturating_sub(500)).await;
        assert!(srv3.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn neg_frame_length_overflow_rejected() {
        let (mut w, mut r) = duplex(64);
        w.write_all(&((MAX_HANDSHAKE_FRAME as u16 + 100).to_be_bytes())).await.unwrap();
        assert!(read_frame_bounded(&mut r, MAX_HANDSHAKE_FRAME).await.is_err());

        let (mut w2, mut r2) = duplex(64);
        w2.write_all(&u16::MAX.to_be_bytes()).await.unwrap();
        assert!(read_frame_bounded(&mut r2, MAX_LINK_FRAME).await.is_err());
    }

    #[tokio::test]
    async fn neg_bridge_downgrade_rejected_when_cb_required() {
        let (esk, epk) = keygen().unwrap();
        let (bsk, bpk) = keygen().unwrap();
        let allowed = vec![bpk];
        let replay = Arc::new(BridgeReplayCache::new());

        let (mut cli, mut srv_stream) = duplex(4096);
        let r2 = replay.clone();
        let srv = tokio::spawn(async move {
            auth_respond(&mut srv_stream, &esk, &allowed, &r2, true).await
        });

        let mut hs = Builder::new(PATTERN.parse().unwrap())
            .prologue(PROLOGUE_BRIDGE)
            .local_private_key(&bsk)
            .remote_public_key(&epk)
            .build_initiator()
            .unwrap();
        let mut buf = vec![0u8; MAX_HANDSHAKE_FRAME];
        let n = hs.write_message(&now_unix().to_be_bytes(), &mut buf).unwrap();
        write_frame(&mut cli, &buf[..n]).await.unwrap();
        let m2 = read_frame_bounded(&mut cli, MAX_HANDSHAKE_FRAME).await.unwrap();
        hs.read_message(&m2, &mut buf).unwrap();
        let ts = hs.into_stateless_transport_mode().unwrap();
        let n = ts.write_message(0, BRIDGE_READY_V1, &mut buf).unwrap();
        write_frame(&mut cli, &buf[..n]).await.unwrap();

        assert!(srv.await.unwrap().is_err(), "v1 READY must be rejected when channel binding is required");
    }
}
