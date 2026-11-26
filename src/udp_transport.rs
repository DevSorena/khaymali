//! Authenticated Reliable UDP Carrier Transport (`udp://HOST:PORT`) with XOR-Parity FEC.
//!
//! Eliminates TCP-over-TCP Head-of-Line blocking under packet loss by running an MTU-safe
//! (1180-byte payload), HMAC-SHA256 authenticated Selective-Repeat ARQ + XOR-Parity FEC stream
//! over UDP with session-ID roaming and adaptive retransmission.
//!
//! Forward Error Correction (FEC):
//!   * Every group of `FEC_GROUP_SIZE = 4` consecutive `FLAG_DATA` packets emits 1 authenticated
//!     `FLAG_FEC` parity packet (`seq = base_seq`, payload = `[len0..len3: 8B][XOR parity]`).
//!   * If any 1 of the 4 data packets is lost in transit, the receiver reconstructs the missing
//!     packet in **0-RTT** immediately upon receiving the parity shard without waiting for ARQ.
//!
//! Datagram wire format (28-byte header + payload + 16-byte HMAC-SHA256 tag):
//!   `[session_id: u64 BE][flags: u8][reserved: u8][len: u16 BE][seq: u32 BE][ack: u32 BE][ack_bits: u32 BE][ts_ms: u32 BE][payload][tag: 16B]`

use crate::stats;
use crate::util::{ct_eq, rand_bytes, BoxRw};
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, timeout};

const HDR_LEN: usize = 28;
const TAG_LEN: usize = 16;
/// MTU-safe UDP payload (28B hdr + 1180B data + 16B tag + 28B IP/UDP = 1252B < 1280B IPv6 min MTU).
const MAX_UDP_PAYLOAD: usize = 1180;
const WINDOW_SIZE: usize = 64;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const RETX_INTERVAL: Duration = Duration::from_millis(60);
const DEFAULT_RTO: Duration = Duration::from_millis(240);
const MAX_UDP_SESSIONS_PER_IP: usize = 32;
/// Legacy / default FEC group size (wire-compatible with v0.10.0 peers).
pub const FEC_GROUP_SIZE: usize = 4;
/// Smallest / largest group size the adaptive FEC may use.
pub const FEC_MIN_K: usize = 2;
pub const FEC_MAX_K: usize = 16;
/// Marker byte that starts a v2 (variable-k) parity payload. A legacy payload starts with a
/// big-endian shard length <= 1196, so its first byte is always <= 0x04 and can never be 0xFE.
const FEC_V2_MARKER: u8 = 0xFE;

const FLAG_SYN: u8 = 1 << 0;
const FLAG_ACK: u8 = 1 << 1;
const FLAG_DATA: u8 = 1 << 2;
const FLAG_FIN: u8 = 1 << 3;
const FLAG_FEC: u8 = 1 << 4;

#[derive(Clone, Debug)]
struct Packet {
    session_id: u64,
    flags: u8,
    seq: u32,
    ack: u32,
    ack_bits: u32,
    ts_ms: u32,
    payload: Vec<u8>,
}

fn compute_tag(key: &[u8], body: &[u8]) -> [u8; TAG_LEN] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key");
    m.update(b"khaymali/udp/v1");
    m.update(body);
    let full = m.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

fn encode_packet(key: &[u8], p: &Packet) -> Vec<u8> {
    let mut out = Vec::with_capacity(HDR_LEN + p.payload.len() + TAG_LEN);
    out.extend_from_slice(&p.session_id.to_be_bytes());
    out.push(p.flags);
    out.push(0);
    out.extend_from_slice(&(p.payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&p.seq.to_be_bytes());
    out.extend_from_slice(&p.ack.to_be_bytes());
    out.extend_from_slice(&p.ack_bits.to_be_bytes());
    out.extend_from_slice(&p.ts_ms.to_be_bytes());
    out.extend_from_slice(&p.payload);
    let tag = compute_tag(key, &out);
    out.extend_from_slice(&tag);
    out
}

fn decode_packet(key: &[u8], raw: &[u8]) -> Option<Packet> {
    if raw.len() < HDR_LEN + TAG_LEN {
        return None;
    }
    let body_len = raw.len() - TAG_LEN;
    let body = &raw[..body_len];
    let tag = &raw[body_len..];
    let expected = compute_tag(key, body);
    if !ct_eq(tag, &expected) {
        return None;
    }
    let plen = u16::from_be_bytes([body[10], body[11]]) as usize;
    if HDR_LEN + plen != body_len || plen > MAX_UDP_PAYLOAD + 16 {
        return None;
    }
    Some(Packet {
        session_id: u64::from_be_bytes(body[0..8].try_into().ok()?),
        flags: body[8],
        seq: u32::from_be_bytes(body[12..16].try_into().ok()?),
        ack: u32::from_be_bytes(body[16..20].try_into().ok()?),
        ack_bits: u32::from_be_bytes(body[20..24].try_into().ok()?),
        ts_ms: u32::from_be_bytes(body[24..28].try_into().ok()?),
        payload: body[HDR_LEN..].to_vec(),
    })
}

/// FEC operating mode of the sender (`KHAYMALI_FEC=off|light|moderate|aggressive|auto`).
///
/// * `off`        — no parity packets (lowest overhead)
/// * `light`      — 1 parity per 8 data packets (12.5% overhead)
/// * `moderate`   — 1 parity per 4 data packets (25%, default, wire-compatible with v0.10.0)
/// * `aggressive` — 1 parity per 2 data packets (50%)
/// * `auto`       — measures the retransmit rate and moves between the levels above
///
/// The receiver needs no configuration: every parity packet carries its own group size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FecMode {
    Off,
    Light,
    Moderate,
    Aggressive,
    Auto,
}

impl FecMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "0" => Some(Self::Off),
            "light" | "low" => Some(Self::Light),
            "moderate" | "medium" | "default" => Some(Self::Moderate),
            "aggressive" | "high" => Some(Self::Aggressive),
            "auto" | "adaptive" => Some(Self::Auto),
            _ => None,
        }
    }

    pub fn from_env() -> Self {
        std::env::var("KHAYMALI_FEC")
            .ok()
            .and_then(|v| Self::parse(&v))
            .unwrap_or(Self::Moderate)
    }

    /// Group size to start with (`0` = FEC disabled).
    pub fn initial_k(self) -> usize {
        match self {
            Self::Off => 0,
            Self::Light => 8,
            Self::Moderate => FEC_GROUP_SIZE,
            Self::Aggressive => 2,
            Self::Auto => FEC_GROUP_SIZE,
        }
    }
}

/// Map a smoothed loss estimate (0.0..=1.0) to an FEC group size for `auto` mode.
pub fn auto_k_for_loss(loss: f64) -> usize {
    if loss < 0.01 {
        8
    } else if loss < 0.04 {
        4
    } else if loss < 0.10 {
        3
    } else {
        2
    }
}

/// Smoothed loss estimator driven by the data/retransmit counters of one session.
pub struct LossEstimator {
    ewma: f64,
    sent: u32,
    retx: u32,
}

impl LossEstimator {
    pub fn new() -> Self {
        Self { ewma: 0.0, sent: 0, retx: 0 }
    }
    pub fn record_sent(&mut self) {
        self.sent = self.sent.saturating_add(1);
    }
    pub fn record_retx(&mut self) {
        self.retx = self.retx.saturating_add(1);
    }
    /// Fold the current window into the EWMA and reset it. Returns `None` when the window is
    /// too small (< 20 data packets) to say anything useful.
    pub fn update(&mut self) -> Option<f64> {
        if self.sent < 20 {
            return None;
        }
        let sample = (self.retx as f64 / self.sent as f64).min(1.0);
        self.ewma = 0.6 * self.ewma + 0.4 * sample;
        self.sent = 0;
        self.retx = 0;
        Some(self.ewma)
    }
}

/// Build an XOR-parity payload for `k = shards.len()` data shards (`FEC_MIN_K..=FEC_MAX_K`).
/// `k == 4` produces the legacy v0.10.0 format `[len0..len3: u16 BE][xor]`; any other `k`
/// produces `[0xFE][k][len0..len(k-1): u16 BE][xor]`.
pub fn encode_fec_parity_k(shards: &[&[u8]]) -> Vec<u8> {
    let k = shards.len();
    let max_len = shards.iter().map(|s| s.len()).max().unwrap_or(0);
    let mut out = Vec::with_capacity(2 + k * 2 + max_len);
    if k != FEC_GROUP_SIZE {
        out.push(FEC_V2_MARKER);
        out.push(k as u8);
    }
    for s in shards {
        out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    }
    let off = out.len();
    out.resize(off + max_len, 0);
    for s in shards {
        for (i, &b) in s.iter().enumerate() {
            out[off + i] ^= b;
        }
    }
    out
}

/// Build an XOR-parity FEC payload from `FEC_GROUP_SIZE` (4) data shards (legacy format).
pub fn encode_fec_parity(shards: &[&[u8]; FEC_GROUP_SIZE]) -> Vec<u8> {
    encode_fec_parity_k(&shards[..])
}

/// Parse a parity payload into `(k, shard_lengths, xor_bytes)`.
fn parse_fec_parity(p: &[u8]) -> Option<(usize, Vec<usize>, &[u8])> {
    let (k, rest) = if p.first() == Some(&FEC_V2_MARKER) {
        if p.len() < 2 {
            return None;
        }
        let k = p[1] as usize;
        if !(FEC_MIN_K..=FEC_MAX_K).contains(&k) {
            return None;
        }
        (k, &p[2..])
    } else {
        (FEC_GROUP_SIZE, p)
    };
    if rest.len() < k * 2 {
        return None;
    }
    let mut lens = Vec::with_capacity(k);
    for i in 0..k {
        let l = u16::from_be_bytes([rest[i * 2], rest[i * 2 + 1]]) as usize;
        if l > MAX_UDP_PAYLOAD + 16 {
            return None;
        }
        lens.push(l);
    }
    Some((k, lens, &rest[k * 2..]))
}

/// Recover the single missing shard of a group of any supported size `k`.
/// `present.len()` must equal the `k` announced by the parity payload.
pub fn recover_fec_shard_k(
    present: &[Option<&[u8]>],
    fec_payload: &[u8],
) -> Option<(usize, Vec<u8>)> {
    let (k, lens, parity) = parse_fec_parity(fec_payload)?;
    if present.len() != k {
        return None;
    }
    let mut missing_idx = None;
    for (idx, item) in present.iter().enumerate() {
        if item.is_none() {
            if missing_idx.is_some() {
                return None; // more than 1 lost in this group -> ARQ handles it
            }
            missing_idx = Some(idx);
        }
    }
    let m_idx = missing_idx?;
    let target_len = lens[m_idx];
    if parity.len() < target_len {
        return None;
    }
    let mut recovered = parity[..target_len].to_vec();
    for (idx, item) in present.iter().enumerate() {
        if idx == m_idx {
            continue;
        }
        let s = (*item)?;
        if s.len() != lens[idx] {
            return None;
        }
        for i in 0..target_len.min(s.len()) {
            recovered[i] ^= s[i];
        }
    }
    Some((m_idx, recovered))
}

/// Recover a single missing shard in a 4-packet FEC group (legacy fixed-size API).
pub fn recover_fec_shard(
    present: &[Option<&[u8]>; FEC_GROUP_SIZE],
    fec_payload: &[u8],
) -> Option<(usize, Vec<u8>)> {
    recover_fec_shard_k(&present[..], fec_payload)
}

/// Receiver-side FEC state. Works for any group size: data shards are kept in a small
/// sequence-indexed cache and a parity packet names its own `base_seq` and `k`.
struct FecReceiver {
    data: BTreeMap<u32, Vec<u8>>,
    parities: BTreeMap<u32, Vec<u8>>,
    done: BTreeSet<u32>,
}

impl FecReceiver {
    fn new() -> Self {
        Self {
            data: BTreeMap::new(),
            parities: BTreeMap::new(),
            done: BTreeSet::new(),
        }
    }

    fn prune(&mut self, min_seq: u32) {
        // Shards just below `min_seq` may still be needed as XOR partners of a missing one.
        let floor = min_seq.saturating_sub(FEC_MAX_K as u32);
        self.data.retain(|&s, _| s >= floor);
        self.parities.retain(|&b, _| b >= floor);
        self.done.retain(|&b| b >= floor);
        while self.data.len() > 512 {
            if let Some(&k) = self.data.keys().next() {
                self.data.remove(&k);
            }
        }
        while self.parities.len() > 64 {
            if let Some(&k) = self.parities.keys().next() {
                self.parities.remove(&k);
            }
        }
        while self.done.len() > 64 {
            if let Some(&k) = self.done.iter().next() {
                self.done.remove(&k);
            }
        }
    }

    fn record_data(&mut self, seq: u32, data: &[u8]) -> Option<(u32, Vec<u8>)> {
        if seq == 0 {
            return None;
        }
        self.data.insert(seq, data.to_vec());
        while self.data.len() > 512 {
            if let Some(&k) = self.data.keys().next() {
                self.data.remove(&k);
            }
        }
        // The group that could contain `seq` is the parity with the greatest base <= seq.
        let base = self.parities.range(..=seq).next_back().map(|(&b, _)| b)?;
        self.try_recover(base)
    }

    fn record_parity(&mut self, base_seq: u32, parity_payload: Vec<u8>) -> Option<(u32, Vec<u8>)> {
        if base_seq == 0 {
            return None;
        }
        self.parities.insert(base_seq, parity_payload);
        while self.parities.len() > 64 {
            if let Some(&k) = self.parities.keys().next() {
                self.parities.remove(&k);
            }
        }
        self.try_recover(base_seq)
    }

    fn try_recover(&mut self, base: u32) -> Option<(u32, Vec<u8>)> {
        if self.done.contains(&base) {
            return None;
        }
        let payload = self.parities.get(&base)?;
        let (k, _, _) = parse_fec_parity(payload)?;
        let refs: Vec<Option<&[u8]>> = (0..k as u32)
            .map(|i| self.data.get(&base.wrapping_add(i)).map(|v| v.as_slice()))
            .collect();
        let (m_idx, recovered) = recover_fec_shard_k(&refs, payload)?;
        let rec_seq = base.wrapping_add(m_idx as u32);
        self.data.insert(rec_seq, recovered.clone());
        self.done.insert(base);
        stats::UDP_FEC_RECOVERED.fetch_add(1, Relaxed);
        Some((rec_seq, recovered))
    }
}

struct InFlight {
    pkt: Packet,
    last_sent: Instant,
    retries: u32,
}

fn spawn_session_engine(
    session_id: u64,
    key: Vec<u8>,
    sock: Arc<UdpSocket>,
    initial_peer: SocketAddr,
    mut rx_net: mpsc::Receiver<(Packet, SocketAddr)>,
    on_close: Option<Box<dyn FnOnce() + Send>>,
) -> BoxRw {
    let (user, internal) = duplex(128 * 1024);
    let (mut app_r, mut app_w) = split(internal);

    stats::UDP_TRANSPORT_SESSIONS.fetch_add(1, Relaxed);

    tokio::spawn(async move {
        let mut peer = initial_peer;
        let mut next_seq: u32 = 1;
        let mut expected_rx_seq: u32 = 1;
        let mut inflight: BTreeMap<u32, InFlight> = BTreeMap::new();
        let mut reorder_buf: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        let fec_mode = FecMode::from_env();
        let mut fec_k: usize = fec_mode.initial_k();
        let mut loss_est = LossEstimator::new();
        let mut last_fec_eval = Instant::now();
        stats::UDP_FEC_GROUP_K.store(fec_k as u64, Relaxed);
        let mut fec_tx_group: Vec<(u32, Vec<u8>)> = Vec::with_capacity(FEC_MAX_K);
        let mut fec_rx = FecReceiver::new();
        let mut last_activity = Instant::now();
        let mut app_eof = false;
        let mut peer_fin = false;
        let mut srtt_ms: f64 = DEFAULT_RTO.as_millis() as f64;
        let mut rttvar_ms: f64 = 60.0;
        let mut rto_base = DEFAULT_RTO;
        let start = Instant::now();
        let mut tick = interval(RETX_INTERVAL);
        let mut read_buf = vec![0u8; MAX_UDP_PAYLOAD];

        let build_ack_bits = |exp: u32, rbuf: &BTreeMap<u32, Vec<u8>>| -> u32 {
            let mut bits = 0u32;
            for offset in 1..=32u32 {
                if rbuf.contains_key(&exp.wrapping_add(offset)) {
                    bits |= 1u32 << (offset - 1);
                }
            }
            bits
        };

        loop {
            if last_activity.elapsed() > IDLE_TIMEOUT {
                break;
            }
            if app_eof && peer_fin && inflight.is_empty() {
                break;
            }
            let can_read_app = !app_eof && inflight.len() < WINDOW_SIZE;

            tokio::select! {
                _ = tick.tick() => {
                    let now = Instant::now();
                    let mut dead = false;
                    for item in inflight.values_mut() {
                        let rto = rto_base * (1u32 << item.retries.min(3));
                        if now.saturating_duration_since(item.last_sent) >= rto {
                            if item.retries >= 12 {
                                dead = true;
                                break;
                            }
                            item.retries += 1;
                            item.last_sent = now;
                            item.pkt.ack = expected_rx_seq;
                            item.pkt.ack_bits = build_ack_bits(expected_rx_seq, &reorder_buf);
                            let wire = encode_packet(&key, &item.pkt);
                            let _ = sock.send_to(&wire, peer).await;
                            stats::UDP_RETRANSMITS.fetch_add(1, Relaxed);
                            loss_est.record_retx();
                        }
                    }
                    if dead {
                        break;
                    }
                    if last_fec_eval.elapsed() >= Duration::from_secs(1) {
                        last_fec_eval = Instant::now();
                        if let Some(loss) = loss_est.update() {
                            stats::UDP_LOSS_PER_MILLE.store((loss * 1000.0).round().clamp(0.0, 1000.0) as u64, Relaxed);
                            if fec_mode == FecMode::Auto {
                                let nk = auto_k_for_loss(loss);
                                if nk != fec_k {
                                    fec_k = nk;
                                    fec_tx_group.clear();
                                    stats::UDP_FEC_GROUP_K.store(nk as u64, Relaxed);
                                }
                            }
                        }
                    }
                }
                res = app_r.read(&mut read_buf), if can_read_app => {
                    match res {
                        Ok(0) => {
                            app_eof = true;
                            let seq = next_seq;
                            next_seq = next_seq.wrapping_add(1);
                            let pkt = Packet {
                                session_id,
                                flags: FLAG_FIN | FLAG_ACK,
                                seq,
                                ack: expected_rx_seq,
                                ack_bits: build_ack_bits(expected_rx_seq, &reorder_buf),
                                ts_ms: start.elapsed().as_millis() as u32,
                                payload: Vec::new(),
                            };
                            let wire = encode_packet(&key, &pkt);
                            let _ = sock.send_to(&wire, peer).await;
                            inflight.insert(seq, InFlight { pkt, last_sent: Instant::now(), retries: 0 });
                            last_activity = Instant::now();
                        }
                        Ok(n) => {
                            let seq = next_seq;
                            next_seq = next_seq.wrapping_add(1);
                            let chunk = read_buf[..n].to_vec();
                            let pkt = Packet {
                                session_id,
                                flags: FLAG_DATA | FLAG_ACK,
                                seq,
                                ack: expected_rx_seq,
                                ack_bits: build_ack_bits(expected_rx_seq, &reorder_buf),
                                ts_ms: start.elapsed().as_millis() as u32,
                                payload: chunk.clone(),
                            };
                            let wire = encode_packet(&key, &pkt);
                            let _ = sock.send_to(&wire, peer).await;
                            inflight.insert(seq, InFlight { pkt, last_sent: Instant::now(), retries: 0 });

                            loss_est.record_sent();

                            // Emit 1 XOR-parity FEC packet per `fec_k` consecutive data packets
                            if fec_k >= FEC_MIN_K {
                                if fec_tx_group.last().map_or(false, |(prev_s, _)| seq != prev_s.wrapping_add(1)) {
                                    fec_tx_group.clear();
                                }
                                fec_tx_group.push((seq, chunk));
                                if fec_tx_group.len() >= fec_k {
                                    let base_seq = fec_tx_group[0].0;
                                    let parity_payload = {
                                        let shards: Vec<&[u8]> =
                                            fec_tx_group.iter().map(|(_, d)| d.as_slice()).collect();
                                        encode_fec_parity_k(&shards)
                                    };
                                    let fec_pkt = Packet {
                                        session_id,
                                        flags: FLAG_FEC | FLAG_ACK,
                                        seq: base_seq,
                                        ack: expected_rx_seq,
                                        ack_bits: build_ack_bits(expected_rx_seq, &reorder_buf),
                                        ts_ms: start.elapsed().as_millis() as u32,
                                        payload: parity_payload,
                                    };
                                    let _ = sock.send_to(&encode_packet(&key, &fec_pkt), peer).await;
                                    fec_tx_group.clear();
                                }
                            }

                            last_activity = Instant::now();
                        }
                        Err(_) => break,
                    }
                }
                maybe = rx_net.recv() => {
                    let Some((pkt, src)) = maybe else { break };
                    peer = src; // Session-ID roaming support across NAT rebinding
                    last_activity = Instant::now();

                    // Process cumulative ACK + selective ACK bitmap (RFC 1982 serial arithmetic)
                    if pkt.flags & FLAG_ACK != 0 {
                        let ack_now = Instant::now();
                        for (&s, item) in &inflight {
                            if (s.wrapping_sub(pkt.ack) as i32) < 0 && item.retries == 0 {
                                let sample = ack_now.saturating_duration_since(item.last_sent).as_secs_f64() * 1000.0;
                                rttvar_ms = 0.75 * rttvar_ms + 0.25 * (srtt_ms - sample).abs();
                                srtt_ms = 0.875 * srtt_ms + 0.125 * sample;
                                let rto_ms = (srtt_ms + 4.0 * rttvar_ms).clamp(120.0, 2000.0) as u64;
                                rto_base = Duration::from_millis(rto_ms);
                            }
                        }
                        inflight.retain(|&s, _| (s.wrapping_sub(pkt.ack) as i32) >= 0);
                        for offset in 1..=32u32 {
                            if pkt.ack_bits & (1u32 << (offset - 1)) != 0 {
                                inflight.remove(&pkt.ack.wrapping_add(offset));
                            }
                        }
                    }

                    // Process incoming FEC parity packet (0-RTT lost-packet reconstruction)
                    if pkt.flags & FLAG_FEC != 0 && !pkt.payload.is_empty() {
                        if let Some((rec_seq, rec_data)) = fec_rx.record_parity(pkt.seq, pkt.payload.clone()) {
                            if rec_seq == expected_rx_seq {
                                if app_w.write_all(&rec_data).await.is_err() {
                                    break;
                                }
                                expected_rx_seq = expected_rx_seq.wrapping_add(1);
                                while let Some(next_data) = reorder_buf.remove(&expected_rx_seq) {
                                    if app_w.write_all(&next_data).await.is_err() {
                                        break;
                                    }
                                    expected_rx_seq = expected_rx_seq.wrapping_add(1);
                                }
                            } else if (rec_seq.wrapping_sub(expected_rx_seq) as i32) > 0 && reorder_buf.len() < WINDOW_SIZE * 2 {
                                reorder_buf.entry(rec_seq).or_insert(rec_data);
                            }
                            fec_rx.prune(expected_rx_seq);
                        }
                    }

                    // Process incoming DATA
                    if pkt.flags & FLAG_DATA != 0 && !pkt.payload.is_empty() {
                        let recovered_pair = fec_rx.record_data(pkt.seq, &pkt.payload);
                        if pkt.seq == expected_rx_seq {
                            if app_w.write_all(&pkt.payload).await.is_err() {
                                break;
                            }
                            expected_rx_seq = expected_rx_seq.wrapping_add(1);
                            while let Some(next_data) = reorder_buf.remove(&expected_rx_seq) {
                                if app_w.write_all(&next_data).await.is_err() {
                                    break;
                                }
                                expected_rx_seq = expected_rx_seq.wrapping_add(1);
                            }
                        } else if (pkt.seq.wrapping_sub(expected_rx_seq) as i32) > 0 && reorder_buf.len() < WINDOW_SIZE * 2 {
                            reorder_buf.entry(pkt.seq).or_insert(pkt.payload);
                        }

                        if let Some((rec_seq, rec_data)) = recovered_pair {
                            if rec_seq == expected_rx_seq {
                                if app_w.write_all(&rec_data).await.is_err() {
                                    break;
                                }
                                expected_rx_seq = expected_rx_seq.wrapping_add(1);
                                while let Some(next_data) = reorder_buf.remove(&expected_rx_seq) {
                                    if app_w.write_all(&next_data).await.is_err() {
                                        break;
                                    }
                                    expected_rx_seq = expected_rx_seq.wrapping_add(1);
                                }
                            } else if (rec_seq.wrapping_sub(expected_rx_seq) as i32) > 0 && reorder_buf.len() < WINDOW_SIZE * 2 {
                                reorder_buf.entry(rec_seq).or_insert(rec_data);
                            }
                        }
                        fec_rx.prune(expected_rx_seq);

                        // Send immediate ACK
                        let ack_pkt = Packet {
                            session_id,
                            flags: FLAG_ACK,
                            seq: 0,
                            ack: expected_rx_seq,
                            ack_bits: build_ack_bits(expected_rx_seq, &reorder_buf),
                            ts_ms: start.elapsed().as_millis() as u32,
                            payload: Vec::new(),
                        };
                        let _ = sock.send_to(&encode_packet(&key, &ack_pkt), peer).await;
                    }

                    // Process FIN
                    if pkt.flags & FLAG_FIN != 0 {
                        if pkt.seq == expected_rx_seq {
                            expected_rx_seq = expected_rx_seq.wrapping_add(1);
                        }
                        peer_fin = true;
                        let _ = app_w.shutdown().await;
                        let ack_pkt = Packet {
                            session_id,
                            flags: FLAG_ACK,
                            seq: 0,
                            ack: expected_rx_seq,
                            ack_bits: 0,
                            ts_ms: start.elapsed().as_millis() as u32,
                            payload: Vec::new(),
                        };
                        let _ = sock.send_to(&encode_packet(&key, &ack_pkt), peer).await;
                    }
                }
            }
        }

        let _ = app_w.shutdown().await;
        stats::UDP_TRANSPORT_SESSIONS.fetch_sub(1, Relaxed);
        if let Some(cb) = on_close {
            cb();
        }
    });

    Box::new(user)
}

/// Dial an authenticated reliable UDP carrier to `addr` (e.g. `1.2.3.4:443`).
pub async fn connect(addr: &str, key: &[u8], connect_timeout: Duration) -> Result<BoxRw> {
    let target: SocketAddr = tokio::net::lookup_host(addr)
        .await?
        .next()
        .context("UDP transport: DNS lookup returned no address")?;
    let bind_addr = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = Arc::new(UdpSocket::bind(bind_addr).await?);
    let session_id = u64::from_be_bytes(rand_bytes::<8>());
    let key_vec = key.to_vec();

    // Handshake: send authenticated SYN until SYN+ACK arrives
    let syn = Packet {
        session_id,
        flags: FLAG_SYN,
        seq: 0,
        ack: 0,
        ack_bits: 0,
        ts_ms: 0,
        payload: Vec::new(),
    };
    let syn_wire = encode_packet(&key_vec, &syn);
    let mut buf = vec![0u8; 2048];
    let peer = timeout(connect_timeout, async {
        for _ in 0..8 {
            sock.send_to(&syn_wire, target).await?;
            match timeout(Duration::from_millis(400), sock.recv_from(&mut buf)).await {
                Ok(Ok((n, src))) => {
                    if let Some(p) = decode_packet(&key_vec, &buf[..n]) {
                        if p.session_id == session_id && (p.flags & (FLAG_SYN | FLAG_ACK) == (FLAG_SYN | FLAG_ACK)) {
                            return Ok::<SocketAddr, anyhow::Error>(src);
                        }
                    }
                }
                _ => continue,
            }
        }
        bail!("UDP carrier handshake timeout")
    })
    .await??;

    let (tx_net, rx_net) = mpsc::channel::<(Packet, SocketAddr)>(128);
    let (closed_tx, mut closed_rx) = watch::channel(false);
    let sock_rx = sock.clone();
    let key_rx = key_vec.clone();
    tokio::spawn(async move {
        let mut rbuf = vec![0u8; 2048];
        loop {
            tokio::select! {
                _ = async {
                    while !*closed_rx.borrow() {
                        if closed_rx.changed().await.is_err() {
                            return;
                        }
                    }
                } => break,
                res = sock_rx.recv_from(&mut rbuf) => {
                    let Ok((n, src)) = res else { break };
                    if let Some(p) = decode_packet(&key_rx, &rbuf[..n]) {
                        if p.session_id == session_id {
                            if tx_net.send((p, src)).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    });

    Ok(spawn_session_engine(
        session_id,
        key_vec,
        sock,
        peer,
        rx_net,
        Some(Box::new(move || {
            let _ = closed_tx.send(true);
        })),
    ))
}

/// Server-side UDP carrier listener: demultiplexes authenticated sessions by `session_id`
/// and yields each accepted session as `(BoxRw, SocketAddr)`.
pub struct UdpCarrierListener {
    rx_accepted: mpsc::Receiver<(BoxRw, SocketAddr)>,
}

impl UdpCarrierListener {
    pub async fn bind(listen_addr: &str, key: Vec<u8>) -> Result<Self> {
        let sock = Arc::new(UdpSocket::bind(listen_addr).await?);
        let (tx_acc, rx_acc) = mpsc::channel::<(BoxRw, SocketAddr)>(64);
        let sessions: Arc<StdMutex<HashMap<u64, (IpAddr, mpsc::Sender<(Packet, SocketAddr)>)>>> =
            Arc::new(StdMutex::new(HashMap::new()));

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, src)) = sock.recv_from(&mut buf).await {
                let Some(pkt) = decode_packet(&key, &buf[..n]) else {
                    continue;
                };
                let existing = sessions.lock().unwrap().get(&pkt.session_id).map(|(_, s)| s.clone());
                if let Some(s_tx) = existing {
                    if pkt.flags & FLAG_SYN != 0 {
                        let syn_ack = Packet {
                            session_id: pkt.session_id,
                            flags: FLAG_SYN | FLAG_ACK,
                            seq: 0,
                            ack: 1,
                            ack_bits: 0,
                            ts_ms: pkt.ts_ms,
                            payload: Vec::new(),
                        };
                        let _ = sock.send_to(&encode_packet(&key, &syn_ack), src).await;
                    } else {
                        let _ = s_tx.try_send((pkt, src));
                    }
                    continue;
                }
                if pkt.flags & FLAG_SYN == 0 {
                    continue;
                }
                {
                    let guard = sessions.lock().unwrap();
                    if guard.len() >= 1024 {
                        continue;
                    }
                    let per_ip = guard.values().filter(|(ip, _)| *ip == src.ip()).count();
                    if per_ip >= MAX_UDP_SESSIONS_PER_IP {
                        continue;
                    }
                }
                let syn_ack = Packet {
                    session_id: pkt.session_id,
                    flags: FLAG_SYN | FLAG_ACK,
                    seq: 0,
                    ack: 1,
                    ack_bits: 0,
                    ts_ms: pkt.ts_ms,
                    payload: Vec::new(),
                };
                if sock.send_to(&encode_packet(&key, &syn_ack), src).await.is_err() {
                    continue;
                }
                let (s_tx, s_rx) = mpsc::channel::<(Packet, SocketAddr)>(128);
                let sid = pkt.session_id;
                sessions.lock().unwrap().insert(sid, (src.ip(), s_tx));
                let sessions_rm = sessions.clone();
                let stream = spawn_session_engine(
                    sid,
                    key.clone(),
                    sock.clone(),
                    src,
                    s_rx,
                    Some(Box::new(move || {
                        sessions_rm.lock().unwrap().remove(&sid);
                    })),
                );
                if tx_acc.send((stream, src)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Self { rx_accepted: rx_acc })
    }

    pub async fn accept(&mut self) -> Option<(BoxRw, SocketAddr)> {
        self.rx_accepted.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_fec_parity_recovers_any_missing_shard_in_group() {
        let s0 = b"packet-zero-alpha";
        let s1 = b"packet-one-bravo-longer";
        let s2 = b"pkt-2";
        let s3 = b"packet-three-delta-12345";
        let parity = encode_fec_parity(&[s0, s1, s2, s3]);

        // Drop packet #1 -> recovers exact bytes of s1
        let (idx, rec) = recover_fec_shard(&[Some(s0), None, Some(s2), Some(s3)], &parity).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(rec, s1);

        // Drop 2 packets -> returns None (defers to Selective-Repeat ARQ)
        assert!(recover_fec_shard(&[Some(s0), None, None, Some(s3)], &parity).is_none());
    }

    #[tokio::test]
    async fn udp_carrier_reliable_128k_roundtrip() {
        let key = b"khaymali-udp-test-secret-key-32b".to_vec();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let mut listener = UdpCarrierListener::bind(&addr.to_string(), key.clone()).await.unwrap();
        let srv = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.unwrap();
            s.write_all(&got[..64]).await.unwrap();
            s.shutdown().await.unwrap();
            got
        });

        let mut cli = connect(&addr.to_string(), &key, Duration::from_secs(3)).await.unwrap();
        let payload: Vec<u8> = (0..131_072u32).map(|i| (i % 251) as u8).collect();
        cli.write_all(&payload).await.unwrap();
        cli.shutdown().await.unwrap();
        let mut ack = vec![0u8; 64];
        cli.read_exact(&mut ack).await.unwrap();
        let got = srv.await.unwrap();
        assert_eq!(got, payload);
        assert_eq!(ack, payload[..64]);
    }
}

#[cfg(test)]
mod fec_v2_tests {
    use super::*;

    fn shards(k: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|i| (0..(20 + i * 7)).map(|j| (i * 31 + j) as u8).collect())
            .collect()
    }

    #[test]
    fn variable_group_size_roundtrip_for_every_k() {
        for k in FEC_MIN_K..=FEC_MAX_K {
            let sh = shards(k);
            let refs: Vec<&[u8]> = sh.iter().map(|v| v.as_slice()).collect();
            let parity = encode_fec_parity_k(&refs);
            for miss in 0..k {
                let present: Vec<Option<&[u8]>> = (0..k)
                    .map(|i| if i == miss { None } else { Some(sh[i].as_slice()) })
                    .collect();
                let (idx, rec) = recover_fec_shard_k(&present, &parity).unwrap();
                assert_eq!(idx, miss);
                assert_eq!(rec, sh[miss]);
            }
        }
    }

    #[test]
    fn k4_uses_legacy_wire_format() {
        let sh = shards(4);
        let refs: Vec<&[u8]> = sh.iter().map(|v| v.as_slice()).collect();
        let parity = encode_fec_parity_k(&refs);
        assert_ne!(parity[0], FEC_V2_MARKER);
        assert_eq!(parity.len(), 8 + sh.iter().map(|s| s.len()).max().unwrap());
    }

    #[test]
    fn two_losses_or_wrong_k_are_rejected() {
        let sh = shards(8);
        let refs: Vec<&[u8]> = sh.iter().map(|v| v.as_slice()).collect();
        let parity = encode_fec_parity_k(&refs);
        let mut present: Vec<Option<&[u8]>> = sh.iter().map(|v| Some(v.as_slice())).collect();
        present[1] = None;
        present[5] = None;
        assert!(recover_fec_shard_k(&present, &parity).is_none());
        let short: Vec<Option<&[u8]>> = present[..4].to_vec();
        assert!(recover_fec_shard_k(&short, &parity).is_none());
    }

    #[test]
    fn receiver_recovers_regardless_of_arrival_order() {
        for k in [2usize, 3, 4, 8] {
            let sh = shards(k);
            let refs: Vec<&[u8]> = sh.iter().map(|v| v.as_slice()).collect();
            let parity = encode_fec_parity_k(&refs);
            let base = 100u32;

            // parity first, then data (one shard never arrives)
            let mut rx = FecReceiver::new();
            assert!(rx.record_parity(base, parity.clone()).is_none());
            let lost = k - 1;
            let mut got = None;
            for i in 0..k {
                if i == lost {
                    continue;
                }
                if let Some(r) = rx.record_data(base + i as u32, &sh[i]) {
                    got = Some(r);
                }
            }
            let (seq, data) = got.expect("recovered after last data shard");
            assert_eq!(seq, base + lost as u32);
            assert_eq!(data, sh[lost]);

            // data first, parity last
            let mut rx = FecReceiver::new();
            for i in 1..k {
                assert!(rx.record_data(base + i as u32, &sh[i]).is_none());
            }
            let (seq, data) = rx.record_parity(base, parity).unwrap();
            assert_eq!(seq, base);
            assert_eq!(data, sh[0]);
        }
    }

    #[test]
    fn mode_parsing_and_auto_levels() {
        assert_eq!(FecMode::parse("OFF"), Some(FecMode::Off));
        assert_eq!(FecMode::parse("auto"), Some(FecMode::Auto));
        assert_eq!(FecMode::parse("nope"), None);
        assert_eq!(FecMode::Off.initial_k(), 0);
        assert_eq!(FecMode::Moderate.initial_k(), FEC_GROUP_SIZE);
        let levels: Vec<usize> = [0.0, 0.02, 0.06, 0.3].iter().map(|&l| auto_k_for_loss(l)).collect();
        assert_eq!(levels, vec![8, 4, 3, 2]);
    }

    #[test]
    fn loss_estimator_needs_enough_samples() {
        let mut e = LossEstimator::new();
        for _ in 0..10 {
            e.record_sent();
        }
        assert!(e.update().is_none());
        for _ in 0..30 {
            e.record_sent();
        }
        for _ in 0..8 {
            e.record_retx();
        }
        let l = e.update().unwrap();
        assert!(l > 0.05 && l < 0.2, "ewma {l}");
    }
}
