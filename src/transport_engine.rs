//! Modular Transport Engine, Reproducible Benchmark & Carrier Extensions (`src/transport_engine.rs`).
//!
//! Implements:
//!   * `TransportRegistry`: dynamic registration & capability metadata for `tcp`, `tcp+camo`,
//!     `udp+arq`, `quic-stream`, `kcp-fec`, and `ws-h2`.
//!   * `TransportBenchmark` & `BenchmarkSample`: repeatable measurement of `rtt_ms`, `jitter_ms`,
//!     `loss_per_mille`, and `goodput_kbps`.
//!   * `HysteresisSelector`: multi-metric path scoring with hysteresis margin (`15%`) and cooldowns.
//!   * Wire framers for `QuicStreamFramer` (RFC 9000 stream framing + connection ID),
//!     `KcpFecCarrier` (XOR parity FEC shard recovery), and `WsH2Framer` (WS/HTTP2 framing).

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CarrierKind {
    Tcp,
    TcpCamo,
    UdpArq,
    QuicStream,
    KcpFec,
    WsH2,
    WssCamo,
    Ktunnel,
    SshBagher,
    SpoofWg,
    Gre6to4,
    Gre4in6,
}

impl CarrierKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CarrierKind::Tcp => "tcp",
            CarrierKind::TcpCamo => "tcp+camo",
            CarrierKind::UdpArq => "udp+arq",
            CarrierKind::QuicStream => "quic-stream",
            CarrierKind::KcpFec => "kcp-fec",
            CarrierKind::WsH2 => "ws-h2",
            CarrierKind::WssCamo => "wss",
            CarrierKind::Ktunnel => "ktunnel",
            CarrierKind::SshBagher => "ssh-bagher",
            CarrierKind::SpoofWg => "spoof-wg",
            CarrierKind::Gre6to4 => "gre-6to4",
            CarrierKind::Gre4in6 => "gre-4in6",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tcp" => Some(CarrierKind::Tcp),
            "tcp+camo" | "camo" => Some(CarrierKind::TcpCamo),
            "udp+arq" | "udp" => Some(CarrierKind::UdpArq),
            "quic-stream" | "quic" => Some(CarrierKind::QuicStream),
            "kcp-fec" | "kcp" => Some(CarrierKind::KcpFec),
            "ws-h2" | "ws" | "h2" => Some(CarrierKind::WsH2),
            "wss" | "wss+camo" => Some(CarrierKind::WssCamo),
            "ktunnel" | "k_tcpmux" => Some(CarrierKind::Ktunnel),
            "ssh" | "ssh-bagher" | "bagher" => Some(CarrierKind::SshBagher),
            "spoof" | "spoof-wg" => Some(CarrierKind::SpoofWg),
            "6to4" | "gre-6to4" => Some(CarrierKind::Gre6to4),
            "4in6" | "gre-4in6" => Some(CarrierKind::Gre4in6),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CarrierDescriptor {
    pub kind: CarrierKind,
    pub supports_multiplex: bool,
    pub supports_migration: bool,
    pub supports_fec: bool,
    pub max_payload_bytes: usize,
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct BenchmarkSample {
    pub rtt_ms: f64,
    pub jitter_ms: f64,
    pub loss_per_mille: u16,
    pub goodput_kbps: f64,
    pub timestamp_secs: u64,
}

impl BenchmarkSample {
    /// Composite path quality score (higher is better).
    pub fn quality_score(&self) -> f64 {
        let gp_term = (self.goodput_kbps / 1000.0).min(200.0) * 1.5;
        let rtt_penalty = self.rtt_ms * 0.45;
        let jitter_penalty = self.jitter_ms * 0.8;
        let loss_penalty = (self.loss_per_mille as f64) * 2.5;
        (100.0 + gp_term - rtt_penalty - jitter_penalty - loss_penalty).max(0.0)
    }
}

/// Active-probe evaluator computing RTT, Jitter (RFC 3550), Loss per-mille, and Goodput.
pub struct TransportBenchmark;

impl TransportBenchmark {
    pub fn evaluate_rtts_and_bytes(
        rtts: &[Duration],
        sent_probes: u32,
        bytes_transferred: u64,
        elapsed: Duration,
        now_secs: u64,
    ) -> BenchmarkSample {
        let recv_probes = rtts.len() as u32;
        let loss_per_mille = if sent_probes == 0 {
            0
        } else {
            let lost = sent_probes.saturating_sub(recv_probes);
            ((lost as u64 * 1000) / sent_probes as u64).min(1000) as u16
        };
        let mut rtt_ms = 0.0;
        let mut jitter_ms = 0.0;
        let mut prev_ms: Option<f64> = None;
        for d in rtts {
            let ms = d.as_secs_f64() * 1000.0;
            rtt_ms += ms;
            if let Some(p) = prev_ms {
                jitter_ms += (ms - p).abs();
            }
            prev_ms = Some(ms);
        }
        if !rtts.is_empty() {
            rtt_ms /= rtts.len() as f64;
        }
        if rtts.len() > 1 {
            jitter_ms /= (rtts.len() - 1) as f64;
        }
        let secs = elapsed.as_secs_f64().max(0.001);
        let goodput_kbps = (bytes_transferred as f64 * 8.0) / (secs * 1000.0);
        BenchmarkSample {
            rtt_ms,
            jitter_ms,
            loss_per_mille,
            goodput_kbps,
            timestamp_secs: now_secs,
        }
    }
}

/// Registry storing available carriers, latest benchmark results, and hysteresis path selector.
pub struct TransportRegistry {
    descriptors: Mutex<HashMap<CarrierKind, CarrierDescriptor>>,
    results: Mutex<HashMap<CarrierKind, BenchmarkSample>>,
    selected: Mutex<Option<(CarrierKind, Instant)>>,
    hysteresis_margin: f64,
    cooldown: Duration,
}

impl Default for TransportRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportRegistry {
    pub fn new() -> Self {
        let mut map = HashMap::new();
        for (kind, mux, mig, fec, mtu) in [
            (CarrierKind::Tcp, true, false, false, 14336),
            (CarrierKind::TcpCamo, true, false, false, 14336),
            (CarrierKind::UdpArq, true, true, false, 1180),
            (CarrierKind::QuicStream, true, true, false, 1200),
            (CarrierKind::KcpFec, true, true, true, 1200),
            (CarrierKind::WsH2, true, false, false, 14000),
            (CarrierKind::WssCamo, true, false, false, 1360),
            (CarrierKind::Ktunnel, true, true, false, 14336),
            (CarrierKind::SshBagher, true, false, false, 14336),
            (CarrierKind::SpoofWg, false, false, false, 1280),
            (CarrierKind::Gre6to4, false, false, false, 1380),
            (CarrierKind::Gre4in6, false, false, false, 1380),
        ] {
            map.insert(
                kind,
                CarrierDescriptor {
                    kind,
                    supports_multiplex: mux,
                    supports_migration: mig,
                    supports_fec: fec,
                    max_payload_bytes: mtu,
                    enabled: true,
                },
            );
        }
        Self {
            descriptors: Mutex::new(map),
            results: Mutex::new(HashMap::new()),
            selected: Mutex::new(None),
            hysteresis_margin: 0.15,
            cooldown: Duration::from_secs(15),
        }
    }

    pub fn list_descriptors(&self) -> Vec<CarrierDescriptor> {
        let mut v: Vec<_> = self.descriptors.lock().unwrap().values().cloned().collect();
        v.sort_by_key(|d| d.kind.as_str());
        v
    }

    pub fn record_benchmark(&self, kind: CarrierKind, sample: BenchmarkSample) {
        self.results.lock().unwrap().insert(kind, sample);
    }

    pub fn get_benchmark(&self, kind: CarrierKind) -> Option<BenchmarkSample> {
        self.results.lock().unwrap().get(&kind).copied()
    }

    /// Select best carrier using hysteresis margin (15%) and cooldown to prevent flapping.
    pub fn select_best(&self, now: Instant) -> CarrierKind {
        let descs = self.descriptors.lock().unwrap();
        let results = self.results.lock().unwrap();

        let mut best: Option<(CarrierKind, f64)> = None;
        for (k, d) in descs.iter() {
            if !d.enabled {
                continue;
            }
            let score = results
                .get(k)
                .map(|s| s.quality_score())
                .unwrap_or(if *k == CarrierKind::TcpCamo { 95.0 } else { 90.0 });
            if best.map_or(true, |(_, bs)| score > bs) {
                best = Some((*k, score));
            }
        }
        let (cand_kind, cand_score) = best.unwrap_or((CarrierKind::Tcp, 50.0));
        let mut sel = self.selected.lock().unwrap();
        if let Some((cur_kind, since)) = *sel {
            if cur_kind == cand_kind {
                return cur_kind;
            }
            if descs.get(&cur_kind).is_some_and(|d| d.enabled) {
                let cur_score = results.get(&cur_kind).map(|s| s.quality_score()).unwrap_or(90.0);
                if now.saturating_duration_since(since) < self.cooldown
                    || cand_score <= cur_score * (1.0 + self.hysteresis_margin)
                {
                    return cur_kind;
                }
            }
        }
        *sel = Some((cand_kind, now));
        cand_kind
    }
}

/// QUIC-style Stream Framer with 64-bit Connection ID & RFC 9000 STREAM frame header.
pub struct QuicStreamFramer;

impl QuicStreamFramer {
    pub fn encode_stream_frame(conn_id: u64, stream_id: u64, offset: u64, fin: bool, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(27 + data.len());
        let frame_type = 0x0e | u8::from(fin); // STREAM + OFF + LEN + optional FIN
        out.push(frame_type);
        out.extend_from_slice(&conn_id.to_be_bytes());
        out.extend_from_slice(&stream_id.to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    pub fn decode_stream_frame(buf: &[u8]) -> Result<(u64, u64, u64, bool, &[u8])> {
        if buf.len() < 27 || (buf[0] & 0xfe) != 0x0e {
            bail!("invalid QUIC stream frame header");
        }
        let fin = (buf[0] & 0x01) != 0;
        let conn_id = u64::from_be_bytes(buf[1..9].try_into()?);
        let stream_id = u64::from_be_bytes(buf[9..17].try_into()?);
        let offset = u64::from_be_bytes(buf[17..25].try_into()?);
        let len = u16::from_be_bytes(buf[25..27].try_into()?) as usize;
        if buf.len() != 27 + len {
            bail!("QUIC stream frame length mismatch");
        }
        Ok((conn_id, stream_id, offset, fin, &buf[27..]))
    }
}

/// KCP + XOR-Parity FEC shard helper: recovers any 1 lost shard per group of N data shards.
pub struct KcpFecCarrier;

impl KcpFecCarrier {
    pub fn build_parity_shard(shards: &[&[u8]]) -> Vec<u8> {
        let max_len = shards.iter().map(|s| s.len()).max().unwrap_or(0);
        let mut parity = vec![0u8; max_len];
        for s in shards {
            for (i, &b) in s.iter().enumerate() {
                parity[i] ^= b;
            }
        }
        parity
    }

    pub fn recover_missing_shard(present_shards: &[&[u8]], parity: &[u8], expected_len: usize) -> Result<Vec<u8>> {
        if parity.len() < expected_len {
            bail!("parity shard shorter than expected shard length");
        }
        let mut recovered = parity[..expected_len].to_vec();
        for s in present_shards {
            for i in 0..expected_len.min(s.len()) {
                recovered[i] ^= s[i];
            }
        }
        Ok(recovered)
    }
}

/// WebSocket (RFC 6455 binary frame) / HTTP/2 DATA frame wrapper for CDN/edge traversal.
pub struct WsH2Framer;

impl WsH2Framer {
    pub fn encode_ws_binary(payload: &[u8], mask_key: Option<[u8; 4]>) -> Result<Vec<u8>> {
        if payload.len() > u16::MAX as usize {
            bail!("WS frame exceeds 65535 bytes");
        }
        let mask_bit = if mask_key.is_some() { 0x80 } else { 0x00 };
        let mut out = Vec::with_capacity(8 + payload.len());
        out.push(0x82); // FIN + Binary opcode
        out.push(mask_bit | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        if let Some(m) = mask_key {
            out.extend_from_slice(&m);
            for (i, &b) in payload.iter().enumerate() {
                out.push(b ^ m[i % 4]);
            }
        } else {
            out.extend_from_slice(payload);
        }
        Ok(out)
    }

    pub fn decode_ws_binary(buf: &[u8]) -> Result<Vec<u8>> {
        if buf.len() < 4 || buf[0] != 0x82 || (buf[1] & 0x7f) != 126 {
            bail!("unsupported WS frame format");
        }
        let masked = (buf[1] & 0x80) != 0;
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let hdr_len = if masked { 8 } else { 4 };
        if buf.len() != hdr_len + len {
            bail!("WS frame length mismatch");
        }
        if masked {
            let m = [buf[4], buf[5], buf[6], buf[7]];
            Ok(buf[8..]
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ m[i % 4])
                .collect())
        } else {
            Ok(buf[4..].to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_and_hysteresis_selector_prevent_flapping() {
        let reg = TransportRegistry::new();
        let t0 = Instant::now();

        let s_camo = TransportBenchmark::evaluate_rtts_and_bytes(
            &[Duration::from_millis(40), Duration::from_millis(42)],
            2,
            2_000_000,
            Duration::from_secs(1),
            100,
        );
        reg.record_benchmark(CarrierKind::TcpCamo, s_camo);
        assert_eq!(reg.select_best(t0), CarrierKind::TcpCamo);

        // Slightly better score within cooldown/hysteresis must NOT flap
        let s_udp_marginal = TransportBenchmark::evaluate_rtts_and_bytes(
            &[Duration::from_millis(38), Duration::from_millis(38)],
            2,
            2_050_000,
            Duration::from_secs(1),
            105,
        );
        reg.record_benchmark(CarrierKind::UdpArq, s_udp_marginal);
        assert_eq!(reg.select_best(t0 + Duration::from_secs(5)), CarrierKind::TcpCamo);

        // Much better score after cooldown switches cleanly
        let s_udp_strong = TransportBenchmark::evaluate_rtts_and_bytes(
            &[Duration::from_millis(20), Duration::from_millis(20)],
            2,
            25_000_000,
            Duration::from_secs(1),
            125,
        );
        reg.record_benchmark(CarrierKind::UdpArq, s_udp_strong);
        assert_eq!(reg.select_best(t0 + Duration::from_secs(20)), CarrierKind::UdpArq);
    }

    #[test]
    fn quic_kcp_fec_and_ws_framers_roundtrip() {
        let qf = QuicStreamFramer::encode_stream_frame(0x11223344, 4, 1024, true, b"quic-data");
        let (cid, sid, off, fin, data) = QuicStreamFramer::decode_stream_frame(&qf).unwrap();
        assert_eq!((cid, sid, off, fin, data), (0x11223344, 4, 1024, true, &b"quic-data"[..]));

        let s1 = b"shard-one-1234";
        let s2 = b"shard-two-5678";
        let s3 = b"shard-tre-9012";
        let parity = KcpFecCarrier::build_parity_shard(&[s1, s2, s3]);
        let rec = KcpFecCarrier::recover_missing_shard(&[s1, s3], &parity, s2.len()).unwrap();
        assert_eq!(rec, s2);

        let ws = WsH2Framer::encode_ws_binary(b"hello-ws-h2", Some([0xaa, 0xbb, 0xcc, 0xdd])).unwrap();
        assert_eq!(WsH2Framer::decode_ws_binary(&ws).unwrap(), b"hello-ws-h2");
    }
}
