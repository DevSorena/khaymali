//! TLS 1.3 camouflage ("camo") delegating unauthenticated traffic to `crate::fallback`.
//!
//! DPI-hardening features:
//!   * Valid X25519 ephemeral public keys in `key_share` (generated via Curve25519 in `snow`).
//!   * Chrome-like extension permutation, ALPS (`0x4469`), and `padding` (`0x0015`) placed before
//!     the trailing GREASE extension.
//!   * Deterministic Certificate record size per `--camo-sni` (derived from `Sha256(sni)`) plus
//!     exact 53-byte TLS 1.3 `Finished` records on both server and client flights.
//!   * Lossless partial-read fallback handoff and explicit Clock Skew diagnostics (`CLOCK_SKEW_DROPPED`).
//!   * Hard-capped fail-closed Replay cache (4096 entries).

use crate::fallback::{mirror_bidirectional, FallbackLimiter};
use crate::shaper::TrafficShaper;
use crate::link;
use crate::stats;
use crate::util::*;
use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

#[derive(Clone)]
pub struct CamoCfg {
    pub secret: Vec<u8>,
    pub sni: String,
    pub fallback: Option<String>,
    pub pad_max: usize,
}

const MAX_SKEW_SECS: u64 = 120;
const FLIGHT_APPDATA: usize = 3;
const TLS13_FINISHED_LEN: usize = 53;
const CCS: [u8; 6] = [0x14, 3, 3, 0, 1, 1];
const MAX_REC: usize = 16640 + 256;
/// Aligned above `2 + link::CHUNK + 16 = 14354` so a full Noise frame never splits across Camo records.
const DATA_CHUNK: usize = 15360;

#[derive(Debug, PartialEq, Eq)]
enum AuthCheck {
    Ok,
    ClockSkew(u64),
    Invalid,
}

fn mac(secret: &[u8], label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("hmac accepts any key length");
    m.update(label);
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn make_auth(secret: &[u8], ts: u64) -> ([u8; 32], [u8; 32]) {
    let nonce: [u8; 16] = rand_bytes();
    let tsb = ts.to_be_bytes();
    let tag = mac(secret, b"auth", &[&nonce, &tsb]);
    let mask = mac(secret, b"ts", &[&nonce]);
    let mut random = [0u8; 32];
    random[..16].copy_from_slice(&nonce);
    random[16..].copy_from_slice(&tag[..16]);
    let mut sid: [u8; 32] = rand_bytes();
    for i in 0..8 {
        sid[i] = tsb[i] ^ mask[i];
    }
    (random, sid)
}

fn check_auth(secret: &[u8], random: &[u8; 32], sid: &[u8; 32], now: u64) -> AuthCheck {
    let nonce = &random[..16];
    let mask = mac(secret, b"ts", &[nonce]);
    let mut tsb = [0u8; 8];
    for i in 0..8 {
        tsb[i] = sid[i] ^ mask[i];
    }
    let tag = mac(secret, b"auth", &[nonce, &tsb]);
    if !ct_eq(&random[16..], &tag[..16]) {
        return AuthCheck::Invalid;
    }
    let ts = u64::from_be_bytes(tsb);
    let diff = ts.abs_diff(now);
    if diff > MAX_SKEW_SECS {
        return AuthCheck::ClockSkew(diff);
    }
    AuthCheck::Ok
}

fn ephemeral_x25519_pub() -> [u8; 32] {
    if let Ok((_, pk)) = link::keygen() {
        if let Ok(arr) = <[u8; 32]>::try_from(pk.as_slice()) {
            return arr;
        }
    }
    rand_bytes::<32>()
}

fn put_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn put_u24(v: &mut Vec<u8>, x: usize) {
    v.extend_from_slice(&(x as u32).to_be_bytes()[1..]);
}

fn ext(v: &mut Vec<u8>, ty: u16, body: &[u8]) {
    put_u16(v, ty);
    put_u16(v, body.len() as u16);
    v.extend_from_slice(body);
}

fn grease() -> u16 {
    let n = (rand_bytes::<1>()[0] >> 4) as u16;
    let b = (n << 4) | 0x0a;
    (b << 8) | b
}

fn shuffle_exts(exts: &mut [(u16, Vec<u8>)]) {
    let len = exts.len();
    for i in (1..len).rev() {
        let j = rand_range(0, i);
        exts.swap(i, j);
    }
}

pub fn build_client_hello(cfg: &CamoCfg, ts: u64) -> Vec<u8> {
    let (random, sid) = make_auth(&cfg.secret, ts);
    let key_share = ephemeral_x25519_pub();
    let g0 = grease();
    let g_last = if g0 == 0xfafa { 0x0a0a } else { g0 + 0x1010 };
    let (g_cs, g_grp, g_ver) = (grease(), grease(), grease());
    let g_ks = g_grp;

    let mut exts: Vec<(u16, Vec<u8>)> = Vec::with_capacity(16);

    // 0x0000 server_name
    let host = cfg.sni.as_bytes();
    let mut sn = Vec::with_capacity(host.len() + 5);
    put_u16(&mut sn, (host.len() + 3) as u16);
    sn.push(0);
    put_u16(&mut sn, host.len() as u16);
    sn.extend_from_slice(host);
    exts.push((0x0000, sn));

    exts.push((0x0017, Vec::new())); // extended_master_secret
    exts.push((0xff01, vec![0]));    // renegotiation_info

    let mut sg = Vec::with_capacity(10);
    put_u16(&mut sg, 8);
    for g in [g_grp, 0x001d, 0x0017, 0x0018] {
        put_u16(&mut sg, g);
    }
    exts.push((0x000a, sg)); // supported_groups
    exts.push((0x000b, vec![1, 0])); // ec_point_formats
    exts.push((0x0023, Vec::new())); // session_ticket

    let mut alpn = Vec::new();
    for p in [&b"h2"[..], &b"http/1.1"[..]] {
        alpn.push(p.len() as u8);
        alpn.extend_from_slice(p);
    }
    let mut al = Vec::with_capacity(2 + alpn.len());
    put_u16(&mut al, alpn.len() as u16);
    al.extend_from_slice(&alpn);
    exts.push((0x0010, al)); // ALPN

    exts.push((0x0005, vec![1, 0, 0, 0, 0])); // status_request

    let mut sa = Vec::with_capacity(18);
    put_u16(&mut sa, 16);
    for a in [0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601] {
        put_u16(&mut sa, a);
    }
    exts.push((0x000d, sa)); // signature_algorithms
    exts.push((0x0012, Vec::new())); // signed_certificate_timestamp

    let mut ks = Vec::with_capacity(43);
    put_u16(&mut ks, 41);
    put_u16(&mut ks, g_ks);
    put_u16(&mut ks, 1);
    ks.push(0);
    put_u16(&mut ks, 0x001d);
    put_u16(&mut ks, 32);
    ks.extend_from_slice(&key_share);
    exts.push((0x0033, ks)); // key_share (valid X25519 pubkey)

    exts.push((0x002d, vec![1, 1])); // psk_key_exchange_modes

    let mut sv = vec![6];
    put_u16(&mut sv, g_ver);
    put_u16(&mut sv, 0x0304);
    put_u16(&mut sv, 0x0303);
    exts.push((0x002b, sv)); // supported_versions

    exts.push((0x001b, vec![2, 0, 2])); // compress_certificate (brotli)
    exts.push((0x4469, vec![0x00, 0x03, 0x02, b'h', b'2'])); // ALPS (h2)

    // Permute non-GREASE extensions like modern Chromium/BoringSSL
    shuffle_exts(&mut exts);

    let mut e = Vec::with_capacity(256);
    ext(&mut e, g0, &[]);
    for (ty, bd) in &exts {
        ext(&mut e, *ty, bd);
    }

    let mut cs = Vec::new();
    for c in [
        g_cs, 0x1301u16, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
        0x009c, 0x009d, 0x002f, 0x0035,
    ] {
        put_u16(&mut cs, c);
    }

    // Place padding (0x0015) BEFORE trailing GREASE extension (matches Chrome layout)
    let g_last_wire_len = 5usize; // 2B type + 2B len + 1B body
    let body_len = |e_len: usize| 2 + 32 + 1 + 32 + 2 + cs.len() + 2 + 2 + e_len;
    let hs_total = 4 + body_len(e.len() + g_last_wire_len);
    if hs_total > 0xff && hs_total < 0x200 {
        let need = 0x200 - hs_total;
        if need >= 4 {
            ext(&mut e, 0x0015, &vec![0u8; need - 4]);
        }
    }
    ext(&mut e, g_last, &[0]);

    let mut body = vec![3, 3];
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(&sid);
    put_u16(&mut body, cs.len() as u16);
    body.extend_from_slice(&cs);
    body.extend_from_slice(&[1, 0]);
    put_u16(&mut body, e.len() as u16);
    body.extend_from_slice(&e);

    let mut hs = vec![1];
    put_u24(&mut hs, body.len());
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 3, 1];
    put_u16(&mut rec, hs.len() as u16);
    rec.extend_from_slice(&hs);
    rec
}

fn parse_hello(rec: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if rec.len() < 5 + 4 + 2 + 32 + 1 + 32 || rec[0] != 0x16 || rec[5] != 1 {
        return None;
    }
    let body = &rec[5..];
    let hs_len = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
    if body.len() < 4 + hs_len {
        return None;
    }
    let mut p = 4 + 2;
    let random: [u8; 32] = body[p..p + 32].try_into().ok()?;
    p += 32;
    if body[p] != 32 || body.len() < p + 1 + 32 {
        return None;
    }
    let sid: [u8; 32] = body[p + 1..p + 33].try_into().ok()?;
    Some((random, sid))
}

/// Deterministic TLS 1.3 server flight:
/// - ServerHello (with valid X25519 key_share) + CCS
/// - Record 1 (EncryptedExtensions): deterministic size for this server/SNI (48..96)
/// - Record 2 (Certificate + CertificateVerify): deterministic size per SNI (2400..3600)
/// - Record 3 (Finished): exact 53-byte TLS 1.3 Finished record (32B MAC + 4B hdr + 1B content type + 16B AEAD tag)
fn build_server_flight(client_sid: &[u8; 32], sni_seed: &str) -> Vec<u8> {
    let mut e = Vec::new();
    ext(&mut e, 0x002b, &[3, 4]);
    let mut ks = Vec::new();
    put_u16(&mut ks, 0x001d);
    put_u16(&mut ks, 32);
    ks.extend_from_slice(&ephemeral_x25519_pub());
    ext(&mut e, 0x0033, &ks);

    let mut body = vec![3, 3];
    body.extend_from_slice(&rand_bytes::<32>());
    body.push(32);
    body.extend_from_slice(client_sid);
    body.extend_from_slice(&[0x13, 0x01, 0]);
    put_u16(&mut body, e.len() as u16);
    body.extend_from_slice(&e);

    let mut hs = vec![2];
    put_u24(&mut hs, body.len());
    hs.extend_from_slice(&body);
    let mut out = vec![0x16, 3, 3];
    put_u16(&mut out, hs.len() as u16);
    out.extend_from_slice(&hs);
    out.extend_from_slice(&CCS);

    let digest = Sha256::digest(sni_seed.as_bytes());
    let ee_len = 48usize + (digest[0] as usize % 49); // deterministic 48..96
    let cert_len = 2400usize + (u16::from_be_bytes([digest[1], digest[2]]) as usize % 1200); // deterministic per SNI
    let sizes = [ee_len, cert_len, TLS13_FINISHED_LEN];

    for n in sizes.into_iter().take(FLIGHT_APPDATA) {
        out.extend_from_slice(&[0x17, 3, 3]);
        put_u16(&mut out, n as u16);
        let start = out.len();
        out.resize(start + n, 0);
        fill_random(&mut out[start..]);
    }
    out
}

fn build_client_finished() -> [u8; 5 + TLS13_FINISHED_LEN] {
    let mut rec = [0u8; 5 + TLS13_FINISHED_LEN];
    rec[0] = 0x17;
    rec[1] = 3;
    rec[2] = 3;
    let len_be = (TLS13_FINISHED_LEN as u16).to_be_bytes();
    rec[3] = len_be[0];
    rec[4] = len_be[1];
    fill_random(&mut rec[5..]);
    rec
}

pub struct Replay(Mutex<HashMap<[u8; 16], Instant>>);

impl Replay {
    pub fn new() -> Replay {
        Replay(Mutex::new(HashMap::new()))
    }

    pub fn check_and_insert(&self, nonce: &[u8]) -> bool {
        let Ok(key) = <[u8; 16]>::try_from(nonce) else { return false };
        let mut m = self.0.lock().unwrap();
        if m.contains_key(&key) {
            return false;
        }
        if m.len() >= 4096 {
            let ttl = Duration::from_secs(MAX_SKEW_SECS * 2);
            m.retain(|_, t| t.elapsed() < ttl);
            // Fail closed at the hard cap rather than allowing attacker-controlled growth.
            if m.len() >= 4096 {
                return false;
            }
        }
        m.insert(key, Instant::now());
        true
    }
}

async fn read_record(tcp: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut h = [0u8; 5];
    tcp.read_exact(&mut h).await?;
    let len = u16::from_be_bytes([h[3], h[4]]) as usize;
    if len > MAX_REC {
        bail!("oversized record");
    }
    let mut b = vec![0u8; len];
    tcp.read_exact(&mut b).await?;
    Ok((h[0], b))
}

async fn handle_fallback(
    mut c: TcpStream,
    peer_ip: IpAddr,
    cfg: &CamoCfg,
    pre: &[u8],
    limiter: &Arc<FallbackLimiter>,
) {
    stats::CAMO_FALLBACK.fetch_add(1, Relaxed);
    let lease = limiter.acquire(peer_ip);
    let Some(fb) = &cfg.fallback else {
        sleep(Duration::from_millis(rand_range(300, 3000) as u64)).await;
        return;
    };
    let mut first = pre.to_vec();
    if pre.len() <= 5 {
        let mut extra = vec![0u8; 16384];
        if let Ok(Ok(n)) = timeout(Duration::from_millis(40), c.read(&mut extra)).await {
            first.extend_from_slice(&extra[..n]);
        }
    }
    let Ok(Ok(mut d)) = timeout(Duration::from_secs(5), TcpStream::connect(fb)).await else {
        return;
    };
    if d.write_all(&first).await.is_err() {
        return;
    }
    lease.touch();
    mirror_bidirectional(c, d, &lease).await;
}

pub async fn server(
    mut tcp: TcpStream,
    peer_ip: IpAddr,
    cfg: &CamoCfg,
    replay: &Replay,
    fb_limiter: &Arc<FallbackLimiter>,
) -> Result<Option<BoxRw>> {
    let mut hdr = [0u8; 5];
    match timeout(Duration::from_secs(10), tcp.read_exact(&mut hdr)).await {
        Ok(Ok(_)) => {}
        _ => return Ok(None),
    }
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let plausible = hdr[0] == 0x16 && hdr[1] == 3 && hdr[2] <= 3 && (42..=16384).contains(&len);
    if !plausible {
        handle_fallback(tcp, peer_ip, cfg, &hdr, fb_limiter).await;
        return Ok(None);
    }

    // Read body incrementally so any partial bytes already received are preserved for decoy fallback
    let mut rec = Vec::with_capacity(5 + len);
    rec.extend_from_slice(&hdr);
    let mut body = vec![0u8; len];
    let mut got = 0usize;
    let deadline = Instant::now() + Duration::from_secs(10);
    while got < len {
        let rem = deadline.saturating_duration_since(Instant::now());
        if rem.is_zero() {
            rec.extend_from_slice(&body[..got]);
            handle_fallback(tcp, peer_ip, cfg, &rec, fb_limiter).await;
            return Ok(None);
        }
        match timeout(rem, tcp.read(&mut body[got..])).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                rec.extend_from_slice(&body[..got]);
                handle_fallback(tcp, peer_ip, cfg, &rec, fb_limiter).await;
                return Ok(None);
            }
            Ok(Ok(n)) => got += n,
        }
    }
    rec.extend_from_slice(&body);

    let parsed = parse_hello(&rec);
    let authed_sid = match parsed {
        Some((r, s)) => match check_auth(&cfg.secret, &r, &s, now_unix()) {
            AuthCheck::Ok => {
                if replay.check_and_insert(&r[..16]) {
                    Some(s)
                } else {
                    None
                }
            }
            AuthCheck::ClockSkew(diff) => {
                stats::CLOCK_SKEW_DROPPED.fetch_add(1, Relaxed);
                stats::log_err_rl(&format!(
                    "[camo] rejected valid client from {peer_ip}: clock skew {diff}s > ±{MAX_SKEW_SECS}s (check NTP)"
                ));
                None
            }
            AuthCheck::Invalid => None,
        },
        None => None,
    };

    let Some(sid) = authed_sid else {
        handle_fallback(tcp, peer_ip, cfg, &rec, fb_limiter).await;
        return Ok(None);
    };

    stats::CAMO_OK.fetch_add(1, Relaxed);
    let sni_seed = if cfg.sni.is_empty() {
        cfg.fallback.as_deref().unwrap_or("khaymali-default")
    } else {
        cfg.sni.as_str()
    };
    tcp.write_all(&build_server_flight(&sid, sni_seed)).await?;
    let mut ccs = [0u8; 6];
    timeout(Duration::from_secs(10), tcp.read_exact(&mut ccs)).await??;
    if ccs != CCS {
        bail!("bad client CCS");
    }
    // Consume client TLS 1.3 Finished record (exact 53 bytes)
    let (ft, fb) = timeout(Duration::from_secs(10), read_record(&mut tcp)).await??;
    if ft != 0x17 || fb.len() != TLS13_FINISHED_LEN {
        bail!("bad client Finished record");
    }
    Ok(Some(spawn_pumps(tcp, cfg.pad_max)))
}

pub async fn client(mut tcp: TcpStream, cfg: &CamoCfg) -> Result<BoxRw> {
    tcp.write_all(&build_client_hello(cfg, now_unix())).await?;
    timeout(Duration::from_secs(10), async {
        let (t, b) = read_record(&mut tcp).await?;
        if t != 0x16 || b.first() != Some(&2) {
            bail!("camo: unexpected server hello (not a khaymali server?)");
        }
        let (t, _) = read_record(&mut tcp).await?;
        if t != 0x14 {
            bail!("camo: expected CCS");
        }
        for i in 0..FLIGHT_APPDATA {
            let (t, body) = read_record(&mut tcp).await?;
            if t != 0x17 {
                bail!("camo: expected handshake-looking record");
            }
            if i + 1 == FLIGHT_APPDATA && body.len() != TLS13_FINISHED_LEN {
                bail!("camo: unexpected server Finished record length");
            }
        }
        Ok(())
    })
    .await??;
    let mut cli_flight = Vec::with_capacity(CCS.len() + 5 + TLS13_FINISHED_LEN);
    cli_flight.extend_from_slice(&CCS);
    cli_flight.extend_from_slice(&build_client_finished());
    tcp.write_all(&cli_flight).await?;
    Ok(spawn_pumps(tcp, cfg.pad_max))
}

fn spawn_pumps(tcp: TcpStream, pad_max: usize) -> BoxRw {
    let (user, inner) = duplex(128 * 1024);
    let (mut tr, mut tw) = tcp.into_split();
    let (mut br, mut bw) = split(inner);

    tokio::spawn(async move {
        let mut buf = vec![0u8; DATA_CHUNK];
        let mut rec = Vec::with_capacity(5 + 2 + DATA_CHUNK + pad_max);
        let mut shaper = TrafficShaper::new(pad_max);
        loop {
            let n = match br.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut offset = 0usize;
            while offset < n {
                let remaining = n - offset;
                let chunk_len = shaper.first_flight_split(remaining);
                let max_extra = MAX_REC.saturating_sub(2 + chunk_len);
                let pad = shaper.next_padding(chunk_len, max_extra);
                let plen = 2 + chunk_len + pad;
                rec.clear();
                rec.extend_from_slice(&[0x17, 3, 3]);
                put_u16(&mut rec, plen as u16);
                put_u16(&mut rec, chunk_len as u16);
                rec.extend_from_slice(&buf[offset..offset + chunk_len]);
                let start = rec.len();
                rec.resize(start + pad, 0);
                fill_random(&mut rec[start..]);
                if tw.write_all(&rec).await.is_err() {
                    let _ = tw.shutdown().await;
                    return;
                }
                offset += chunk_len;
            }
        }
        let _ = tw.shutdown().await;
    });

    tokio::spawn(async move {
        let mut hdr = [0u8; 5];
        let mut body = vec![0u8; MAX_REC];
        loop {
            if tr.read_exact(&mut hdr).await.is_err() || hdr[0] != 0x17 {
                break;
            }
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            if len < 2 || len > MAX_REC {
                break;
            }
            if tr.read_exact(&mut body[..len]).await.is_err() {
                break;
            }
            let real = u16::from_be_bytes([body[0], body[1]]) as usize;
            if 2 + real > len || bw.write_all(&body[2..2 + real]).await.is_err() {
                break;
            }
        }
        let _ = bw.shutdown().await;
    });

    Box::new(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camo_auth_detects_clock_skew_separately() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let now = now_unix();
        let (r_ok, s_ok) = make_auth(secret, now);
        assert_eq!(check_auth(secret, &r_ok, &s_ok, now), AuthCheck::Ok);

        let (r_skew, s_skew) = make_auth(secret, now.saturating_sub(300));
        assert!(matches!(check_auth(secret, &r_skew, &s_skew, now), AuthCheck::ClockSkew(_)));

        let mut r_bad = r_ok;
        r_bad[20] ^= 0xff;
        assert_eq!(check_auth(secret, &r_bad, &s_ok, now), AuthCheck::Invalid);
    }

    #[test]
    fn camo_server_flight_has_deterministic_cert_and_53b_finished() {
        let sid = [7u8; 32];
        let f1 = build_server_flight(&sid, "example.com");
        let f2 = build_server_flight(&sid, "example.com");
        assert_eq!(f1.len(), f2.len(), "server flight length must stay deterministic per SNI");
        // Final record must be exact 53-byte Finished
        let last_len = u16::from_be_bytes([f1[f1.len() - 55], f1[f1.len() - 54]]) as usize;
        assert_eq!(last_len, TLS13_FINISHED_LEN);
    }

    #[test]
    #[ignore]
    fn dump_hello() {
        let c = CamoCfg {
            secret: b"0123456789abcdef0123456789abcdef".to_vec(),
            sni: "decoy.example".into(),
            fallback: None,
            pad_max: 32,
        };
        std::fs::write("/tmp/khaymali-hello.bin", build_client_hello(&c, now_unix())).unwrap();
    }
}
