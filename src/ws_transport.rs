//! RFC 6455 WebSocket & WSS-over-Camo Carrier Transport (`ws://HOST:PORT`, `wss://HOST:PORT`).
//!
//! Ported from Khaymali's `wss_carrier.go` + FRP/Backhaul `ws`/`wss` transports with zero extra
//! crate dependencies (pure-Rust SHA-1 + Base64 for RFC 6455 `Sec-WebSocket-Accept`):
//!   * `ws://HOST:PORT`: HTTP/1.1 Upgrade + masked client / unmasked server binary WebSocket frames.
//!   * `wss://HOST:PORT`: Runs RFC 6455 WebSocket *inside* Khaymali's TLS 1.3 Camouflage
//!     (`camo::client` / `camo::server`) so DPI sees standard TLS 1.3 + HTTPS and unauthenticated
//!     probes fall back cleanly to the configured Decoy site.
//!   * Constant-time `X-Khaymali-Auth` HMAC-SHA256 header when `auth_key` is provided.
//!   * Exposes `BoxRw` (`AsyncRead + AsyncWrite`) so `Noise_IK` and `MuxCarrier` run natively on top.

use crate::camo::{self, CamoCfg, Replay};
use crate::fallback::FallbackLimiter;
use crate::link;
use crate::stats;
use crate::util::{ct_eq, hex, rand_bytes, BoxRw};
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

type HmacSha256 = Hmac<Sha256>;

const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HTTP_HDR: usize = 8192;
const MAX_WS_FRAME: usize = 64 * 1024;
const WS_CHUNK: usize = 16 * 1024;
const DEFAULT_WS_PATH: &str = "/ws/tunnel";

/// Pure-Rust SHA-1 (FIPS 180-4) strictly for RFC 6455 `Sec-WebSocket-Accept`.
pub fn sha1_digest(input: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg = input.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Standard Base64 encoder (RFC 4648) with `=` padding.
pub fn b64_encode(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(((data.len() + 2) / 3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TBL[((n >> 18) & 0x3F) as usize] as char);
        out.push(TBL[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TBL[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TBL[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// URL-safe Base64 encoder without padding (matches Khaymali `pt1_` / bundle codes).
pub fn b64url_encode(data: &[u8]) -> String {
    b64_encode(data)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// URL-safe or standard Base64 decoder.
pub fn b64_decode(input: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity((input.len() * 3) / 4);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for b in input.trim().bytes() {
        if b == b'=' || b.is_ascii_whitespace() {
            continue;
        }
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => bail!("invalid base64 byte: {b}"),
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// Computes RFC 6455 `Sec-WebSocket-Accept` for a given `Sec-WebSocket-Key`.
pub fn ws_accept_key(client_key: &str) -> String {
    let mut buf = Vec::with_capacity(client_key.len() + WS_GUID.len());
    buf.extend_from_slice(client_key.trim().as_bytes());
    buf.extend_from_slice(WS_GUID);
    b64_encode(&sha1_digest(&buf))
}

fn compute_auth_tag(auth_key: &[u8], ws_key: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(auth_key).expect("HMAC accepts any key size");
    mac.update(b"khaymali-ws-v1:");
    mac.update(ws_key.trim().as_bytes());
    hex(&mac.finalize().into_bytes()[..16])
}

async fn read_http_headers<R: AsyncRead + Unpin>(r: &mut R) -> Result<String> {
    let mut buf = Vec::with_capacity(512);
    let mut b = [0u8; 1];
    while buf.len() < MAX_HTTP_HDR {
        let n = r.read(&mut b).await?;
        if n == 0 {
            bail!("ws handshake EOF before end of HTTP headers");
        }
        buf.push(b[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            return Ok(String::from_utf8_lossy(&buf).into_owned());
        }
    }
    bail!("ws HTTP header exceeded {MAX_HTTP_HDR} bytes")
}

fn find_header<'a>(hdrs: &'a str, name: &str) -> Option<&'a str> {
    for line in hdrs.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

async fn write_ws_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    opcode: u8,
    payload: &[u8],
    mask: bool,
) -> Result<()> {
    let mut hdr = Vec::with_capacity(14);
    hdr.push(0x80 | (opcode & 0x0F));
    let mask_bit = if mask { 0x80u8 } else { 0x00u8 };
    let len = payload.len();
    if len <= 125 {
        hdr.push(mask_bit | (len as u8));
    } else if len <= 65535 {
        hdr.push(mask_bit | 126);
        hdr.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        hdr.push(mask_bit | 127);
        hdr.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if mask {
        let mk = rand_bytes::<4>();
        hdr.extend_from_slice(&mk);
        w.write_all(&hdr).await?;
        let mut masked = payload.to_vec();
        for (i, b) in masked.iter_mut().enumerate() {
            *b ^= mk[i & 3];
        }
        w.write_all(&masked).await?;
    } else {
        w.write_all(&hdr).await?;
        if !payload.is_empty() {
            w.write_all(payload).await?;
        }
    }
    w.flush().await?;
    Ok(())
}

async fn read_ws_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<(u8, Vec<u8>)> {
    let mut b2 = [0u8; 2];
    r.read_exact(&mut b2).await?;
    let opcode = b2[0] & 0x0F;
    let masked = (b2[1] & 0x80) != 0;
    let len7 = (b2[1] & 0x7F) as usize;
    let payload_len = match len7 {
        0..=125 => len7,
        126 => {
            let mut ext = [0u8; 2];
            r.read_exact(&mut ext).await?;
            u16::from_be_bytes(ext) as usize
        }
        127 => {
            let mut ext = [0u8; 8];
            r.read_exact(&mut ext).await?;
            let v = u64::from_be_bytes(ext);
            if v > MAX_WS_FRAME as u64 {
                bail!("ws frame too large: {v}");
            }
            v as usize
        }
        _ => unreachable!(),
    };
    if payload_len > MAX_WS_FRAME {
        bail!("ws frame exceeds {MAX_WS_FRAME} bytes");
    }
    let mask_key = if masked {
        let mut mk = [0u8; 4];
        r.read_exact(&mut mk).await?;
        Some(mk)
    } else {
        None
    };
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        r.read_exact(&mut payload).await?;
    }
    if let Some(mk) = mask_key {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mk[i & 3];
        }
    }
    Ok((opcode, payload))
}

fn wrap_ws_stream(inner: BoxRw, is_client: bool, is_wss: bool) -> BoxRw {
    let (app_side, pump_side) = tokio::io::duplex(64 * 1024);
    let (mut app_r, mut app_w) = tokio::io::split(pump_side);
    let (mut net_r, mut net_w) = tokio::io::split(inner);
    let (pong_tx, mut pong_rx) = mpsc::channel::<Vec<u8>>(8);

    if is_wss {
        stats::WSS_SESSIONS_ACTIVE.fetch_add(1, Relaxed);
    } else {
        stats::WS_SESSIONS_ACTIVE.fetch_add(1, Relaxed);
    }

    tokio::spawn(async move {
        let mut buf = vec![0u8; WS_CHUNK];
        loop {
            tokio::select! {
                Some(ping_data) = pong_rx.recv() => {
                    if write_ws_frame(&mut net_w, 0x0A, &ping_data, is_client).await.is_err() {
                        break;
                    }
                }
                res = app_r.read(&mut buf) => match res {
                    Ok(0) | Err(_) => {
                        let _ = write_ws_frame(&mut net_w, 0x08, &[], is_client).await;
                        break;
                    }
                    Ok(n) => {
                        if write_ws_frame(&mut net_w, 0x02, &buf[..n], is_client).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
        let _ = net_w.shutdown().await;
    });

    tokio::spawn(async move {
        while let Ok((opcode, payload)) = read_ws_frame(&mut net_r).await {
            match opcode {
                0x00..=0x02 => {
                    if !payload.is_empty() && app_w.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                0x08 => break,
                0x09 => {
                    let _ = pong_tx.try_send(payload);
                }
                0x0A => {}
                _ => break,
            }
        }
        let _ = app_w.shutdown().await;
        if is_wss {
            stats::WSS_SESSIONS_ACTIVE.fetch_sub(1, Relaxed);
        } else {
            stats::WS_SESSIONS_ACTIVE.fetch_sub(1, Relaxed);
        }
    });

    Box::new(app_side)
}

pub async fn client_upgrade(
    mut stream: BoxRw,
    host_hdr: &str,
    auth_key: &[u8],
    is_wss: bool,
) -> Result<BoxRw> {
    let nonce = rand_bytes::<16>();
    let ws_key = b64_encode(&nonce);
    let expected_accept = ws_accept_key(&ws_key);

    let mut req = format!(
        "GET {DEFAULT_WS_PATH} HTTP/1.1\r\n\
         Host: {host_hdr}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {ws_key}\r\n\
         Sec-WebSocket-Version: 13\r\n"
    );
    if !auth_key.is_empty() {
        let tag = compute_auth_tag(auth_key, &ws_key);
        req.push_str(&format!("X-Khaymali-Auth: {tag}\r\n"));
    }
    req.push_str("\r\n");

    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let resp = read_http_headers(&mut stream).await?;
    let first = resp.lines().next().unwrap_or("");
    if !first.contains(" 101 ") {
        bail!("ws upgrade rejected: {first}");
    }
    let accept = find_header(&resp, "Sec-WebSocket-Accept")
        .context("missing Sec-WebSocket-Accept header")?;
    if !ct_eq(accept.as_bytes(), expected_accept.as_bytes()) {
        bail!("ws Sec-WebSocket-Accept mismatch");
    }

    Ok(wrap_ws_stream(stream, true, is_wss))
}

pub async fn server_upgrade(
    mut stream: BoxRw,
    auth_key: &[u8],
    is_wss: bool,
) -> Result<BoxRw> {
    let req = read_http_headers(&mut stream).await?;
    let ws_key = find_header(&req, "Sec-WebSocket-Key")
        .context("missing Sec-WebSocket-Key")?;
    if !auth_key.is_empty() {
        let provided = find_header(&req, "X-Khaymali-Auth").unwrap_or("");
        let expected = compute_auth_tag(auth_key, ws_key);
        if !ct_eq(provided.as_bytes(), expected.as_bytes()) {
            let _ = stream
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await;
            bail!("ws auth header mismatch");
        }
    }
    let accept = ws_accept_key(ws_key);
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(wrap_ws_stream(stream, false, is_wss))
}

pub async fn connect_ws(
    addr: &str,
    auth_key: &[u8],
    connect_timeout: Duration,
) -> Result<BoxRw> {
    let clean = addr.strip_prefix("ws://").unwrap_or(addr);
    let tcp = timeout(connect_timeout, TcpStream::connect(clean)).await??;
    link::tune(&tcp);
    timeout(connect_timeout, client_upgrade(Box::new(tcp), clean, auth_key, false)).await?
}

pub async fn connect_wss(
    addr: &str,
    camo_cfg: &CamoCfg,
    connect_timeout: Duration,
) -> Result<BoxRw> {
    let clean = addr.strip_prefix("wss://").unwrap_or(addr);
    let tcp = timeout(connect_timeout, TcpStream::connect(clean)).await??;
    link::tune(&tcp);
    let tls_stream = timeout(connect_timeout, camo::client(tcp, camo_cfg)).await??;
    let host_hdr = if camo_cfg.sni.is_empty() { clean } else { camo_cfg.sni.as_str() };
    timeout(
        connect_timeout,
        client_upgrade(tls_stream, host_hdr, &camo_cfg.secret, true),
    )
    .await?
}

pub struct WsCarrierListener {
    listener: TcpListener,
    auth_key: Vec<u8>,
    camo: Option<CamoCfg>,
    replay: Arc<Replay>,
    fb_limiter: Arc<FallbackLimiter>,
}

impl WsCarrierListener {
    pub async fn bind(
        listen_addr: &str,
        auth_key: Vec<u8>,
        camo: Option<CamoCfg>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(listen_addr).await?;
        Ok(Self {
            listener,
            auth_key,
            camo,
            replay: Arc::new(Replay::new()),
            fb_limiter: FallbackLimiter::default_limiter(),
        })
    }

    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr)> {
        Ok(self.listener.accept().await?)
    }

    pub async fn handshake(&self, tcp: TcpStream, peer_ip: IpAddr) -> Result<Option<BoxRw>> {
        link::tune(&tcp);
        let is_wss = self.camo.is_some();
        let inner: BoxRw = match &self.camo {
            Some(c) => match camo::server(tcp, peer_ip, c, &self.replay, &self.fb_limiter).await? {
                Some(s) => s,
                None => return Ok(None),
            },
            None => Box::new(tcp),
        };
        let upgraded = timeout(
            Duration::from_secs(10),
            server_upgrade(inner, &self.auth_key, is_wss),
        )
        .await??;
        Ok(Some(upgraded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6455_accept_vector_and_base64_roundtrip() {
        assert_eq!(ws_accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        let raw = b"khaymali-tunnel-v0.18";
        let enc = b64url_encode(raw);
        assert_eq!(b64_decode(&enc).unwrap(), raw);
    }

    #[tokio::test]
    async fn ws_client_server_roundtrip_over_duplex() {
        let (c_end, s_end) = tokio::io::duplex(64 * 1024);
        let secret = b"0123456789abcdef".to_vec();
        let sec_s = secret.clone();
        let srv = tokio::spawn(async move {
            let mut st = server_upgrade(Box::new(s_end), &sec_s, false).await.unwrap();
            let mut buf = [0u8; 11];
            st.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello-hashe");
            st.write_all(b"ws-pong").await.unwrap();
            st.flush().await.unwrap();
        });
        let mut cli = client_upgrade(Box::new(c_end), "cdn.example:443", &secret, false)
            .await
            .unwrap();
        cli.write_all(b"hello-hashe").await.unwrap();
        cli.flush().await.unwrap();
        let mut resp = [0u8; 7];
        cli.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"ws-pong");
        drop(cli);
        srv.await.unwrap();
    }
}
