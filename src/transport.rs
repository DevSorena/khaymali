//! Transport abstraction, encrypted capability negotiation, and secret-bound directional
//! Channel Binding for Entry <-> Bridge (SPEC §2.2, §3.1).
//!
//! Security model:
//!   * Keys derive via `HKDF-SHA256(salt = h, ikm = cb_secret)` where `cb_secret` is 32 CSPRNG
//!     bytes transmitted inside the encrypted Noise `READY v2` message.
//!   * Cryptographic anti-injection & anti-replay come from the 128-bit directional HMAC-SHA256
//!     bound to strict monotonic `seq` (`checked_add(1)`).
//!   * Honest caveat on length masking: XOR-masking the 2-byte length header is cosmetic parser
//!     hardening only; on-path observers still see TCP segment/frame sizes.

use crate::camo::{self, CamoCfg};
use crate::ktunnel;
use crate::link;
use crate::udp_transport;
use crate::util::{ct_eq, BoxRw};
use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub const PROTO_VERSION: u8 = 1;
pub const FEAT_CHANNEL_BINDING: u16 = 1 << 0;
pub const FEAT_CAP_NEGOTIATION: u16 = 1 << 1;
pub const FEAT_GRACEFUL_DRAIN: u16 = 1 << 2;
pub const KNOWN_FEATURES_MASK: u16 =
    FEAT_CHANNEL_BINDING | FEAT_CAP_NEGOTIATION | FEAT_GRACEFUL_DRAIN;

pub const MAX_BOUND_FRAME: usize = 16 * 1024;
const BOUND_TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityHeader {
    pub version: u8,
    pub features: u16,
    pub reserved: u8,
}

impl CapabilityHeader {
    pub const fn current(features: u16) -> Self {
        Self {
            version: PROTO_VERSION,
            features: features & KNOWN_FEATURES_MASK,
            reserved: 0,
        }
    }

    pub fn encode(self) -> [u8; 4] {
        let fb = self.features.to_be_bytes();
        [self.version, fb[0], fb[1], 0]
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < 4 {
            bail!("capability header too short");
        }
        if b[0] != PROTO_VERSION {
            bail!("unsupported protocol version {}", b[0]);
        }
        let raw_feats = u16::from_be_bytes([b[1], b[2]]);
        Ok(Self {
            version: b[0],
            features: raw_feats & KNOWN_FEATURES_MASK,
            reserved: 0,
        })
    }

    pub fn negotiate(local: u16, remote: u16) -> u16 {
        (local & remote) & KNOWN_FEATURES_MASK
    }
}

pub trait Transport: Send + Sync {
    fn name(&self) -> &'static str;
    fn dial<'a>(&'a self, addr: &'a str) -> Pin<Box<dyn Future<Output = Result<BoxRw>> + Send + 'a>>;
}

pub struct TcpTransport {
    pub connect_timeout: Duration,
}

impl Transport for TcpTransport {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn dial<'a>(&'a self, addr: &'a str) -> Pin<Box<dyn Future<Output = Result<BoxRw>> + Send + 'a>> {
        Box::pin(async move {
            let tcp = timeout(self.connect_timeout, TcpStream::connect(addr)).await??;
            link::tune(&tcp);
            Ok(Box::new(tcp) as BoxRw)
        })
    }
}

pub struct CamoTransport {
    pub cfg: CamoCfg,
    pub connect_timeout: Duration,
}

impl Transport for CamoTransport {
    fn name(&self) -> &'static str {
        "tcp+camo"
    }

    fn dial<'a>(&'a self, addr: &'a str) -> Pin<Box<dyn Future<Output = Result<BoxRw>> + Send + 'a>> {
        Box::pin(async move {
            let tcp = timeout(self.connect_timeout, TcpStream::connect(addr)).await??;
            link::tune(&tcp);
            camo::client(tcp, &self.cfg).await
        })
    }
}

/// Reliable HMAC-authenticated UDP Carrier Transport (`udp://HOST:PORT`).
pub struct UdpTransport {
    pub auth_key: Vec<u8>,
    pub connect_timeout: Duration,
}

impl Transport for UdpTransport {
    fn name(&self) -> &'static str {
        "udp+arq"
    }

    fn dial<'a>(&'a self, addr: &'a str) -> Pin<Box<dyn Future<Output = Result<BoxRw>> + Send + 'a>> {
        let clean = addr.strip_prefix("udp://").unwrap_or(addr).to_string();
        Box::pin(async move {
            udp_transport::connect(&clean, &self.auth_key, self.connect_timeout).await
        })
    }
}

/// Scheme-aware transport router: dials `udp://HOST:PORT` via `UdpTransport` and
/// plain/camouflaged TCP addresses via `CamoTransport` or `TcpTransport`.
/// Multi-Flow FakeTLS-Mux Carrier Transport (`ktunnel://HOST:PORT`).
pub struct KtunnelTransport {
    pub auth_key: Vec<u8>,
    pub flow_count: usize,
    pub connect_timeout: Duration,
}

impl Transport for KtunnelTransport {
    fn name(&self) -> &'static str {
        "ktunnel+mux"
    }

    fn dial<'a>(&'a self, addr: &'a str) -> Pin<Box<dyn Future<Output = Result<BoxRw>> + Send + 'a>> {
        let clean = addr.strip_prefix("ktunnel://").unwrap_or(addr).to_string();
        let flows = self.flow_count;
        Box::pin(async move {
            ktunnel::connect(&clean, &self.auth_key, flows, self.connect_timeout).await
        })
    }
}

pub struct AutoTransport {
    pub camo: Option<CamoCfg>,
    pub udp_auth_key: Vec<u8>,
    pub connect_timeout: Duration,
}

impl Transport for AutoTransport {
    fn name(&self) -> &'static str {
        if self.camo.is_some() {
            "auto(udp+fec/ktunnel/camo/tcp)"
        } else {
            "auto(udp+fec/ktunnel/tcp)"
        }
    }

    fn dial<'a>(&'a self, addr: &'a str) -> Pin<Box<dyn Future<Output = Result<BoxRw>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(auto_addr) = addr.strip_prefix("auto://") {
                let stage_timeout = (self.connect_timeout / 3).max(Duration::from_secs(2));
                if !self.udp_auth_key.is_empty() {
                    if let Ok(s) = udp_transport::connect(auto_addr, &self.udp_auth_key, stage_timeout).await {
                        return Ok(s);
                    }
                    if let Ok(s) = ktunnel::connect(
                        auto_addr,
                        &self.udp_auth_key,
                        ktunnel::DEFAULT_KTUN_FLOWS,
                        stage_timeout,
                    )
                    .await
                    {
                        return Ok(s);
                    }
                }
                let tcp = timeout(stage_timeout, TcpStream::connect(auto_addr)).await??;
                link::tune(&tcp);
                return match &self.camo {
                    Some(cfg) => camo::client(tcp, cfg).await,
                    None => Ok(Box::new(tcp) as BoxRw),
                };
            }
            if let Some(ktun_addr) = addr.strip_prefix("ktunnel://") {
                return ktunnel::connect(ktun_addr, &self.udp_auth_key, ktunnel::DEFAULT_KTUN_FLOWS, self.connect_timeout).await;
            }
            if let Some(udp_addr) = addr.strip_prefix("udp://") {
                return udp_transport::connect(udp_addr, &self.udp_auth_key, self.connect_timeout).await;
            }
            let clean = addr.strip_prefix("tcp://").unwrap_or(addr);
            let tcp = timeout(self.connect_timeout, TcpStream::connect(clean)).await??;
            link::tune(&tcp);
            match &self.camo {
                Some(cfg) => camo::client(tcp, cfg).await,
                None => Ok(Box::new(tcp) as BoxRw),
            }
        })
    }
}

#[derive(Clone, Copy)]
pub struct DirectionKeys {
    pub mac_key: [u8; 32],
    pub len_key: [u8; 32],
}

#[derive(Clone, Copy)]
pub struct ChannelBindingKeys {
    pub b2e: DirectionKeys,
    pub e2b: DirectionKeys,
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let actual_salt = if salt.is_empty() { &[0u8; 32][..] } else { salt };
    hmac_sha256(actual_salt, &[ikm])
}

pub fn hkdf_expand_32(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    hmac_sha256(prk, &[info, &[0x01]])
}

pub fn derive_channel_binding_keys(
    handshake_hash: &[u8; 32],
    cb_secret: &[u8; 32],
) -> ChannelBindingKeys {
    let prk = hkdf_extract(handshake_hash, cb_secret);
    ChannelBindingKeys {
        b2e: DirectionKeys {
            mac_key: hkdf_expand_32(&prk, b"khaymali/cb/v2/b2e/mac"),
            len_key: hkdf_expand_32(&prk, b"khaymali/cb/v2/b2e/len"),
        },
        e2b: DirectionKeys {
            mac_key: hkdf_expand_32(&prk, b"khaymali/cb/v2/e2b/mac"),
            len_key: hkdf_expand_32(&prk, b"khaymali/cb/v2/e2b/len"),
        },
    }
}

#[inline]
fn len_mask(len_key: &[u8; 32], seq: u64) -> [u8; 2] {
    let m = hmac_sha256(len_key, &[&seq.to_be_bytes()]);
    [m[0], m[1]]
}

pub fn seal_bound_frame_into(
    keys: &DirectionKeys,
    seq: u64,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    if payload.len() > MAX_BOUND_FRAME {
        bail!("bound frame payload exceeds MAX_BOUND_FRAME ({})", payload.len());
    }
    let len_be = (payload.len() as u16).to_be_bytes();
    let mask = len_mask(&keys.len_key, seq);
    let masked_len = [len_be[0] ^ mask[0], len_be[1] ^ mask[1]];
    let full_mac = hmac_sha256(&keys.mac_key, &[&seq.to_be_bytes(), &len_be, payload]);

    out.clear();
    out.extend_from_slice(&masked_len);
    out.extend_from_slice(&full_mac[..BOUND_TAG_LEN]);
    out.extend_from_slice(payload);
    Ok(())
}

pub fn seal_bound_frame(keys: &DirectionKeys, seq: u64, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(2 + BOUND_TAG_LEN + payload.len());
    seal_bound_frame_into(keys, seq, payload, &mut out)?;
    Ok(out)
}

pub fn unmask_bound_len(keys: &DirectionKeys, expected_seq: u64, masked_hdr: [u8; 2]) -> Result<usize> {
    let mask = len_mask(&keys.len_key, expected_seq);
    let len = u16::from_be_bytes([masked_hdr[0] ^ mask[0], masked_hdr[1] ^ mask[1]]) as usize;
    if len > MAX_BOUND_FRAME {
        bail!("unmasked bound frame length {len} exceeds MAX_BOUND_FRAME");
    }
    Ok(len)
}

pub fn verify_bound_body<'a>(
    keys: &DirectionKeys,
    expected_seq: u64,
    payload_len: usize,
    tag_and_payload: &'a [u8],
) -> Result<&'a [u8]> {
    if payload_len > MAX_BOUND_FRAME || tag_and_payload.len() != BOUND_TAG_LEN + payload_len {
        bail!("invalid bound frame body length");
    }
    let tag = &tag_and_payload[..BOUND_TAG_LEN];
    let payload = &tag_and_payload[BOUND_TAG_LEN..];
    let len_be = (payload_len as u16).to_be_bytes();
    let expected = hmac_sha256(&keys.mac_key, &[&expected_seq.to_be_bytes(), &len_be, payload]);
    if !ct_eq(tag, &expected[..BOUND_TAG_LEN]) {
        bail!("channel binding MAC mismatch");
    }
    Ok(payload)
}

/// Wrap any `BoxRw` with secret-bound directional HMAC framing using fixed reusable buffers.
pub fn wrap_bound_stream(inner: BoxRw, tx_keys: DirectionKeys, rx_keys: DirectionKeys) -> BoxRw {
    let (user, internal) = duplex(128 * 1024);
    let (mut net_r, mut net_w) = split(inner);
    let (mut app_r, mut app_w) = split(internal);

    tokio::spawn(async move {
        let mut read_buf = vec![0u8; MAX_BOUND_FRAME];
        let mut frame_buf = Vec::with_capacity(2 + BOUND_TAG_LEN + MAX_BOUND_FRAME);
        let mut seq: u64 = 0;
        loop {
            let n = match app_r.read(&mut read_buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if seal_bound_frame_into(&tx_keys, seq, &read_buf[..n], &mut frame_buf).is_err() {
                break;
            }
            if net_w.write_all(&frame_buf).await.is_err() {
                break;
            }
            let Some(next_seq) = seq.checked_add(1) else {
                break;
            };
            seq = next_seq;
        }
        let _ = net_w.shutdown().await;
    });

    tokio::spawn(async move {
        let mut body_buf = vec![0u8; BOUND_TAG_LEN + MAX_BOUND_FRAME];
        let mut seq: u64 = 0;
        let mut masked_hdr = [0u8; 2];
        loop {
            if net_r.read_exact(&mut masked_hdr).await.is_err() {
                break;
            }
            let Ok(payload_len) = unmask_bound_len(&rx_keys, seq, masked_hdr) else {
                break;
            };
            let need = BOUND_TAG_LEN + payload_len;
            if net_r.read_exact(&mut body_buf[..need]).await.is_err() {
                break;
            }
            let Ok(plain) = verify_bound_body(&rx_keys, seq, payload_len, &body_buf[..need]) else {
                break;
            };
            if app_w.write_all(plain).await.is_err() {
                break;
            }
            let Some(next_seq) = seq.checked_add(1) else {
                break;
            };
            seq = next_seq;
        }
        let _ = app_w.shutdown().await;
    });

    Box::new(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_negotiation_ignores_reserved_bits() {
        let h = CapabilityHeader::current(FEAT_CHANNEL_BINDING | FEAT_CAP_NEGOTIATION);
        let raw = h.encode();
        let dec = CapabilityHeader::decode(&raw).unwrap();
        assert_eq!(dec, h);
        let with_unknown = [PROTO_VERSION, 0xff, 0xff, 0xaa];
        let dec2 = CapabilityHeader::decode(&with_unknown).unwrap();
        assert_eq!(dec2.features, KNOWN_FEATURES_MASK);
        assert!(CapabilityHeader::decode(&[99, 0, 0, 0]).is_err());
    }

    #[test]
    fn neg_channel_binding_secret_required() {
        let public_h = [0x42u8; 32];
        let real_secret = [0x99u8; 32];
        let attacker_guess = [0x00u8; 32];

        let real_keys = derive_channel_binding_keys(&public_h, &real_secret);
        let attacker_keys = derive_channel_binding_keys(&public_h, &attacker_guess);
        assert_ne!(real_keys.b2e.mac_key, real_keys.e2b.mac_key);
        assert_ne!(real_keys.b2e.mac_key, attacker_keys.b2e.mac_key);

        let payload = b"opaque-noise-ciphertext";
        let forged = seal_bound_frame(&attacker_keys.b2e, 0, payload).unwrap();
        let forged_ok = unmask_bound_len(&real_keys.b2e, 0, [forged[0], forged[1]])
            .and_then(|l| verify_bound_body(&real_keys.b2e, 0, l, &forged[2..]));
        assert!(forged_ok.is_err());
        assert!(seal_bound_frame(&real_keys.b2e, 0, &vec![0u8; MAX_BOUND_FRAME + 1]).is_err());
    }

    /// SPEC §8 Test #9 (Fix #4): Real async `wrap_bound_stream` over `tokio::io::duplex`:
    ///   (a) Bidirectional 64 KiB round-trip intact
    ///   (b) Live wire byte injection rejected with 0 corrupted bytes delivered
    ///   (c) Live wire frame replay rejected immediately
    #[tokio::test]
    async fn wrap_bound_stream_duplex_roundtrip_injection_and_replay() {
        let keys = derive_channel_binding_keys(&[0x11u8; 32], &[0x22u8; 32]);

        // (a) Bidirectional 64 KiB round-trip across multiple bound frames
        let (wire_a, wire_b) = duplex(1 << 16);
        let mut bridge_end = wrap_bound_stream(Box::new(wire_a), keys.b2e, keys.e2b);
        let mut entry_end = wrap_bound_stream(Box::new(wire_b), keys.e2b, keys.b2e);

        let msg: Vec<u8> = (0..65_536u32).map(|i| (i % 251) as u8).collect();
        let msg_clone = msg.clone();
        let echo_task = tokio::spawn(async move {
            let mut got = vec![0u8; msg_clone.len()];
            entry_end.read_exact(&mut got).await.unwrap();
            assert_eq!(got, msg_clone);
            entry_end.write_all(b"ENTRY-ACK").await.unwrap();
            entry_end.shutdown().await.unwrap();
        });
        bridge_end.write_all(&msg).await.unwrap();
        let mut ack = [0u8; 9];
        bridge_end.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"ENTRY-ACK");
        echo_task.await.unwrap();

        // (b) Live wire byte injection: middlebox flips 1 bit in payload -> receiver drops cleanly
        let (mut raw_tx, wire_rx) = duplex(4096);
        let mut bound_rx = wrap_bound_stream(Box::new(wire_rx), keys.e2b, keys.b2e);
        let mut frame0 = seal_bound_frame(&keys.b2e, 0, b"legit-packet").unwrap();
        let last = frame0.len() - 1;
        frame0[last] ^= 0x01; // inject 1-bit tamper on wire
        raw_tx.write_all(&frame0).await.unwrap();
        raw_tx.shutdown().await.unwrap();
        let mut out = Vec::new();
        let n = bound_rx.read_to_end(&mut out).await.unwrap();
        assert_eq!(n, 0, "tampered wire frame must deliver 0 bytes and close stream");

        // (c) Live wire frame replay: send valid frame seq=0 twice -> 2nd copy rejected
        let (mut raw_tx2, wire_rx2) = duplex(4096);
        let mut bound_rx2 = wrap_bound_stream(Box::new(wire_rx2), keys.e2b, keys.b2e);
        let valid_f0 = seal_bound_frame(&keys.b2e, 0, b"first-only").unwrap();
        raw_tx2.write_all(&valid_f0).await.unwrap();
        raw_tx2.write_all(&valid_f0).await.unwrap(); // replay seq=0 at expected seq=1
        raw_tx2.shutdown().await.unwrap();
        let mut out2 = Vec::new();
        bound_rx2.read_to_end(&mut out2).await.unwrap();
        assert_eq!(out2, b"first-only", "replayed second frame must be rejected cleanly");
    }
}
