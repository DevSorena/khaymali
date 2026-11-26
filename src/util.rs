//! Shared helpers: randomness, hex, constant-time compare, 12-char & SHA-256 root fingerprints,
//! IP prefix bucketing (/24 & /64), safe manifest state dir reservation, and anti-SSRF /
//! anti-DNS-rebinding destination policy (SPEC §1.2, §2.3, §4.1).

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::lookup_host;
use tokio::time::{timeout, Duration};

/// Reserved path for Phase 3 Signed Exit Manifest anti-rollback state (SPEC §2.3).
pub const MANIFEST_STATE_PATH: &str = "/var/lib/khaymali/manifest.state";

/// Safely creates and secures the parent directory for `MANIFEST_STATE_PATH`.
/// Refuses to `chmod` system/arbitrary directories: the parent directory's leaf name MUST
/// literally be `"khaymali"` (prevents accidental `chmod 0700` on `/var/lib` or `/tmp`).
pub fn ensure_manifest_state_dir(path: &str) -> Result<()> {
    let p = std::path::Path::new(path);
    let Some(parent) = p.parent() else {
        bail!("manifest state path has no parent directory");
    };
    if parent.file_name() != Some(OsStr::new("khaymali")) {
        bail!(
            "refusing to manage manifest directory '{}': leaf directory must be named 'khaymali'",
            parent.display()
        );
    }
    let existed = parent.exists();
    std::fs::create_dir_all(parent)?;
    if !existed {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

pub trait Rw: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Rw for T {}
pub type BoxRw = Box<dyn Rw>;

/// Prefix bucket key: IPv4 `/24` or IPv6 `/64` (prevents IPv6 rotation bypass, SPEC §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrefixKey {
    V4([u8; 3]),
    V6([u16; 4]),
}

pub fn ip_prefix_key(ip: IpAddr) -> PrefixKey {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            PrefixKey::V4([o[0], o[1], o[2]])
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            PrefixKey::V6([s[0], s[1], s[2], s[3]])
        }
    }
}

pub fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS randomness unavailable");
    b
}

pub fn fill_random(b: &mut [u8]) {
    getrandom::getrandom(b).expect("OS randomness unavailable");
}

pub fn rand_range(lo: usize, hi: usize) -> usize {
    if hi <= lo {
        return lo;
    }
    let r = u32::from_be_bytes(rand_bytes::<4>()) as usize;
    lo + r % (hi - lo + 1)
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// 6-char UI quick label (`XXX-XXX`, ~30 bits) — visual UI tag ONLY, never security proof.
pub fn check_code_short(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(7);
    for i in 0..6 {
        if i == 3 {
            out.push('-');
        }
        out.push(ALPHABET[(digest[i] as usize) % ALPHABET.len()] as char);
    }
    out
}

/// 12-char out-of-band verification code (`XXXX-XXXX-XXXX`, ~60 bits, SPEC §2.3).
pub fn root_check_code(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(14);
    for i in 0..12 {
        if i == 4 || i == 8 {
            out.push('-');
        }
        out.push(ALPHABET[(digest[i] as usize) % ALPHABET.len()] as char);
    }
    out
}

/// Full 64-hex SHA-256 fingerprint for high-assurance out-of-band root verification (SPEC §2.3).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    hex(&d)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 || !s.is_ascii() {
        bail!("bad hex string");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}

pub fn addr_len(b: &[u8]) -> Option<usize> {
    let n = match *b.first()? {
        1 => 7,
        4 => 19,
        3 => 2 + *b.get(1)? as usize + 2,
        _ => return None,
    };
    (b.len() >= n).then_some(n)
}

pub fn parse_addr(b: &[u8]) -> Result<(String, u16, usize)> {
    let Some(n) = addr_len(b) else { bail!("bad address") };
    let host = match b[0] {
        1 => IpAddr::from([b[1], b[2], b[3], b[4]]).to_string(),
        4 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[1..17]);
            IpAddr::from(a).to_string()
        }
        _ => String::from_utf8(b[2..n - 2].to_vec())?,
    };
    Ok((host, u16::from_be_bytes([b[n - 2], b[n - 1]]), n))
}

pub fn encode_sockaddr(sa: SocketAddr) -> Vec<u8> {
    let mut v = Vec::with_capacity(19);
    match sa.ip() {
        IpAddr::V4(a) => {
            v.push(1);
            v.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            v.push(4);
            v.extend_from_slice(&a.octets());
        }
    }
    v.extend_from_slice(&sa.port().to_be_bytes());
    v
}

fn is_prohibited_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    // 0.0.0.0/8 ("This network", RFC 1122) — also blocks IPv4-compatible ::2 -> 0.0.0.2
    o[0] == 0
        || a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_documentation()
        || (o[0] == 100 && (o[1] & 0xc0) == 64)       // CGNAT 100.64.0.0/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)    // IETF 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18)       // Benchmarking 198.18.0.0/15
        || o[0] >= 240                                // Reserved 240.0.0.0/4
}

/// Comprehensive destination policy (SPEC §1.2, §4.1). Compatible with rustc 1.75.
pub fn is_prohibited_destination(ip: IpAddr, extra_nat64_96: &[[u16; 6]]) -> bool {
    match ip {
        IpAddr::V4(a) => is_prohibited_v4(a),
        IpAddr::V6(a) => {
            let s = a.segments();
            if a.is_loopback() || a.is_unspecified() || a.is_multicast() {
                return true;
            }
            let embedded_v4 = || {
                Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                )
            };
            if s[0..5] == [0, 0, 0, 0, 0] && (s[5] == 0xffff || s[5] == 0) {
                return is_prohibited_v4(embedded_v4());
            }
            let is_wk_nat64 = s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0];
            let is_extra_nat64 = extra_nat64_96.iter().any(|p| s[0..6] == p[..]);
            if is_wk_nat64 || is_extra_nat64 {
                return is_prohibited_v4(embedded_v4());
            }
            // 6to4 2002::/16 (RFC 3056) and Teredo 2001:0000::/32 (RFC 4380)
            if s[0] == 0x2002 || (s[0] == 0x2001 && s[1] == 0x0000) {
                return true;
            }
            (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001)
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xffc0) == 0xfec0
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
        }
    }
}

pub fn is_private(ip: IpAddr) -> bool {
    is_prohibited_destination(ip, &[])
}

/// Validates a resolved address set atomically against DNS rebinding:
/// if `!allow_private` and ANY resolved IP is prohibited, the entire set is rejected (SPEC §1.1).
pub fn validate_resolved_addrs(addrs: Vec<SocketAddr>, allow_private: bool) -> Result<Vec<SocketAddr>> {
    if addrs.is_empty() {
        bail!("no addresses resolved");
    }
    if !allow_private {
        for sa in &addrs {
            if is_prohibited_destination(sa.ip(), &[]) {
                bail!("prohibited destination address {}", sa.ip());
            }
        }
    }
    Ok(addrs)
}

/// Resolve once with bounded timeout and return validated SocketAddrs (never re-resolve by hostname).
pub async fn resolve_validated(
    host: &str,
    port: u16,
    allow_private: bool,
    dns_timeout: Duration,
) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return validate_resolved_addrs(vec![SocketAddr::new(ip, port)], allow_private);
    }
    let resolved: Vec<SocketAddr> = timeout(dns_timeout, lookup_host((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("DNS lookup timeout"))??
        .collect();
    validate_resolved_addrs(resolved, allow_private)
}
