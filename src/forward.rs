//! L4 Port Forwarding on Entry (TCP single/remap/range + real UDP relay) with per-port quotas,
//! monotonic Token Bucket rate pacing, optional HAProxy PROXY Protocol v2 client-IP forwarding
//! (`proxy=v2`), live per-user connection tracking, and Control API telemetry.
//!
//! Spec grammar (`--forward SPEC`, repeatable):
//!   "443"                                         -> 0.0.0.0:443/tcp -> 127.0.0.1:443
//!   "8080=80"                                     -> 0.0.0.0:8080/tcp -> 127.0.0.1:80
//!   "2053/udp"                                    -> 0.0.0.0:2053/udp -> 127.0.0.1:2053
//!   "2000-2010"                                   -> 0.0.0.0:2000..=2010/tcp -> 127.0.0.1:p
//!   "443@name=VLESS,target=127.0.0.1:443,quota=1000G,rate=100M,proxy=v2,failover=helsinki"
//!
//! Security bounds:
//!   * Port ranges are capped at MAX_PORTS_PER_RANGE (64) to prevent accidental FD exhaustion.
//!   * Exit still enforces its own anti-SSRF destination policy (`is_prohibited_destination`).

use crate::link::{Link, CHUNK};
use crate::recovery::AdaptiveRuntime;
use crate::stats;
use crate::util::{addr_len, encode_sockaddr, now_unix};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

pub const MAX_PORTS_PER_RANGE: u16 = 64;
const UDP_FWD_IDLE: Duration = Duration::from_secs(120);

/// 12-byte HAProxy PROXY Protocol v2 binary signature.
pub const PROXY_V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Encode a binary HAProxy PROXY Protocol v2 header conveying the real client `src` and
/// Entry listener `dst` address/port to backend panels (Xray, 3x-ui, Marzban, Nginx, etc.).
pub fn encode_proxy_v2_header(src: SocketAddr, dst: SocketAddr, proto: ForwardProto) -> Vec<u8> {
    let normalize = |ip: IpAddr| -> IpAddr {
        match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            v4 => v4,
        }
    };
    let s_ip = normalize(src.ip());
    let d_ip = normalize(dst.ip());

    match (s_ip, d_ip) {
        (IpAddr::V4(sv4), IpAddr::V4(dv4)) => {
            let fam_proto = match proto {
                ForwardProto::Tcp => 0x11u8, // AF_INET + STREAM
                ForwardProto::Udp => 0x12u8, // AF_INET + DGRAM
            };
            let mut out = Vec::with_capacity(28);
            out.extend_from_slice(&PROXY_V2_SIG);
            out.push(0x21); // Version 2, Command PROXY (1)
            out.push(fam_proto);
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&sv4.octets());
            out.extend_from_slice(&dv4.octets());
            out.extend_from_slice(&src.port().to_be_bytes());
            out.extend_from_slice(&dst.port().to_be_bytes());
            out
        }
        (s_any, d_any) => {
            let sv6 = match s_any {
                IpAddr::V6(v6) => v6,
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            };
            let dv6 = match d_any {
                IpAddr::V6(v6) => v6,
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            };
            let fam_proto = match proto {
                ForwardProto::Tcp => 0x21u8, // AF_INET6 + STREAM
                ForwardProto::Udp => 0x22u8, // AF_INET6 + DGRAM
            };
            let mut out = Vec::with_capacity(52);
            out.extend_from_slice(&PROXY_V2_SIG);
            out.push(0x21); // Version 2, Command PROXY (1)
            out.push(fam_proto);
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&sv6.octets());
            out.extend_from_slice(&dv6.octets());
            out.extend_from_slice(&src.port().to_be_bytes());
            out.extend_from_slice(&dst.port().to_be_bytes());
            out
        }
    }
}

/// Monotonic Token Bucket rate limiter (accurate across low and high bitrates without RTT spikes).
pub struct TokenBucket {
    rate_bps: f64,
    capacity: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate_bps: u64) -> Self {
        let r = rate_bps.max(1024) as f64;
        let cap = (r * 0.25).clamp(1500.0, (CHUNK as f64) * 2.0);
        Self {
            rate_bps: r,
            capacity: cap,
            tokens: cap,
            last: Instant::now(),
        }
    }

    pub async fn consume(&mut self, bytes: usize) {
        let mut remaining = bytes as f64;
        while remaining > 0.0 {
            let now = Instant::now();
            let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
            self.last = now;
            self.tokens = (self.tokens + elapsed * self.rate_bps).min(self.capacity);
            let take = remaining.min(self.capacity);
            if self.tokens >= take {
                self.tokens -= take;
                remaining -= take;
            } else {
                let deficit = take - self.tokens;
                let wait_secs = (deficit / self.rate_bps).clamp(0.001, 0.1);
                sleep(Duration::from_secs_f64(wait_secs)).await;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardProto {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardMode {
    Userspace,
    KernelTransparent,
}

impl ForwardMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ForwardMode::Userspace => "userspace",
            ForwardMode::KernelTransparent => "kernel",
        }
    }
}

impl ForwardProto {
    pub fn as_str(self) -> &'static str {
        match self {
            ForwardProto::Tcp => "tcp",
            ForwardProto::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardSpec {
    pub raw_port: String,
    pub bind_ip: String,
    pub listen_start: u16,
    pub listen_end: u16,
    pub target_host: String,
    pub target_port: Option<u16>, // None => mirror listen port
    pub proto: ForwardProto,
    pub name: String,
    pub tunnel_label: String,
    pub failover_label: String,
    pub quota_bytes: Option<u64>,
    pub rate_bps: Option<u64>,
    pub proxy_v2: bool,
    pub mode: ForwardMode,
}

impl ForwardSpec {
    /// Parse a compact size/rate suffix: e.g. "50G", "1T", "100M", "512K".
    pub fn parse_scaled_bytes(s: &str) -> Result<u64> {
        let s = s.trim().to_ascii_uppercase();
        if s.is_empty() {
            bail!("empty numeric value");
        }
        let (num_part, mult) = if let Some(n) = s.strip_suffix("TB").or_else(|| s.strip_suffix('T')) {
            (n, 1024u64 * 1024 * 1024 * 1024)
        } else if let Some(n) = s.strip_suffix("GB").or_else(|| s.strip_suffix('G')) {
            (n, 1024u64 * 1024 * 1024)
        } else if let Some(n) = s.strip_suffix("MB").or_else(|| s.strip_suffix('M')) {
            (n, 1024u64 * 1024)
        } else if let Some(n) = s.strip_suffix("KB").or_else(|| s.strip_suffix('K')) {
            (n, 1024u64)
        } else {
            (s.as_str(), 1u64)
        };
        let v: u64 = num_part.trim().parse().context("invalid scaled integer")?;
        v.checked_mul(mult).context("scaled integer overflow")
    }

    pub fn parse(input: &str) -> Result<Self> {
        let (port_expr, opts) = match input.split_once('@') {
            Some((p, o)) => (p.trim(), Some(o.trim())),
            None => (input.trim(), None),
        };
        if port_expr.is_empty() {
            bail!("empty forward spec");
        }
        let (base_port, proto) = if let Some(p) = port_expr.strip_suffix("/udp") {
            (p, ForwardProto::Udp)
        } else if let Some(p) = port_expr.strip_suffix("/tcp") {
            (p, ForwardProto::Tcp)
        } else {
            (port_expr, ForwardProto::Tcp)
        };

        let (listen_start, listen_end, target_port) = if let Some((l, r)) = base_port.split_once('=') {
            let lp: u16 = l.parse().context("bad listen port")?;
            let rp: u16 = r.parse().context("bad target port")?;
            if lp == 0 || rp == 0 {
                bail!("port cannot be 0");
            }
            (lp, lp, Some(rp))
        } else if let Some((a, b)) = base_port.split_once('-') {
            let s: u16 = a.parse().context("bad range start")?;
            let e: u16 = b.parse().context("bad range end")?;
            if s == 0 || e < s {
                bail!("invalid port range {a}-{b}");
            }
            let count = e - s + 1;
            if count > MAX_PORTS_PER_RANGE {
                bail!(
                    "port range {s}-{e} ({count} ports) exceeds MAX_PORTS_PER_RANGE ({MAX_PORTS_PER_RANGE})"
                );
            }
            (s, e, None)
        } else {
            let p: u16 = base_port.parse().context("bad port number")?;
            if p == 0 {
                bail!("port cannot be 0");
            }
            (p, p, Some(p))
        };

        let mut spec = ForwardSpec {
            raw_port: port_expr.to_string(),
            bind_ip: "0.0.0.0".to_string(),
            listen_start,
            listen_end,
            target_host: "127.0.0.1".to_string(),
            target_port,
            proto,
            name: "-".to_string(),
            tunnel_label: "default".to_string(),
            failover_label: "-".to_string(),
            quota_bytes: None,
            rate_bps: None,
            proxy_v2: false,
            mode: ForwardMode::Userspace,
        };

        if let Some(opt_str) = opts {
            for kv in opt_str.split(',').filter(|s| !s.trim().is_empty()) {
                let (k, v) = kv
                    .split_once('=')
                    .with_context(|| format!("bad forward option '{kv}' (expected k=v)"))?;
                let (k, v) = (k.trim(), v.trim());
                match k {
                    "name" => spec.name = v.to_string(),
                    "bind" => spec.bind_ip = v.to_string(),
                    "tunnel" => spec.tunnel_label = v.to_string(),
                    "failover" => spec.failover_label = v.to_string(),
                    "quota" => spec.quota_bytes = Some(Self::parse_scaled_bytes(v)?),
                    "rate" => {
                        let bits_per_sec = Self::parse_scaled_bytes(v)?;
                        spec.rate_bps = Some((bits_per_sec / 8).max(1024));
                    }
                    "mode" => {
                        match v.to_ascii_lowercase().as_str() {
                            "kernel" | "transparent" | "dnat" => spec.mode = ForwardMode::KernelTransparent,
                            "userspace" | "proxy" | "default" => spec.mode = ForwardMode::Userspace,
                            _ => bail!("unsupported forward mode '{v}' (expected userspace or kernel)"),
                        }
                    }
                    "transparent" => {
                        match v.to_ascii_lowercase().as_str() {
                            "true" | "1" | "on" | "yes" => spec.mode = ForwardMode::KernelTransparent,
                            "false" | "0" | "off" | "no" => spec.mode = ForwardMode::Userspace,
                            _ => bail!("invalid transparent flag '{v}'"),
                        }
                    }
                    "proxy" | "proxy_protocol" => {
                        match v.to_ascii_lowercase().as_str() {
                            "v2" | "2" | "true" | "on" => spec.proxy_v2 = true,
                            "off" | "none" | "false" | "0" => spec.proxy_v2 = false,
                            _ => bail!("unsupported proxy protocol '{v}' (expected v2 or off)"),
                        }
                    }
                    "target" => {
                        if let Some((th, tp)) = v.rsplit_once(':') {
                            spec.target_host = th.trim_matches(|c| c == '[' || c == ']').to_string();
                            spec.target_port = Some(tp.parse().context("bad target port")?);
                        } else {
                            spec.target_host = v.to_string();
                        }
                    }
                    _ => bail!("unknown forward option '{k}'"),
                }
            }
        }
        Ok(spec)
    }

    /// Parse comma-separated port expressions sharing optional `@options` (e.g. `"443,2052,8443@name=Edge,proxy=v2"`).
    pub fn parse_many(input: &str) -> Result<Vec<Self>> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            bail!("empty forward spec");
        }
        let (ports_part, opts_suffix) = match trimmed.split_once('@') {
            Some((p, o)) => (p.trim(), Some(o.trim())),
            None => (trimmed, None),
        };
        let parts: Vec<&str> = ports_part
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if parts.is_empty() {
            bail!("empty port list in forward spec");
        }
        if parts.len() > MAX_PORTS_PER_RANGE as usize {
            bail!("too many comma-separated ports ({} > {MAX_PORTS_PER_RANGE})", parts.len());
        }
        let mut out = Vec::with_capacity(parts.len());
        for p in parts {
            let single = match opts_suffix {
                Some(o) => format!("{p}@{o}"),
                None => p.to_string(),
            };
            out.push(Self::parse(&single)?);
        }
        Ok(out)
    }

    pub fn target_for_listen_port(&self, listen_port: u16) -> (String, u16) {
        (self.target_host.clone(), self.target_port.unwrap_or(listen_port))
    }
}

#[derive(Clone, Debug)]
pub struct ActiveUserSnap {
    pub peer: String,
    pub proto: &'static str,
    pub age_secs: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[derive(Clone, Debug)]
pub struct ForwardSnap {
    pub port: String,
    pub proto: &'static str,
    pub name: String,
    pub tunnel: String,
    pub target: String,
    pub failover: String,
    pub state: &'static str,
    pub users: usize,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub quota_bytes: u64,
    pub rate_bps: u64,
    pub proxy_v2: bool,
    pub mode: &'static str,
    pub counted_since: u64,
    pub active_users: Vec<ActiveUserSnap>,
}

struct ActiveUserEntry {
    peer: String,
    proto: &'static str,
    started: Instant,
    bytes_up: Arc<AtomicU64>,
    bytes_down: Arc<AtomicU64>,
}

pub struct ForwardState {
    pub spec: ForwardSpec,
    pub enabled: AtomicBool,
    pub counted_since: u64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    next_user_id: AtomicU64,
    users: Mutex<HashMap<u64, ActiveUserEntry>>,
}

pub struct UserSessionGuard {
    id: u64,
    state: Arc<ForwardState>,
    pub bytes_up: Arc<AtomicU64>,
    pub bytes_down: Arc<AtomicU64>,
}

impl Drop for UserSessionGuard {
    fn drop(&mut self) {
        self.state.users.lock().unwrap().remove(&self.id);
    }
}

impl ForwardState {
    pub fn new(spec: ForwardSpec) -> Arc<Self> {
        Arc::new(Self {
            spec,
            enabled: AtomicBool::new(true),
            counted_since: now_unix(),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            next_user_id: AtomicU64::new(1),
            users: Mutex::new(HashMap::new()),
        })
    }

    pub fn used_bytes(&self) -> u64 {
        self.bytes_up.load(Relaxed).saturating_add(self.bytes_down.load(Relaxed))
    }

    pub fn quota_reached(&self) -> bool {
        self.spec
            .quota_bytes
            .map_or(false, |q| self.used_bytes() >= q)
    }

    pub fn state_label(&self) -> &'static str {
        if !self.enabled.load(Relaxed) {
            "off"
        } else if self.quota_reached() {
            "quota reached"
        } else {
            "on"
        }
    }

    pub fn add_usage(&self, up: u64, down: u64) {
        if up > 0 {
            self.bytes_up.fetch_add(up, Relaxed);
        }
        if down > 0 {
            self.bytes_down.fetch_add(down, Relaxed);
        }
    }

    pub fn register_user(self: &Arc<Self>, peer: SocketAddr) -> UserSessionGuard {
        let id = self.next_user_id.fetch_add(1, Relaxed);
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        self.users.lock().unwrap().insert(
            id,
            ActiveUserEntry {
                peer: peer.to_string(),
                proto: self.spec.proto.as_str(),
                started: Instant::now(),
                bytes_up: up.clone(),
                bytes_down: down.clone(),
            },
        );
        UserSessionGuard {
            id,
            state: self.clone(),
            bytes_up: up,
            bytes_down: down,
        }
    }

    pub fn snapshot(&self) -> ForwardSnap {
        let users_map = self.users.lock().unwrap();
        let mut active_users: Vec<ActiveUserSnap> = users_map
            .values()
            .map(|u| ActiveUserSnap {
                peer: u.peer.clone(),
                proto: u.proto,
                age_secs: u.started.elapsed().as_secs(),
                bytes_up: u.bytes_up.load(Relaxed),
                bytes_down: u.bytes_down.load(Relaxed),
            })
            .collect();
        active_users.sort_by(|a, b| b.bytes_down.cmp(&a.bytes_down));
        active_users.truncate(32);

        let target = match self.spec.target_port {
            Some(p) => format!("{}:{p}", self.spec.target_host),
            None => format!("{}:{}-{}", self.spec.target_host, self.spec.listen_start, self.spec.listen_end),
        };

        ForwardSnap {
            port: self.spec.raw_port.clone(),
            proto: self.spec.proto.as_str(),
            name: self.spec.name.clone(),
            tunnel: self.spec.tunnel_label.clone(),
            target,
            failover: self.spec.failover_label.clone(),
            state: self.state_label(),
            users: users_map.len(),
            bytes_up: self.bytes_up.load(Relaxed),
            bytes_down: self.bytes_down.load(Relaxed),
            quota_bytes: self.spec.quota_bytes.unwrap_or(0),
            rate_bps: self.spec.rate_bps.unwrap_or(0),
            proxy_v2: self.spec.proxy_v2,
            mode: self.spec.mode.as_str(),
            counted_since: self.counted_since,
            active_users,
        }
    }
}

pub struct ForwardRegistry {
    entries: Mutex<Vec<Arc<ForwardState>>>,
}

impl ForwardRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(Vec::new()),
        })
    }

    pub fn register(&self, spec: ForwardSpec) -> Arc<ForwardState> {
        let st = ForwardState::new(spec);
        self.entries.lock().unwrap().push(st.clone());
        st
    }

    pub fn remove_by_port(&self, port_label: &str) -> usize {
        let mut list = self.entries.lock().unwrap();
        let before = list.len();
        list.retain(|f| {
            if f.spec.raw_port == port_label {
                f.enabled.store(false, Relaxed);
                false
            } else {
                true
            }
        });
        before - list.len()
    }

    pub fn snapshot(&self) -> Vec<ForwardSnap> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.snapshot())
            .collect()
    }
}

/// Encode SOCKS5-style address payload (ATYP + ADDR + PORT).
pub fn encode_target_addr(host: &str, port: u16) -> Result<Vec<u8>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(encode_sockaddr(SocketAddr::new(ip, port)));
    }
    let hb = host.as_bytes();
    if hb.is_empty() || hb.len() > 255 {
        bail!("invalid forward target host '{host}'");
    }
    let mut addr = Vec::with_capacity(4 + hb.len());
    addr.push(3);
    addr.push(hb.len() as u8);
    addr.extend_from_slice(hb);
    addr.extend_from_slice(&port.to_be_bytes());
    Ok(addr)
}

/// Encode target host:port as a SOCKS5-style address payload for Exit `0x01` TCP connect.
pub fn encode_target_req(host: &str, port: u16) -> Result<Vec<u8>> {
    let mut req = vec![1u8];
    req.extend_from_slice(&encode_target_addr(host, port)?);
    Ok(req)
}

/// Relay TCP bytes between a forwarded client and a Noise `Link` while enforcing quota,
/// Token Bucket rate pacing, optional PROXY Protocol v2 header injection, and live accounting.
pub async fn pipe_forwarded_tcp(
    link: Link,
    tcp: TcpStream,
    fwd: Arc<ForwardState>,
    user: UserSessionGuard,
) -> Result<()> {
    pipe_forwarded_tcp_adaptive(link, tcp, fwd, user, None).await
}

pub async fn pipe_forwarded_tcp_adaptive(
    link: Link,
    tcp: TcpStream,
    fwd: Arc<ForwardState>,
    user: UserSessionGuard,
    adaptive: Option<Arc<AdaptiveRuntime>>,
) -> Result<()> {
    stats::STREAMS_TOTAL.fetch_add(1, Relaxed);
    stats::STREAMS_ACTIVE.fetch_add(1, Relaxed);
    let peer_sa = tcp
        .peer_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let local_sa = tcp
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], fwd.spec.listen_start)));
    let r = pipe_forwarded_inner(link, tcp, peer_sa, local_sa, &fwd, &user, adaptive.as_deref()).await;
    stats::STREAMS_ACTIVE.fetch_sub(1, Relaxed);
    r
}

async fn pipe_forwarded_inner(
    link: Link,
    tcp: TcpStream,
    peer_sa: SocketAddr,
    local_sa: SocketAddr,
    fwd: &ForwardState,
    user: &UserSessionGuard,
    adaptive: Option<&AdaptiveRuntime>,
) -> Result<()> {
    let (mut tr, mut tw) = tcp.into_split();
    let (mut lr, mut lw) = link.split();
    let rate_bps = fwd.spec.rate_bps;
    let send_proxy_v2 = fwd.spec.proxy_v2;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let shared_bucket = rate_bps.map(|r| Arc::new(tokio::sync::Mutex::new(TokenBucket::new(r))));

    let stop_tx_up = stop_tx.clone();
    let mut stop_rx_up = stop_rx.clone();
    let bucket_up = shared_bucket.clone();
    let up = async move {
        if send_proxy_v2 {
            let hdr = encode_proxy_v2_header(peer_sa, local_sa, ForwardProto::Tcp);
            lw.send(&hdr).await?;
        }
        let mut buf = vec![0u8; CHUNK];
        loop {
            if fwd.quota_reached() || !fwd.enabled.load(Relaxed) {
                let _ = lw.send(&[]).await;
                let _ = stop_tx_up.send(true);
                return Ok::<(), anyhow::Error>(());
            }
            let lim = adaptive
                .map(|a| a.current_chunk_size().min(CHUNK))
                .unwrap_or(CHUNK);
            let n = tokio::select! {
                r = stop_rx_up.wait_for(|&v| v) => {
                    drop(r);
                    0
                }
                r = tr.read(&mut buf[..lim]) => r?,
            };
            if n == 0 {
                lw.send(&[]).await?;
                return Ok::<(), anyhow::Error>(());
            }
            if let Some(ref b) = bucket_up {
                b.lock().await.consume(n).await;
            }
            let n64 = n as u64;
            stats::BYTES_UP.fetch_add(n64, Relaxed);
            fwd.bytes_up.fetch_add(n64, Relaxed);
            user.bytes_up.fetch_add(n64, Relaxed);
            lw.send(&buf[..n]).await?;
            if let Some(a) = adaptive {
                let p_us = a.current_pacing_us();
                if p_us > 0 {
                    sleep(Duration::from_micros(p_us)).await;
                }
            }
            if fwd.quota_reached() || !fwd.enabled.load(Relaxed) {
                let _ = lw.send(&[]).await;
                let _ = stop_tx_up.send(true);
                return Ok(());
            }
        }
    };

    let stop_tx_dn = stop_tx;
    let mut stop_rx_dn = stop_rx;
    let bucket_dn = shared_bucket;
    let down = async move {
        let mut plain = vec![0u8; CHUNK + 16];
        loop {
            if fwd.quota_reached() || !fwd.enabled.load(Relaxed) {
                let _ = tw.shutdown().await;
                let _ = stop_tx_dn.send(true);
                return Ok::<(), anyhow::Error>(());
            }
            let n = tokio::select! {
                r = stop_rx_dn.wait_for(|&v| v) => {
                    drop(r);
                    0
                }
                r = lr.recv_into(&mut plain) => r?,
            };
            if n == 0 {
                let _ = tw.shutdown().await;
                return Ok::<(), anyhow::Error>(());
            }
            if let Some(ref b) = bucket_dn {
                b.lock().await.consume(n).await;
            }
            let n64 = n as u64;
            stats::BYTES_DOWN.fetch_add(n64, Relaxed);
            fwd.bytes_down.fetch_add(n64, Relaxed);
            user.bytes_down.fetch_add(n64, Relaxed);
            tw.write_all(&plain[..n]).await?;
            if fwd.quota_reached() || !fwd.enabled.load(Relaxed) {
                let _ = tw.shutdown().await;
                let _ = stop_tx_dn.send(true);
                return Ok(());
            }
        }
    };

    tokio::try_join!(up, down)?;
    Ok(())
}

/// Real L4 UDP forward session relay for a single client peer over a `[2]` UDP Link.
pub async fn relay_forwarded_udp(
    link: Link,
    listen_sock: Arc<UdpSocket>,
    peer: SocketAddr,
    target_addr_prefix: Vec<u8>,
    mut rx_from_client: mpsc::Receiver<Vec<u8>>,
    fwd: Arc<ForwardState>,
    user: UserSessionGuard,
) -> Result<()> {
    stats::UDP_FORWARDS_ACTIVE.fetch_add(1, Relaxed);
    let r = relay_forwarded_udp_inner(
        link,
        listen_sock,
        peer,
        target_addr_prefix,
        &mut rx_from_client,
        &fwd,
        &user,
    )
    .await;
    stats::UDP_FORWARDS_ACTIVE.fetch_sub(1, Relaxed);
    r
}

async fn relay_forwarded_udp_inner(
    link: Link,
    listen_sock: Arc<UdpSocket>,
    peer: SocketAddr,
    target_addr_prefix: Vec<u8>,
    rx_from_client: &mut mpsc::Receiver<Vec<u8>>,
    fwd: &ForwardState,
    user: &UserSessionGuard,
) -> Result<()> {
    let (mut lr, mut lw) = link.split();
    let rate_bps = fwd.spec.rate_bps;
    let send_proxy_v2 = fwd.spec.proxy_v2;
    let local_udp = listen_sock
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], fwd.spec.listen_start)));

    let up = async {
        let mut frame = Vec::with_capacity(CHUNK);
        let mut bucket = rate_bps.map(TokenBucket::new);
        loop {
            if fwd.quota_reached() || !fwd.enabled.load(Relaxed) {
                return Ok::<(), anyhow::Error>(());
            }
            let Some(pkt) = timeout(UDP_FWD_IDLE, rx_from_client.recv()).await.ok().flatten() else {
                return Ok(());
            };
            let proxy_hdr = if send_proxy_v2 {
                encode_proxy_v2_header(peer, local_udp, ForwardProto::Udp)
            } else {
                Vec::new()
            };
            if target_addr_prefix.len() + proxy_hdr.len() + pkt.len() > CHUNK {
                continue;
            }
            if let Some(ref mut b) = bucket {
                b.consume(pkt.len()).await;
            }
            frame.clear();
            frame.extend_from_slice(&target_addr_prefix);
            if !proxy_hdr.is_empty() {
                frame.extend_from_slice(&proxy_hdr);
            }
            frame.extend_from_slice(&pkt);
            let n64 = pkt.len() as u64;
            stats::BYTES_UP.fetch_add(n64, Relaxed);
            fwd.bytes_up.fetch_add(n64, Relaxed);
            user.bytes_up.fetch_add(n64, Relaxed);
            lw.send(&frame).await?;
        }
    };

    let down = async {
        let mut plain = vec![0u8; CHUNK + 64];
        let mut bucket = rate_bps.map(TokenBucket::new);
        loop {
            if fwd.quota_reached() || !fwd.enabled.load(Relaxed) {
                return Ok::<(), anyhow::Error>(());
            }
            let n = match timeout(UDP_FWD_IDLE, lr.recv_into(&mut plain)).await {
                Ok(Ok(0)) | Err(_) => return Ok::<(), anyhow::Error>(()),
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
            };
            let Some(alen) = addr_len(&plain[..n]) else {
                continue;
            };
            let payload = &plain[alen..n];
            if let Some(ref mut b) = bucket {
                b.consume(payload.len()).await;
            }
            let n64 = payload.len() as u64;
            stats::BYTES_DOWN.fetch_add(n64, Relaxed);
            fwd.bytes_down.fetch_add(n64, Relaxed);
            user.bytes_down.fetch_add(n64, Relaxed);
            let _ = listen_sock.send_to(payload, peer).await;
        }
    };

    tokio::select! {
        r = up => r,
        r = down => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_spec_parsing_and_bounds() {
        let s1 = ForwardSpec::parse("443@name=VLESS,quota=1T,rate=100M,proxy=v2,failover=helsinki").unwrap();
        assert_eq!(s1.listen_start, 443);
        assert_eq!(s1.listen_end, 443);
        assert_eq!(s1.name, "VLESS");
        assert!(s1.proxy_v2);
        assert_eq!(s1.quota_bytes, Some(1024u64.pow(4)));
        assert_eq!(s1.failover_label, "helsinki");

        let s2 = ForwardSpec::parse("8080=80@name=Mirror,quota=50G").unwrap();
        assert_eq!(s2.listen_start, 8080);
        assert_eq!(s2.target_port, Some(80));
        assert!(!s2.proxy_v2);

        let s3 = ForwardSpec::parse("2053/udp@name=Games,proxy=v2").unwrap();
        assert_eq!(s3.proto, ForwardProto::Udp);
        assert_eq!(s3.listen_start, 2053);
        assert!(s3.proxy_v2);

        let s4 = ForwardSpec::parse("2000-2010").unwrap();
        assert_eq!((s4.listen_start, s4.listen_end), (2000, 2010));
        assert_eq!(s4.target_for_listen_port(2005).1, 2005);

        // Oversized port range MUST be rejected to prevent FD exhaustion
        assert!(ForwardSpec::parse("1-65535").is_err());
        assert!(ForwardSpec::parse("1000-1100").is_err());
    }

    #[test]
    fn proxy_v2_header_encodes_ipv4_and_ipv6_correctly() {
        let src4: SocketAddr = "198.51.100.42:54321".parse().unwrap();
        let dst4: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let hdr4 = encode_proxy_v2_header(src4, dst4, ForwardProto::Tcp);
        assert_eq!(hdr4.len(), 28);
        assert_eq!(&hdr4[..12], &PROXY_V2_SIG);
        assert_eq!(hdr4[12], 0x21); // v2 PROXY
        assert_eq!(hdr4[13], 0x11); // IPv4 TCP
        assert_eq!(&hdr4[14..16], &12u16.to_be_bytes());
        assert_eq!(&hdr4[16..20], &[198, 51, 100, 42]);
        assert_eq!(&hdr4[20..24], &[203, 0, 113, 10]);
        assert_eq!(&hdr4[24..26], &54321u16.to_be_bytes());
        assert_eq!(&hdr4[26..28], &443u16.to_be_bytes());

        let src6: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();
        let dst6: SocketAddr = "[2001:db8::2]:8443".parse().unwrap();
        let hdr6 = encode_proxy_v2_header(src6, dst6, ForwardProto::Udp);
        assert_eq!(hdr6.len(), 52);
        assert_eq!(hdr6[12], 0x21);
        assert_eq!(hdr6[13], 0x22); // IPv6 UDP
        assert_eq!(&hdr6[14..16], &36u16.to_be_bytes());
    }

    #[test]
    fn forward_quota_triggers_quota_reached_state() {
        let spec = ForwardSpec::parse("8080=80@name=Mirror,quota=10K").unwrap();
        let st = ForwardState::new(spec);
        assert_eq!(st.state_label(), "on");
        st.add_usage(4096, 4096);
        assert_eq!(st.state_label(), "on");
        st.add_usage(2048, 0);
        assert!(st.quota_reached());
        assert_eq!(st.state_label(), "quota reached");
    }

    #[tokio::test]
    async fn token_bucket_enforces_low_rate_without_cap_bypass() {
        let mut tb = TokenBucket::new(10_000); // 10 KB/s (80 kbps, well below old 524 kbps floor)
        let t0 = Instant::now();
        tb.consume(2500).await; // consumes initial burst capacity
        tb.consume(1500).await; // must pace ~150ms
        assert!(t0.elapsed() >= Duration::from_millis(80));
    }
}
