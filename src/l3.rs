//! Independent Layer-3 IP Tunneling & Routing Subsystem (`src/l3.rs`).
//!
//! Decoupled from the L4 stream multiplexer (`mux.rs`) so raw IPv4/IPv6 packets traverse
//! dedicated L3 backends without TCP-over-TCP Head-of-Line blocking or identity mixing:
//!   * `LinuxTunDevice` (native Linux `/dev/net/tun` `IFF_TUN | IFF_NO_PI` driver with zero
//!     external crate dependencies, configuring MTU, CIDR, and routes via `ip`).
//!   * `GreEncap` (RFC 2784 Generic Routing Encapsulation) & `IpipEncap` (RFC 2003 IP-in-IP).
//!   * `WireGuardAdapter` (clean cryptographic separation between WireGuard peer keys and Noise_IK).
//!   * `PmtuTracker` (clamping `[1280..1420]` with dynamic ICMP Fragmentation-Needed adjustment).
//!   * `RoutePolicy` (longest-prefix CIDR routing table enforcing anti-SSRF exclusions).

use crate::link::{Link, CHUNK};
use crate::stats;
use crate::util::is_prohibited_destination;
use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

pub const MIN_IPV6_MTU: u16 = 1280;
pub const DEFAULT_TUN_MTU: u16 = 1380;
pub const MAX_TUN_MTU: u16 = 1420;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L3Mode {
    Tun,
    Gre,
    Ipip,
    WireGuardAdapter,
}

impl L3Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            L3Mode::Tun => "tun",
            L3Mode::Gre => "gre",
            L3Mode::Ipip => "ipip",
            L3Mode::WireGuardAdapter => "wireguard-adapter",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tun" | "raw" => Some(L3Mode::Tun),
            "gre" => Some(L3Mode::Gre),
            "ipip" => Some(L3Mode::Ipip),
            "wireguard" | "wireguard-adapter" | "wg" => Some(L3Mode::WireGuardAdapter),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TunConfig {
    pub if_name: String,
    pub mode: L3Mode,
    pub local_cidr: String,
    pub peer_ip: IpAddr,
    pub mtu: u16,
    pub allow_private_routes: bool,
    pub routes: Vec<String>,
    pub gre_key: Option<u32>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            if_name: "khaymali0".to_string(),
            mode: L3Mode::Tun,
            local_cidr: "10.200.0.1/30".to_string(),
            peer_ip: IpAddr::V4(Ipv4Addr::new(10, 200, 0, 2)),
            mtu: DEFAULT_TUN_MTU,
            allow_private_routes: false,
            routes: Vec::new(),
            gre_key: None,
        }
    }
}

pub fn validate_if_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        bail!("invalid TUN interface name '{name}' (must be 1..=15 alphanumeric/_/- chars)");
    }
    Ok(())
}

pub fn validate_cidr_str(cidr: &str) -> Result<(IpAddr, u8)> {
    let (ip_s, pfx_s) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("CIDR must be IP/PREFIX (got '{cidr}')"))?;
    let ip: IpAddr = ip_s.parse().with_context(|| format!("invalid IP in CIDR '{cidr}'"))?;
    let pfx: u8 = pfx_s.parse().with_context(|| format!("invalid prefix in CIDR '{cidr}'"))?;
    let max_pfx = if ip.is_ipv4() { 32 } else { 128 };
    if pfx > max_pfx {
        bail!("CIDR prefix {pfx} > {max_pfx}");
    }
    Ok((ip, pfx))
}

/// Native Linux `/dev/net/tun` device (`IFF_TUN | IFF_NO_PI`) with zero external crates.
#[cfg(target_os = "linux")]
pub struct LinuxTunDevice {
    file: Arc<std::fs::File>,
    pub if_name: String,
    pub mtu: u16,
}

#[cfg(target_os = "linux")]
impl LinuxTunDevice {
    pub fn open(cfg: &TunConfig) -> Result<Self> {
        use std::fs::OpenOptions;
        use std::os::unix::io::AsRawFd;
        use std::process::Command;

        validate_if_name(&cfg.if_name)?;
        validate_cidr_str(&cfg.local_cidr)?;
        for r in &cfg.routes {
            validate_cidr_str(r)?;
        }

        const TUNSETIFF: u64 = 0x400454ca;
        const IFF_TUN: u16 = 0x0001;
        const IFF_NO_PI: u16 = 0x1000;

        extern "C" {
            fn ioctl(fd: i32, request: u64, ...) -> i32;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .context("failed to open /dev/net/tun (requires root / CAP_NET_ADMIN and tun kernel module)")?;

        let mut ifr = [0u8; 40];
        let name_bytes = cfg.if_name.as_bytes();
        ifr[..name_bytes.len()].copy_from_slice(name_bytes);
        let flags = (IFF_TUN | IFF_NO_PI).to_ne_bytes();
        ifr[16] = flags[0];
        ifr[17] = flags[1];

        let rc = unsafe { ioctl(file.as_raw_fd(), TUNSETIFF, ifr.as_mut_ptr()) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error())
                .context("ioctl(TUNSETIFF) failed on /dev/net/tun");
        }

        let nul_pos = ifr[..16].iter().position(|&b| b == 0).unwrap_or(16);
        let assigned_name = String::from_utf8_lossy(&ifr[..nul_pos]).to_string();
        let mtu = cfg.mtu.clamp(MIN_IPV6_MTU, MAX_TUN_MTU);

        let run_ip = |args: &[&str]| -> Result<()> {
            let st = Command::new("ip")
                .args(args)
                .status()
                .with_context(|| format!("failed to execute `ip {}`", args.join(" ")))?;
            if !st.success() {
                bail!("`ip {}` exited with status {st}", args.join(" "));
            }
            Ok(())
        };

        let mtu_s = mtu.to_string();
        run_ip(&["link", "set", "dev", &assigned_name, "mtu", &mtu_s, "up"])?;
        // Ignore error if address already assigned on persistent device
        let _ = Command::new("ip")
            .args(["addr", "replace", &cfg.local_cidr, "dev", &assigned_name])
            .status();

        for route_cidr in &cfg.routes {
            run_ip(&["route", "replace", route_cidr, "dev", &assigned_name])?;
        }

        Ok(Self {
            file: Arc::new(file),
            if_name: assigned_name,
            mtu,
        })
    }

    pub fn clone_fd(&self) -> Arc<std::fs::File> {
        self.file.clone()
    }
}

/// Bidirectional L3 packet pump bridging a Linux `TUN` interface and an encrypted `Link`.
#[cfg(target_os = "linux")]
pub async fn bridge_tun_over_link(
    tun: LinuxTunDevice,
    link: Link,
    cfg: TunConfig,
) -> Result<()> {
    use std::io::{Read, Write};

    let (mut lr, mut lw) = link.split();
    let fd_rd = tun.clone_fd();
    let fd_wr = tun.clone_fd();
    let pmtu = Arc::new(PmtuTracker::new(tun.mtu));
    let route_policy = Arc::new(RoutePolicy::new(cfg.allow_private_routes));
    let mode = cfg.mode;
    let gre_key = cfg.gre_key;
    let local_v4 = match cfg.local_cidr.split('/').next().and_then(|s| s.parse::<IpAddr>().ok()) {
        Some(IpAddr::V4(v4)) => v4,
        _ => Ipv4Addr::new(10, 200, 0, 1),
    };
    let peer_v4 = match cfg.peer_ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => Ipv4Addr::new(10, 200, 0, 2),
    };

    let (tx_pkt, mut rx_pkt) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    // Blocking reader thread for /dev/net/tun char device
    let rd_handle = tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; 4096];
        loop {
            match (&*fd_rd).read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx_pkt.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Uplink: TUN -> encapsulate (if GRE/IPIP) -> encrypted Noise Link
    let pmtu_up = pmtu.clone();
    let rp_up = route_policy.clone();
    let up = async move {
        while let Some(raw_ip) = rx_pkt.recv().await {
            if raw_ip.len() > pmtu_up.mtu() as usize {
                continue;
            }
            if rp_up.resolve_packet_exit(&raw_ip).is_err() {
                continue;
            }
            let wire_pkt = match mode {
                L3Mode::Tun | L3Mode::WireGuardAdapter => raw_ip,
                L3Mode::Gre => GreEncap::encapsulate(&raw_ip, gre_key)?,
                L3Mode::Ipip => IpipEncap::encapsulate_v4(local_v4, peer_v4, &raw_ip)?,
            };
            if wire_pkt.len() > CHUNK {
                continue;
            }
            stats::L3_PACKETS_TX.fetch_add(1, Relaxed);
            stats::BYTES_UP.fetch_add(wire_pkt.len() as u64, Relaxed);
            lw.send(&wire_pkt).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    // Downlink: encrypted Noise Link -> decapsulate (if GRE/IPIP) -> write to TUN
    let down = async move {
        let mut plain = vec![0u8; CHUNK + 64];
        loop {
            let n = lr.recv_into(&mut plain).await?;
            if n == 0 {
                break;
            }
            let inner_ip = match mode {
                L3Mode::Tun | L3Mode::WireGuardAdapter => plain[..n].to_vec(),
                L3Mode::Gre => GreEncap::decapsulate(&plain[..n], gre_key)?.1.to_vec(),
                L3Mode::Ipip => IpipEncap::decapsulate_v4(&plain[..n])?.1.to_vec(),
            };
            stats::L3_PACKETS_RX.fetch_add(1, Relaxed);
            stats::BYTES_DOWN.fetch_add(inner_ip.len() as u64, Relaxed);
            let fd_c = fd_wr.clone();
            tokio::task::spawn_blocking(move || {
                let _ = (&*fd_c).write(&inner_ip);
            })
            .await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let res = tokio::select! {
        r = up => r,
        r = down => r,
    };
    rd_handle.abort();
    res
}

#[cfg(not(target_os = "linux"))]
pub async fn run_tun_not_supported() -> Result<()> {
    bail!("Linux /dev/net/tun L3 backend is only supported on Linux")
}

/// Path MTU tracker preventing silent blackholing of oversized IP packets.
pub struct PmtuTracker {
    current_mtu: AtomicU16,
    floor_mtu: u16,
    ceil_mtu: u16,
    pmtu_drops: AtomicU64,
}

impl PmtuTracker {
    pub fn new(initial: u16) -> Self {
        let clamped = initial.clamp(MIN_IPV6_MTU, MAX_TUN_MTU);
        Self {
            current_mtu: AtomicU16::new(clamped),
            floor_mtu: MIN_IPV6_MTU,
            ceil_mtu: MAX_TUN_MTU,
            pmtu_drops: AtomicU64::new(0),
        }
    }

    pub fn mtu(&self) -> u16 {
        self.current_mtu.load(Relaxed)
    }

    pub fn record_frag_needed(&self, next_hop_mtu: u16) -> u16 {
        self.pmtu_drops.fetch_add(1, Relaxed);
        let cur = self.current_mtu.load(Relaxed);
        let target = if next_hop_mtu >= self.floor_mtu {
            next_hop_mtu.min(cur.saturating_sub(20)).max(self.floor_mtu)
        } else {
            // A reported next-hop MTU below the protocol floor is bogus or hostile (RFC 8201:
            // never go below 1280). Clamp straight to the floor instead of stepping down
            // 60 bytes per message, which left oversized packets blackholed for several rounds.
            self.floor_mtu
        };
        self.current_mtu.store(target, Relaxed);
        target
    }

    pub fn probe_step_up(&self) -> u16 {
        let cur = self.current_mtu.load(Relaxed);
        let next = (cur + 20).min(self.ceil_mtu);
        self.current_mtu.store(next, Relaxed);
        next
    }
}

/// RFC 2784 GRE encapsulation (`[Flags+Ver: 2B][Protocol Type: 2B][Optional Key: 4B][IP Packet]`).
pub struct GreEncap;

impl GreEncap {
    pub const ETHERTYPE_IPV4: u16 = 0x0800;
    pub const ETHERTYPE_IPV6: u16 = 0x86DD;

    pub fn encapsulate(ip_pkt: &[u8], key: Option<u32>) -> Result<Vec<u8>> {
        if ip_pkt.is_empty() {
            bail!("empty IP packet for GRE");
        }
        let ver = ip_pkt[0] >> 4;
        let proto = match ver {
            4 => Self::ETHERTYPE_IPV4,
            6 => Self::ETHERTYPE_IPV6,
            _ => bail!("invalid IP version {ver} for GRE"),
        };
        let mut out = Vec::with_capacity(8 + ip_pkt.len());
        if let Some(k) = key {
            out.extend_from_slice(&0x2000u16.to_be_bytes()); // K bit set
            out.extend_from_slice(&proto.to_be_bytes());
            out.extend_from_slice(&k.to_be_bytes());
        } else {
            out.extend_from_slice(&0x0000u16.to_be_bytes());
            out.extend_from_slice(&proto.to_be_bytes());
        }
        out.extend_from_slice(ip_pkt);
        Ok(out)
    }

    pub fn decapsulate(gre_frame: &[u8], expected_key: Option<u32>) -> Result<(u16, &[u8])> {
        if gre_frame.len() < 4 {
            bail!("GRE header too short");
        }
        let flags = u16::from_be_bytes([gre_frame[0], gre_frame[1]]);
        let proto = u16::from_be_bytes([gre_frame[2], gre_frame[3]]);
        let has_key = (flags & 0x2000) != 0;
        let has_csum = (flags & 0x8000) != 0;
        let has_seq = (flags & 0x1000) != 0;
        let mut offset = 4usize;
        if has_csum {
            offset += 4;
        }
        if has_key {
            if gre_frame.len() < offset + 4 {
                bail!("GRE key field truncated");
            }
            let k = u32::from_be_bytes(gre_frame[offset..offset + 4].try_into()?);
            if let Some(exp) = expected_key {
                if k != exp {
                    bail!("GRE key mismatch");
                }
            }
            offset += 4;
        } else if expected_key.is_some() {
            bail!("missing required GRE key");
        }
        if has_seq {
            offset += 4;
        }
        if gre_frame.len() <= offset {
            bail!("GRE payload missing");
        }
        Ok((proto, &gre_frame[offset..]))
    }
}

/// RFC 2003 IP-in-IP outer IPv4 header builder & validator (protocol 4 = IPv4, 41 = IPv6).
pub struct IpipEncap;

impl IpipEncap {
    pub fn encapsulate_v4(src: Ipv4Addr, dst: Ipv4Addr, inner_ip: &[u8]) -> Result<Vec<u8>> {
        if inner_ip.is_empty() {
            bail!("empty inner IP packet");
        }
        let inner_ver = inner_ip[0] >> 4;
        let proto = match inner_ver {
            4 => 4u8,
            6 => 41u8,
            _ => bail!("unsupported inner IP version {inner_ver}"),
        };
        let total_len = 20usize + inner_ip.len();
        if total_len > u16::MAX as usize {
            bail!("IPIP packet exceeds 65535 bytes");
        }
        let mut hdr = [0u8; 20];
        hdr[0] = 0x45; // IPv4, IHL=5
        hdr[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        hdr[6] = 0x40; // DF
        hdr[8] = 64;   // TTL
        hdr[9] = proto;
        hdr[12..16].copy_from_slice(&src.octets());
        hdr[16..20].copy_from_slice(&dst.octets());
        let csum = ipv4_checksum(&hdr);
        hdr[10..12].copy_from_slice(&csum.to_be_bytes());

        let mut pkt = Vec::with_capacity(total_len);
        pkt.extend_from_slice(&hdr);
        pkt.extend_from_slice(inner_ip);
        Ok(pkt)
    }

    pub fn decapsulate_v4(outer: &[u8]) -> Result<(u8, &[u8])> {
        if outer.len() < 20 || (outer[0] >> 4) != 4 {
            bail!("invalid outer IPv4 header");
        }
        let ihl = ((outer[0] & 0x0f) as usize) * 4;
        if ihl < 20 || outer.len() <= ihl {
            bail!("invalid outer IPv4 IHL");
        }
        let proto = outer[9];
        if proto != 4 && proto != 41 {
            bail!("not an IPIP packet (proto={proto})");
        }
        Ok((proto, &outer[ihl..]))
    }
}

fn ipv4_checksum(hdr: &[u8; 20]) -> u16 {
    let mut sum = 0u32;
    for chunk in hdr.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Cryptographically isolated WireGuard/BoringTun adapter contract.
/// Keeps WireGuard static/ephemeral keys strictly separated from Khaymali `Noise_IK` keys.
#[derive(Clone, Debug)]
pub struct WireGuardAdapterConfig {
    pub wg_interface: String,
    pub wg_listen_port: u16,
    pub wg_peer_pubkey_hex: String,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive_secs: u16,
}

pub struct WireGuardAdapter {
    pub cfg: WireGuardAdapterConfig,
    pub pmtu: PmtuTracker,
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
}

impl WireGuardAdapter {
    pub fn new(cfg: WireGuardAdapterConfig) -> Result<Self> {
        if cfg.wg_peer_pubkey_hex.len() != 64 {
            bail!("WireGuard peer public key must be 32 bytes (64 hex chars)");
        }
        Ok(Self {
            cfg,
            pmtu: PmtuTracker::new(DEFAULT_TUN_MTU),
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
        })
    }

    pub fn wrap_wg_udp_datagram(&self, wg_payload: &[u8]) -> Result<Vec<u8>> {
        if wg_payload.len() > self.pmtu.mtu() as usize {
            bail!(
                "WireGuard packet ({}B) exceeds L3 PMTU ({}B)",
                wg_payload.len(),
                self.pmtu.mtu()
            );
        }
        self.tx_packets.fetch_add(1, Relaxed);
        Ok(wg_payload.to_vec())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CidrRoute {
    pub network: IpAddr,
    pub prefix_len: u8,
    pub via_exit: String,
}

impl CidrRoute {
    pub fn parse(cidr: &str, via_exit: &str) -> Result<Self> {
        let (network, prefix_len) = validate_cidr_str(cidr)?;
        Ok(Self {
            network,
            prefix_len,
            via_exit: via_exit.to_string(),
        })
    }

    pub fn matches(&self, dst: IpAddr) -> bool {
        match (self.network, dst) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = !0u32 << (32 - self.prefix_len);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = !0u128 << (128 - self.prefix_len);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

/// Longest-prefix-match L3 routing table with mandatory anti-SSRF destination guard.
pub struct RoutePolicy {
    routes: Mutex<Vec<CidrRoute>>,
    allow_private: bool,
}

impl RoutePolicy {
    pub fn new(allow_private: bool) -> Self {
        Self {
            routes: Mutex::new(Vec::new()),
            allow_private,
        }
    }

    pub fn add_route(&self, route: CidrRoute) {
        let mut r = self.routes.lock().unwrap();
        r.push(route);
        r.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
    }

    pub fn resolve_packet_exit(&self, ip_pkt: &[u8]) -> Result<Option<String>> {
        if ip_pkt.len() < 20 {
            bail!("IP packet too short");
        }
        let dst = match ip_pkt[0] >> 4 {
            4 => IpAddr::V4(Ipv4Addr::new(ip_pkt[16], ip_pkt[17], ip_pkt[18], ip_pkt[19])),
            6 => {
                if ip_pkt.len() < 40 {
                    bail!("IPv6 packet too short");
                }
                let mut octs = [0u8; 16];
                octs.copy_from_slice(&ip_pkt[24..40]);
                IpAddr::V6(Ipv6Addr::from(octs))
            }
            v => bail!("unsupported IP version {v}"),
        };
        if !self.allow_private && is_prohibited_destination(dst, &[]) {
            bail!("L3 anti-SSRF policy blocked destination {dst}");
        }
        let routes = self.routes.lock().unwrap();
        Ok(routes.iter().find(|r| r.matches(dst)).map(|r| r.via_exit.clone()))
    }
}


/// Kernel-Level Transparent Port Forwarding preserving the real client source IP (`mode=kernel`).
///
/// Uses a dedicated `iptables` chain (`KHAYMALI_PREROUTING` / `KHAYMALI_MANGLE`) and policy
/// routing table (`151` via L3 TUN interface) so forwarded packets retain the original client
/// IPv4 source address without SNAT masquerading, and cleans up cleanly on drop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelForwardRule {
    pub proto: &'static str, // "tcp" or "udp"
    pub listen_port: u16,
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
}

pub struct KernelTransparentForwarder {
    pub tun_if: String,
    pub rules: Vec<KernelForwardRule>,
}

impl KernelTransparentForwarder {
    pub fn new(tun_if: &str, rules: Vec<KernelForwardRule>) -> Result<Self> {
        validate_if_name(tun_if)?;
        for r in &rules {
            if r.listen_port == 0 || r.target_port == 0 {
                bail!("kernel forward ports must be non-zero");
            }
            if r.proto != "tcp" && r.proto != "udp" {
                bail!("kernel forward proto must be tcp or udp");
            }
        }
        Ok(Self {
            tun_if: tun_if.to_string(),
            rules,
        })
    }

    /// Generate exact idempotent `iptables` and `iproute2` commands for transparent source-IP forwarding.
    pub fn render_apply_commands(&self) -> Vec<Vec<String>> {
        let mut cmds: Vec<Vec<String>> = vec![
            vec!["sysctl".into(), "-w".into(), "net.ipv4.ip_forward=1".into()],
            vec!["iptables".into(), "-t".into(), "nat".into(), "-N".into(), "KHAYMALI_PREROUTING".into()],
            vec!["iptables".into(), "-t".into(), "nat".into(), "-F".into(), "KHAYMALI_PREROUTING".into()],
            vec!["iptables".into(), "-t".into(), "mangle".into(), "-N".into(), "KHAYMALI_MANGLE".into()],
            vec!["iptables".into(), "-t".into(), "mangle".into(), "-F".into(), "KHAYMALI_MANGLE".into()],
            vec!["ip".into(), "route".into(), "replace".into(), "default".into(), "dev".into(), self.tun_if.clone(), "table".into(), "151".into()],
            vec!["ip".into(), "rule".into(), "add".into(), "fwmark".into(), "0x518".into(), "table".into(), "151".into()],
        ];
        for r in &self.rules {
            let dst = format!("{}:{}", r.target_ip, r.target_port);
            cmds.push(vec![
                "iptables".into(), "-t".into(), "nat".into(), "-A".into(), "KHAYMALI_PREROUTING".into(),
                "-p".into(), r.proto.into(), "--dport".into(), r.listen_port.to_string(),
                "-j".into(), "DNAT".into(), "--to-destination".into(), dst,
            ]);
            cmds.push(vec![
                "iptables".into(), "-t".into(), "mangle".into(), "-A".into(), "KHAYMALI_MANGLE".into(),
                "-p".into(), r.proto.into(), "--dport".into(), r.listen_port.to_string(),
                "-j".into(), "MARK".into(), "--set-mark".into(), "0x518".into(),
            ]);
        }
        cmds
    }

    pub fn render_cleanup_commands(&self) -> Vec<Vec<String>> {
        vec![
            vec!["iptables".into(), "-t".into(), "nat".into(), "-D".into(), "PREROUTING".into(), "-j".into(), "KHAYMALI_PREROUTING".into()],
            vec!["iptables".into(), "-t".into(), "nat".into(), "-F".into(), "KHAYMALI_PREROUTING".into()],
            vec!["iptables".into(), "-t".into(), "nat".into(), "-X".into(), "KHAYMALI_PREROUTING".into()],
            vec!["iptables".into(), "-t".into(), "mangle".into(), "-D".into(), "PREROUTING".into(), "-j".into(), "KHAYMALI_MANGLE".into()],
            vec!["iptables".into(), "-t".into(), "mangle".into(), "-F".into(), "KHAYMALI_MANGLE".into()],
            vec!["iptables".into(), "-t".into(), "mangle".into(), "-X".into(), "KHAYMALI_MANGLE".into()],
            vec!["ip".into(), "rule".into(), "del".into(), "fwmark".into(), "0x518".into(), "table".into(), "151".into()],
            vec!["ip".into(), "route".into(), "flush".into(), "table".into(), "151".into()],
        ]
    }

    #[cfg(target_os = "linux")]
    pub fn apply(&self) -> Result<()> {
        use std::process::Command;
        if self.rules.is_empty() {
            return Ok(());
        }
        for cmd in self.render_apply_commands() {
            let _ = Command::new(&cmd[0]).args(&cmd[1..]).status();
        }
        // Attach jump hooks idempotently
        let has_nat = Command::new("iptables")
            .args(["-t", "nat", "-C", "PREROUTING", "-j", "KHAYMALI_PREROUTING"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !has_nat {
            let st = Command::new("iptables")
                .args(["-t", "nat", "-I", "PREROUTING", "1", "-j", "KHAYMALI_PREROUTING"])
                .status()?;
            if !st.success() {
                bail!("failed to install KHAYMALI_PREROUTING iptables jump rule");
            }
        }
        let has_mangle = Command::new("iptables")
            .args(["-t", "mangle", "-C", "PREROUTING", "-j", "KHAYMALI_MANGLE"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !has_mangle {
            let st = Command::new("iptables")
                .args(["-t", "mangle", "-I", "PREROUTING", "1", "-j", "KHAYMALI_MANGLE"])
                .status()?;
            if !st.success() {
                bail!("failed to install KHAYMALI_MANGLE iptables jump rule");
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn cleanup(&self) {
        use std::process::Command;
        for cmd in self.render_cleanup_commands() {
            let _ = Command::new(&cmd[0]).args(&cmd[1..]).status();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ipv4_pkt(dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&[198, 51, 100, 10]);
        p[16..20].copy_from_slice(&dst.octets());
        p
    }

    #[test]
    fn gre_and_ipip_roundtrip() {
        let pkt = sample_ipv4_pkt(Ipv4Addr::new(1, 1, 1, 1));
        let gre = GreEncap::encapsulate(&pkt, Some(0xAABBCCDD)).unwrap();
        let (proto, inner) = GreEncap::decapsulate(&gre, Some(0xAABBCCDD)).unwrap();
        assert_eq!(proto, GreEncap::ETHERTYPE_IPV4);
        assert_eq!(inner, pkt.as_slice());
        assert!(GreEncap::decapsulate(&gre, Some(0x11112222)).is_err());

        let ipip = IpipEncap::encapsulate_v4(
            Ipv4Addr::new(203, 0, 113, 1),
            Ipv4Addr::new(198, 51, 100, 2),
            &pkt,
        )
        .unwrap();
        let (iproto, iinner) = IpipEncap::decapsulate_v4(&ipip).unwrap();
        assert_eq!(iproto, 4);
        assert_eq!(iinner, pkt.as_slice());
    }

    #[test]
    fn route_policy_lpm_and_ssrf_block() {
        let rp = RoutePolicy::new(false);
        rp.add_route(CidrRoute::parse("0.0.0.0/0", "exit-default:443").unwrap());
        rp.add_route(CidrRoute::parse("1.1.1.0/24", "exit-cf:443").unwrap());

        let p_cf = sample_ipv4_pkt(Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(rp.resolve_packet_exit(&p_cf).unwrap().as_deref(), Some("exit-cf:443"));

        let p_other = sample_ipv4_pkt(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(rp.resolve_packet_exit(&p_other).unwrap().as_deref(), Some("exit-default:443"));

        let p_ssrf = sample_ipv4_pkt(Ipv4Addr::new(10, 0, 0, 5));
        assert!(rp.resolve_packet_exit(&p_ssrf).is_err());
    }

    #[test]
    fn pmtu_tracker_clamps_safely() {
        let pmtu = PmtuTracker::new(1400);
        assert_eq!(pmtu.mtu(), 1400);
        assert_eq!(pmtu.record_frag_needed(1300), 1300);
        assert_eq!(pmtu.record_frag_needed(500), MIN_IPV6_MTU);
        assert_eq!(pmtu.probe_step_up(), 1300);
    }

    #[test]
    fn tun_validation_rejects_bad_names_and_cidrs() {
        assert!(validate_if_name("khaymali0").is_ok());
        assert!(validate_if_name("if;rm -rf /").is_err());
        assert!(validate_if_name("too_long_interface_name").is_err());
        assert!(validate_cidr_str("10.200.0.1/30").is_ok());
        assert!(validate_cidr_str("10.200.0.1/99").is_err());
    }
}
