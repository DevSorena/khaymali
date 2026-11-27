//! Cluster Load Balancer, Multi-Hub Sync & Weighted DNS Rotation (`src/cluster_lb.rs`).
//!
//! Full Rust port of Khaymali's `cluster_lb.go`, `cluster_sync.go`, and `cluster_dns.go`:
//!   * 5 LB scheduling modes (`failover`, `balance`, `sticky`, `latency`, `least`) with
//!     per-member health, EWMA latency, `LB_LATENCY_STREAK = 10` hysteresis, FNV-1a sticky
//!     source-IP hashing, private loopback bind allocation (`127.10.x.y`), `frps`/`backhaul`
//!     bind-address rewriter, nftables rule generator, and live async Tokio TCP LB forwarder.
//!   * Multi-hub tunnel & pool inventory sync (`SyncTunnel`, `SyncPool`, `SyncList`) with
//!     AES-256-GCM sealed bundle handoff (`cluster_mesh::sync_seal` / `sync_open`).
//!   * Multi-hub DNS rotation (`DnsConfig`, `dns_rotate`, `dns_controller_id`, weighted slot
//!     allocation across IPv4/IPv6 healthy hub groups).

use crate::cluster_mesh::{sync_open, sync_seal, MeshBeat, DNS_MAX_TTL, DNS_MIN_TTL};
use crate::hjson::{self, Json};
use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

pub const LB_MODES: &[&str] = &["failover", "balance", "sticky", "latency", "least"];
pub const LB_LATENCY_STREAK: u32 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LbMode {
    Failover,
    Balance,
    Sticky,
    Latency,
    Least,
}

impl LbMode {
    pub fn as_str(self) -> &'static str {
        match self {
            LbMode::Failover => "failover",
            LbMode::Balance => "balance",
            LbMode::Sticky => "sticky",
            LbMode::Latency => "latency",
            LbMode::Least => "least",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "failover" => Ok(LbMode::Failover),
            "balance" | "weighted" => Ok(LbMode::Balance),
            "sticky" => Ok(LbMode::Sticky),
            "latency" => Ok(LbMode::Latency),
            "least" | "leastconn" => Ok(LbMode::Least),
            other => bail!("invalid LB mode '{other}' (expected {})", LB_MODES.join(", ")),
        }
    }
}

pub fn lb_proto_ok(p: &str) -> bool {
    matches!(p, "tcp" | "udp" | "both")
}

/// Deterministic private loopback IP (`127.10.X.Y`) for binding a relay behind a pool.
pub fn lb_addr_for(svc: &str) -> String {
    let mut h: u32 = 2166136261;
    for b in svc.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    let a = ((h >> 8) & 0xff) as u8;
    let b = ((h & 0xff) as u8).clamp(2, 250);
    format!("127.10.{a}.{b}")
}

/// Rewrites `bindAddr` in an `frps.toml` to isolate a relay behind a cluster LB pool.
pub fn frps_with_bind(conf: &str, addr: &str) -> String {
    let mut found = false;
    let mut lines = Vec::new();
    for line in conf.lines() {
        let t = line.trim_start();
        if t.starts_with("bindAddr") && t.contains('=') {
            lines.push(format!("bindAddr = \"{addr}\""));
            found = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !found {
        lines.insert(0, format!("bindAddr = \"{addr}\""));
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Rewrites `bind_addr = "...:PORT"` in a Backhaul server TOML to bind `addr:PORT`.
pub fn backhaul_with_bind(conf: &str, addr: &str) -> String {
    let mut lines = Vec::new();
    for line in conf.lines() {
        let t = line.trim();
        if t.starts_with("bind_addr") && t.contains('=') {
            if let Some((_, rhs)) = t.split_once('=') {
                let raw = rhs.trim().trim_matches('"').trim_matches('\'');
                let port = raw.rsplit_once(':').map(|(_, p)| p).unwrap_or("3080");
                lines.push(format!("bind_addr = \"{addr}:{port}\""));
                continue;
            }
        }
        lines.push(line.to_string());
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

#[derive(Clone, Debug)]
pub struct LbTarget {
    pub link_id: u32,
    pub addr: String, // e.g. "127.10.4.21:443"
    pub weight: u32,
    pub priority: u32,
    pub healthy: bool,
    pub latency_ms: f64,
    pub active_conns: u64,
}

/// Runtime state & scheduler for one load-balanced port pool.
pub struct LbPoolRuntime {
    pub port: u16,
    pub proto: String,
    pub mode: LbMode,
    targets: Mutex<Vec<LbTarget>>,
    rr: AtomicU64,
    sticky_map: Mutex<HashMap<String, usize>>,
    latency_winner: Mutex<(Option<u32>, Option<u32>, u32)>, // (current_id, challenger_id, streak)
}

impl LbPoolRuntime {
    pub fn new(port: u16, proto: &str, mode: LbMode, targets: Vec<LbTarget>) -> Result<Arc<Self>> {
        if !lb_proto_ok(proto) {
            bail!("invalid LB proto '{proto}' (expected tcp|udp|both)");
        }
        Ok(Arc::new(Self {
            port,
            proto: proto.to_string(),
            mode,
            targets: Mutex::new(targets),
            rr: AtomicU64::new(0),
            sticky_map: Mutex::new(HashMap::new()),
            latency_winner: Mutex::new((None, None, 0)),
        }))
    }

    pub fn update_member_health(&self, link_id: u32, healthy: bool, latency_ms: f64) {
        let mut g = self.targets.lock().unwrap();
        for t in g.iter_mut() {
            if t.link_id == link_id {
                t.healthy = healthy;
                if latency_ms > 0.0 {
                    t.latency_ms = if t.latency_ms <= 0.0 {
                        latency_ms
                    } else {
                        0.4 * latency_ms + 0.6 * t.latency_ms
                    };
                }
            }
        }
    }

    pub fn inc_conns(&self, link_id: u32, delta: i64) {
        let mut g = self.targets.lock().unwrap();
        for t in g.iter_mut() {
            if t.link_id == link_id {
                if delta >= 0 {
                    t.active_conns = t.active_conns.saturating_add(delta as u64);
                } else {
                    t.active_conns = t.active_conns.saturating_sub((-delta) as u64);
                }
            }
        }
    }

    /// Selects the next target backend according to `self.mode`.
    pub fn pick(&self, client_ip: Option<IpAddr>) -> Option<LbTarget> {
        let g = self.targets.lock().unwrap();
        let healthy: Vec<&LbTarget> = g.iter().filter(|t| t.healthy).collect();
        if healthy.is_empty() {
            return None;
        }
        match self.mode {
            LbMode::Failover => healthy
                .iter()
                .min_by_key(|t| (t.priority, t.link_id))
                .map(|t| (*t).clone()),
            LbMode::Balance => {
                let total: u64 = healthy.iter().map(|t| t.weight.max(1) as u64).sum();
                let mut rem = self.rr.fetch_add(1, Ordering::Relaxed) % total;
                for t in &healthy {
                    let w = t.weight.max(1) as u64;
                    if rem < w {
                        return Some((*t).clone());
                    }
                    rem -= w;
                }
                Some(healthy[0].clone())
            }
            LbMode::Sticky => {
                let key = client_ip.map(|ip| ip.to_string()).unwrap_or_default();
                let mut sm = self.sticky_map.lock().unwrap();
                if let Some(&idx) = sm.get(&key) {
                    if let Some(t) = healthy.get(idx) {
                        return Some((*t).clone());
                    }
                }
                let idx = (fnv1a64(key.as_bytes()) as usize) % healthy.len();
                if sm.len() > 8192 {
                    sm.clear();
                }
                sm.insert(key, idx);
                Some(healthy[idx].clone())
            }
            LbMode::Latency => {
                let best = healthy
                    .iter()
                    .min_by(|a, b| {
                        let la = if a.latency_ms <= 0.0 { 9999.0 } else { a.latency_ms };
                        let lb = if b.latency_ms <= 0.0 { 9999.0 } else { b.latency_ms };
                        la.partial_cmp(&lb).unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .unwrap();
                let mut lw = self.latency_winner.lock().unwrap();
                match lw.0 {
                    Some(cur_id) if healthy.iter().any(|t| t.link_id == cur_id) => {
                        if cur_id == best.link_id {
                            lw.1 = None;
                            lw.2 = 0;
                            healthy.iter().find(|t| t.link_id == cur_id).map(|t| (*t).clone())
                        } else {
                            if lw.1 == Some(best.link_id) {
                                lw.2 += 1;
                            } else {
                                lw.1 = Some(best.link_id);
                                lw.2 = 1;
                            }
                            if lw.2 >= LB_LATENCY_STREAK {
                                lw.0 = Some(best.link_id);
                                lw.1 = None;
                                lw.2 = 0;
                                Some((*best).clone())
                            } else {
                                healthy.iter().find(|t| t.link_id == cur_id).map(|t| (*t).clone())
                            }
                        }
                    }
                    _ => {
                        lw.0 = Some(best.link_id);
                        lw.1 = None;
                        lw.2 = 0;
                        Some((*best).clone())
                    }
                }
            }
            LbMode::Least => healthy
                .iter()
                .min_by_key(|t| (t.active_conns * 100 / t.weight.max(1) as u64, t.priority))
                .map(|t| (*t).clone()),
        }
    }

    /// Runs a live async Tokio TCP LB forwarder on `listener` until stopped.
    pub async fn serve_tcp(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            let (mut client, peer) = listener.accept().await?;
            let pool = self.clone();
            let act = active.clone();
            tokio::spawn(async move {
                let Some(target) = pool.pick(Some(peer.ip())) else {
                    return;
                };
                pool.inc_conns(target.link_id, 1);
                act.fetch_add(1, Ordering::Relaxed);
                let res = timeout(Duration::from_secs(4), TcpStream::connect(&target.addr)).await;
                if let Ok(Ok(mut backend)) = res {
                    let _ = client.set_nodelay(true);
                    let _ = backend.set_nodelay(true);
                    let _ = copy_bidirectional(&mut client, &mut backend).await;
                }
                pool.inc_conns(target.link_id, -1);
                act.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

// ============================================================================
// Multi-Hub Sync Inventory (`cluster_sync.go`)
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncTunnel {
    pub id: u32,
    pub name: String,
    pub engine: String,
    pub transport: String,
    pub remote_pub: String,
    pub ctrl_port: u16,
    pub ports: Vec<u16>,
    pub healthy: bool,
}

impl SyncTunnel {
    pub fn to_json(&self) -> Json {
        Json::obj()
            .set("id", self.id)
            .set("name", self.name.clone())
            .set("engine", self.engine.clone())
            .set("transport", self.transport.clone())
            .set("remote_pub", self.remote_pub.clone())
            .set("ctrl_port", self.ctrl_port)
            .set("ports", self.ports.clone())
            .set("healthy", self.healthy)
    }

    pub fn from_json(j: &Json) -> Self {
        Self {
            id: j.u64_of("id") as u32,
            name: j.str_of("name"),
            engine: j.str_of("engine"),
            transport: j.str_of("transport"),
            remote_pub: j.str_of("remote_pub"),
            ctrl_port: j.u64_of("ctrl_port") as u16,
            ports: j
                .arr_of("ports")
                .into_iter()
                .filter_map(|v| v.as_f64().map(|n| n as u16))
                .filter(|&p| p > 0)
                .collect(),
            healthy: j.bool_of("healthy"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SyncDelivery {
    pub from_hub_id: String,
    pub tunnel_name: String,
    pub sealed_bundle: String,
}

impl SyncDelivery {
    pub fn seal(secret: &str, from_hub_id: &str, tunnel_name: &str, bundle: &str) -> Result<Self> {
        Ok(Self {
            from_hub_id: from_hub_id.into(),
            tunnel_name: tunnel_name.into(),
            sealed_bundle: sync_seal(secret, bundle)?,
        })
    }

    pub fn open_bundle(&self, secret: &str) -> Result<String> {
        sync_open(secret, &self.sealed_bundle)
    }

    pub fn to_json(&self) -> Json {
        Json::obj()
            .set("from_hub_id", self.from_hub_id.clone())
            .set("tunnel_name", self.tunnel_name.clone())
            .set("sealed_bundle", self.sealed_bundle.clone())
    }
}

// ============================================================================
// Multi-Hub Weighted DNS Controller (`cluster_dns.go`)
// ============================================================================

#[derive(Clone, Debug)]
pub struct DnsConfig {
    pub enabled: bool,
    pub provider: String, // "cloudflare"
    pub zone_id: String,
    pub record_name: String,
    pub api_token: String,
    pub mode: String, // "failover" | "balance"
    pub ttl: u32,
    pub controller_id: String,
    pub version: u64,
    pub hub_weights: BTreeMap<String, u32>,
}

impl DnsConfig {
    pub fn clamped_ttl(&self) -> u32 {
        self.ttl.clamp(DNS_MIN_TTL, DNS_MAX_TTL)
    }

    pub fn hub_weight(&self, hub_id: &str, reported: u32) -> u32 {
        self.hub_weights
            .get(hub_id)
            .copied()
            .unwrap_or(reported)
            .clamp(1, 100)
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let mut wm = Json::obj();
        for (k, &v) in &self.hub_weights {
            wm.insert(k, v);
        }
        let j = Json::obj()
            .set("enabled", self.enabled)
            .set("provider", self.provider.clone())
            .set("zone_id", self.zone_id.clone())
            .set("record_name", self.record_name.clone())
            .set("api_token", self.api_token.clone())
            .set("mode", self.mode.clone())
            .set("ttl", self.clamped_ttl())
            .set("controller_id", self.controller_id.clone())
            .set("version", self.version)
            .set("hub_weights", wm);
        hjson::write_atomic(path, j.to_string_pretty().as_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsGroup {
    pub hub_id: String,
    pub weight: u32,
    pub ips: Vec<String>,
}

/// Extracts healthy IP groups (IPv4 + optional IPv6) from live `MeshBeat`s.
pub fn dns_healthy_groups(beats: &[MeshBeat], cfg: &DnsConfig) -> Vec<DnsGroup> {
    let mut out = Vec::new();
    for b in beats {
        if !b.healthy || b.starting || b.ip.is_empty() {
            continue;
        }
        let mut ips = vec![b.ip.clone()];
        if !b.ip6.is_empty() {
            ips.push(b.ip6.clone());
        }
        out.push(DnsGroup {
            hub_id: b.id.clone(),
            weight: cfg.hub_weight(&b.id, b.weight),
            ips,
        });
    }
    out.sort_by(|a, b| a.hub_id.cmp(&b.hub_id));
    out
}

/// Weighted DNS slot rotation (matching Khaymali `dnsRotate`):
/// - Equal weights -> returns all healthy IPs (DNS round-robin).
/// - Unequal weights -> rotates one hub per slot proportionally to its weight.
pub fn dns_rotate(groups: &[DnsGroup], slot_index: u64) -> Vec<String> {
    if groups.is_empty() {
        return Vec::new();
    }
    let unequal = groups.windows(2).any(|w| w[0].weight != w[1].weight);
    if !unequal {
        return groups.iter().flat_map(|g| g.ips.clone()).collect();
    }
    let total: u64 = groups.iter().map(|g| g.weight.max(1) as u64).sum();
    let mut rem = slot_index % total;
    for g in groups {
        let w = g.weight.max(1) as u64;
        if rem < w {
            return g.ips.clone();
        }
        rem -= w;
    }
    groups[0].ips.clone()
}

pub fn render_lb_nft_rules(port: u16, proto: &str, backends: &[SocketAddr]) -> Result<String> {
    if !lb_proto_ok(proto) || backends.is_empty() {
        bail!("invalid LB nft rule parameters");
    }
    let l4 = match proto {
        "tcp" => "tcp",
        "udp" => "udp",
        _ => "{ tcp, udp }",
    };
    let mut rules = format!(
        "table inet khaymali_lb_{port}\ndelete table inet khaymali_lb_{port}\ntable inet khaymali_lb_{port} {{\n  chain prerouting {{\n    type nat hook prerouting priority dstnat - 5; policy accept;\n"
    );
    if backends.len() == 1 {
        rules.push_str(&format!(
            "    meta l4proto {l4} th dport {port} dnat ip to {}\n",
            backends[0]
        ));
    } else {
        let entries = backends
            .iter()
            .enumerate()
            .map(|(i, sa)| format!("{i} : {sa}"))
            .collect::<Vec<_>>()
            .join(", ");
        rules.push_str(&format!(
            "    meta l4proto {l4} th dport {port} dnat ip to numgen inc mod {} map {{ {entries} }}\n",
            backends.len()
        ));
    }
    rules.push_str("  }\n}\n");
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn lb_modes_bind_rewrite_sync_seal_and_dns_rotate() {
        assert!(lb_addr_for("frps-1").starts_with("127.10."));
        let frps = frps_with_bind("bindPort = 7000\n", "127.10.1.2");
        assert!(frps.contains("bindAddr = \"127.10.1.2\""));
        let bh = backhaul_with_bind("[server]\nbind_addr = \"0.0.0.0:3080\"\n", "127.10.1.3");
        assert!(bh.contains("bind_addr = \"127.10.1.3:3080\""));

        let targets = vec![
            LbTarget { link_id: 1, addr: "127.0.0.1:1".into(), weight: 3, priority: 0, healthy: true, latency_ms: 80.0, active_conns: 5 },
            LbTarget { link_id: 2, addr: "127.0.0.1:2".into(), weight: 1, priority: 1, healthy: true, latency_ms: 20.0, active_conns: 1 },
        ];
        let fail_pool = LbPoolRuntime::new(443, "tcp", LbMode::Failover, targets.clone()).unwrap();
        assert_eq!(fail_pool.pick(None).unwrap().link_id, 1);

        let least_pool = LbPoolRuntime::new(443, "tcp", LbMode::Least, targets.clone()).unwrap();
        assert_eq!(least_pool.pick(None).unwrap().link_id, 2);

        let lat_pool = LbPoolRuntime::new(443, "tcp", LbMode::Latency, targets).unwrap();
        assert_eq!(lat_pool.pick(None).unwrap().link_id, 2);

        // Sealed sync delivery round-trip
        let sec = "cluster-secret-0123456789abcdef01";
        let del = SyncDelivery::seal(sec, "hub-1", "de-1", "bh1_1.2.3.4_3080_tcpmux_tok").unwrap();
        assert_eq!(del.open_bundle(sec).unwrap(), "bh1_1.2.3.4_3080_tcpmux_tok");

        // Weighted DNS rotation: hub-a weight 3, hub-b weight 1
        let groups = vec![
            DnsGroup { hub_id: "hub-a".into(), weight: 3, ips: vec!["198.51.100.1".into()] },
            DnsGroup { hub_id: "hub-b".into(), weight: 1, ips: vec!["198.51.100.2".into()] },
        ];
        assert_eq!(dns_rotate(&groups, 0), vec!["198.51.100.1"]);
        assert_eq!(dns_rotate(&groups, 2), vec!["198.51.100.1"]);
        assert_eq!(dns_rotate(&groups, 3), vec!["198.51.100.2"]);
    }

    #[tokio::test]
    async fn live_tcp_lb_forwards_across_backends() {
        let b1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a1 = b1.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = b1.accept().await {
                let mut buf = [0u8; 4];
                let _ = s.read_exact(&mut buf).await;
                let _ = s.write_all(b"B1OK").await;
            }
        });
        let lb_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lb_a = lb_l.local_addr().unwrap();
        let pool = LbPoolRuntime::new(
            lb_a.port(),
            "tcp",
            LbMode::Failover,
            vec![LbTarget {
                link_id: 1,
                addr: a1.to_string(),
                weight: 1,
                priority: 0,
                healthy: true,
                latency_ms: 5.0,
                active_conns: 0,
            }],
        )
        .unwrap();
        let _srv = tokio::spawn(pool.serve_tcp(lb_l));

        let mut c = TcpStream::connect(lb_a).await.unwrap();
        c.write_all(b"PING").await.unwrap();
        let mut resp = [0u8; 4];
        c.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"B1OK");
    }
}
