//! Cluster Iran-to-Iran Hub Mesh & DNS Failover (`src/cluster_mesh.rs`).
//!
//! Full Rust port of Khaymali's `cluster_mesh.go`, `cluster_dns.go`, `cluster_dns_pick.go`,
//! and `cluster_sync.go` (`syncSeal`/`syncOpen` AES-256-GCM):
//!   * Real Tokio HTTP/1.1 Mesh Server & Client on `/_hc/hello`, `/_hc/beat`, `/_hc/adopt`.
//!   * Khaymali HMAC-SHA256 headers (`X-Khaymali-Ts`, `X-Khaymali-Nonce`, `X-Khaymali-Sig`) over
//!     `ts + "\n" + nonce + "\n" + body` with ±90s clock skew and replay protection.
//!     Unsigned or invalid requests receive a stealth `404 Not Found`.
//!   * `hc1_<raw-url-b64(JSON)>` hub join codes, multi-hub `/_hc/adopt` secret handoff
//!     sealed with pure-Rust AES-256-GCM, transitive `mesh_meet`, graceful `bye` unlink,
//!     EWMA traffic rate estimator, and 3-second heartbeat loop feeding DNS writer election.

use crate::hjson::{self, Json};
use crate::util::{ct_eq, hex, now_unix, rand_bytes};
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

type HmacSha256 = Hmac<Sha256>;

pub const MESH_MAX_SKEW_SECS: u64 = 60;
pub const MESH_HTTP_MAX_SKEW_SECS: u64 = 90;
pub const MESH_ROUTE_PREFIX: &str = "/_hc";
pub const MESH_CODE_HEAD: &str = "hc1_";
pub const MESH_EVERY_SECS: u64 = 3;
pub const MESH_FALL_MISSES: u32 = 3;
pub const DNS_MIN_TTL: u32 = 60;
pub const DNS_MAX_TTL: u32 = 3600;

// ============================================================================
// DNS Failover / Weighted Balance Core (v0.18 API preserved)
// ============================================================================

#[derive(Clone, Debug)]
pub struct HubBeat {
    pub node_id: String,
    pub public_ipv4: String,
    pub public_ipv6: Option<String>,
    pub healthy_pools: Vec<u16>,
    pub has_nat_pools: bool,
    pub can_reach_dns_provider: bool,
    pub is_controller: bool,
    pub weight: u32,
    pub load_pct: f64,
    pub ts_unix: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsMode {
    Failover,
    Balance,
}

impl DnsMode {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "failover" => Ok(DnsMode::Failover),
            "balance" | "weighted" => Ok(DnsMode::Balance),
            other => bail!("invalid dns mode '{other}' (expected failover|balance)"),
        }
    }
}

pub fn sign_heartbeat(secret: &[u8], ts_unix: u64, nonce: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(&ts_unix.to_be_bytes());
    mac.update(b"|");
    mac.update(nonce.as_bytes());
    mac.update(b"|");
    mac.update(body);
    hex(&mac.finalize().into_bytes())
}

pub struct MeshVerifier {
    seen_nonces: Mutex<HashMap<String, u64>>,
}

impl MeshVerifier {
    pub fn new() -> Self {
        Self { seen_nonces: Mutex::new(HashMap::new()) }
    }

    pub fn verify(
        &self,
        secret: &[u8],
        ts_unix: u64,
        nonce: &str,
        body: &[u8],
        provided_sig_hex: &str,
        now_unix_ts: u64,
    ) -> Result<()> {
        if now_unix_ts.abs_diff(ts_unix) > MESH_MAX_SKEW_SECS {
            bail!("mesh heartbeat timestamp skew exceeds {MESH_MAX_SKEW_SECS}s");
        }
        let expected = sign_heartbeat(secret, ts_unix, nonce, body);
        if !ct_eq(expected.as_bytes(), provided_sig_hex.trim().as_bytes()) {
            bail!("mesh heartbeat HMAC mismatch");
        }
        let mut g = self.seen_nonces.lock().unwrap();
        g.retain(|_, &mut seen_at| now_unix_ts.saturating_sub(seen_at) <= MESH_MAX_SKEW_SECS * 2);
        if g.contains_key(nonce) {
            bail!("mesh heartbeat nonce replayed");
        }
        if g.len() >= 4096 {
            g.clear();
        }
        g.insert(nonce.to_string(), now_unix_ts);
        Ok(())
    }
}

pub fn elect_dns_writer(hubs: &[HubBeat]) -> Option<String> {
    let mut cands: Vec<&HubBeat> = hubs.iter().collect();
    cands.sort_by(|a, b| {
        b.can_reach_dns_provider
            .cmp(&a.can_reach_dns_provider)
            .then_with(|| b.is_controller.cmp(&a.is_controller))
            .then_with(|| a.node_id.cmp(&b.node_id))
    });
    cands.first().map(|h| h.node_id.clone())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsTargetRecords {
    pub writer_node_id: Option<String>,
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
}

pub fn compute_dns_records(
    hubs: &[HubBeat],
    mode: DnsMode,
    slot_index: u64,
) -> DnsTargetRecords {
    let writer = elect_dns_writer(hubs);
    let healthy: Vec<&HubBeat> = hubs
        .iter()
        .filter(|h| !h.healthy_pools.is_empty() && !h.public_ipv4.is_empty())
        .collect();
    if healthy.is_empty() {
        return DnsTargetRecords { writer_node_id: writer, a_records: vec![], aaaa_records: vec![] };
    }

    let selected: Vec<&HubBeat> = match mode {
        DnsMode::Failover => vec![healthy[0]],
        DnsMode::Balance => {
            let weights_differ = healthy.windows(2).any(|w| w[0].weight != w[1].weight);
            if !weights_differ {
                healthy.clone()
            } else {
                let total_w: u64 = healthy.iter().map(|h| h.weight.max(1) as u64).sum();
                let mut rem = slot_index % total_w;
                let mut picked = healthy[0];
                for &h in &healthy {
                    let w = h.weight.max(1) as u64;
                    if rem < w {
                        picked = h;
                        break;
                    }
                    rem -= w;
                }
                vec![picked]
            }
        }
    };

    let mut seen_v4 = HashSet::new();
    let mut a_records = Vec::new();
    let mut seen_v6 = HashSet::new();
    let mut aaaa_records = Vec::new();

    for h in selected {
        if seen_v4.insert(h.public_ipv4.clone()) {
            a_records.push(h.public_ipv4.clone());
        }
        if !h.has_nat_pools {
            if let Some(v6) = &h.public_ipv6 {
                if !v6.is_empty() && seen_v6.insert(v6.clone()) {
                    aaaa_records.push(v6.clone());
                }
            }
        }
    }

    DnsTargetRecords { writer_node_id: writer, a_records, aaaa_records }
}

pub fn render_hub_forward_rules(port: u16, proto: &str, peer_hub_ip: &str) -> Result<Vec<Vec<String>>> {
    let protos: Vec<&str> = match proto {
        "tcp" => vec!["tcp"],
        "udp" => vec!["udp"],
        "both" => vec!["tcp", "udp"],
        other => bail!("invalid proto '{other}' (expected tcp|udp|both)"),
    };
    let mut cmds = vec![
        vec!["iptables".into(), "-t".into(), "nat".into(), "-N".into(), "KHAYMALI-HUBFWD".into()],
    ];
    for p in protos {
        cmds.push(vec![
            "iptables".into(), "-t".into(), "nat".into(), "-A".into(), "KHAYMALI-HUBFWD".into(),
            "-p".into(), p.into(), "--dport".into(), port.to_string(),
            "-j".into(), "DNAT".into(), "--to-destination".into(), format!("{peer_hub_ip}:{port}"),
        ]);
        cmds.push(vec![
            "iptables".into(), "-t".into(), "nat".into(), "-A".into(), "POSTROUTING".into(),
            "-p".into(), p.into(), "-d".into(), peer_hub_ip.into(), "--dport".into(), port.to_string(),
            "-j".into(), "MASQUERADE".into(),
        ]);
    }
    Ok(cmds)
}

pub fn cloudflare_upsert_curl_config(
    zone_id: &str,
    api_token: &str,
    record_name: &str,
    record_type: &str,
    content_ip: &str,
    ttl: u32,
    proxy_socks5: Option<&str>,
) -> String {
    let ttl = ttl.clamp(DNS_MIN_TTL, DNS_MAX_TTL);
    let body = format!(
        "{{\"type\":\"{record_type}\",\"name\":\"{record_name}\",\"content\":\"{content_ip}\",\"ttl\":{ttl},\"proxied\":false}}"
    );
    let mut cfg = format!(
        "url = \"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records\"\n\
         request = \"POST\"\n\
         header = \"Authorization: Bearer {api_token}\"\n\
         header = \"Content-Type: application/json\"\n\
         data = \"{}\"\n",
        body.replace('\\', "\\\\").replace('"', "\\\"")
    );
    if let Some(p) = proxy_socks5 {
        cfg.push_str(&format!("proxy = \"{p}\"\n"));
    }
    cfg
}

// ============================================================================
// Khaymali Wire Protocol: HMAC-SHA256 Headers + AES-256-GCM syncSeal / syncOpen
// ============================================================================

/// Khaymali `meshSign`: HMAC-SHA256(secret, ts + "\n" + nonce + "\n" + body).
pub fn mesh_sign_khaymali(secret: &str, ts: &str, nonce: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(ts.as_bytes());
    mac.update(b"\n");
    mac.update(nonce.as_bytes());
    mac.update(b"\n");
    mac.update(body);
    hex(&mac.finalize().into_bytes())
}

pub fn make_signed_headers(secret: &str, body: &[u8]) -> Vec<(String, String)> {
    let ts = now_unix().to_string();
    let nonce = hex(&rand_bytes::<12>());
    let sig = mesh_sign_khaymali(secret, &ts, &nonce, body);
    vec![
        ("X-Khaymali-Ts".into(), ts),
        ("X-Khaymali-Nonce".into(), nonce),
        ("X-Khaymali-Sig".into(), sig),
    ]
}

pub struct KhaymaliMeshVerifier {
    seen_nonces: Mutex<HashMap<String, u64>>,
}

impl KhaymaliMeshVerifier {
    pub fn new() -> Self {
        Self { seen_nonces: Mutex::new(HashMap::new()) }
    }

    pub fn verify_headers(
        &self,
        secret: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
        now_ts: u64,
    ) -> Result<()> {
        if secret.is_empty() {
            bail!("no cluster secret");
        }
        let ts = headers.get("x-khaymali-ts").map(|s| s.as_str()).unwrap_or("");
        let nonce = headers.get("x-khaymali-nonce").map(|s| s.as_str()).unwrap_or("");
        let sig = headers.get("x-khaymali-sig").map(|s| s.as_str()).unwrap_or("");
        let sec: u64 = ts.parse().context("unsigned")?;
        if nonce.len() < 16 || sig.is_empty() {
            bail!("unsigned");
        }
        if now_ts.abs_diff(sec) > MESH_HTTP_MAX_SKEW_SECS {
            bail!("clock skew exceeds {MESH_HTTP_MAX_SKEW_SECS}s");
        }
        let want = mesh_sign_khaymali(secret, ts, nonce, body);
        if !ct_eq(want.as_bytes(), sig.trim().as_bytes()) {
            bail!("bad signature");
        }
        let mut g = self.seen_nonces.lock().unwrap();
        g.retain(|_, &mut seen_at| now_ts.saturating_sub(seen_at) <= MESH_HTTP_MAX_SKEW_SECS * 2);
        if g.contains_key(nonce) {
            bail!("replayed request");
        }
        if g.len() >= 8192 {
            g.clear();
        }
        g.insert(nonce.to_string(), now_ts);
        Ok(())
    }
}

/// Derives Khaymali `syncSealKey`: `SHA256("khaymali-hub-bundle-v1\n" + secret)`.
pub fn sync_seal_key(secret: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"khaymali-hub-bundle-v1\n");
    h.update(secret.as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Khaymali-compatible AES-256-GCM `syncSeal(secret, plain)` -> raw-url-b64(nonce12 || ct || tag16).
pub fn sync_seal(secret: &str, plain: &str) -> Result<String> {
    let key = sync_seal_key(secret);
    let nonce = rand_bytes::<12>();
    let ct_tag = aes256_gcm_encrypt(&key, &nonce, plain.as_bytes());
    let mut blob = Vec::with_capacity(12 + ct_tag.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct_tag);
    Ok(hjson::b64url_encode(&blob))
}

/// Khaymali-compatible AES-256-GCM `syncOpen(secret, sealed)`.
pub fn sync_open(secret: &str, sealed: &str) -> Result<String> {
    let raw = hjson::b64_decode(sealed.trim())?;
    if raw.len() < 12 + 16 {
        bail!("sealed payload too short");
    }
    let key = sync_seal_key(secret);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&raw[..12]);
    let pt = aes256_gcm_decrypt(&key, &nonce, &raw[12..])?;
    String::from_utf8(pt).context("decrypted payload is not UTF-8")
}

// ============================================================================
// Live Mesh Data Structures & EWMA Traffic Estimator
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HubPeer {
    pub id: String,
    pub name: String,
    pub url: String,
    pub public_ip: String,
}

impl HubPeer {
    pub fn to_json(&self) -> Json {
        Json::obj()
            .set("id", self.id.clone())
            .set("name", self.name.clone())
            .set("url", self.url.clone())
            .set("public_ip", self.public_ip.clone())
    }
    pub fn from_json(j: &Json) -> Option<Self> {
        let id = j.str_of("id");
        let url = j.str_of("url");
        if id.is_empty() || url.is_empty() {
            return None;
        }
        Some(Self {
            id,
            name: j.str_of("name"),
            url,
            public_ip: j.str_of("public_ip"),
        })
    }
}

#[derive(Clone, Debug)]
pub struct MeshPoolState {
    pub state: String,
    pub healthy: u32,
    pub members: u32,
}

#[derive(Clone, Debug)]
pub struct MeshLink {
    pub id: i32,
    pub name: String,
    pub remote: String,
    pub engine: String,
    pub up: bool,
    pub ms: f64,
    pub bps: f64,
}

#[derive(Clone, Debug, Default)]
pub struct MeshBeat {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub ip6: String,
    pub port: u16,
    pub healthy: bool,
    pub pools: BTreeMap<String, MeshPoolState>,
    pub hubs: Vec<HubPeer>,
    pub version: String,
    pub bye: bool,
    pub weight: u32,
    pub master: bool,
    pub dns_down: bool,
    pub starting: bool,
    pub load_bps: Option<f64>,
    pub links: Vec<MeshLink>,
}

impl MeshBeat {
    pub fn to_json(&self) -> Json {
        let mut pools_obj = Json::obj();
        for (k, v) in &self.pools {
            pools_obj.insert(
                k,
                Json::obj()
                    .set("state", v.state.clone())
                    .set("healthy", v.healthy)
                    .set("members", v.members),
            );
        }
        let hubs_arr: Vec<Json> = self.hubs.iter().map(|h| h.to_json()).collect();
        let links_arr: Vec<Json> = self
            .links
            .iter()
            .map(|l| {
                Json::obj()
                    .set("id", l.id)
                    .set("name", l.name.clone())
                    .set("remote", l.remote.clone())
                    .set("engine", l.engine.clone())
                    .set("up", l.up)
                    .set("ms", l.ms)
                    .set("bps", l.bps)
            })
            .collect();
        let mut j = Json::obj()
            .set("id", self.id.clone())
            .set("name", self.name.clone())
            .set("ip", self.ip.clone())
            .set("port", self.port)
            .set("healthy", self.healthy)
            .set("pools", pools_obj)
            .set("version", self.version.clone())
            .set("weight", self.weight.max(1));
        if !self.ip6.is_empty() {
            j.insert("ip6", self.ip6.clone());
        }
        if !hubs_arr.is_empty() {
            j.insert("hubs", hubs_arr);
        }
        if self.bye {
            j.insert("bye", true);
        }
        if self.master {
            j.insert("master", true);
        }
        if self.dns_down {
            j.insert("dns_down", true);
        }
        if self.starting {
            j.insert("starting", true);
        }
        if let Some(load) = self.load_bps {
            j.insert("load", load);
        }
        if !links_arr.is_empty() {
            j.insert("links", links_arr);
        }
        j
    }

    pub fn from_json(j: &Json) -> Result<Self> {
        let id = j.str_of("id");
        if id.is_empty() {
            bail!("mesh beat missing id");
        }
        let mut pools = BTreeMap::new();
        if let Some(Json::Obj(m)) = j.get("pools") {
            for (k, v) in m {
                pools.insert(
                    k.clone(),
                    MeshPoolState {
                        state: v.str_of("state"),
                        healthy: v.u64_of("healthy") as u32,
                        members: v.u64_of("members") as u32,
                    },
                );
            }
        }
        let hubs = j
            .arr_of("hubs")
            .iter()
            .filter_map(HubPeer::from_json)
            .collect();
        let links = j
            .arr_of("links")
            .iter()
            .map(|l| MeshLink {
                id: l.i64_of("id") as i32,
                name: l.str_of("name"),
                remote: l.str_of("remote"),
                engine: l.str_of("engine"),
                up: l.bool_of("up"),
                ms: l.num_of("ms"),
                bps: l.num_of("bps"),
            })
            .collect();
        Ok(Self {
            id,
            name: j.str_of("name"),
            ip: j.str_of("ip"),
            ip6: j.str_of("ip6"),
            port: j.u64_of("port") as u16,
            healthy: j.bool_of("healthy"),
            pools,
            hubs,
            version: j.str_of("version"),
            bye: j.bool_of("bye"),
            weight: (j.u64_of("weight") as u32).max(1),
            master: j.bool_of("master"),
            dns_down: j.bool_of("dns_down"),
            starting: j.bool_of("starting"),
            load_bps: j.get("load").and_then(|v| v.as_f64()),
            links,
        })
    }
}

#[derive(Clone, Debug)]
pub struct MeshCode {
    pub id: String,
    pub name: String,
    pub url: String,
    pub ip: String,
    pub secret: String,
}

impl MeshCode {
    pub fn encode(&self) -> String {
        let j = Json::obj()
            .set("i", self.id.clone())
            .set("n", self.name.clone())
            .set("u", self.url.clone())
            .set("a", self.ip.clone())
            .set("s", self.secret.clone());
        format!("{MESH_CODE_HEAD}{}", hjson::b64url_encode(j.to_string_compact().as_bytes()))
    }

    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let enc = s
            .strip_prefix(MESH_CODE_HEAD)
            .with_context(|| format!("not a hub join code (must start with {MESH_CODE_HEAD})"))?;
        let raw = hjson::b64_decode(enc).context("hub join code is damaged")?;
        let text = String::from_utf8(raw).context("hub join code is not UTF-8")?;
        let j = Json::parse(&text).context("hub join code JSON is damaged")?;
        let id = j.str_of("i");
        let url = j.str_of("u");
        let secret = j.str_of("s");
        if id.is_empty() || url.is_empty() || secret.len() < 32 {
            bail!("hub join code is incomplete or secret too short");
        }
        Ok(Self {
            id,
            name: j.str_of("n"),
            url,
            ip: j.str_of("a"),
            secret,
        })
    }
}

/// EWMA link traffic rate calculator (`0.6 * cur + 0.4 * prev`, minimum 2s window).
#[derive(Default)]
pub struct LinkRateTracker {
    entries: Mutex<HashMap<String, (u64, Instant, f64)>>,
}

impl LinkRateTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, key: &str, rx_bytes: u64, tx_bytes: u64, now: Instant) -> f64 {
        let total = rx_bytes.saturating_add(tx_bytes);
        let mut m = self.entries.lock().unwrap();
        if let Some((prev_bytes, prev_at, prev_bps)) = m.get_mut(key) {
            let dt = now.saturating_duration_since(*prev_at).as_secs_f64();
            if dt < 2.0 {
                return *prev_bps;
            }
            if total < *prev_bytes {
                *prev_bytes = total;
                *prev_at = now;
                return *prev_bps;
            }
            let cur = (total - *prev_bytes) as f64 / dt;
            if *prev_bps == 0.0 || dt > 30.0 {
                *prev_bps = cur;
            } else {
                *prev_bps = 0.6 * cur + 0.4 * *prev_bps;
            }
            *prev_bytes = total;
            *prev_at = now;
            return prev_bps.round();
        }
        if m.len() > 512 {
            m.clear();
        }
        m.insert(key.to_string(), (total, now, 0.0));
        0.0
    }
}

#[derive(Clone, Debug)]
pub struct HubRuntime {
    pub up: bool,
    pub misses: u32,
    pub last_seen_unix: u64,
    pub latency_ms: f64,
    pub beat: MeshBeat,
    pub err: String,
}

#[derive(Clone, Debug)]
pub struct ClusterMeshConfig {
    pub node_id: String,
    pub name: String,
    pub public_ip: String,
    pub public_ip6: String,
    pub listen_port: u16,
    pub secret: String,
    pub weight: u32,
    pub master: bool,
    pub healthy_pools: Vec<u16>,
    pub hubs: Vec<HubPeer>,
}

impl ClusterMeshConfig {
    pub fn self_url(&self) -> String {
        if self.public_ip.is_empty() || self.listen_port == 0 {
            return String::new();
        }
        if self.public_ip.contains(':') {
            format!("http://[{}]:{}", self.public_ip, self.listen_port)
        } else {
            format!("http://{}:{}", self.public_ip, self.listen_port)
        }
    }

    pub fn upsert_hub(&mut self, h: HubPeer) {
        if h.id == self.node_id || h.id.is_empty() {
            return;
        }
        for existing in &mut self.hubs {
            if existing.id == h.id {
                *existing = h;
                return;
            }
        }
        self.hubs.push(h);
        self.hubs.sort_by(|a, b| a.id.cmp(&b.id));
    }

    pub fn to_json(&self) -> Json {
        let hubs_arr: Vec<Json> = self.hubs.iter().map(|h| h.to_json()).collect();
        Json::obj()
            .set("node_id", self.node_id.clone())
            .set("name", self.name.clone())
            .set("public_ip", self.public_ip.clone())
            .set("public_ip6", self.public_ip6.clone())
            .set("listen_port", self.listen_port)
            .set("secret", self.secret.clone())
            .set("weight", self.weight.max(1))
            .set("master", self.master)
            .set("healthy_pools", self.healthy_pools.clone())
            .set("hubs", hubs_arr)
    }

    pub fn from_json(j: &Json) -> Result<Self> {
        let hubs = j.arr_of("hubs").iter().filter_map(HubPeer::from_json).collect();
        let healthy_pools = j
            .arr_of("healthy_pools")
            .into_iter()
            .filter_map(|v| v.as_f64().map(|n| n as u16))
            .filter(|&p| p > 0)
            .collect();
        Ok(Self {
            node_id: j.str_of("node_id"),
            name: j.str_of("name"),
            public_ip: j.str_of("public_ip"),
            public_ip6: j.str_of("public_ip6"),
            listen_port: j.u64_of("listen_port") as u16,
            secret: j.str_of("secret"),
            weight: (j.u64_of("weight") as u32).max(1),
            master: j.bool_of("master"),
            healthy_pools,
            hubs,
        })
    }

    pub fn load(path: &str) -> Result<Option<Self>> {
        match hjson::read_json_file(path)? {
            Some(j) => Ok(Some(Self::from_json(&j)?)),
            None => Ok(None),
        }
    }

    pub fn save(&self, path: &str) -> Result<()> {
        hjson::write_atomic(path, self.to_json().to_string_pretty().as_bytes())
    }
}

/// Live cluster mesh node handling `/_hc/hello`, `/_hc/beat`, `/_hc/adopt`,
/// heartbeat loops, and peer runtime state.
pub struct MeshNode {
    pub cfg: Mutex<ClusterMeshConfig>,
    pub runtime: Mutex<HashMap<String, HubRuntime>>,
    pub verifier: KhaymaliMeshVerifier,
    pub state_path: Option<String>,
}

impl MeshNode {
    pub fn new(cfg: ClusterMeshConfig, state_path: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            cfg: Mutex::new(cfg),
            runtime: Mutex::new(HashMap::new()),
            verifier: KhaymaliMeshVerifier::new(),
            state_path,
        })
    }

    fn persist_locked(&self, cfg: &ClusterMeshConfig) {
        if let Some(p) = &self.state_path {
            let _ = cfg.save(p);
        }
    }

    pub fn join_code(&self) -> Result<String> {
        let mut cfg = self.cfg.lock().unwrap();
        if cfg.secret.is_empty() {
            cfg.secret = hex(&rand_bytes::<32>());
            self.persist_locked(&cfg);
        }
        let url = cfg.self_url();
        if url.is_empty() {
            bail!("hub public_ip and listen_port must be set to create a join code");
        }
        Ok(MeshCode {
            id: cfg.node_id.clone(),
            name: cfg.name.clone(),
            url,
            ip: cfg.public_ip.clone(),
            secret: cfg.secret.clone(),
        }
        .encode())
    }

    pub fn self_beat(&self) -> MeshBeat {
        let cfg = self.cfg.lock().unwrap();
        let mut pools = BTreeMap::new();
        for &p in &cfg.healthy_pools {
            pools.insert(
                p.to_string(),
                MeshPoolState {
                    state: "healthy".into(),
                    healthy: 1,
                    members: 1,
                },
            );
        }
        MeshBeat {
            id: cfg.node_id.clone(),
            name: cfg.name.clone(),
            ip: cfg.public_ip.clone(),
            ip6: cfg.public_ip6.clone(),
            port: cfg.listen_port,
            healthy: !cfg.healthy_pools.is_empty(),
            pools,
            hubs: Vec::new(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            bye: false,
            weight: cfg.weight.max(1),
            master: cfg.master,
            dns_down: false,
            starting: false,
            load_bps: None,
            links: Vec::new(),
        }
    }

    /// Links with the hub encoded in `code`. If this hub already leads a multi-hub cluster
    /// with a different secret, invokes `/_hc/adopt` to bring the new hub onto our secret.
    pub async fn add_hub(self: &Arc<Self>, code: &str) -> Result<HubPeer> {
        let mc = MeshCode::parse(code)?;
        let (node_id, name, cur_secret, cur_hubs) = {
            let cfg = self.cfg.lock().unwrap();
            if mc.id == cfg.node_id {
                bail!("cannot link a hub with its own join code");
            }
            (
                cfg.node_id.clone(),
                cfg.name.clone(),
                cfg.secret.clone(),
                cfg.hubs.clone(),
            )
        };

        let mut secret = mc.secret.clone();
        if !cur_secret.is_empty() && cur_secret != mc.secret && !cur_hubs.is_empty() {
            // Adopt the new standalone hub into our existing cluster
            let sealed = sync_seal(&mc.secret, &cur_secret)?;
            let req_body = Json::obj()
                .set("id", node_id.clone())
                .set("name", name)
                .set("secret", sealed)
                .to_string_compact();
            let (status, resp_hdrs, resp_body) =
                mesh_http_post(&mc.url, "/adopt", &mc.secret, req_body.as_bytes()).await?;
            if status != 200 {
                bail!("adopt refused by {} (HTTP {status})", mc.url);
            }
            self.verifier
                .verify_headers(&mc.secret, &resp_hdrs, &resp_body, now_unix())
                .context("adopt response signature invalid")?;
            let ans = Json::parse(&String::from_utf8_lossy(&resp_body))?;
            if !ans.bool_of("ok") {
                bail!("adopt rejected: {}", ans.str_of("error"));
            }
            secret = cur_secret;
        }

        let mut self_beat = self.self_beat();
        self_beat.hubs = cur_hubs;
        let (ans, lat) = self.post_beat(&mc.url, "/hello", &secret, &self_beat).await?;
        if ans.id != mc.id {
            bail!("hub at {} answered as {}, expected {}", mc.url, ans.id, mc.id);
        }
        let peer = HubPeer {
            id: ans.id.clone(),
            name: ans.name.clone(),
            url: mc.url.clone(),
            public_ip: ans.ip.clone(),
        };
        self.record_beat(&ans, lat, None);
        {
            let mut cfg = self.cfg.lock().unwrap();
            cfg.secret = secret.clone();
            cfg.upsert_hub(peer.clone());
            for o in &ans.hubs {
                if o.id != cfg.node_id && o.id != peer.id {
                    cfg.upsert_hub(o.clone());
                }
            }
            self.persist_locked(&cfg);
        }
        // Introduce ourselves to hubs learned from the answer
        let mut intro = self.self_beat();
        intro.hubs.clear();
        for o in &ans.hubs {
            if o.id != node_id && o.id != peer.id {
                let _ = self.post_beat(&o.url, "/hello", &secret, &intro).await;
            }
        }
        Ok(peer)
    }

    pub async fn remove_hub(&self, id: &str) -> bool {
        let (gone, secret) = {
            let mut cfg = self.cfg.lock().unwrap();
            let mut removed = None;
            cfg.hubs.retain(|h| {
                if h.id == id {
                    removed = Some(h.clone());
                    false
                } else {
                    true
                }
            });
            if removed.is_some() {
                self.persist_locked(&cfg);
            }
            (removed, cfg.secret.clone())
        };
        let Some(peer) = gone else {
            return false;
        };
        self.runtime.lock().unwrap().remove(id);
        let mut bye = self.self_beat();
        bye.bye = true;
        let _ = self.post_beat(&peer.url, "/beat", &secret, &bye).await;
        true
    }

    pub async fn post_beat(&self, url: &str, path: &str, secret: &str, beat: &MeshBeat) -> Result<(MeshBeat, f64)> {
        let body = beat.to_json().to_string_compact();
        let start = Instant::now();
        let (status, hdrs, data) = mesh_http_post(url, path, secret, body.as_bytes()).await?;
        let lat_ms = start.elapsed().as_secs_f64() * 1000.0;
        if status != 200 {
            bail!("mesh HTTP {status}");
        }
        self.verifier
            .verify_headers(secret, &hdrs, &data, now_unix())
            .context("mesh response signature untrusted")?;
        let j = Json::parse(&String::from_utf8_lossy(&data))?;
        Ok((MeshBeat::from_json(&j)?, lat_ms))
    }

    pub fn record_beat(&self, beat: &MeshBeat, lat_ms: f64, err: Option<&str>) {
        let mut rt = self.runtime.lock().unwrap();
        let entry = rt.entry(beat.id.clone()).or_insert_with(|| HubRuntime {
            up: false,
            misses: 0,
            last_seen_unix: 0,
            latency_ms: 0.0,
            beat: beat.clone(),
            err: String::new(),
        });
        if let Some(e) = err {
            entry.misses = entry.misses.saturating_add(1);
            entry.err = e.to_string();
            if entry.misses >= MESH_FALL_MISSES {
                entry.up = false;
            }
            return;
        }
        entry.up = true;
        entry.misses = 0;
        entry.err.clear();
        entry.last_seen_unix = now_unix();
        entry.beat = beat.clone();
        if lat_ms > 0.0 {
            entry.latency_ms = (lat_ms * 10.0).round() / 10.0;
        }
    }

    /// Sends one heartbeat round to all configured peer hubs.
    pub async fn beat_once(&self) {
        let (hubs, secret) = {
            let cfg = self.cfg.lock().unwrap();
            (cfg.hubs.clone(), cfg.secret.clone())
        };
        if secret.is_empty() || hubs.is_empty() {
            return;
        }
        let self_b = self.self_beat();
        for peer in hubs {
            match self.post_beat(&peer.url, "/beat", &secret, &self_b).await {
                Ok((ans, lat)) => self.record_beat(&ans, lat, None),
                Err(e) => {
                    let stub = MeshBeat {
                        id: peer.id.clone(),
                        name: peer.name.clone(),
                        ..Default::default()
                    };
                    self.record_beat(&stub, 0.0, Some(&e.to_string()));
                }
            }
        }
    }

    /// Converts self + live peer beats into `HubBeat` records for `compute_dns_records`.
    pub fn snapshot_hub_beats(&self) -> Vec<HubBeat> {
        let mut out = Vec::new();
        {
            let cfg = self.cfg.lock().unwrap();
            out.push(HubBeat {
                node_id: cfg.node_id.clone(),
                public_ipv4: cfg.public_ip.clone(),
                public_ipv6: if cfg.public_ip6.is_empty() { None } else { Some(cfg.public_ip6.clone()) },
                healthy_pools: cfg.healthy_pools.clone(),
                has_nat_pools: false,
                can_reach_dns_provider: true,
                is_controller: cfg.master,
                weight: cfg.weight.max(1),
                load_pct: 0.0,
                ts_unix: now_unix(),
            });
        }
        let rt = self.runtime.lock().unwrap();
        for h in rt.values() {
            if !h.up {
                continue;
            }
            let pools: Vec<u16> = h
                .beat
                .pools
                .iter()
                .filter(|(_, st)| st.healthy > 0)
                .filter_map(|(k, _)| k.parse::<u16>().ok())
                .collect();
            out.push(HubBeat {
                node_id: h.beat.id.clone(),
                public_ipv4: h.beat.ip.clone(),
                public_ipv6: if h.beat.ip6.is_empty() { None } else { Some(h.beat.ip6.clone()) },
                healthy_pools: pools,
                has_nat_pools: false,
                can_reach_dns_provider: !h.beat.dns_down,
                is_controller: h.beat.master,
                weight: h.beat.weight.max(1),
                load_pct: h.beat.load_bps.unwrap_or(0.0),
                ts_unix: h.last_seen_unix,
            });
        }
        out
    }

    /// Serves `/_hc/hello`, `/_hc/beat`, and `/_hc/adopt` on an already-bound `TcpListener`.
    pub async fn serve_listener(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let node = self.clone();
            tokio::spawn(async move {
                let _ = node.handle_http_conn(stream, peer_addr).await;
            });
        }
    }

    async fn handle_http_conn(self: &Arc<Self>, mut stream: TcpStream, peer_addr: SocketAddr) -> Result<()> {
        let Some((method, path, headers, body)) = read_http_request(&mut stream, 65536).await? else {
            return Ok(());
        };
        if method != "POST" {
            write_http_response(&mut stream, 404, &[], b"not found").await?;
            return Ok(());
        }
        let secret = self.cfg.lock().unwrap().secret.clone();
        if secret.is_empty()
            || self
                .verifier
                .verify_headers(&secret, &headers, &body, now_unix())
                .is_err()
        {
            write_http_response(&mut stream, 404, &[], b"not found").await?;
            return Ok(());
        }

        let sub = path.strip_prefix(MESH_ROUTE_PREFIX).unwrap_or("");
        match sub {
            "/adopt" => {
                let text = String::from_utf8_lossy(&body);
                let Ok(req) = Json::parse(&text) else {
                    write_http_response(&mut stream, 404, &[], b"not found").await?;
                    return Ok(());
                };
                let req_id = req.str_of("id");
                let sealed = req.str_of("secret");
                let (ok, err_msg) = {
                    let mut cfg = self.cfg.lock().unwrap();
                    if req_id.is_empty() || req_id == cfg.node_id {
                        (false, "invalid requester id".to_string())
                    } else if !cfg.hubs.is_empty() {
                        (false, "hub is already linked with other hubs".to_string())
                    } else {
                        match sync_open(&cfg.secret, &sealed) {
                            Ok(new_sec) if new_sec.len() >= 32 => {
                                cfg.secret = new_sec;
                                self.persist_locked(&cfg);
                                (true, String::new())
                            }
                            _ => (false, "the adopt request cannot be read".to_string()),
                        }
                    }
                };
                let mut ans = Json::obj().set("ok", ok);
                if !err_msg.is_empty() {
                    ans.insert("error", err_msg);
                }
                let out = ans.to_string_compact();
                // Sign answer with the OLD secret (the code's secret) just like Khaymali's handleMeshAdopt
                let hdrs = make_signed_headers(&secret, out.as_bytes());
                write_http_response(&mut stream, 200, &hdrs, out.as_bytes()).await?;
            }
            "/hello" | "/beat" => {
                let hello = sub == "/hello";
                let text = String::from_utf8_lossy(&body);
                let Ok(j) = Json::parse(&text) else {
                    write_http_response(&mut stream, 400, &[], b"bad beat").await?;
                    return Ok(());
                };
                let Ok(in_beat) = MeshBeat::from_json(&j) else {
                    write_http_response(&mut stream, 400, &[], b"bad beat").await?;
                    return Ok(());
                };
                let mut to_meet = Vec::new();
                let reject_status: Option<(u16, &'static [u8])> = {
                    let mut cfg = self.cfg.lock().unwrap();
                    if in_beat.id == cfg.node_id {
                        Some((400, b"self beat"))
                    } else {
                        let known = cfg.hubs.iter().any(|h| h.id == in_beat.id);
                        if in_beat.bye {
                            cfg.hubs.retain(|h| h.id != in_beat.id);
                            self.persist_locked(&cfg);
                            self.runtime.lock().unwrap().remove(&in_beat.id);
                            None
                        } else if !hello && !known {
                            Some((404, b"not found"))
                        } else if hello {
                        let ip = if in_beat.ip.is_empty() {
                            peer_addr.ip().to_string()
                        } else {
                            in_beat.ip.clone()
                        };
                        let url = if ip.contains(':') {
                            format!("http://[{}]:{}", ip, in_beat.port)
                        } else {
                            format!("http://{}:{}", ip, in_beat.port)
                        };
                        cfg.upsert_hub(HubPeer {
                            id: in_beat.id.clone(),
                            name: in_beat.name.clone(),
                            url,
                            public_ip: ip,
                        });
                        self.persist_locked(&cfg);
                        for o in &in_beat.hubs {
                            if o.id != cfg.node_id && !cfg.hubs.iter().any(|h| h.id == o.id) {
                                to_meet.push(o.clone());
                            }
                        }
                        None
                    } else {
                        None
                    }
                    }
                };
                if let Some((code, msg)) = reject_status {
                    write_http_response(&mut stream, code, &[], msg).await?;
                    return Ok(());
                }
                if !in_beat.bye {
                    self.record_beat(&in_beat, 0.0, None);
                }
                if !to_meet.is_empty() {
                    let node_clone = self.clone();
                    tokio::spawn(async move {
                        node_clone.meet_hubs(to_meet).await;
                    });
                }
                let mut out_beat = self.self_beat();
                if hello {
                    out_beat.hubs = self.cfg.lock().unwrap().hubs.clone();
                }
                let out_str = out_beat.to_json().to_string_compact();
                let hdrs = make_signed_headers(&secret, out_str.as_bytes());
                write_http_response(&mut stream, 200, &hdrs, out_str.as_bytes()).await?;
            }
            _ => {
                write_http_response(&mut stream, 404, &[], b"not found").await?;
            }
        }
        Ok(())
    }

    async fn meet_hubs(&self, hubs: Vec<HubPeer>) {
        let (node_id, secret) = {
            let cfg = self.cfg.lock().unwrap();
            (cfg.node_id.clone(), cfg.secret.clone())
        };
        let self_b = self.self_beat();
        for o in hubs {
            if o.id.is_empty() || o.id == node_id || o.url.is_empty() {
                continue;
            }
            if let Ok((ans, lat)) = self.post_beat(&o.url, "/hello", &secret, &self_b).await {
                if ans.id == o.id {
                    self.record_beat(&ans, lat, None);
                    let mut cfg = self.cfg.lock().unwrap();
                    cfg.upsert_hub(HubPeer {
                        id: ans.id,
                        name: ans.name,
                        url: o.url,
                        public_ip: ans.ip,
                    });
                    self.persist_locked(&cfg);
                }
            }
        }
    }
}

// ============================================================================
// Minimal Zero-Dependency HTTP/1.1 Client & Server Helpers (shared with carrier_swap)
// ============================================================================

pub(crate) fn parse_http_url(base_url: &str) -> Result<(String, u16, String)> {
    let rest = base_url
        .trim()
        .strip_prefix("http://")
        .with_context(|| format!("only http:// mesh/peer URLs are supported (got '{base_url}')"))?;
    let (hostport, base_path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].trim_end_matches('/').to_string()),
        None => (rest, String::new()),
    };
    if hostport.starts_with('[') {
        let end = hostport.find(']').context("malformed IPv6 host")?;
        let host = hostport[1..end].to_string();
        let port = hostport[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(80);
        Ok((host, port, base_path))
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        Ok((h.to_string(), p.parse().context("invalid URL port")?, base_path))
    } else {
        Ok((hostport.to_string(), 80, base_path))
    }
}

pub(crate) async fn mesh_http_post(
    base_url: &str,
    sub_path: &str,
    secret: &str,
    body: &[u8],
) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    let full_path = format!("{MESH_ROUTE_PREFIX}{sub_path}");
    signed_http_request("POST", base_url, &full_path, secret, body, Duration::from_millis(2500)).await
}

pub(crate) async fn signed_http_request(
    method: &str,
    base_url: &str,
    path: &str,
    secret: &str,
    body: &[u8],
    io_timeout: Duration,
) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    let (host, port, base_path) = parse_http_url(base_url)?;
    let full_path = format!("{base_path}{path}");
    let addr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut stream = timeout(io_timeout, TcpStream::connect(&addr))
        .await
        .with_context(|| format!("connect timeout to {addr}"))??;
    let sig_headers = make_signed_headers(secret, body);
    let mut req = format!(
        "{method} {full_path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in sig_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    timeout(io_timeout, stream.write_all(req.as_bytes())).await??;
    if !body.is_empty() {
        timeout(io_timeout, stream.write_all(body)).await??;
    }
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = timeout(io_timeout, stream.read(&mut chunk)).await??;
        if n == 0 {
            break;
        }
        if raw.len() + n > 256 * 1024 {
            bail!("HTTP response too large");
        }
        raw.extend_from_slice(&chunk[..n]);
    }
    let hdr_end = find_subslice(&raw, b"\r\n\r\n").context("malformed HTTP response")?;
    let hdr_text = String::from_utf8_lossy(&raw[..hdr_end]);
    let mut lines = hdr_text.split("\r\n");
    let status_line = lines.next().context("empty HTTP response")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("bad HTTP status")?;
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let resp_body = raw[hdr_end + 4..].to_vec();
    Ok((status, headers, resp_body))
}

pub(crate) async fn read_http_request(
    stream: &mut TcpStream,
    max_body: usize,
) -> Result<Option<(String, String, HashMap<String, String>, Vec<u8>)>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 2048];
    let hdr_end = loop {
        let n = match timeout(Duration::from_secs(5), stream.read(&mut tmp)).await {
            Ok(Ok(0)) => return Ok(None),
            Ok(Ok(n)) => n,
            _ => return Ok(None),
        };
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 16384 {
            bail!("HTTP headers too large");
        }
    };
    let hdr_text = String::from_utf8_lossy(&buf[..hdr_end]).into_owned();
    let mut lines = hdr_text.split("\r\n");
    let first = lines.next().context("empty request line")?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let clen: usize = headers
        .get("content-length")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if clen > max_body {
        bail!("HTTP body too large ({clen} > {max_body})");
    }
    let mut body = buf[hdr_end + 4..].to_vec();
    while body.len() < clen {
        let n = timeout(Duration::from_secs(5), stream.read(&mut tmp)).await??;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(clen);
    Ok(Some((method, path, headers, body)))
}

pub(crate) async fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    extra_headers: &[(String, String)],
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    };
    let mut hdr = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in extra_headers {
        hdr.push_str(&format!("{k}: {v}\r\n"));
    }
    hdr.push_str("\r\n");
    stream.write_all(hdr.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ============================================================================
// Pure-Rust AES-256-GCM (zero extra crates, matches Go crypto/cipher.NewGCM)
// ============================================================================

const AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];
const AES_RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

fn aes256_expand(key: &[u8; 32]) -> [u32; 60] {
    let mut w = [0u32; 60];
    for i in 0..8 {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    for i in 8..60 {
        let mut t = w[i - 1];
        if i % 8 == 0 {
            t = t.rotate_left(8);
            t = ((AES_SBOX[((t >> 24) & 0xff) as usize] as u32) << 24)
                | ((AES_SBOX[((t >> 16) & 0xff) as usize] as u32) << 16)
                | ((AES_SBOX[((t >> 8) & 0xff) as usize] as u32) << 8)
                | (AES_SBOX[(t & 0xff) as usize] as u32);
            t ^= (AES_RCON[i / 8 - 1] as u32) << 24;
        } else if i % 8 == 4 {
            t = ((AES_SBOX[((t >> 24) & 0xff) as usize] as u32) << 24)
                | ((AES_SBOX[((t >> 16) & 0xff) as usize] as u32) << 16)
                | ((AES_SBOX[((t >> 8) & 0xff) as usize] as u32) << 8)
                | (AES_SBOX[(t & 0xff) as usize] as u32);
        }
        w[i] = w[i - 8] ^ t;
    }
    w
}

#[inline]
fn xtime(a: u8) -> u8 {
    if (a & 0x80) != 0 {
        (a << 1) ^ 0x1b
    } else {
        a << 1
    }
}

fn aes256_encrypt_block(rk: &[u32; 60], blk: &[u8; 16]) -> [u8; 16] {
    let mut s = *blk;
    let add_rk = |st: &mut [u8; 16], r: usize| {
        for c in 0..4 {
            let w = rk[r * 4 + c];
            st[4 * c] ^= ((w >> 24) & 0xff) as u8;
            st[4 * c + 1] ^= ((w >> 16) & 0xff) as u8;
            st[4 * c + 2] ^= ((w >> 8) & 0xff) as u8;
            st[4 * c + 3] ^= (w & 0xff) as u8;
        }
    };
    add_rk(&mut s, 0);
    for r in 1..=14 {
        for b in &mut s {
            *b = AES_SBOX[*b as usize];
        }
        s = [
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11],
        ];
        if r < 14 {
            for c in 0..4 {
                let (a0, a1, a2, a3) = (s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]);
                let t = a0 ^ a1 ^ a2 ^ a3;
                s[4 * c] = a0 ^ t ^ xtime(a0 ^ a1);
                s[4 * c + 1] = a1 ^ t ^ xtime(a1 ^ a2);
                s[4 * c + 2] = a2 ^ t ^ xtime(a2 ^ a3);
                s[4 * c + 3] = a3 ^ t ^ xtime(a3 ^ a0);
            }
        }
        add_rk(&mut s, r);
    }
    s
}

fn ghash_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        if ((x >> (127 - i)) & 1) != 0 {
            z ^= v;
        }
        if (v & 1) != 0 {
            v = (v >> 1) ^ (0xe1u128 << 120);
        } else {
            v >>= 1;
        }
    }
    z
}

fn ghash(h_bytes: &[u8; 16], ct: &[u8]) -> [u8; 16] {
    let h = u128::from_be_bytes(*h_bytes);
    let mut y = 0u128;
    for chunk in ct.chunks(16) {
        let mut blk = [0u8; 16];
        blk[..chunk.len()].copy_from_slice(chunk);
        y = ghash_mul(y ^ u128::from_be_bytes(blk), h);
    }
    let lens = (ct.len() as u128) * 8;
    y = ghash_mul(y ^ lens, h);
    y.to_be_bytes()
}

pub fn aes256_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plain: &[u8]) -> Vec<u8> {
    let rk = aes256_expand(key);
    let h = aes256_encrypt_block(&rk, &[0u8; 16]);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    let mut ct = Vec::with_capacity(plain.len() + 16);
    let mut ctr: u32 = 2;
    for chunk in plain.chunks(16) {
        let mut cb = [0u8; 16];
        cb[..12].copy_from_slice(nonce);
        cb[12..16].copy_from_slice(&ctr.to_be_bytes());
        let ks = aes256_encrypt_block(&rk, &cb);
        for (i, &p) in chunk.iter().enumerate() {
            ct.push(p ^ ks[i]);
        }
        ctr = ctr.wrapping_add(1);
    }
    let s = ghash(&h, &ct);
    let mask = aes256_encrypt_block(&rk, &j0);
    for i in 0..16 {
        ct.push(s[i] ^ mask[i]);
    }
    ct
}

pub fn aes256_gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], ct_tag: &[u8]) -> Result<Vec<u8>> {
    if ct_tag.len() < 16 {
        bail!("ciphertext too short");
    }
    let (ct, tag) = ct_tag.split_at(ct_tag.len() - 16);
    let rk = aes256_expand(key);
    let h = aes256_encrypt_block(&rk, &[0u8; 16]);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    let s = ghash(&h, ct);
    let mask = aes256_encrypt_block(&rk, &j0);
    let mut expected_tag = [0u8; 16];
    for i in 0..16 {
        expected_tag[i] = s[i] ^ mask[i];
    }
    if !ct_eq(&expected_tag, tag) {
        bail!("AES-256-GCM authentication tag mismatch");
    }
    let mut pt = Vec::with_capacity(ct.len());
    let mut ctr: u32 = 2;
    for chunk in ct.chunks(16) {
        let mut cb = [0u8; 16];
        cb[..12].copy_from_slice(nonce);
        cb[12..16].copy_from_slice(&ctr.to_be_bytes());
        let ks = aes256_encrypt_block(&rk, &cb);
        for (i, &c) in chunk.iter().enumerate() {
            pt.push(c ^ ks[i]);
        }
        ctr = ctr.wrapping_add(1);
    }
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_heartbeat_verifies_and_blocks_replay() {
        let v = MeshVerifier::new();
        let sec = b"cluster-secret-32-bytes-key-test";
        let sig = sign_heartbeat(sec, 1_700_000_000, "n1", b"{\"ok\":true}");
        assert!(v.verify(sec, 1_700_000_000, "n1", b"{\"ok\":true}", &sig, 1_700_000_005).is_ok());
        assert!(v.verify(sec, 1_700_000_000, "n1", b"{\"ok\":true}", &sig, 1_700_000_006).is_err());
        assert!(v.verify(sec, 1_700_000_000, "n2", b"{\"ok\":true}", &sig, 1_700_000_200).is_err());
    }

    #[test]
    fn dns_writer_election_and_record_selection() {
        let hubs = vec![
            HubBeat {
                node_id: "hub-b".into(), public_ipv4: "198.51.100.2".into(),
                public_ipv6: Some("2001:db8::2".into()), healthy_pools: vec![443],
                has_nat_pools: true, can_reach_dns_provider: true, is_controller: false,
                weight: 1, load_pct: 20.0, ts_unix: 100,
            },
            HubBeat {
                node_id: "hub-a".into(), public_ipv4: "198.51.100.1".into(),
                public_ipv6: Some("2001:db8::1".into()), healthy_pools: vec![443],
                has_nat_pools: false, can_reach_dns_provider: true, is_controller: true,
                weight: 1, load_pct: 10.0, ts_unix: 100,
            },
        ];
        let rec = compute_dns_records(&hubs, DnsMode::Balance, 0);
        assert_eq!(rec.writer_node_id.as_deref(), Some("hub-a"));
        assert_eq!(rec.a_records, vec!["198.51.100.2", "198.51.100.1"]);
        assert_eq!(rec.aaaa_records, vec!["2001:db8::1"]);
    }

    #[test]
    fn aes256_gcm_matches_openssl_vector_and_sync_seal() {
        let secret = "0123456789abcdef0123456789abcdef";
        let key = sync_seal_key(secret);
        let nonce_v = crate::util::unhex("000102030405060708090a0b").unwrap();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_v);
        let ct = aes256_gcm_encrypt(&key, &nonce, b"fedcba9876543210fedcba9876543210");
        assert_eq!(
            hex(&ct),
            "b05c3ee7a418a90cad814569f17950ccd1266c2c7c821231c6a36456c21595608c1d847e0f0d05383c7ed2cdcdced80d"
        );
        let pt = aes256_gcm_decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, b"fedcba9876543210fedcba9876543210");

        let sealed = sync_seal(secret, "new-cluster-secret-0123456789abcdef").unwrap();
        assert_eq!(sync_open(secret, &sealed).unwrap(), "new-cluster-secret-0123456789abcdef");
        assert!(sync_open("wrong-secret-0123456789abcdef0123", &sealed).is_err());
    }

    #[tokio::test]
    async fn live_three_hub_mesh_join_adopt_stealth404_and_bye() {
        let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p1 = l1.local_addr().unwrap().port();
        let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p2 = l2.local_addr().unwrap().port();
        let l3 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p3 = l3.local_addr().unwrap().port();

        let n1 = MeshNode::new(
            ClusterMeshConfig {
                node_id: "hub-1".into(), name: "Tehran-1".into(), public_ip: "127.0.0.1".into(),
                public_ip6: String::new(), listen_port: p1, secret: String::new(),
                weight: 1, master: true, healthy_pools: vec![443], hubs: vec![],
            },
            None,
        );
        let n2 = MeshNode::new(
            ClusterMeshConfig {
                node_id: "hub-2".into(), name: "Tehran-2".into(), public_ip: "127.0.0.1".into(),
                public_ip6: String::new(), listen_port: p2, secret: String::new(),
                weight: 1, master: false, healthy_pools: vec![443], hubs: vec![],
            },
            None,
        );
        let n3 = MeshNode::new(
            ClusterMeshConfig {
                node_id: "hub-3".into(), name: "Tehran-3".into(), public_ip: "127.0.0.1".into(),
                public_ip6: String::new(), listen_port: p3, secret: String::new(),
                weight: 1, master: false, healthy_pools: vec![443], hubs: vec![],
            },
            None,
        );

        let _t1 = tokio::spawn(n1.clone().serve_listener(l1));
        let _t2 = tokio::spawn(n2.clone().serve_listener(l2));
        let _t3 = tokio::spawn(n3.clone().serve_listener(l3));

        // 1. Hub-2 joins Hub-1 via hc1_ join code
        let c1 = n1.join_code().unwrap();
        assert!(c1.starts_with("hc1_"));
        let peer1 = n2.add_hub(&c1).await.unwrap();
        assert_eq!(peer1.id, "hub-1");

        // 2. Hub-3 creates its own join code (different secret), Hub-2 adopts Hub-3 into cluster!
        let c3 = n3.join_code().unwrap();
        let peer3 = n2.add_hub(&c3).await.unwrap();
        assert_eq!(peer3.id, "hub-3");
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(n1.cfg.lock().unwrap().secret, n3.cfg.lock().unwrap().secret);

        // 3. Unsigned / wrong-secret request gets stealth 404
        let (st, _, _) = mesh_http_post(&format!("http://127.0.0.1:{p1}"), "/beat", "wrong-secret", b"{}")
            .await
            .unwrap();
        assert_eq!(st, 404);

        // 4. Heartbeat round updates runtime & DNS target records
        n1.beat_once().await;
        let beats = n1.snapshot_hub_beats();
        let dns = compute_dns_records(&beats, DnsMode::Balance, 0);
        assert_eq!(dns.writer_node_id.as_deref(), Some("hub-1"));
        assert!(!dns.a_records.is_empty());

        // 5. Graceful bye removes hub
        assert!(n2.remove_hub("hub-3").await);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!n3.cfg.lock().unwrap().hubs.iter().any(|h| h.id == "hub-2"));
    }
}
