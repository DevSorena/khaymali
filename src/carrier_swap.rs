//! Live Carrier Swap Coordinator & Transactional Unit Switcher (`src/carrier_swap.rs`).
//!
//! Full Rust port of Khaymali's `carrier_swap.go` and `engineSwitchTx`:
//!   * `CarrierChoice` parser supporting `frp:<tcp|kcp|quic|websocket>`,
//!     `backhaul:<tcp|tcpmux|ws|wss|wsmux|wssmux|udp>`, `gre-backhaul:<...>`,
//!     and native `khaymali:<ws|wss|ssh|spoof|udp|tcp>`.
//!   * `UnitSwitchTx`: atomic config-file backup + systemd unit switch with complete
//!     rollback of modified files and previously-active units on any failure.
//!   * `SwapCoordinator` 4-phase state machine (`foreign` -> `local` -> `verify` -> automatic
//!     `revert` on both sides when verification fails), plus `manual` bundle mode (`hsh1_`/`bh1_`/`gh1_`).
//!   * `ForeignSwapAgent` HTTP server implementing `/api/peer/swap-carrier` and
//!     `/api/peer/swap-status` signed with Khaymali HMAC-SHA256 headers.

use crate::cluster_mesh::{
    make_signed_headers, read_http_request, signed_http_request, write_http_response,
    KhaymaliMeshVerifier,
};
use crate::hjson::{self, Json};
use crate::setup_bundle;
use crate::sysrun;
use crate::util::now_unix;
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::sleep;

pub const FRP_PROTOCOLS: &[&str] = &["tcp", "kcp", "quic", "websocket"];
pub const BACKHAUL_TRANSPORTS: &[&str] = &["tcp", "tcpmux", "ws", "wss", "wsmux", "wssmux", "udp"];
pub const KHAYMALI_TRANSPORTS: &[&str] = &["ws", "wss", "ssh", "spoof", "udp", "tcp"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarrierChoice {
    pub engine: String,
    pub transport: String,
}

impl CarrierChoice {
    pub fn id(&self) -> String {
        format!("{}:{}", self.engine, self.transport)
    }

    pub fn needs_gre(&self) -> bool {
        self.engine == "frp" || self.engine == "gre-backhaul"
    }

    pub fn label(&self) -> String {
        match self.engine.as_str() {
            "frp" => format!("GRE + FRP ({})", self.transport),
            "gre-backhaul" => format!("Backhaul over GRE ({})", self.transport),
            "backhaul" => format!("Backhaul ({})", self.transport),
            "khaymali" => format!("Khaymali Native ({})", self.transport),
            _ => self.id(),
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let s = raw.trim().to_ascii_lowercase();
        let (eng, tr_raw) = s.split_once(':').unwrap_or((s.as_str(), ""));
        let tr = match eng {
            "frp" => {
                let t = match tr_raw {
                    "" => "tcp",
                    "ws" => "websocket",
                    other => other,
                };
                if !FRP_PROTOCOLS.contains(&t) {
                    bail!("unknown FRP transport '{t}' (expected {})", FRP_PROTOCOLS.join(", "));
                }
                t.to_string()
            }
            "backhaul" | "gre-backhaul" => {
                let t = if tr_raw.is_empty() { "tcpmux" } else { tr_raw };
                if !BACKHAUL_TRANSPORTS.contains(&t) {
                    bail!(
                        "unknown Backhaul transport '{t}' (expected {})",
                        BACKHAUL_TRANSPORTS.join(", ")
                    );
                }
                t.to_string()
            }
            "khaymali" => {
                let t = if tr_raw.is_empty() { "wss" } else { tr_raw };
                if !KHAYMALI_TRANSPORTS.contains(&t) {
                    bail!(
                        "unknown Khaymali transport '{t}' (expected {})",
                        KHAYMALI_TRANSPORTS.join(", ")
                    );
                }
                t.to_string()
            }
            other => bail!(
                "unknown carrier engine '{other}' (expected frp:<t>, backhaul:<t>, gre-backhaul:<t>, or khaymali:<t>)"
            ),
        };
        Ok(Self {
            engine: eng.to_string(),
            transport: tr,
        })
    }

    pub fn main_unit(&self, is_iran: bool) -> String {
        match (self.engine.as_str(), is_iran) {
            ("frp", true) => "frps".into(),
            ("frp", false) => "frpc".into(),
            ("backhaul" | "gre-backhaul", true) => "backhaul-server".into(),
            ("backhaul" | "gre-backhaul", false) => "backhaul-client".into(),
            ("khaymali", true) => "khaymali-entry".into(),
            ("khaymali", false) => "khaymali-exit".into(),
            _ => "khaymali-entry".into(),
        }
    }
}

pub fn is_main_unit(svc: &str) -> bool {
    matches!(
        svc,
        "frps" | "frpc" | "backhaul-server" | "backhaul-client" | "khaymali-entry" | "khaymali-exit"
    )
}

pub fn peer_unit_for(id: u32, choice: &CarrierChoice, is_iran: bool) -> String {
    if id == 0 {
        return choice.main_unit(is_iran);
    }
    match (choice.engine.as_str(), is_iran) {
        ("frp", true) => format!("frps-{id}"),
        ("frp", false) => format!("frpc-{id}"),
        ("backhaul" | "gre-backhaul", true) => format!("backhaul-server-{id}"),
        ("backhaul" | "gre-backhaul", false) => format!("backhaul-client-{id}"),
        _ => format!("khaymali-peer-{id}"),
    }
}

// ============================================================================
// Transactional Config + Systemd Unit Switcher (`UnitSwitchTx`)
// ============================================================================

/// Atomic file + systemd transaction mirroring Khaymali's `engineSwitchTx`.
/// Backs up overwritten files and records which services were previously active,
/// restoring both on [`UnitSwitchTx::rollback`].
pub struct UnitSwitchTx {
    was_active: BTreeMap<String, bool>,
    file_backups: BTreeMap<String, Option<Vec<u8>>>,
    svcs: Vec<String>,
    gre_unit: Option<String>,
}

impl UnitSwitchTx {
    pub fn begin(svcs: Vec<String>, gre_unit: Option<String>) -> Self {
        let mut was_active = BTreeMap::new();
        for s in &svcs {
            was_active.insert(s.clone(), sysrun::unit_active(s));
        }
        Self {
            was_active,
            file_backups: BTreeMap::new(),
            svcs,
            gre_unit,
        }
    }

    /// Snapshots `path`'s current contents once before overwriting.
    pub fn backup_file(&mut self, path: &str) {
        if self.file_backups.contains_key(path) {
            return;
        }
        let prev = std::fs::read(path).ok();
        self.file_backups.insert(path.to_string(), prev);
    }

    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.backup_file(path);
        if sysrun::is_dry_run() {
            let _ = sysrun::run(&crate::v!["write-file", path, format!("{}B", data.len())]);
            return Ok(());
        }
        hjson::write_atomic(path, data)
    }

    pub fn stop_unused(&self, keep: &[&str]) {
        for s in &self.svcs {
            if keep.iter().any(|k| *k == s.as_str()) {
                continue;
            }
            if self.gre_unit.as_deref() == Some(s.as_str()) {
                continue;
            }
            let _ = sysrun::run(&crate::v!["systemctl", "disable", "--now", s]);
        }
    }

    pub fn start_and_verify(&self, svc: &str) -> Result<()> {
        sysrun::must(&crate::v!["systemctl", "restart", svc])
            .with_context(|| format!("systemctl restart {svc} failed"))?;
        let _ = sysrun::run(&crate::v!["systemctl", "enable", svc]);
        if !sysrun::unit_active(svc) {
            bail!("{svc} exited right after restart");
        }
        Ok(())
    }

    /// Restores all backed-up files and returns every unit (leaving GRE up) to its prior state.
    pub fn rollback(&self) {
        for (path, prev) in &self.file_backups {
            if sysrun::is_dry_run() {
                let _ = sysrun::run(&crate::v!["rollback-file", path]);
                continue;
            }
            match prev {
                Some(bytes) => {
                    let _ = hjson::write_atomic(path, bytes);
                }
                None => {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        let _ = sysrun::run(&crate::v!["systemctl", "daemon-reload"]);
        for s in &self.svcs {
            let was = *self.was_active.get(s).unwrap_or(&false);
            if was {
                let _ = sysrun::run(&crate::v!["systemctl", "restart", s]);
                let _ = sysrun::run(&crate::v!["systemctl", "enable", s]);
            } else if self.gre_unit.as_deref() != Some(s.as_str()) {
                let _ = sysrun::run(&crate::v!["systemctl", "disable", "--now", s]);
            }
        }
    }
}

// ============================================================================
// Swap Tunnel Model, State Persistence (`carrier_swap.json` / `tunnel_links.json`)
// ============================================================================

#[derive(Clone, Debug)]
pub struct SwapTunnel {
    pub id: u32,
    pub name: String,
    pub main: bool,
    pub current: CarrierChoice,
    pub gre_ok: bool,
    pub ctrl_port: u16,
    pub remote_pub: String,
    pub local_pub: String,
    pub local_gre: String,
    pub peer_gre: String,
    pub token: String,
    pub ports: Vec<u16>,
    pub raw_ports: Vec<String>,
    pub udp_companion_port: u16,
}

impl SwapTunnel {
    /// Generates the Khaymali manual foreign setup bundle (`hsh1_`, `bh1_`, or `gh1_`) for `to`.
    pub fn manual_bundle(&self, to: &CarrierChoice) -> String {
        if self.token.is_empty() || self.local_pub.is_empty() || self.ctrl_port == 0 {
            return String::new();
        }
        let raw = if self.raw_ports.is_empty() {
            self.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>()
        } else {
            self.raw_ports.clone()
        };
        let bh_tr = setup_bundle::backhaul_bundle_transport(&to.transport, self.udp_companion_port);
        match to.engine.as_str() {
            "backhaul" => {
                setup_bundle::make_backhaul_bundle(&self.local_pub, self.ctrl_port, &bh_tr, &self.token, &raw)
            }
            "gre-backhaul" => setup_bundle::make_gre_backhaul_bundle(
                &self.local_pub,
                self.ctrl_port,
                &self.local_gre,
                &self.peer_gre,
                &bh_tr,
                &self.token,
                &raw,
            ),
            _ => setup_bundle::make_frp_bundle(
                &self.local_pub,
                self.ctrl_port,
                &self.local_gre,
                &self.peer_gre,
                &self.token,
                &self.ports,
                &to.transport,
                443,
                55555,
            ),
        }
    }

    pub fn foreign_request(&self, to: &CarrierChoice, delay_ms: u64) -> PeerSwapRequest {
        PeerSwapRequest {
            engine: to.engine.clone(),
            transport: to.transport.clone(),
            port: self.ctrl_port,
            ports: self.ports.clone(),
            raw: self.raw_ports.clone(),
            remote: self.local_pub.clone(),
            peer_gre: self.local_gre.clone(),
            delay_ms,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TunnelLink {
    pub id: u32,
    pub peer_url: String,
    pub secret: String,
    pub last_seen_unix: u64,
}

pub fn load_swap_state(path: &str) -> Result<BTreeMap<u32, String>> {
    let mut out = BTreeMap::new();
    let Some(Json::Obj(m)) = hjson::read_json_file(path)? else {
        return Ok(out);
    };
    for (k, v) in m {
        if let (Ok(id), Some(s)) = (k.parse::<u32>(), v.as_str()) {
            out.insert(id, s.to_string());
        }
    }
    Ok(out)
}

pub fn save_swap_state(path: &str, id: u32, carrier_id: &str) -> Result<()> {
    let mut cur = load_swap_state(path).unwrap_or_default();
    cur.insert(id, carrier_id.to_string());
    let mut j = Json::obj();
    for (k, v) in cur {
        j.insert(&k.to_string(), v);
    }
    hjson::write_atomic(path, j.to_string_pretty().as_bytes())
}

pub fn load_tunnel_links(path: &str) -> Result<BTreeMap<u32, TunnelLink>> {
    let mut out = BTreeMap::new();
    let Some(Json::Obj(m)) = hjson::read_json_file(path)? else {
        return Ok(out);
    };
    for (k, v) in m {
        if let Ok(id) = k.parse::<u32>() {
            out.insert(
                id,
                TunnelLink {
                    id,
                    peer_url: v.str_of("peer_url"),
                    secret: v.str_of("secret"),
                    last_seen_unix: v.u64_of("last_seen_unix"),
                },
            );
        }
    }
    Ok(out)
}

pub fn save_tunnel_link(path: &str, link: &TunnelLink) -> Result<()> {
    let mut all = load_tunnel_links(path).unwrap_or_default();
    all.insert(link.id, link.clone());
    let mut j = Json::obj();
    for (k, v) in all {
        j.insert(
            &k.to_string(),
            Json::obj()
                .set("peer_url", v.peer_url)
                .set("secret", v.secret)
                .set("last_seen_unix", v.last_seen_unix),
        );
    }
    hjson::write_atomic(path, j.to_string_pretty().as_bytes())
}

// ============================================================================
// Foreign Peer Swap Protocol (`/api/peer/swap-carrier` & `/api/peer/swap-status`)
// ============================================================================

#[derive(Clone, Debug)]
pub struct PeerSwapRequest {
    pub engine: String,
    pub transport: String,
    pub port: u16,
    pub ports: Vec<u16>,
    pub raw: Vec<String>,
    pub remote: String,
    pub peer_gre: String,
    pub delay_ms: u64,
}

impl PeerSwapRequest {
    pub fn to_json(&self) -> Json {
        Json::obj()
            .set("engine", self.engine.clone())
            .set("transport", self.transport.clone())
            .set("port", self.port)
            .set("ports", self.ports.clone())
            .set("raw", self.raw.clone())
            .set("remote", self.remote.clone())
            .set("peer_gre", self.peer_gre.clone())
            .set("delay_ms", self.delay_ms)
    }

    pub fn from_json(j: &Json) -> Result<Self> {
        let engine = j.str_of("engine");
        let transport = j.str_of("transport");
        let _ = CarrierChoice::parse(&format!("{engine}:{transport}"))?;
        let ports = j
            .arr_of("ports")
            .into_iter()
            .filter_map(|v| v.as_f64().map(|n| n as u16))
            .filter(|&p| p > 0)
            .collect();
        let raw = j
            .arr_of("raw")
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        Ok(Self {
            engine,
            transport,
            port: j.u64_of("port") as u16,
            ports,
            raw,
            remote: j.str_of("remote"),
            peer_gre: j.str_of("peer_gre"),
            delay_ms: j.u64_of("delay_ms"),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct ForeignSwapState {
    pub state: String, // "" | "switching" | "ok" | "failed"
    pub carrier: String,
    pub error: String,
    pub seq: u64,
}

pub type ForeignApplyFn = Arc<dyn Fn(&CarrierChoice, &PeerSwapRequest) -> Result<()> + Send + Sync>;

/// Foreign-side agent receiving signed swap instructions from the Iran server.
pub struct ForeignSwapAgent {
    pub secret: String,
    pub state: Mutex<ForeignSwapState>,
    pub verifier: KhaymaliMeshVerifier,
    pub apply_fn: ForeignApplyFn,
}

impl ForeignSwapAgent {
    pub fn new(secret: String, apply_fn: ForeignApplyFn) -> Arc<Self> {
        Arc::new(Self {
            secret,
            state: Mutex::new(ForeignSwapState::default()),
            verifier: KhaymaliMeshVerifier::new(),
            apply_fn,
        })
    }

    pub async fn serve_listener(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        loop {
            let (mut stream, _) = listener.accept().await?;
            let agent = self.clone();
            tokio::spawn(async move {
                let Ok(Some((method, path, headers, body))) = read_http_request(&mut stream, 65536).await else {
                    return;
                };
                if agent
                    .verifier
                    .verify_headers(&agent.secret, &headers, &body, now_unix())
                    .is_err()
                {
                    let _ = write_http_response(&mut stream, 404, &[], b"not found").await;
                    return;
                }
                match (method.as_str(), path.as_str()) {
                    ("GET", "/api/peer/swap-status") => {
                        let st = agent.state.lock().unwrap().clone();
                        let out = Json::obj()
                            .set("state", st.state)
                            .set("carrier", st.carrier)
                            .set("error", st.error)
                            .set("seq", st.seq)
                            .to_string_compact();
                        let hdrs = make_signed_headers(&agent.secret, out.as_bytes());
                        let _ = write_http_response(&mut stream, 200, &hdrs, out.as_bytes()).await;
                    }
                    ("POST", "/api/peer/swap-carrier") => {
                        let Ok(j) = Json::parse(&String::from_utf8_lossy(&body)) else {
                            let _ = write_http_response(&mut stream, 400, &[], b"{\"error\":\"invalid json\"}").await;
                            return;
                        };
                        let Ok(req) = PeerSwapRequest::from_json(&j) else {
                            let _ = write_http_response(&mut stream, 400, &[], b"{\"error\":\"invalid carrier\"}").await;
                            return;
                        };
                        let choice = CarrierChoice::parse(&format!("{}:{}", req.engine, req.transport)).unwrap();
                        let seq_opt = {
                            let mut st = agent.state.lock().unwrap();
                            if st.state == "switching" {
                                None
                            } else {
                                st.seq += 1;
                                st.state = "switching".into();
                                st.carrier = choice.id();
                                st.error.clear();
                                Some(st.seq)
                            }
                        };
                        let Some(seq) = seq_opt else {
                            let _ = write_http_response(
                                &mut stream,
                                400,
                                &[],
                                b"{\"error\":\"swap already running\"}",
                            )
                            .await;
                            return;
                        };
                        let out = Json::obj()
                            .set("status", "accepted")
                            .set("carrier", choice.id())
                            .set("seq", seq)
                            .to_string_compact();
                        let hdrs = make_signed_headers(&agent.secret, out.as_bytes());
                        let _ = write_http_response(&mut stream, 200, &hdrs, out.as_bytes()).await;

                        let delay = Duration::from_millis(req.delay_ms.min(10_000));
                        let ag = agent.clone();
                        tokio::spawn(async move {
                            if !delay.is_zero() {
                                sleep(delay).await;
                            }
                            let res = (ag.apply_fn)(&choice, &req);
                            let mut st = ag.state.lock().unwrap();
                            if st.seq != seq {
                                return;
                            }
                            match res {
                                Ok(()) => {
                                    st.state = "ok".into();
                                    st.error.clear();
                                }
                                Err(e) => {
                                    st.state = "failed".into();
                                    st.error = e.to_string();
                                }
                            }
                        });
                    }
                    _ => {
                        let _ = write_http_response(&mut stream, 404, &[], b"not found").await;
                    }
                }
            });
        }
    }
}

// ============================================================================
// Iran-Side 4-Phase Swap State Machine (`SwapCoordinator`)
// ============================================================================

#[derive(Clone, Debug)]
pub struct SwapStep {
    pub key: String,
    pub state: String, // pending | run | ok | fail | skip
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct SwapJob {
    pub id: u32,
    pub name: String,
    pub from: String,
    pub to: String,
    pub manual: bool,
    pub state: String, // running | ok | manual | reverted | failed
    pub error: String,
    pub bundle: String,
    pub reverted_foreign: bool,
    pub steps: Vec<SwapStep>,
}

impl SwapJob {
    fn new(t: &SwapTunnel, to: &CarrierChoice, manual: bool) -> Self {
        Self {
            id: t.id,
            name: t.name.clone(),
            from: t.current.id(),
            to: to.id(),
            manual,
            state: "running".into(),
            error: String::new(),
            bundle: String::new(),
            reverted_foreign: false,
            steps: vec![
                SwapStep { key: "foreign".into(), state: "pending".into(), detail: String::new() },
                SwapStep { key: "local".into(), state: "pending".into(), detail: String::new() },
                SwapStep { key: "verify".into(), state: "pending".into(), detail: String::new() },
            ],
        }
    }

    fn set_step(&mut self, key: &str, state: &str, detail: &str) {
        if let Some(s) = self.steps.iter_mut().find(|s| s.key == key) {
            s.state = state.into();
            s.detail = detail.into();
        } else {
            self.steps.push(SwapStep {
                key: key.into(),
                state: state.into(),
                detail: detail.into(),
            });
        }
    }

    pub fn to_json(&self) -> Json {
        let steps_arr: Vec<Json> = self
            .steps
            .iter()
            .map(|s| {
                Json::obj()
                    .set("key", s.key.clone())
                    .set("state", s.state.clone())
                    .set("detail", s.detail.clone())
            })
            .collect();
        Json::obj()
            .set("id", self.id)
            .set("name", self.name.clone())
            .set("from", self.from.clone())
            .set("to", self.to.clone())
            .set("manual", self.manual)
            .set("state", self.state.clone())
            .set("error", self.error.clone())
            .set("bundle", self.bundle.clone())
            .set("reverted_foreign", self.reverted_foreign)
            .set("steps", steps_arr)
    }
}

pub struct SwapOptions {
    pub manual: bool,
    pub foreign_delay_ms: u64,
    pub verify_wait: Duration,
    pub revert_wait: Duration,
    pub poll_interval: Duration,
    pub state_path: Option<String>,
}

impl Default for SwapOptions {
    fn default() -> Self {
        Self {
            manual: false,
            foreign_delay_ms: 1500,
            verify_wait: Duration::from_secs(20),
            revert_wait: Duration::from_secs(15),
            poll_interval: Duration::from_millis(500),
            state_path: None,
        }
    }
}

/// Runs the full 4-phase Khaymali live carrier swap:
/// 1. Tell foreign server via signed Peer Link (`/api/peer/swap-carrier`)
/// 2. Switch local (Iran) server carrier via `local_switch`
/// 3. Poll `verify_linked` (and foreign `/api/peer/swap-status`) until connected or timed out
/// 4. On verification failure, automatically revert BOTH foreign and local servers to `t.current`.
pub async fn execute_live_swap<FSwitch, FVerify>(
    t: &SwapTunnel,
    to: &CarrierChoice,
    peer_link: Option<&TunnelLink>,
    opts: SwapOptions,
    mut local_switch: FSwitch,
    mut verify_linked: FVerify,
) -> SwapJob
where
    FSwitch: FnMut(&SwapTunnel, &CarrierChoice) -> Result<()>,
    FVerify: FnMut(&SwapTunnel, &CarrierChoice) -> bool,
{
    let from = t.current.clone();
    let mut job = SwapJob::new(t, to, opts.manual);

    if to.needs_gre() && !t.gre_ok {
        job.state = "failed".into();
        job.error = format!("{} requires GRE, which is not configured on this tunnel", to.label());
        return job;
    }

    // Phase 1: Foreign server
    if opts.manual {
        job.set_step("foreign", "skip", "manual mode: apply the generated bundle on the foreign server");
    } else {
        job.set_step("foreign", "run", "");
        match tell_foreign(t, to, peer_link, opts.foreign_delay_ms).await {
            Ok(detail) => job.set_step("foreign", "ok", &detail),
            Err(e) => {
                job.set_step("foreign", "fail", &e.to_string());
                job.set_step("local", "skip", "");
                job.set_step("verify", "skip", "");
                job.state = "failed".into();
                job.error = format!("foreign server unreachable, nothing changed: {e}");
                return job;
            }
        }
    }

    // Phase 2: Local server
    job.set_step("local", "run", "");
    if let Err(e) = local_switch(t, to) {
        job.set_step("local", "fail", &e.to_string());
        job.set_step("verify", "skip", "");
        if !opts.manual {
            let _ = tell_foreign(t, &from, peer_link, 0).await;
        }
        job.state = "failed".into();
        job.error = format!("local switch failed; staying on {}: {e}", from.label());
        return job;
    }
    job.set_step("local", "ok", &to.id());
    if let Some(p) = &opts.state_path {
        let _ = save_swap_state(p, t.id, &to.id());
    }

    if opts.manual {
        job.set_step("verify", "skip", "");
        job.bundle = t.manual_bundle(to);
        job.state = "manual".into();
        return job;
    }

    // Phase 3: Verify new carrier link
    job.set_step("verify", "run", "");
    let (linked, why) = wait_linked(t, to, peer_link, opts.verify_wait, opts.poll_interval, &mut verify_linked).await;
    if linked {
        job.set_step("verify", "ok", "tunnel linked on new carrier");
        job.state = "ok".into();
        return job;
    }
    let fail_reason = if why.is_empty() {
        format!("tunnel did not link on {} within {:?}", to.label(), opts.verify_wait)
    } else {
        why
    };
    job.set_step("verify", "fail", &fail_reason);

    // Phase 4: Automatic rollback of both ends
    job.set_step("revert", "run", "");
    let f_revert = tell_foreign(t, &from, peer_link, 0).await;
    job.reverted_foreign = f_revert.is_ok();
    let mut back_tunnel = t.clone();
    back_tunnel.current = to.clone();
    if let Err(e) = local_switch(&back_tunnel, &from) {
        job.set_step("revert", "fail", &e.to_string());
        job.state = "failed".into();
        job.error = format!("{fail_reason}; local revert failed: {e}");
        return job;
    }
    if let Some(p) = &opts.state_path {
        let _ = save_swap_state(p, t.id, &from.id());
    }
    let (back_ok, _) = wait_linked(t, &from, None, opts.revert_wait, opts.poll_interval, &mut verify_linked).await;
    if back_ok {
        job.set_step("revert", "ok", &format!("reverted to {}", from.label()));
        job.state = "reverted".into();
        job.error = fail_reason;
    } else {
        let mut d = format!("reverted local to {}, waiting for reconnect", from.label());
        if let Err(e) = f_revert {
            d.push_str(&format!(" (foreign unreachable: {e})"));
        }
        job.set_step("revert", "fail", &d);
        job.state = "failed".into();
        job.error = format!("{fail_reason}; {d}");
    }
    job
}

async fn tell_foreign(
    t: &SwapTunnel,
    to: &CarrierChoice,
    peer_link: Option<&TunnelLink>,
    delay_ms: u64,
) -> Result<String> {
    let link = peer_link.context("no Peer Link configured for foreign server")?;
    let req = t.foreign_request(to, delay_ms).to_json().to_string_compact();
    let (status, _, body) = signed_http_request(
        "POST",
        &link.peer_url,
        "/api/peer/swap-carrier",
        &link.secret,
        req.as_bytes(),
        Duration::from_secs(5),
    )
    .await?;
    if status != 200 {
        bail!("foreign returned HTTP {status}: {}", String::from_utf8_lossy(&body).trim());
    }
    Ok(format!("accepted via {}", link.peer_url))
}

async fn query_foreign_failed(peer_link: Option<&TunnelLink>, to: &CarrierChoice) -> Option<String> {
    let link = peer_link?;
    let (status, _, body) = signed_http_request(
        "GET",
        &link.peer_url,
        "/api/peer/swap-status",
        &link.secret,
        &[],
        Duration::from_secs(2),
    )
    .await
    .ok()?;
    if status != 200 {
        return None;
    }
    let j = Json::parse(&String::from_utf8_lossy(&body)).ok()?;
    if j.str_of("state") == "failed" && j.str_of("carrier") == to.id() {
        return Some(format!("foreign swap failed: {}", j.str_of("error")));
    }
    None
}

async fn wait_linked<FVerify>(
    t: &SwapTunnel,
    to: &CarrierChoice,
    peer_link: Option<&TunnelLink>,
    max_wait: Duration,
    poll: Duration,
    verify_linked: &mut FVerify,
) -> (bool, String)
where
    FVerify: FnMut(&SwapTunnel, &CarrierChoice) -> bool,
{
    let start = std::time::Instant::now();
    loop {
        if verify_linked(t, to) {
            return (true, String::new());
        }
        if let Some(err) = query_foreign_failed(peer_link, to).await {
            return (false, err);
        }
        if start.elapsed() >= max_wait {
            return (false, String::new());
        }
        sleep(poll).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tunnel() -> SwapTunnel {
        SwapTunnel {
            id: 0,
            name: "main".into(),
            main: true,
            current: CarrierChoice::parse("frp:tcp").unwrap(),
            gre_ok: true,
            ctrl_port: 7000,
            remote_pub: "203.0.113.20".into(),
            local_pub: "198.51.100.10".into(),
            local_gre: "10.10.0.1".into(),
            peer_gre: "10.10.0.2".into(),
            token: "tok_secret_1234567890".into(),
            ports: vec![443, 8443],
            raw_ports: vec!["443".into(), "8443".into()],
            udp_companion_port: 0,
        }
    }

    #[test]
    fn carrier_choice_parsing_and_manual_bundles() {
        assert_eq!(CarrierChoice::parse("frp:ws").unwrap().id(), "frp:websocket");
        assert_eq!(CarrierChoice::parse("backhaul").unwrap().id(), "backhaul:tcpmux");
        assert!(CarrierChoice::parse("gre-backhaul:wsmux").unwrap().needs_gre());
        assert!(CarrierChoice::parse("unknown:x").is_err());

        let t = sample_tunnel();
        let bh = CarrierChoice::parse("backhaul:tcpmux").unwrap();
        assert!(t.manual_bundle(&bh).starts_with("bh1_198.51.100.10_7000_tcpmux_"));
        let gh = CarrierChoice::parse("gre-backhaul:wsmux").unwrap();
        assert!(t.manual_bundle(&gh).starts_with("gh1_198.51.100.10_7000_10.10.0.1_10.10.0.2_wsmux_"));
        let frp = CarrierChoice::parse("frp:quic").unwrap();
        assert!(t.manual_bundle(&frp).starts_with("hsh1_198.51.100.10_7000_10.10.0.1_10.10.0.2_"));
    }

    #[test]
    fn unit_switch_tx_rolls_back_files_cleanly() {
        let dir = std::env::temp_dir().join(format!("khaymali-tx-{}", now_unix()));
        let _ = std::fs::create_dir_all(&dir);
        let existing = dir.join("frps.toml");
        let created = dir.join("backhaul.toml");
        std::fs::write(&existing, b"original-frp").unwrap();

        sysrun::set_dry_run(true);
        let mut tx = UnitSwitchTx::begin(vec!["frps".into(), "backhaul-server".into()], Some("gre-tunnel".into()));
        // Manually test real filesystem backup+restore by toggling dry-run off for file ops
        sysrun::set_dry_run(false);
        tx.write_file(existing.to_str().unwrap(), b"modified-frp").unwrap();
        tx.write_file(created.to_str().unwrap(), b"new-bh").unwrap();
        assert_eq!(std::fs::read(&existing).unwrap(), b"modified-frp");
        assert!(created.exists());
        tx.rollback();
        assert_eq!(std::fs::read(&existing).unwrap(), b"original-frp");
        assert!(!created.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn live_swap_succeeds_and_auto_reverts_on_verify_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let secret = "peer-link-secret-0123456789abcdef".to_string();
        let foreign_carrier = Arc::new(Mutex::new("frp:tcp".to_string()));
        let fc_clone = foreign_carrier.clone();

        let agent = ForeignSwapAgent::new(
            secret.clone(),
            Arc::new(move |choice, _req| {
                *fc_clone.lock().unwrap() = choice.id();
                Ok(())
            }),
        );
        let _srv = tokio::spawn(agent.serve_listener(listener));

        let link = TunnelLink {
            id: 0,
            peer_url: format!("http://127.0.0.1:{port}"),
            secret,
            last_seen_unix: now_unix(),
        };
        let t = sample_tunnel();
        let to = CarrierChoice::parse("backhaul:tcpmux").unwrap();

        // 1. Successful live swap
        let local_carrier = Arc::new(Mutex::new("frp:tcp".to_string()));
        let lc = local_carrier.clone();
        let job_ok = execute_live_swap(
            &t,
            &to,
            Some(&link),
            SwapOptions {
                manual: false,
                foreign_delay_ms: 10,
                verify_wait: Duration::from_millis(400),
                revert_wait: Duration::from_millis(300),
                poll_interval: Duration::from_millis(25),
                state_path: None,
            },
            move |_t, c| {
                *lc.lock().unwrap() = c.id();
                Ok(())
            },
            |_t, c| *foreign_carrier.lock().unwrap() == c.id(),
        )
        .await;
        assert_eq!(job_ok.state, "ok");
        assert_eq!(*local_carrier.lock().unwrap(), "backhaul:tcpmux");

        // 2. Verify fails -> automatic revert of BOTH Iran and Foreign back to frp:tcp
        let mut t2 = sample_tunnel();
        t2.current = CarrierChoice::parse("frp:tcp").unwrap();
        let lc2 = local_carrier.clone();
        let job_rev = execute_live_swap(
            &t2,
            &CarrierChoice::parse("frp:quic").unwrap(),
            Some(&link),
            SwapOptions {
                manual: false,
                foreign_delay_ms: 5,
                verify_wait: Duration::from_millis(120),
                revert_wait: Duration::from_millis(300),
                poll_interval: Duration::from_millis(25),
                state_path: None,
            },
            move |_t, c| {
                *lc2.lock().unwrap() = c.id();
                Ok(())
            },
            // Only frp:tcp ever links -> quic fails verify, revert to frp:tcp succeeds
            |_t, c| c.id() == "frp:tcp",
        )
        .await;
        assert_eq!(job_rev.state, "reverted");
        assert!(job_rev.reverted_foreign);
        assert_eq!(*local_carrier.lock().unwrap(), "frp:tcp");
    }
}
