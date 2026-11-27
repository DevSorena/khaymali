//! Unix Socket Control Plane API (SPEC §4.2).
//! Enforces `0600` mode, `SO_PEERCRED` UID match, 8 KiB message cap, escape-safe JSON parsing,
//! and strictly read-only inspection (`status`, `peers.list`, `health.history`, `forwards.list`,
//! `recovery.status`, `kani.diagnose`) + `drain`.
//! No RPC command may mutate keys, allowlists, or destination policy.

use crate::dial_route::{DialMode, DialRouter};
use crate::forward::ForwardRegistry;
use crate::health::Exits;
use crate::kani_nlp::TinyNetNlp;
use crate::recovery::AdaptiveRuntime;
use crate::stats;
use crate::util::{root_check_code, sha256_hex};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Notify, RwLock};

pub struct ControlState {
    pub role: &'static str,
    pub transport: &'static str,
    pub started: Instant,
    pub exits: Option<Arc<Exits>>,
    pub forwards: Option<Arc<ForwardRegistry>>,
    pub adaptive: Option<Arc<AdaptiveRuntime>>,
    pub dial_router: Option<Arc<DialRouter>>,
    pub socks_addr: Option<String>,
    pub peers: Arc<RwLock<Vec<Vec<u8>>>>,
    pub draining: Arc<AtomicBool>,
    pub drain_notify: Arc<Notify>,
}

impl ControlState {
    pub fn new(role: &'static str, exits: Option<Arc<Exits>>, peers: Vec<Vec<u8>>) -> Arc<Self> {
        Self::with_runtime(role, "tcp", exits, None, None, peers)
    }

    pub fn with_forwards(
        role: &'static str,
        exits: Option<Arc<Exits>>,
        forwards: Option<Arc<ForwardRegistry>>,
        peers: Vec<Vec<u8>>,
    ) -> Arc<Self> {
        Self::with_runtime(role, "tcp", exits, forwards, None, peers)
    }

    pub fn with_runtime(
        role: &'static str,
        transport: &'static str,
        exits: Option<Arc<Exits>>,
        forwards: Option<Arc<ForwardRegistry>>,
        adaptive: Option<Arc<AdaptiveRuntime>>,
        peers: Vec<Vec<u8>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            role,
            transport,
            started: Instant::now(),
            exits,
            forwards,
            adaptive,
            dial_router: None,
            socks_addr: None,
            peers: Arc::new(RwLock::new(peers)),
            draining: Arc::new(AtomicBool::new(false)),
            drain_notify: Arc::new(Notify::new()),
        })
    }

    pub fn with_khaymali_extensions(
        role: &'static str,
        transport: &'static str,
        exits: Option<Arc<Exits>>,
        forwards: Option<Arc<ForwardRegistry>>,
        adaptive: Option<Arc<AdaptiveRuntime>>,
        dial_router: Option<Arc<DialRouter>>,
        socks_addr: Option<String>,
        peers: Vec<Vec<u8>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            role,
            transport,
            started: Instant::now(),
            exits,
            forwards,
            adaptive,
            dial_router,
            socks_addr,
            peers: Arc::new(RwLock::new(peers)),
            draining: Arc::new(AtomicBool::new(false)),
            drain_notify: Arc::new(Notify::new()),
        })
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Relaxed)
    }

    pub fn trigger_drain(&self) {
        self.draining.store(true, Relaxed);
        self.drain_notify.notify_waiters();
    }
}

/// Escape-aware, string-boundary-safe top-level JSON string field extractor.
/// Properly handles escaped quotes (`\"`), backslashes (`\\`), and avoids matching
/// duplicate keys embedded inside other string values.
pub fn extract_json_str(line: &str, target_key: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut depth = 0i32;

    fn parse_quoted(bytes: &[u8], start: usize) -> Option<(String, usize)> {
        if start >= bytes.len() || bytes[start] != b'"' {
            return None;
        }
        let mut out = String::new();
        let mut i = start + 1;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'\\' {
                i += 1;
                if i >= bytes.len() {
                    return None;
                }
                match bytes[i] {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    other => out.push(other as char),
                }
                i += 1;
            } else if b == b'"' {
                return Some((out, i + 1));
            } else {
                // Preserve UTF-8 characters safely
                let ch = std::str::from_utf8(&bytes[i..]).ok()?.chars().next()?;
                out.push(ch);
                i += ch.len_utf8();
            }
        }
        None
    }

    while i < len {
        match bytes[i] {
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth -= 1;
                i += 1;
            }
            b'"' => {
                let (s, next_i) = parse_quoted(bytes, i)?;
                i = next_i;
                if depth == 1 {
                    let mut j = i;
                    while j < len && bytes[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j < len && bytes[j] == b':' {
                        j += 1;
                        while j < len && bytes[j].is_ascii_whitespace() {
                            j += 1;
                        }
                        if s == target_key && j < len && bytes[j] == b'"' {
                            let (val, _) = parse_quoted(bytes, j)?;
                            return Some(val);
                        }
                        i = j;
                    }
                }
            }
            _ => i += 1,
        }
    }
    None
}

#[cfg(unix)]
mod unix_impl {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::Semaphore;
    use tokio::time::timeout;

    const MAX_RPC_LINE: usize = 8192;
    const MAX_RPC_CONNS: usize = 16;

    fn process_euid() -> Option<u32> {
        std::fs::metadata("/proc/self").ok().map(|m| m.uid())
    }

    fn peer_authorized(stream: &UnixStream) -> bool {
        let Ok(cred) = stream.peer_cred() else { return false };
        let uid = cred.uid();
        uid == 0 || process_euid().map_or(false, |my_uid| uid == my_uid)
    }

    fn esc_json(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r")
    }

    async fn dispatch(line: &str, st: &ControlState) -> String {
        let method = extract_json_str(line, "method").unwrap_or_else(|| line.trim().to_string());
        match method.as_str() {
            "status" => {
                let (chunk_bytes, pacing_us, loss_pct, pattern, action) = match &st.adaptive {
                    Some(a) => {
                        let s = a.snapshot();
                        (
                            s.chunk_bytes,
                            s.pacing_us,
                            (s.loss_per_mille as f64) / 10.0,
                            s.pattern.as_str(),
                            s.action.as_str(),
                        )
                    }
                    None => (stats::ADAPTIVE_CHUNK_BYTES.load(Relaxed), 0, 0.0, "healthy", "keep"),
                };
                format!(
                    "{{\"ok\":true,\"role\":\"{}\",\"transport\":\"{}\",\"version\":\"{}\",\"uptime_secs\":{},\"draining\":{},\"links_ready\":{},\"mux_carriers\":{},\"rekeys\":{},\"udp_sessions\":{},\"ktunnel_sessions\":{},\"ktunnel_flows\":{},\"udp_fec_recovered\":{},\"reverse_exits\":{},\"streams_active\":{},\"streams_total\":{},\"bytes_up\":{},\"bytes_down\":{},\"fallback_active\":{},\"decoy_up\":{},\"chunk_bytes\":{},\"pacing_us\":{},\"loss_pct\":{:.2},\"recovery_pattern\":\"{}\",\"recovery_action\":\"{}\"}}\n",
                    st.role,
                    st.transport,
                    env!("CARGO_PKG_VERSION"),
                    st.started.elapsed().as_secs(),
                    st.is_draining(),
                    stats::LINKS_READY.load(Relaxed),
                    stats::MUX_CARRIERS_ACTIVE.load(Relaxed),
                    stats::REKEY_ROTATIONS.load(Relaxed),
                    stats::UDP_TRANSPORT_SESSIONS.load(Relaxed),
                    stats::KTUNNEL_SESSIONS_ACTIVE.load(Relaxed),
                    stats::KTUNNEL_FLOWS_ACTIVE.load(Relaxed),
                    stats::UDP_FEC_RECOVERED.load(Relaxed),
                    stats::REVERSE_EXITS_CONNECTED.load(Relaxed),
                    stats::STREAMS_ACTIVE.load(Relaxed),
                    stats::STREAMS_TOTAL.load(Relaxed),
                    stats::BYTES_UP.load(Relaxed),
                    stats::BYTES_DOWN.load(Relaxed),
                    stats::FALLBACK_ACTIVE.load(Relaxed),
                    stats::DECOY_UP.load(Relaxed),
                    chunk_bytes,
                    pacing_us,
                    loss_pct,
                    pattern,
                    action,
                )
            }
            "adapt.status" => match crate::adapt::global() {
                Some(a) => a.status_json(),
                None => "{\"ok\":false,\"error\":\"adapt_not_running\"}\n".to_string(),
            },
            "recovery.status" => {
                if let Some(a) = &st.adaptive {
                    let s = a.snapshot();
                    let prob_json = s.degradation_probability.map(|p| format!("{p:.4}")).unwrap_or_else(|| "null".to_string());
                    format!(
                        "{{\"ok\":true,\"pattern\":\"{}\",\"action\":\"{}\",\"confidence\":{},\"chunk_bytes\":{},\"pacing_us\":{},\"concurrency_cap\":{},\"loss_pct\":{:.2},\"recovery_actions\":{},\"clock_skew_dropped\":{},\"keepalive_dropped\":{},\"nlp_intent\":\"{}\",\"nlp_action\":\"{}\",\"nlp_confidence\":{:.3},\"nlp_abstained\":{},\"nlp_online_updates\":{},\"nlp_candidate_updates\":{},\"intelligence_mode\":\"{}\",\"predicted_severity\":{},\"projected_severity\":{},\"degradation_likely\":{},\"degradation_probability\":{},\"intelligence_path_score\":{:.1},\"measured_goodput_kbps\":{:.1},\"measured_jitter_ms\":{:.1},\"calibration_samples\":{},\"nlp_reverts\":{},\"nlp_rate_limited\":{},\"nlp_persist_failures\":{}}}\n",
                        s.pattern.as_str(), s.action.as_str(), s.confidence, s.chunk_bytes, s.pacing_us,
                        s.concurrency_cap, (s.loss_per_mille as f64) / 10.0, s.recovery_actions,
                        stats::CLOCK_SKEW_DROPPED.load(Relaxed), stats::POOL_KEEPALIVE_DROPPED.load(Relaxed),
                        s.nlp_intent.as_str(), s.nlp_action.as_str(), s.nlp_confidence, s.nlp_abstained,
                        s.nlp_online_updates, s.nlp_candidate_updates,
                        s.intelligence_mode.map(|m| m.as_str()).unwrap_or("unknown"),
                        s.predicted_severity, s.projected_severity, s.degradation_likely, prob_json,
                        s.intelligence_path_score, s.measured_goodput_kbps, s.measured_jitter_ms, s.calibration_samples,
                        stats::NLP_REVERTS.load(Relaxed), stats::NLP_RATE_LIMITED.load(Relaxed), stats::NLP_PERSIST_FAILURES.load(Relaxed),
                    )
                } else {
                    "{\"ok\":true,\"pattern\":\"healthy\",\"action\":\"keep\",\"confidence\":95,\"chunk_bytes\":14336,\"pacing_us\":0,\"concurrency_cap\":0,\"loss_pct\":0.00,\"recovery_actions\":0,\"intelligence_mode\":\"unknown\",\"predicted_severity\":0,\"projected_severity\":0,\"degradation_likely\":false,\"degradation_probability\":null,\"intelligence_path_score\":0.0,\"calibration_samples\":0}\n".to_string()
                }
            }
            "peers.list" => {
                let peers = st.peers.read().await;
                let items: Vec<String> = peers
                    .iter()
                    .map(|k| {
                        format!(
                            "{{\"check_code\":\"{}\",\"sha256\":\"{}\"}}",
                            root_check_code(k),
                            sha256_hex(k)
                        )
                    })
                    .collect();
                format!("{{\"ok\":true,\"count\":{},\"peers\":[{}]}}\n", items.len(), items.join(","))
            }
            "health.history" => {
                let mut items = Vec::new();
                if let Some(exits) = &st.exits {
                    for h in exits.history() {
                        items.push(format!(
                            "{{\"ts\":{},\"addr\":\"{}\",\"ewma_ms\":{:.1},\"jitter_ms\":{:.1},\"timeout_fails\":{},\"reset_fails\":{},\"up\":{},\"selectable\":{}}}",
                            h.ts, esc_json(&h.addr), h.ewma_ms, h.jitter_ms, h.timeout_fails, h.reset_fails, h.up, h.selectable
                        ));
                    }
                }
                format!("{{\"ok\":true,\"history\":[{}]}}\n", items.join(","))
            }
            "forwards.list" => {
                let mut items = Vec::new();
                if let Some(fwds) = &st.forwards {
                    for f in fwds.snapshot() {
                        let users_json: Vec<String> = f
                            .active_users
                            .iter()
                            .map(|u| {
                                format!(
                                    "{{\"peer\":\"{}\",\"proto\":\"{}\",\"age_secs\":{},\"bytes_up\":{},\"bytes_down\":{}}}",
                                    esc_json(&u.peer), u.proto, u.age_secs, u.bytes_up, u.bytes_down
                                )
                            })
                            .collect();
                        items.push(format!(
                            "{{\"port\":\"{}\",\"proto\":\"{}\",\"name\":\"{}\",\"tunnel\":\"{}\",\"target\":\"{}\",\"failover\":\"{}\",\"state\":\"{}\",\"users\":{},\"bytes_up\":{},\"bytes_down\":{},\"quota_bytes\":{},\"rate_bps\":{},\"proxy_v2\":{},\"mode\":\"{}\",\"counted_since\":{},\"active_users\":[{}]}}",
                            esc_json(&f.port),
                            f.proto,
                            esc_json(&f.name),
                            esc_json(&f.tunnel),
                            esc_json(&f.target),
                            esc_json(&f.failover),
                            f.state,
                            f.users,
                            f.bytes_up,
                            f.bytes_down,
                            f.quota_bytes,
                            f.rate_bps,
                            f.proxy_v2,
                            f.mode,
                            f.counted_since,
                            users_json.join(",")
                        ));
                    }
                }
                format!("{{\"ok\":true,\"forwards\":[{}]}}\n", items.join(","))
            }
            "forwards.add" => {
                let spec_str = extract_json_str(line, "spec").unwrap_or_default();
                if let Some(fwds) = &st.forwards {
                    match crate::forward::ForwardSpec::parse_many(&spec_str) {
                        Ok(specs) => {
                            let added = specs.len();
                            for sp in specs {
                                fwds.register(sp);
                            }
                            format!("{{\"ok\":true,\"added\":{added}}}\n")
                        }
                        Err(e) => format!("{{\"ok\":false,\"error\":\"{}\"}}\n", esc_json(&e.to_string())),
                    }
                } else {
                    "{\"ok\":false,\"error\":\"forwards_unavailable\"}\n".to_string()
                }
            }
            "forwards.remove" => {
                let port = extract_json_str(line, "port").unwrap_or_default();
                if let Some(fwds) = &st.forwards {
                    let removed = fwds.remove_by_port(&port);
                    format!("{{\"ok\":true,\"removed\":{removed}}}\n")
                } else {
                    "{\"ok\":false,\"error\":\"forwards_unavailable\"}\n".to_string()
                }
            }
            "kani.diagnose" => {
                let symptom = extract_json_str(line, "symptom").unwrap_or_default();
                let nlp = TinyNetNlp::load_configured_or_pretrained();
                let pred = nlp.classify(&symptom);
                format!(
                    "{{\"ok\":true,\"intent\":\"{}\",\"confidence\":{:.3},\"abstained\":{},\"recommended_action\":\"{}\"}}\n",
                    pred.intent.as_str(),
                    pred.confidence,
                    pred.abstained,
                    pred.action.as_str()
                )
            }
            "kani.reset" => {
                if let Some(a) = &st.adaptive {
                    let persisted = a.reset_nlp_online_weights();
                    format!("{{\"ok\":true,\"reset\":\"online_delta_cleared\",\"persisted\":{}}}\n", persisted)
                } else {
                    "{\"ok\":false,\"error\":\"adaptive_unavailable\"}\n".to_string()
                }
            }
            "kani.reload" => {
                let ok = st.adaptive.as_ref().map(|a| a.reload_nlp_model()).unwrap_or(false);
                format!("{{\"ok\":{},\"reloaded\":\"nlp_model\"}}\n", ok)
            }
            "intelligence.reload_calibrator" => {
                let ok = st.adaptive.as_ref().map(|a| a.reload_risk_calibrator()).unwrap_or(false);
                format!("{{\"ok\":{},\"reloaded\":\"risk_calibrator\"}}\n", ok)
            }
            "kani.rollback" => {
                let ok = st.adaptive.as_ref().map(|a| a.rollback_nlp_model()).unwrap_or(false);
                format!("{{\"ok\":{},\"rolled_back\":\"nlp_model\"}}\n", ok)
            }
            "intelligence.paths" => {
                if let Some(a) = &st.adaptive {
                    let items: Vec<String> = a.ranked_paths().iter().map(|p| {
                        format!("{{\"path_id\":\"{}\",\"score\":{:.1},\"observations\":{}}}", esc_json(&p.path_id), p.score, p.observations)
                    }).collect();
                    format!("{{\"ok\":true,\"paths\":[{}]}}\n", items.join(","))
                } else {
                    "{\"ok\":true,\"paths\":[]}\n".to_string()
                }
            }
            "intelligence.export_calibration" => {
                if let Some(a) = &st.adaptive {
                    format!("{{\"ok\":true,\"samples\":{},\"tsv\":\"{}\"}}\n", a.calibration_samples(), esc_json(&a.export_calibration_tsv()))
                } else {
                    "{\"ok\":false,\"error\":\"adaptive_unavailable\"}\n".to_string()
                }
            }
            "sessions.status" => {
                format!(
                    "{{\"ok\":true,\"resumable_sessions_active\":{},\"sessions_resumed_total\":{}}}\n",
                    stats::RESUMABLE_SESSIONS_ACTIVE.load(Relaxed),
                    stats::SESSIONS_RESUMED.load(Relaxed),
                )
            }
            "transports.list" => {
                let reg = crate::transport_engine::TransportRegistry::new();
                let items: Vec<String> = reg
                    .list_descriptors()
                    .iter()
                    .map(|d| {
                        format!(
                            "{{\"name\":\"{}\",\"mux\":{},\"migration\":{},\"fec\":{},\"mtu\":{}}}",
                            d.kind.as_str(),
                            d.supports_multiplex,
                            d.supports_migration,
                            d.supports_fec,
                            d.max_payload_bytes
                        )
                    })
                    .collect();
                format!("{{\"ok\":true,\"transports\":[{}]}}\n", items.join(","))
            }
            "l3.status" => {
                format!(
                    "{{\"ok\":true,\"l3_packets_tx\":{},\"l3_packets_rx\":{}}}\n",
                    stats::L3_PACKETS_TX.load(Relaxed),
                    stats::L3_PACKETS_RX.load(Relaxed),
                )
            }
            "pool.status" => match st.exits.as_ref() {
                Some(e) => e.pool_status_json(),
                None => "{\"ok\":false,\"error\":\"no_exits\"}\n".to_string(),
            },
            "pool.drain" | "pool.undrain" => {
                let addr = extract_json_str(line, "addr").unwrap_or_default();
                let on = method == "pool.drain";
                match st.exits.as_ref() {
                    Some(e) if e.set_drain(&addr, on) => format!("{{\"ok\":true,\"addr\":\"{}\",\"drain\":{}}}\n", addr.replace('"', ""), on),
                    _ => "{\"ok\":false,\"error\":\"unknown_member (declare it with ;w= or --pool-mode)\"}\n".to_string(),
                }
            }
            "pool.failback" => match st.exits.as_ref() {
                Some(e) => {
                    e.fail_back_now();
                    "{\"ok\":true,\"failback\":true}\n".to_string()
                }
                None => "{\"ok\":false,\"error\":\"no_exits\"}\n".to_string(),
            },
            "carrier.swap" => {
                let target = extract_json_str(line, "addr").unwrap_or_default();
                match st.exits.as_ref() {
                    Some(e) => {
                        if target.is_empty() || target.eq_ignore_ascii_case("auto") {
                            e.force(None);
                            "{\"ok\":true,\"forced\":null}\n".to_string()
                        } else {
                            e.force(Some(target.clone()));
                            format!("{{\"ok\":true,\"forced\":\"{}\"}}\n", esc_json(&target))
                        }
                    }
                    None => "{\"ok\":false,\"error\":\"no_exits\"}\n".to_string(),
                }
            }
            "carriers.summary" => {
                format!(
                    "{{\"ok\":true,\"ws_sessions\":{},\"wss_sessions\":{},\"ssh_sessions\":{},\"udp_sessions\":{},\"ktunnel_sessions\":{},\"reverse_exits\":{},\"watchdog_events\":{}}}\n",
                    stats::WS_SESSIONS_ACTIVE.load(Relaxed),
                    stats::WSS_SESSIONS_ACTIVE.load(Relaxed),
                    stats::SSH_CARRIER_SESSIONS.load(Relaxed),
                    stats::UDP_TRANSPORT_SESSIONS.load(Relaxed),
                    stats::KTUNNEL_SESSIONS_ACTIVE.load(Relaxed),
                    stats::REVERSE_EXITS_CONNECTED.load(Relaxed),
                    stats::WATCHDOG_EVENTS.load(Relaxed),
                )
            }
            "dial.status" => match st.dial_router.as_ref() {
                Some(dr) => dr.status_json(),
                None => "{\"ok\":false,\"error\":\"dial_router_not_configured\"}\n".to_string(),
            },
            "dial.set" => {
                let mode_str = extract_json_str(line, "mode").unwrap_or_default();
                match (st.dial_router.as_ref(), DialMode::parse(&mode_str)) {
                    (Some(dr), Ok(m)) => {
                        dr.set_mode(m);
                        dr.status_json()
                    }
                    (None, _) => "{\"ok\":false,\"error\":\"dial_router_not_configured\"}\n".to_string(),
                    (_, Err(e)) => format!("{{\"ok\":false,\"error\":\"{}\"}}\n", esc_json(&e.to_string())),
                }
            }
            "health.three_layer" => match st.exits.as_ref() {
                Some(e) => {
                    let res = crate::watchdog::check_three_layer_live(e, st.socks_addr.as_deref()).await;
                    format!(
                        "{{\"ok\":true,\"verdict\":\"{}\",\"service\":{},\"session\":{},\"data\":{},\"rtt_ms\":{:.1},\"detail\":\"{}\"}}\n",
                        res.verdict.as_str(),
                        res.service_ok,
                        res.session_ok,
                        res.data_ok,
                        res.data_rtt_ms,
                        esc_json(&res.detail),
                    )
                }
                None => "{\"ok\":false,\"error\":\"no_exits\"}\n".to_string(),
            },
            "harsh_nlp.status" => match st.adaptive.as_ref() {
                Some(a) => a.harsh_nlp_status_json(),
                None => "{\"ok\":false,\"error\":\"adaptive_disabled\"}\n".to_string(),
            },
            "harsh_nlp.mode" => {
                let m = extract_json_str(line, "mode").unwrap_or_else(|| "shadow".into());
                let parsed = crate::harsh_nlp::PolicyMode::parse(&m);
                match st.adaptive.as_ref() {
                    Some(a) => {
                        a.set_harsh_nlp_mode(parsed);
                        a.harsh_nlp_status_json()
                    }
                    None => "{\"ok\":false,\"error\":\"adaptive_disabled\"}\n".to_string(),
                }
            }
            "drain" => {
                st.trigger_drain();
                "{\"ok\":true,\"draining\":true}\n".to_string()
            }
            _ => "{\"ok\":false,\"error\":\"unknown_method\"}\n".to_string(),
        }
    }

    pub async fn serve(path: String, st: Arc<ControlState>) {
        if let Some(parent) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::remove_file(&path);
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => return eprintln!("[control] cannot bind {path}: {e}"),
        };
        if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
            eprintln!("[control] failed to chmod 0600 {path}: {e}");
            let _ = std::fs::remove_file(&path);
            return;
        }
        eprintln!("[control] unix://{path} (mode 0600, SO_PEERCRED enforced)");
        let sem = Arc::new(Semaphore::new(MAX_RPC_CONNS));
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            if !peer_authorized(&stream) {
                drop(stream);
                continue;
            }
            let Ok(permit) = sem.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let st = st.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let (rd, mut wr) = stream.into_split();
                let mut limited = BufReader::new(tokio::io::AsyncReadExt::take(rd, MAX_RPC_LINE as u64));
                let mut line = String::new();
                if let Ok(Ok(n)) = timeout(Duration::from_secs(3), limited.read_line(&mut line)).await {
                    if n > 0 && n <= MAX_RPC_LINE {
                        let resp = dispatch(&line, &st).await;
                        let _ = timeout(Duration::from_secs(2), wr.write_all(resp.as_bytes())).await;
                    }
                }
            });
        }
    }
}

#[cfg(unix)]
pub use unix_impl::serve;

#[cfg(not(unix))]
pub async fn serve(_path: String, _st: Arc<ControlState>) {
    eprintln!("[control] Unix socket control API is only available on Unix platforms");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_extractor_handles_escapes_and_embedded_keys() {
        let s = r#"{"symptom":"saw \"method\":\"drain\" inside log","method":"kani.diagnose"}"#;
        assert_eq!(extract_json_str(s, "method").as_deref(), Some("kani.diagnose"));
        assert_eq!(
            extract_json_str(s, "symptom").as_deref(),
            Some("saw \"method\":\"drain\" inside log")
        );
    }
}
