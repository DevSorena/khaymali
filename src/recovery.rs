//! Adaptive recovery engine & packet-pattern detector for degraded paths.
//!
//! Classifies live transport symptoms (early reset, handshake timeout, mid-stream stall,
//! PMTU/large-frame blackhole, intermittent loss, queueing congestion) with hysteresis and
//! cooldowns, and applies strictly bounded Data Plane adjustments (chunk sizing, pacing,
//! concurrency cap, jittered backoff). Never weakens authentication, camouflage, SSRF policy,
//! or replay protection.

use crate::harsh_nlp::{HarshNlpController, MicroNlpDecision, PolicyMode, TelemetrySnapshot};
use crate::kani_nlp::{DiagnosticAction, LinkMetrics, NetIntent, NlpAdvisor};
use crate::intelligence::{IntelligenceReport, NetworkIntelligence, NetworkMode, NetworkSample, PathRanking};
use crate::stats;
use crate::util::rand_range;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const CHUNK_NORMAL: usize = 14 * 1024;
pub const CHUNK_DEGRADED: usize = 4 * 1024;
pub const CHUNK_SURVIVAL: usize = 1200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathPattern {
    Healthy,
    EarlyReset,
    HandshakeTimeout,
    MidStreamStall,
    PmtuOrLargeFrameLoss,
    CongestionOrQueueing,
    IntermittentLoss,
}

impl PathPattern {
    pub fn as_str(self) -> &'static str {
        match self {
            PathPattern::Healthy => "healthy",
            PathPattern::EarlyReset => "early_reset",
            PathPattern::HandshakeTimeout => "handshake_timeout",
            PathPattern::MidStreamStall => "mid_stream_stall",
            PathPattern::PmtuOrLargeFrameLoss => "pmtu_or_large_frame_loss",
            PathPattern::CongestionOrQueueing => "congestion_or_queueing",
            PathPattern::IntermittentLoss => "intermittent_loss",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    Keep,
    ReconnectWithBackoff,
    TryAlternateExit,
    ReduceConcurrency,
    RecommendSmallerFrame,
    RecommendPacing,
    OperatorCheckClockOrFirewall,
}

impl RecoveryAction {
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryAction::Keep => "keep",
            RecoveryAction::ReconnectWithBackoff => "reconnect_with_backoff",
            RecoveryAction::TryAlternateExit => "try_alternate_exit",
            RecoveryAction::ReduceConcurrency => "reduce_concurrency",
            RecoveryAction::RecommendSmallerFrame => "shrink_frame",
            RecoveryAction::RecommendPacing => "enable_pacing",
            RecoveryAction::OperatorCheckClockOrFirewall => "check_clock_or_firewall",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PathObservation {
    pub connect_failures: u32,
    pub handshake_timeouts: u32,
    pub resets: u32,
    pub stalls: u32,
    pub loss_per_mille: u16,
    pub rtt_ms: u32,
    pub baseline_rtt_ms: u32,
    pub queue_depth: u32,
    pub mtu_probe_failed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryDecision {
    pub pattern: PathPattern,
    pub action: RecoveryAction,
    pub confidence: u8,
    pub cooldown: Duration,
}

pub struct RecoveryController {
    last_action: Option<(RecoveryAction, Instant)>,
    consecutive_bad: u8,
}

impl Default for RecoveryController {
    fn default() -> Self {
        Self { last_action: None, consecutive_bad: 0 }
    }
}

impl RecoveryController {
    pub fn observe(&mut self, o: PathObservation, now: Instant) -> RecoveryDecision {
        let (pattern, action, confidence, cooldown) = if o.mtu_probe_failed {
            (PathPattern::PmtuOrLargeFrameLoss, RecoveryAction::RecommendSmallerFrame, 90, Duration::from_secs(30))
        } else if o.handshake_timeouts >= 2 || o.connect_failures >= 3 {
            (PathPattern::HandshakeTimeout, RecoveryAction::TryAlternateExit, 85, Duration::from_secs(20))
        } else if o.resets >= 2 {
            (PathPattern::EarlyReset, RecoveryAction::ReconnectWithBackoff, 80, Duration::from_secs(15))
        } else if o.stalls >= 2 {
            (PathPattern::MidStreamStall, RecoveryAction::ReconnectWithBackoff, 78, Duration::from_secs(20))
        } else if o.loss_per_mille >= 80 || (o.baseline_rtt_ms > 0 && o.rtt_ms > o.baseline_rtt_ms.saturating_mul(3)) {
            (PathPattern::IntermittentLoss, RecoveryAction::RecommendPacing, 75, Duration::from_secs(20))
        } else if o.queue_depth >= 32 || (o.baseline_rtt_ms > 0 && o.rtt_ms > o.baseline_rtt_ms.saturating_mul(2)) {
            (PathPattern::CongestionOrQueueing, RecoveryAction::ReduceConcurrency, 70, Duration::from_secs(30))
        } else {
            (PathPattern::Healthy, RecoveryAction::Keep, 95, Duration::from_secs(5))
        };

        if pattern == PathPattern::Healthy {
            self.consecutive_bad = 0;
            return RecoveryDecision { pattern, action, confidence, cooldown };
        }
        self.consecutive_bad = self.consecutive_bad.saturating_add(1);

        // Hysteresis: require repeated observations before triggering disruptive recovery.
        let action = if self.consecutive_bad < 2 {
            RecoveryAction::Keep
        } else if let Some((previous, at)) = self.last_action {
            if now.duration_since(at) < cooldown {
                previous
            } else {
                action
            }
        } else {
            action
        };
        if action != RecoveryAction::Keep {
            self.last_action = Some((action, now));
        }
        RecoveryDecision { pattern, action, confidence, cooldown }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum TransportEvent {
    ConnectOk { rtt_ms: u32 },
    ConnectFail,
    HandshakeTimeout,
    EarlyReset { bytes_transferred: u64 },
    MidStreamStall { bytes_transferred: u64, frame_size: usize },
    KeepaliveOk,
    KeepaliveFail,
    StreamOk { bytes: u64 },
}

#[derive(Clone, Debug)]
pub struct AdaptiveSnapshot {
    pub pattern: PathPattern,
    pub action: RecoveryAction,
    pub confidence: u8,
    pub chunk_bytes: usize,
    pub pacing_us: u64,
    pub concurrency_cap: usize,
    pub loss_per_mille: u16,
    pub recovery_actions: u64,
    pub nlp_intent: NetIntent,
    pub nlp_action: DiagnosticAction,
    pub nlp_confidence: f32,
    pub nlp_abstained: bool,
    pub nlp_online_updates: u32,
    pub nlp_candidate_updates: u32,
    pub intelligence_mode: Option<NetworkMode>,
    pub predicted_severity: u8,
    pub projected_severity: u8,
    pub degradation_likely: bool,
    pub intelligence_path_score: f64,
    pub measured_goodput_kbps: f64,
    pub measured_jitter_ms: f64,
    pub degradation_probability: Option<f64>,
    pub calibration_samples: usize,
}

const MAX_RUNTIME_PATHS: usize = 64;

const GOODPUT_WINDOW: Duration = Duration::from_secs(5);
const MAX_GOODPUT_SAMPLES: usize = 512;

fn update_windowed_goodput(buf: &mut VecDeque<(Instant, u64)>, bytes: u64, now: Instant, ewma_goodput_kbps: &mut f64) {
    while let Some(&(ts, _)) = buf.front() {
        if now.saturating_duration_since(ts) > GOODPUT_WINDOW || buf.len() >= MAX_GOODPUT_SAMPLES {
            buf.pop_front();
        } else { break; }
    }
    if bytes > 0 { buf.push_back((now, bytes)); }
    if buf.len() >= 2 {
        let first_ts = buf.front().unwrap().0;
        let span = now.saturating_duration_since(first_ts).as_secs_f64();
        if span >= 0.5 {
            let total_bytes: u64 = buf.iter().skip(1).map(|(_, b)| *b).sum();
            if total_bytes > 0 {
                let measured = (total_bytes as f64 * 8.0) / (span * 1000.0);
                *ewma_goodput_kbps = if *ewma_goodput_kbps == 0.0 { measured } else { *ewma_goodput_kbps * 0.75 + measured * 0.25 };
            }
        }
    }
}

#[derive(Default)]
struct PathRuntimeTelemetry {
    window: VecDeque<(Instant, TransportEvent)>,
    bytes_window: VecDeque<(Instant, u64)>,
    baseline_rtt_ms: u32,
    latest_rtt_ms: u32,
    ewma_jitter_ms: f64,
    ewma_goodput_kbps: f64,
    last_seen: Option<Instant>,
}

impl PathRuntimeTelemetry {
    fn observe(&mut self, ev: TransportEvent, now: Instant, udp_loss_pct: f64) -> NetworkSample {
        self.last_seen = Some(now);
        while let Some((at, _)) = self.window.front() {
            if now.saturating_duration_since(*at) > Duration::from_secs(30) || self.window.len() >= 128 {
                self.window.pop_front();
            } else { break; }
        }
        self.window.push_back((now, ev));
        match ev {
            TransportEvent::ConnectOk { rtt_ms } => {
                if self.latest_rtt_ms > 0 {
                    let delta = (rtt_ms as f64 - self.latest_rtt_ms as f64).abs();
                    self.ewma_jitter_ms = if self.ewma_jitter_ms == 0.0 { delta } else { self.ewma_jitter_ms * 0.75 + delta * 0.25 };
                }
                self.latest_rtt_ms = rtt_ms;
                if self.baseline_rtt_ms == 0 || rtt_ms < self.baseline_rtt_ms {
                    self.baseline_rtt_ms = rtt_ms.max(1);
                } else {
                    self.baseline_rtt_ms = ((self.baseline_rtt_ms as u64 * 99 + rtt_ms as u64) / 100).max(1) as u32;
                }
            }
            TransportEvent::StreamOk { bytes } => {
                update_windowed_goodput(&mut self.bytes_window, bytes, now, &mut self.ewma_goodput_kbps);
            }
            _ => {}
        }
        let attempts = self.window.iter().filter(|(_, e)| matches!(e,
            TransportEvent::ConnectOk { .. } | TransportEvent::ConnectFail | TransportEvent::HandshakeTimeout)).count();
        let successes = self.window.iter().filter(|(_, e)| matches!(e, TransportEvent::ConnectOk { .. })).count();
        let connect_success_pct = if attempts == 0 { 100.0 } else { successes as f64 * 100.0 / attempts as f64 };
        NetworkSample {
            rtt_ms: self.latest_rtt_ms as f64,
            baseline_rtt_ms: self.baseline_rtt_ms as f64,
            jitter_ms: self.ewma_jitter_ms,
            loss_pct: udp_loss_pct,
            retransmit_pct: udp_loss_pct,
            goodput_kbps: self.ewma_goodput_kbps,
            connect_success_pct,
        }
    }
}

struct DetectorState {
    window: VecDeque<(Instant, TransportEvent)>,
    controller: RecoveryController,
    baseline_rtt_ms: u32,
    latest_rtt_ms: u32,
    healthy_streak: u32,
    last_decision: RecoveryDecision,
    nlp_advisor: NlpAdvisor,
    last_nlp_intent: NetIntent,
    last_nlp_action: DiagnosticAction,
    last_nlp_conf: f32,
    last_nlp_abstained: bool,
    intelligence: NetworkIntelligence,
    last_intelligence: Option<IntelligenceReport>,
    bytes_window: VecDeque<(Instant, u64)>,
    ewma_goodput_kbps: f64,
    ewma_jitter_ms: f64,
    path_telemetry: HashMap<String, PathRuntimeTelemetry>,
    /// v0.15.1: safety envelope around NLP-applied knob changes.
    nlp_guard: NlpActionGuard,
    /// v0.22.0: compact fixed-weight Harsh-Network Micro-NLP controller.
    harsh_nlp: HarshNlpController,
    last_harsh_decision: Option<MicroNlpDecision>,
}

/// v0.15.1 NLP action safety envelope.
/// * rate cap: at most `MAX_NLP_ACTIONS_PER_MIN` applied changes per rolling minute, one under
///   evaluation at a time;
/// * pre-action baseline: window success ratio and goodput are stored with each change;
/// * automatic revert: if after >= `MIN_EVENTS_FOR_VERDICT` events (within `REVERT_WINDOW`) success
///   drops >= 10 points or goodput >= 25 %, the previous knob values are restored (only knobs NLP
///   still owns) and that action kind is locked for `ACTION_LOCKOUT`.
const MAX_NLP_ACTIONS_PER_MIN: usize = 6;
const REVERT_WINDOW: Duration = Duration::from_secs(30);
const ACTION_LOCKOUT: Duration = Duration::from_secs(600);
const MIN_EVENTS_FOR_VERDICT: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NlpKnob { Chunk, Pacing }

#[derive(Clone, Copy, Debug)]
struct AppliedNlpAction {
    kind: NlpKnob,
    at: Instant,
    prev_chunk: usize,
    prev_pacing: u64,
    set_chunk: usize,
    set_pacing: u64,
    base_success: f64,
    base_goodput_kbps: f64,
    ok_after: u32,
    bad_after: u32,
}

#[derive(Default)]
struct NlpActionGuard {
    recent: VecDeque<Instant>,
    pending: Option<AppliedNlpAction>,
    locked_until: [Option<Instant>; 2],
}

impl NlpActionGuard {
    fn idx(k: NlpKnob) -> usize { match k { NlpKnob::Chunk => 0, NlpKnob::Pacing => 1 } }

    fn allow(&mut self, kind: NlpKnob, now: Instant) -> bool {
        while let Some(t) = self.recent.front() {
            if now.saturating_duration_since(*t) >= Duration::from_secs(60) { self.recent.pop_front(); } else { break; }
        }
        if self.locked_until[Self::idx(kind)].is_some_and(|t| now < t) { return false; }
        if self.pending.is_some() { return false; }
        self.recent.len() < MAX_NLP_ACTIONS_PER_MIN
    }

    fn record(&mut self, a: AppliedNlpAction) {
        self.recent.push_back(a.at);
        self.pending = Some(a);
    }
}

/// v0.15.1: write deferred model artifacts without holding the runtime lock. Inside a Tokio
/// runtime the blocking fsync goes to the blocking pool; otherwise (CLI/tests) it runs inline.
fn flush_pending_writes(writes: Vec<crate::kani_nlp::PendingWrite>) {
    if writes.is_empty() { return; }
    let job = move || {
        for w in &writes {
            if let Err(e) = w.write_atomic() {
                stats::NLP_PERSIST_FAILURES.fetch_add(1, Relaxed);
                stats::log_err_rl(&format!("[nlp] deferred artifact write failed for {}: {e}", w.path.display()));
            }
        }
    };
    match tokio::runtime::Handle::try_current() {
        Ok(h) => { drop(h.spawn_blocking(job)); }
        Err(_) => job(),
    }
}

#[cfg(test)]
static TEST_FORCE_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `KHAYMALI_NLP_MODE` (active | shadow | off); defaults to shadow until explicitly enabled.
fn nlp_mode() -> &'static str {
    #[cfg(test)]
    if TEST_FORCE_ACTIVE.load(Relaxed) { return "active"; }
    static MODE: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    MODE.get_or_init(|| match std::env::var("KHAYMALI_NLP_MODE").as_deref() {
        Ok("off") | Ok("0") => "off",
        Ok("active") => "active",
        _ => "shadow",
    })
}

fn nlp_online_learning_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("KHAYMALI_NLP_ONLINE_LEARNING")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false))
}

/// Live Data-Plane adaptive runtime wired into Entry, Bridge, and Link relay loops.
pub struct AdaptiveRuntime {
    max_concurrency: usize,
    chunk_bytes: AtomicUsize,
    pacing_us: AtomicU64,
    concurrency_cap: AtomicUsize,
    recovery_actions: AtomicU64,
    loss_per_mille: AtomicU64,
    state: Mutex<DetectorState>,
}

impl AdaptiveRuntime {
    pub fn new(max_concurrency: usize) -> Arc<Self> {
        let cap = max_concurrency.max(16);
        stats::ADAPTIVE_CHUNK_BYTES.store(CHUNK_NORMAL, Relaxed);
        Arc::new(Self {
            max_concurrency: cap,
            chunk_bytes: AtomicUsize::new(CHUNK_NORMAL),
            pacing_us: AtomicU64::new(0),
            concurrency_cap: AtomicUsize::new(cap),
            recovery_actions: AtomicU64::new(0),
            loss_per_mille: AtomicU64::new(0),
            state: Mutex::new(DetectorState {
                window: VecDeque::with_capacity(128),
                controller: RecoveryController::default(),
                baseline_rtt_ms: 0,
                latest_rtt_ms: 0,
                healthy_streak: 0,
                last_decision: RecoveryDecision {
                    pattern: PathPattern::Healthy,
                    action: RecoveryAction::Keep,
                    confidence: 95,
                    cooldown: Duration::from_secs(5),
                },
                nlp_advisor: NlpAdvisor::new(),
                last_nlp_intent: NetIntent::Healthy,
                last_nlp_action: DiagnosticAction::KeepNormal,
                last_nlp_conf: 0.0,
                last_nlp_abstained: false,
                intelligence: NetworkIntelligence::new(),
                last_intelligence: None,
                bytes_window: VecDeque::with_capacity(64),
                ewma_goodput_kbps: 0.0,
                ewma_jitter_ms: 0.0,
                path_telemetry: HashMap::with_capacity(8),
                nlp_guard: NlpActionGuard::default(),
                harsh_nlp: HarshNlpController::new(PolicyMode::parse(nlp_mode())),
                last_harsh_decision: None,
            }),
        })
    }

    #[inline]
    pub fn current_chunk_size(&self) -> usize {
        self.chunk_bytes.load(Relaxed).clamp(CHUNK_SURVIVAL, CHUNK_NORMAL)
    }

    #[inline]
    pub fn current_pacing_us(&self) -> u64 {
        self.pacing_us.load(Relaxed)
    }

    #[inline]
    pub fn current_concurrency_cap(&self) -> usize {
        self.concurrency_cap.load(Relaxed).clamp(16, self.max_concurrency)
    }

    /// Jittered reconnect backoff (±25%) to avoid robotic DPI timing patterns.
    pub fn jittered_backoff(base: Duration) -> Duration {
        let ms = base.as_millis().max(50) as usize;
        let lo = (ms * 75) / 100;
        let hi = (ms * 125) / 100;
        Duration::from_millis(rand_range(lo, hi) as u64)
    }

    pub fn record(&self, ev: TransportEvent, queue_depth: u32) -> RecoveryDecision {
        self.record_at_with_log(ev, queue_depth, Instant::now(), None)
    }

    pub fn record_with_log(
        &self,
        ev: TransportEvent,
        queue_depth: u32,
        log: Option<&str>,
    ) -> RecoveryDecision {
        self.record_at_with_log(ev, queue_depth, Instant::now(), log)
    }

    /// Fit the horizon-specific risk calibrator from an independently labeled validation set.
    /// No probability is exposed until this operation succeeds.
    pub fn fit_risk_calibrator(&self, examples: &[crate::intelligence::CalibrationExample]) -> bool {
        self.state.lock().unwrap().intelligence.fit_calibrator(examples)
    }

    pub fn set_harsh_nlp_mode(&self, mode: PolicyMode) {
        if let Ok(mut st) = self.state.lock() {
            st.harsh_nlp.mode = mode;
        }
    }

    pub fn harsh_nlp_status_json(&self) -> String {
        let Ok(st) = self.state.lock() else {
            return "{\"ok\":false,\"error\":\"lock_poisoned\"}\n".to_string();
        };
        let now_ts = crate::util::now_unix();
        let mut obj = crate::hjson::Json::obj()
            .set("ok", true)
            .set("mode", st.harsh_nlp.mode.as_str())
            .set("locked", st.harsh_nlp.is_locked(now_ts))
            .set("rollbacks", st.harsh_nlp.rollbacks)
            .set("current", st.harsh_nlp.current.to_json());
        if let Some(ref dec) = st.last_harsh_decision {
            obj.insert("last_decision", dec.to_json());
        }
        let mut out = obj.to_string_compact();
        out.push('\n');
        out
    }

    pub fn reload_nlp_model(&self) -> bool {
        let mut st = self.state.lock().unwrap();
        let ok = st.nlp_advisor.reload_configured_model();
        if ok {
            stats::NLP_ONLINE_UPDATES.store(st.nlp_advisor.nlp().online_updates_total() as u64, Relaxed);
            stats::NLP_CANDIDATE_UPDATES.store(st.nlp_advisor.candidate_online_updates_total() as u64, Relaxed);
        }
        ok
    }

    pub fn reload_risk_calibrator(&self) -> bool {
        self.state.lock().unwrap().intelligence.reload_calibrator()
    }

    pub fn promote_nlp_candidate(
        &self,
        holdout: &[(&str, NetIntent)],
        min_samples: usize,
        min_accuracy_gain_pp: f64,
        max_false_positive_increase_pp: f64,
    ) -> crate::kani_nlp::CandidatePromotionDecision {
        let mut st = self.state.lock().unwrap();
        let decision = st.nlp_advisor.evaluate_and_promote_candidate(
            holdout, min_samples, min_accuracy_gain_pp, max_false_positive_increase_pp);
        if decision == crate::kani_nlp::CandidatePromotionDecision::Promoted {
            stats::NLP_ONLINE_UPDATES.store(st.nlp_advisor.nlp().online_updates_total() as u64, Relaxed);
            stats::NLP_CANDIDATE_UPDATES.store(0, Relaxed);
        }
        decision
    }

    pub fn rollback_nlp_model(&self) -> bool {
        let mut st = self.state.lock().unwrap();
        let ok = st.nlp_advisor.rollback_promoted_model();
        if ok {
            stats::NLP_ONLINE_UPDATES.store(st.nlp_advisor.nlp().online_updates_total() as u64, Relaxed);
            stats::NLP_CANDIDATE_UPDATES.store(0, Relaxed);
        }
        ok
    }

    pub fn reset_nlp_online_weights(&self) -> bool {
        let mut st = self.state.lock().unwrap();
        let persisted = st.nlp_advisor.reset_online_learning_and_persist();
        st.last_nlp_intent = NetIntent::Healthy;
        st.last_nlp_action = DiagnosticAction::KeepNormal;
        st.last_nlp_conf = 0.0;
        st.last_nlp_abstained = false;
        stats::NLP_LAST_INTENT.store(NetIntent::Healthy as i64, Relaxed);
        stats::NLP_ONLINE_UPDATES.store(0, Relaxed);
        stats::NLP_CANDIDATE_UPDATES.store(0, Relaxed);
        persisted
    }

    pub fn record_at(&self, ev: TransportEvent, queue_depth: u32, now: Instant) -> RecoveryDecision {
        self.record_at_with_log(ev, queue_depth, now, None)
    }

    pub fn record_at_with_log(
        &self,
        ev: TransportEvent,
        queue_depth: u32,
        now: Instant,
        log: Option<&str>,
    ) -> RecoveryDecision {
        self.record_at_with_path_and_log(ev, queue_depth, now, "runtime-default", log)
    }

    pub fn record_with_path(&self, ev: TransportEvent, queue_depth: u32, path_id: &str) -> RecoveryDecision {
        self.record_at_with_path_and_log(ev, queue_depth, Instant::now(), path_id, None)
    }

    pub fn record_with_path_and_log(&self, ev: TransportEvent, queue_depth: u32, path_id: &str, log: Option<&str>) -> RecoveryDecision {
        self.record_at_with_path_and_log(ev, queue_depth, Instant::now(), path_id, log)
    }

    pub fn path_score(&self, path_id: &str) -> Option<(f64, u64)> {
        self.state.lock().unwrap().intelligence.score_for_path(path_id)
    }

    pub fn ranked_paths(&self) -> Vec<PathRanking> {
        self.state.lock().unwrap().intelligence.rank_paths()
    }

    pub fn calibration_samples(&self) -> usize {
        self.state.lock().unwrap().intelligence.calibration_samples()
    }

    pub fn export_calibration_tsv(&self) -> String {
        self.state.lock().unwrap().intelligence.export_calibration_tsv()
    }

    pub fn record_at_with_path_and_log(
        &self,
        ev: TransportEvent,
        queue_depth: u32,
        now: Instant,
        path_id: &str,
        log: Option<&str>,
    ) -> RecoveryDecision {
        let path_id = if path_id.trim().is_empty() || path_id.len() > 96 { "runtime-default" } else { path_id };
        let mut st = self.state.lock().unwrap();

        while let Some((ts, _)) = st.window.front() {
            if now.saturating_duration_since(*ts) > Duration::from_secs(30) || st.window.len() >= 128 {
                st.window.pop_front();
            } else {
                break;
            }
        }
        st.window.push_back((now, ev));

        // Keep independent telemetry windows per path. The NLP recovery window below remains
        // runtime-wide, while predictive/path scoring receives only this path's observations.
        if !st.path_telemetry.contains_key(path_id) && st.path_telemetry.len() >= MAX_RUNTIME_PATHS {
            // Bounded LRU eviction: remove the least recently observed path from both layers.
            if let Some(oldest) = st.path_telemetry.iter()
                .min_by_key(|(_, telemetry)| telemetry.last_seen.unwrap_or(now))
                .map(|(id, _)| id.clone()) {
                st.path_telemetry.remove(&oldest);
                st.intelligence.remove_path(&oldest);
            }
        }
        let udp_loss_pct = if stats::UDP_TRANSPORT_SESSIONS.load(Relaxed) > 0 {
            (stats::UDP_LOSS_PER_MILLE.load(Relaxed).min(1000) as f64) / 10.0
        } else { 0.0 };
        let path_sample = Some(st.path_telemetry.entry(path_id.to_string()).or_default().observe(ev, now, udp_loss_pct));

        // Feed the actual transport event into TinyNetNlp's bounded temporal window.
        // This makes sequence features live rather than test-only.
        let temporal_token: &'static str = match ev {
            TransportEvent::ConnectOk { .. } => "link stable",
            TransportEvent::ConnectFail => "unreachable",
            TransportEvent::HandshakeTimeout => "handshake timeout",
            TransportEvent::EarlyReset { .. } => "rst_early",
            TransportEvent::MidStreamStall { .. } => "freeze_bytes",
            TransportEvent::KeepaliveOk => "keepalive ok",
            TransportEvent::KeepaliveFail => "keepalive timeout",
            TransportEvent::StreamOk { .. } => "stream active",
        };
        st.nlp_advisor.push_event_token(temporal_token);

        match ev {
            TransportEvent::ConnectOk { rtt_ms } => {
                if st.latest_rtt_ms > 0 {
                    let delta = (rtt_ms as f64 - st.latest_rtt_ms as f64).abs();
                    st.ewma_jitter_ms = if st.ewma_jitter_ms == 0.0 { delta } else { st.ewma_jitter_ms * 0.75 + delta * 0.25 };
                }
                st.latest_rtt_ms = rtt_ms;
                if st.baseline_rtt_ms == 0 || rtt_ms < st.baseline_rtt_ms {
                    st.baseline_rtt_ms = rtt_ms.max(1);
                } else {
                    st.baseline_rtt_ms =
                        ((st.baseline_rtt_ms as u64 * 99 + rtt_ms as u64) / 100).max(1) as u32;
                }
                st.healthy_streak = st.healthy_streak.saturating_add(1);
            }
            TransportEvent::StreamOk { .. } | TransportEvent::KeepaliveOk => {
                st.healthy_streak = st.healthy_streak.saturating_add(1);
            }
            _ => {
                st.healthy_streak = 0;
            }
        }

        let (mut connect_failures, mut handshake_timeouts, mut resets, mut stalls) = (0u32, 0u32, 0u32, 0u32);
        let (mut ok_cnt, mut bad_cnt, mut large_stalls, mut small_oks) = (0u32, 0u32, 0u32, 0u32);

        for (_, e) in &st.window {
            match *e {
                TransportEvent::ConnectOk { .. } | TransportEvent::StreamOk { .. } => ok_cnt += 1,
                TransportEvent::KeepaliveOk => {
                    ok_cnt += 1;
                    small_oks += 1;
                }
                TransportEvent::ConnectFail | TransportEvent::KeepaliveFail => {
                    connect_failures += 1;
                    bad_cnt += 1;
                }
                TransportEvent::HandshakeTimeout => {
                    handshake_timeouts += 1;
                    bad_cnt += 1;
                }
                TransportEvent::EarlyReset { .. } => {
                    resets += 1;
                    bad_cnt += 1;
                }
                TransportEvent::MidStreamStall { frame_size, .. } => {
                    stalls += 1;
                    bad_cnt += 1;
                    if frame_size >= CHUNK_DEGRADED {
                        large_stalls += 1;
                    }
                }
            }
        }

        let total = ok_cnt + bad_cnt;
        let loss_pm = if total >= 4 {
            ((bad_cnt as u64 * 1000) / total as u64).min(1000) as u16
        } else {
            0
        };
        self.loss_per_mille.store(loss_pm as u64, Relaxed);

        let mtu_probe_failed = large_stalls >= 3 || (large_stalls >= 2 && small_oks >= 1);
        let obs = PathObservation {
            connect_failures,
            handshake_timeouts,
            resets,
            stalls,
            loss_per_mille: loss_pm,
            rtt_ms: st.latest_rtt_ms,
            baseline_rtt_ms: st.baseline_rtt_ms,
            queue_depth,
            mtu_probe_failed,
        };

        let decision = st.controller.observe(obs, now);
        st.last_decision = decision;

        match decision.action {
            RecoveryAction::RecommendSmallerFrame => {
                let cur = self.chunk_bytes.load(Relaxed);
                let next = if cur > CHUNK_DEGRADED {
                    CHUNK_DEGRADED
                } else {
                    CHUNK_SURVIVAL
                };
                if next != cur {
                    self.chunk_bytes.store(next, Relaxed);
                    stats::ADAPTIVE_CHUNK_BYTES.store(next, Relaxed);
                    self.recovery_actions.fetch_add(1, Relaxed);
                    stats::ADAPTIVE_ACTIONS.fetch_add(1, Relaxed);
                }
            }
            RecoveryAction::RecommendPacing => {
                let cur_p = self.pacing_us.load(Relaxed);
                let next_p = (cur_p + 500).min(2500);
                self.pacing_us.store(next_p, Relaxed);
                if self.chunk_bytes.load(Relaxed) > CHUNK_DEGRADED {
                    self.chunk_bytes.store(CHUNK_DEGRADED, Relaxed);
                    stats::ADAPTIVE_CHUNK_BYTES.store(CHUNK_DEGRADED, Relaxed);
                }
                self.recovery_actions.fetch_add(1, Relaxed);
                stats::ADAPTIVE_ACTIONS.fetch_add(1, Relaxed);
            }
            RecoveryAction::ReduceConcurrency => {
                let cur_c = self.concurrency_cap.load(Relaxed);
                let next_c = (cur_c / 2).max(16);
                if next_c != cur_c {
                    self.concurrency_cap.store(next_c, Relaxed);
                    self.recovery_actions.fetch_add(1, Relaxed);
                    stats::ADAPTIVE_ACTIONS.fetch_add(1, Relaxed);
                }
            }
            RecoveryAction::ReconnectWithBackoff | RecoveryAction::TryAlternateExit => {
                if self.chunk_bytes.load(Relaxed) > CHUNK_DEGRADED && stalls >= 2 {
                    self.chunk_bytes.store(CHUNK_DEGRADED, Relaxed);
                    stats::ADAPTIVE_CHUNK_BYTES.store(CHUNK_DEGRADED, Relaxed);
                }
                self.recovery_actions.fetch_add(1, Relaxed);
                stats::ADAPTIVE_ACTIONS.fetch_add(1, Relaxed);
            }
            RecoveryAction::Keep | RecoveryAction::OperatorCheckClockOrFirewall => {
                if decision.pattern == PathPattern::Healthy && st.healthy_streak >= 20 {
                    st.healthy_streak = 0;
                    let cur_ch = self.chunk_bytes.load(Relaxed);
                    if cur_ch < CHUNK_DEGRADED {
                        self.chunk_bytes.store(CHUNK_DEGRADED, Relaxed);
                        stats::ADAPTIVE_CHUNK_BYTES.store(CHUNK_DEGRADED, Relaxed);
                    } else if cur_ch < CHUNK_NORMAL {
                        self.chunk_bytes.store(CHUNK_NORMAL, Relaxed);
                        stats::ADAPTIVE_CHUNK_BYTES.store(CHUNK_NORMAL, Relaxed);
                    }
                    let cur_p = self.pacing_us.load(Relaxed);
                    if cur_p > 0 {
                        self.pacing_us.store(cur_p.saturating_sub(500), Relaxed);
                    }
                    let cur_c = self.concurrency_cap.load(Relaxed);
                    if cur_c < self.max_concurrency {
                        self.concurrency_cap.store((cur_c * 3 / 2).min(self.max_concurrency), Relaxed);
                    }
                }
            }
        }

        // Live TinyNetNlp v4 advisory fusion (`active` | `shadow` | `off`)
        let nlp_mode = nlp_mode();
        {
            let last_stall_bytes = if stalls >= 2 {
                st.window.iter().rev().find_map(|(_, e)| match *e {
                    TransportEvent::MidStreamStall { bytes_transferred, .. } => Some(bytes_transferred),
                    _ => None,
                })
            } else {
                None
            };
            let connect_fail_ratio = if total >= 4 {
                (connect_failures + handshake_timeouts) as f32 / total as f32
            } else {
                0.0
            };
            let metrics = LinkMetrics {
                loss_pct: (loss_pm as f32) / 10.0,
                rtt_ms: st.latest_rtt_ms,
                base_rtt_ms: st.baseline_rtt_ms,
                jitter_ms: st.ewma_jitter_ms.round().clamp(0.0, u32::MAX as f64) as u32,
                retransmit_pct: udp_loss_pct as f32,
                stall_bytes: last_stall_bytes,
                rx_idle_ms: if stalls >= 2 { 6_000 } else { 0 },
                resets_last_min: resets,
                connect_fail_ratio,
                big_frames_lost: large_stalls >= 2,
                small_frames_ok: small_oks >= 1,
            };
            if let TransportEvent::StreamOk { bytes } = ev {
                let mut gp = st.ewma_goodput_kbps;
                update_windowed_goodput(&mut st.bytes_window, bytes, now, &mut gp);
                st.ewma_goodput_kbps = gp;
            }
            let intelligence_report = path_sample.and_then(|sample| st.intelligence.observe(path_id, sample, now));
            st.last_intelligence = intelligence_report;
            if let Some(ref report) = st.last_intelligence {
                stats::INTELLIGENCE_MODE.store(match report.mode {
                    NetworkMode::Normal => 0, NetworkMode::Watch => 1,
                    NetworkMode::Degraded => 2, NetworkMode::Critical => 3,
                }, Relaxed);
                stats::INTELLIGENCE_PREDICTED_SEVERITY.store(report.prediction.severity_now as u64, Relaxed);
                stats::INTELLIGENCE_PROJECTED_SEVERITY.store(report.prediction.projected_severity as u64, Relaxed);
                stats::INTELLIGENCE_DEGRADATION_LIKELY.store(report.prediction.degradation_likely as u64, Relaxed);
                stats::INTELLIGENCE_PATH_SCORE_TENTHS.store((report.path.score * 10.0).round().max(0.0) as u64, Relaxed);
                stats::INTELLIGENCE_GOODPUT_BPS.store((st.ewma_goodput_kbps * 1000.0).round().max(0.0) as u64, Relaxed);
                stats::INTELLIGENCE_JITTER_TENTHS_MS.store((st.ewma_jitter_ms * 10.0).round().max(0.0) as u64, Relaxed);
                stats::INTELLIGENCE_RISK_CALIBRATED.store(report.degradation_probability.is_some() as u64, Relaxed);
                stats::INTELLIGENCE_RISK_PROB_MILLI.store((report.degradation_probability.unwrap_or(0.0) * 1000.0).round().clamp(0.0, 1000.0) as u64, Relaxed);
                stats::INTELLIGENCE_CALIBRATION_SAMPLES.store(st.intelligence.calibration_samples() as u64, Relaxed);
            }
            if nlp_mode != "off" {
            // Feed live telemetry into the compact Harsh-Network Micro-NLP controller
            {
                let big_drop = if large_stalls >= 2 && small_oks >= 1 {
                    0.85
                } else if large_stalls >= 1 {
                    0.45
                } else {
                    0.0
                };
                let hsnap = TelemetrySnapshot {
                    ts_unix: crate::util::now_unix(),
                    rtt_ms: st.latest_rtt_ms as f32,
                    base_rtt_ms: st.baseline_rtt_ms.max(10) as f32,
                    jitter_ms: st.ewma_jitter_ms as f32,
                    loss_pct: (loss_pm as f32) / 10.0,
                    retransmit_pct: udp_loss_pct as f32,
                    disconnects_per_min: resets + connect_failures,
                    big_pkt_drop_ratio: big_drop,
                    goodput_kbps: st.ewma_goodput_kbps as f32,
                    recent_log: log.unwrap_or("").to_string(),
                };
                let _ = st.harsh_nlp.verify_or_rollback(&hsnap);
                let hdec = st.harsh_nlp.evaluate(&hsnap);
                if hdec.applied {
                    let next_chunk = (hdec.recommended.chunk_bytes as usize).clamp(CHUNK_SURVIVAL, CHUNK_NORMAL);
                    self.chunk_bytes.store(next_chunk, Relaxed);
                    stats::ADAPTIVE_CHUNK_BYTES.store(next_chunk, Relaxed);
                    let next_pacing_us = if hdec.recommended.pacing_kbps > 0 {
                        ((next_chunk as u64 * 8 * 1000) / (hdec.recommended.pacing_kbps as u64).max(1)).min(2_500)
                    } else {
                        0
                    };
                    self.pacing_us.store(next_pacing_us, Relaxed);
                }
                st.last_harsh_decision = Some(hdec);
            }
            // Publish the same numeric snapshot consumed by classify_combined so replay
            // datasets can carry genuine LinkMetrics rather than unrelated Prometheus counters.
            stats::NLP_LINK_LOSS_PER_MILLE.store(loss_pm as u64, Relaxed);
            stats::NLP_LINK_RTT_MS.store(st.latest_rtt_ms as u64, Relaxed);
            stats::NLP_LINK_BASE_RTT_MS.store(st.baseline_rtt_ms as u64, Relaxed);
            stats::NLP_LINK_JITTER_MS.store(metrics.jitter_ms as u64, Relaxed);
            stats::NLP_LINK_RETRANSMIT_TENTHS.store((metrics.retransmit_pct * 10.0).max(0.0) as u64, Relaxed);
            stats::NLP_LINK_HAS_STALL.store(if metrics.stall_bytes.is_some() { 1 } else { 0 }, Relaxed);
            stats::NLP_LINK_STALL_BYTES.store(metrics.stall_bytes.unwrap_or(0), Relaxed);
            stats::NLP_LINK_RX_IDLE_MS.store(metrics.rx_idle_ms as u64, Relaxed);
            stats::NLP_LINK_RESETS_LAST_MIN.store(resets as u64, Relaxed);
            stats::NLP_LINK_CONNECT_FAIL_PER_MILLE.store((connect_fail_ratio * 1000.0).round().max(0.0) as u64, Relaxed);
            stats::NLP_LINK_BIG_FRAMES_LOST.store(if metrics.big_frames_lost { 1 } else { 0 }, Relaxed);
            stats::NLP_LINK_SMALL_FRAMES_OK.store(if metrics.small_frames_ok { 1 } else { 0 }, Relaxed);

            let nlp_action = match log {
                Some(txt) if !txt.trim().is_empty() => {
                    st.nlp_advisor.observe_combined_at(txt, &metrics, now)
                }
                _ => st.nlp_advisor.observe_metrics_at(&metrics, now),
            };
            if let Some((intent, conf, abstained)) = st
                .nlp_advisor
                .last_prediction()
                .map(|p| (p.intent, p.confidence, p.abstained))
            {
                st.last_nlp_intent = intent;
                st.last_nlp_action = nlp_action;
                st.last_nlp_conf = conf;
                st.last_nlp_abstained = abstained;
                stats::NLP_LAST_INTENT.store(intent as i64, Relaxed);
                if abstained {
                    stats::NLP_ABSTENTIONS.fetch_add(1, Relaxed);
                }
            }

            let streak = st.healthy_streak;
            let outcome_verified = metrics.has_live_signal() && !metrics.has_fault_signal();
            if nlp_online_learning_enabled() && outcome_verified && streak >= 3
                && st.nlp_advisor.record_outcome(streak, now) {
                stats::NLP_ONLINE_UPDATES.store(
                    st.nlp_advisor.nlp().online_updates_total() as u64,
                    Relaxed,
                );
                stats::NLP_CANDIDATE_UPDATES.store(st.nlp_advisor.candidate_online_updates_total() as u64, Relaxed);
            }

            // ---- v0.15.1: evaluate the previous NLP change before applying a new one ----
            let is_ok_ev = matches!(ev, TransportEvent::ConnectOk { .. } | TransportEvent::StreamOk { .. } | TransportEvent::KeepaliveOk);
            let window_success = if total == 0 { 1.0 } else { ok_cnt as f64 / total as f64 };
            let goodput_now = st.ewma_goodput_kbps;
            let mut revert_to: Option<AppliedNlpAction> = None;
            if let Some(mut p) = st.nlp_guard.pending {
                if is_ok_ev { p.ok_after += 1; } else { p.bad_after += 1; }
                let n = p.ok_after + p.bad_after;
                let age = now.saturating_duration_since(p.at);
                let mut done = false;
                if n >= MIN_EVENTS_FOR_VERDICT || age >= REVERT_WINDOW {
                    let after_success = if n == 0 { 1.0 } else { p.ok_after as f64 / n as f64 };
                    let success_drop = p.base_success - after_success >= 0.10;
                    let goodput_drop = p.base_goodput_kbps > 0.0 && goodput_now > 0.0
                        && goodput_now < p.base_goodput_kbps * 0.75;
                    if n >= MIN_EVENTS_FOR_VERDICT && (success_drop || goodput_drop) {
                        revert_to = Some(p);
                    }
                    done = true;
                }
                st.nlp_guard.pending = if done { None } else { Some(p) };
            }
            if let Some(p) = revert_to {
                // Restore only knobs that still hold the value NLP set (a newer rule-engine
                // decision is never undone).
                if self.chunk_bytes.load(Relaxed) == p.set_chunk {
                    self.chunk_bytes.store(p.prev_chunk, Relaxed);
                    stats::ADAPTIVE_CHUNK_BYTES.store(p.prev_chunk, Relaxed);
                }
                if self.pacing_us.load(Relaxed) == p.set_pacing {
                    self.pacing_us.store(p.prev_pacing, Relaxed);
                }
                st.nlp_guard.locked_until[NlpActionGuard::idx(p.kind)] = Some(now + ACTION_LOCKOUT);
                stats::NLP_REVERTS.fetch_add(1, Relaxed);
                st.nlp_advisor.drop_pending_feedback(); // a harmful action is never learned as success
                stats::log_nlp(&format!(
                    "[nlp] reverted {:?} change after {}s -> chunk={} pacing_us={} (locked {}s)",
                    p.kind, now.saturating_duration_since(p.at).as_secs(), p.prev_chunk, p.prev_pacing,
                    ACTION_LOCKOUT.as_secs()));
            }

            if nlp_mode == "active" && nlp_action != DiagnosticAction::KeepNormal {
                let knob = match nlp_action {
                    DiagnosticAction::ShrinkFrameSize { .. } | DiagnosticAction::ReduceChunkSize { .. } => Some(NlpKnob::Chunk),
                    DiagnosticAction::EnablePacingAndSplit => Some(NlpKnob::Pacing),
                    _ => None,
                };
                let prev_chunk = self.chunk_bytes.load(Relaxed);
                let prev_pacing = self.pacing_us.load(Relaxed);
                let allowed = knob.map_or(true, |k| st.nlp_guard.allow(k, now));
                if !allowed {
                    stats::NLP_RATE_LIMITED.fetch_add(1, Relaxed);
                } else {
                    let mut applied = false;
                    match nlp_action {
                        DiagnosticAction::ShrinkFrameSize { target_bytes } => {
                            if decision.action != RecoveryAction::RecommendSmallerFrame {
                                let target = (target_bytes as usize).clamp(CHUNK_SURVIVAL, CHUNK_NORMAL);
                                let next = if prev_chunk > CHUNK_DEGRADED { CHUNK_DEGRADED.max(target) } else { target };
                                if next < prev_chunk {
                                    self.chunk_bytes.store(next, Relaxed);
                                    stats::ADAPTIVE_CHUNK_BYTES.store(next, Relaxed);
                                    applied = true;
                                }
                            }
                        }
                        DiagnosticAction::ReduceChunkSize { target_bytes } => {
                            if decision.action != RecoveryAction::RecommendSmallerFrame {
                                // v0.15.1: one level per verdict (14K -> 4K -> 1200), never straight to survival.
                                let floor = (target_bytes as usize).clamp(CHUNK_SURVIVAL, CHUNK_DEGRADED);
                                let next = if prev_chunk > CHUNK_DEGRADED { CHUNK_DEGRADED } else { floor };
                                if next < prev_chunk {
                                    self.chunk_bytes.store(next, Relaxed);
                                    stats::ADAPTIVE_CHUNK_BYTES.store(next, Relaxed);
                                    applied = true;
                                }
                            }
                        }
                        DiagnosticAction::EnablePacingAndSplit => {
                            if prev_pacing < 2_500 {
                                self.pacing_us.store((prev_pacing + 500).min(2_500), Relaxed);
                                applied = true;
                            }
                            if decision.action != RecoveryAction::RecommendSmallerFrame && prev_chunk > CHUNK_DEGRADED {
                                self.chunk_bytes.store(CHUNK_DEGRADED, Relaxed);
                                stats::ADAPTIVE_CHUNK_BYTES.store(CHUNK_DEGRADED, Relaxed);
                                applied = true;
                            }
                        }
                        // Recommendations are counted separately and are not reported as executed actions.
                        DiagnosticAction::RecommendExitOrBridge
                        | DiagnosticAction::RecommendSurvivalFallback => {
                            stats::NLP_RECOMMENDATIONS.fetch_add(1, Relaxed);
                        }
                        DiagnosticAction::KeepNormal => {}
                    }
                    if applied {
                        self.recovery_actions.fetch_add(1, Relaxed);
                        stats::ADAPTIVE_ACTIONS.fetch_add(1, Relaxed);
                        stats::NLP_ACTIONS.fetch_add(1, Relaxed);
                        if let Some(kind) = knob {
                            st.nlp_guard.record(AppliedNlpAction {
                                kind, at: now, prev_chunk, prev_pacing,
                                set_chunk: self.chunk_bytes.load(Relaxed), set_pacing: self.pacing_us.load(Relaxed),
                                base_success: window_success, base_goodput_kbps: goodput_now,
                                ok_after: 0, bad_after: 0,
                            });
                        }
                    }
                    // v0.15.1 explanation log (rate-limited): why, what changed, which evidence.
                    if applied || knob.is_none() {
                        let evidence = match log { Some(t) if !t.trim().is_empty() => t.to_string(), _ => metrics.tokens().join(" ") };
                        let why = st.nlp_advisor.nlp().explain(&evidence, st.last_nlp_intent, 4);
                        stats::log_nlp(&format!(
                            "[nlp] {} intent={} conf={:.2} chunk {}->{} pacing_us {}->{} evidence=[{}] loss_pm={} rtt={}ms base={}ms resets={} stalls={} cfr={:.2}",
                            nlp_action.as_str(), st.last_nlp_intent.as_str(), st.last_nlp_conf,
                            prev_chunk, self.chunk_bytes.load(Relaxed), prev_pacing, self.pacing_us.load(Relaxed),
                            why, loss_pm, st.latest_rtt_ms, st.baseline_rtt_ms, resets, stalls, connect_fail_ratio));
                    }
                }
            }
            }
        }
        // v0.15.1: artifacts were serialized under the lock; write them after releasing it.
        let writes = st.nlp_advisor.take_pending_writes();
        drop(st);
        flush_pending_writes(writes);
        decision
    }

    pub fn snapshot(&self) -> AdaptiveSnapshot {
        let st = self.state.lock().unwrap();
        AdaptiveSnapshot {
            pattern: st.last_decision.pattern,
            action: st.last_decision.action,
            confidence: st.last_decision.confidence,
            chunk_bytes: self.current_chunk_size(),
            pacing_us: self.current_pacing_us(),
            concurrency_cap: self.current_concurrency_cap(),
            loss_per_mille: self.loss_per_mille.load(Relaxed) as u16,
            recovery_actions: self.recovery_actions.load(Relaxed),
            nlp_intent: st.last_nlp_intent,
            nlp_action: st.last_nlp_action,
            nlp_confidence: st.last_nlp_conf,
            nlp_abstained: st.last_nlp_abstained,
            nlp_online_updates: st.nlp_advisor.nlp().online_updates_total(),
            nlp_candidate_updates: st.nlp_advisor.candidate_online_updates_total(),
            intelligence_mode: st.last_intelligence.as_ref().map(|r| r.mode),
            predicted_severity: st.last_intelligence.as_ref().map(|r| r.prediction.severity_now).unwrap_or(0),
            projected_severity: st.last_intelligence.as_ref().map(|r| r.prediction.projected_severity).unwrap_or(0),
            degradation_likely: st.last_intelligence.as_ref().map(|r| r.prediction.degradation_likely).unwrap_or(false),
            intelligence_path_score: st.last_intelligence.as_ref().map(|r| r.path.score).unwrap_or(0.0),
            measured_goodput_kbps: st.ewma_goodput_kbps,
            measured_jitter_ms: st.ewma_jitter_ms,
            degradation_probability: st.last_intelligence.as_ref().and_then(|r| r.degradation_probability),
            calibration_samples: st.intelligence.calibration_samples(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs() -> PathObservation {
        PathObservation {
            connect_failures: 0, handshake_timeouts: 0, resets: 0, stalls: 0,
            loss_per_mille: 0, rtt_ms: 30, baseline_rtt_ms: 30,
            queue_depth: 0, mtu_probe_failed: false,
        }
    }

    #[test]
    fn requires_two_bad_observations_before_recovery() {
        let mut c = RecoveryController::default();
        let mut o = obs(); o.mtu_probe_failed = true;
        let t = Instant::now();
        assert_eq!(c.observe(o, t).action, RecoveryAction::Keep);
        assert_eq!(c.observe(o, t + Duration::from_secs(1)).action, RecoveryAction::RecommendSmallerFrame);
    }

    #[test]
    fn congestion_recommends_less_concurrency() {
        let mut c = RecoveryController::default();
        let mut o = obs(); o.queue_depth = 64;
        let t = Instant::now();
        c.observe(o, t);
        assert_eq!(c.observe(o, t + Duration::from_secs(1)).action, RecoveryAction::ReduceConcurrency);
    }

    #[test]
    fn healthy_path_clears_bad_streak() {
        let mut c = RecoveryController::default();
        let mut o = obs(); o.resets = 3;
        let t = Instant::now();
        c.observe(o, t);
        c.observe(o, t + Duration::from_secs(1));
        assert_eq!(c.observe(obs(), t + Duration::from_secs(2)).action, RecoveryAction::Keep);
    }

    #[test]
    fn adaptive_runtime_shrinks_chunk_on_pmtu_pattern() {
        let rt = AdaptiveRuntime::new(128);
        let t0 = Instant::now();
        assert_eq!(rt.current_chunk_size(), CHUNK_NORMAL);
        rt.record_at(TransportEvent::KeepaliveOk, 0, t0);
        rt.record_at(TransportEvent::MidStreamStall { bytes_transferred: 16384, frame_size: CHUNK_NORMAL }, 0, t0 + Duration::from_millis(100));
        rt.record_at(TransportEvent::MidStreamStall { bytes_transferred: 16384, frame_size: CHUNK_NORMAL }, 0, t0 + Duration::from_millis(200));
        rt.record_at(TransportEvent::MidStreamStall { bytes_transferred: 16384, frame_size: CHUNK_NORMAL }, 0, t0 + Duration::from_millis(300));
        assert!(rt.current_chunk_size() <= CHUNK_DEGRADED);
        let snap = rt.snapshot();
        assert_eq!(snap.pattern, PathPattern::PmtuOrLargeFrameLoss);
        assert!(snap.recovery_actions >= 1);
    }

    #[test]
    fn per_path_telemetry_keeps_path_measurements_isolated() {
        let now = Instant::now();
        let mut a = PathRuntimeTelemetry::default();
        let mut b = PathRuntimeTelemetry::default();
        let sa = a.observe(TransportEvent::ConnectOk { rtt_ms: 40 }, now, 0.0);
        let sb = b.observe(TransportEvent::ConnectOk { rtt_ms: 400 }, now, 0.0);
        assert_eq!(sa.rtt_ms, 40.0);
        assert_eq!(sb.rtt_ms, 400.0);
        assert_ne!(sa.baseline_rtt_ms, sb.baseline_rtt_ms);
    }


    #[test]
    fn windowed_goodput_and_jitter_feed_telemetry_cleanly() {
        let rt = AdaptiveRuntime::new(64);
        let t0 = Instant::now();
        rt.record_at_with_path_and_log(TransportEvent::ConnectOk { rtt_ms: 40 }, 0, t0, "10.0.0.1:4440", None);
        rt.record_at_with_path_and_log(TransportEvent::ConnectOk { rtt_ms: 140 }, 0, t0 + Duration::from_millis(200), "10.0.0.1:4440", None);
        rt.record_at_with_path_and_log(TransportEvent::StreamOk { bytes: 65_536 }, 0, t0 + Duration::from_millis(500), "10.0.0.1:4440", None);
        rt.record_at_with_path_and_log(TransportEvent::StreamOk { bytes: 65_536 }, 0, t0 + Duration::from_millis(1500), "10.0.0.1:4440", None);
        let snap = rt.snapshot();
        assert!(snap.measured_jitter_ms > 0.0);
        assert!(snap.measured_goodput_kbps > 0.0);
        assert!(rt.path_score("10.0.0.1:4440").is_some());
    }

    fn applied(kind: NlpKnob, at: Instant) -> AppliedNlpAction {
        AppliedNlpAction { kind, at, prev_chunk: CHUNK_NORMAL, prev_pacing: 0, set_chunk: CHUNK_DEGRADED,
            set_pacing: 500, base_success: 0.9, base_goodput_kbps: 1000.0, ok_after: 0, bad_after: 0 }
    }

    #[test]
    fn v0151_nlp_guard_caps_actions_per_minute() {
        let mut g = NlpActionGuard::default();
        let t0 = Instant::now();
        let mut granted = 0;
        for i in 0..20u64 {
            let t = t0 + Duration::from_secs(i);
            if g.allow(NlpKnob::Chunk, t) {
                granted += 1;
                g.record(applied(NlpKnob::Chunk, t));
                g.pending = None;
            }
        }
        assert_eq!(granted, MAX_NLP_ACTIONS_PER_MIN);
        assert!(g.allow(NlpKnob::Chunk, t0 + Duration::from_secs(61)));
    }

    #[test]
    fn v0151_nlp_guard_one_pending_and_lockout() {
        let mut g = NlpActionGuard::default();
        let t0 = Instant::now();
        assert!(g.allow(NlpKnob::Pacing, t0));
        g.record(applied(NlpKnob::Pacing, t0));
        assert!(!g.allow(NlpKnob::Chunk, t0 + Duration::from_secs(1)));
        g.pending = None;
        g.locked_until[NlpActionGuard::idx(NlpKnob::Pacing)] = Some(t0 + ACTION_LOCKOUT);
        assert!(!g.allow(NlpKnob::Pacing, t0 + Duration::from_secs(5)));
        assert!(g.allow(NlpKnob::Chunk, t0 + Duration::from_secs(5)));
    }

    #[test]
    fn v0151_active_mode_keeps_knobs_bounded_and_evaluates_changes() {
        TEST_FORCE_ACTIVE.store(true, Relaxed);
        let rt = AdaptiveRuntime::new(64);
        let mut t = Instant::now();
        let mut step = |ev: TransportEvent| { t += Duration::from_millis(30); rt.record_at(ev, 0, t); };
        for _ in 0..12 { step(TransportEvent::ConnectOk { rtt_ms: 40 }); step(TransportEvent::StreamOk { bytes: 65536 }); }
        for _ in 0..6 {
            step(TransportEvent::KeepaliveOk);
            step(TransportEvent::MidStreamStall { bytes_transferred: 16384, frame_size: CHUNK_NORMAL });
        }
        for _ in 0..20 { step(TransportEvent::ConnectFail); }
        TEST_FORCE_ACTIVE.store(false, Relaxed);
        let c = rt.current_chunk_size();
        assert!((CHUNK_SURVIVAL..=CHUNK_NORMAL).contains(&c));
        assert!(rt.state.lock().unwrap().nlp_guard.pending.is_none(), "no change left unevaluated");
    }

    #[test]
    fn v0151_record_releases_lock() {
        let rt = AdaptiveRuntime::new(64);
        for _ in 0..50 {
            rt.record(TransportEvent::EarlyReset { bytes_transferred: 0 }, 0);
            let _ = rt.snapshot();
        }
    }
}
