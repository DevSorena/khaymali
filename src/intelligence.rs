//! Lightweight adaptive network intelligence primitives (v0.15.0 unified).
//!
//! Strictly bounded and deterministic: predicts degradation (heuristic trend + optional
//! Platt-calibrated probability), ranks observed paths with evidence weighting, collects
//! horizon-labeled calibration datasets, simulates bounded packet/queue digital-twin scenarios,
//! explains decisions with numeric evidence, and enforces hard count + memory budgets.
//!
//! Never opens sockets, executes shell commands, or weakens authentication, camouflage, or SSRF.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub const MAX_HISTORY: usize = 64;
pub const MAX_PATHS: usize = 64;
pub const MAX_EXPERIMENTS: usize = 32;
pub const DEFAULT_COOLDOWN: Duration = Duration::from_secs(20);
pub const DEFAULT_CALIBRATION_HORIZON: Duration = Duration::from_secs(30);
const MAX_PENDING_CALIBRATION: usize = 1024;
const MAX_RESOLVED_CALIBRATION: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NetworkSample {
    pub rtt_ms: f64,
    pub baseline_rtt_ms: f64,
    pub jitter_ms: f64,
    pub loss_pct: f64,
    pub retransmit_pct: f64,
    pub goodput_kbps: f64,
    pub connect_success_pct: f64,
}

impl Default for NetworkSample {
    fn default() -> Self {
        Self {
            rtt_ms: 0.0,
            baseline_rtt_ms: 0.0,
            jitter_ms: 0.0,
            loss_pct: 0.0,
            retransmit_pct: 0.0,
            goodput_kbps: 0.0,
            connect_success_pct: 100.0,
        }
    }
}

impl NetworkSample {
    pub fn is_valid(&self) -> bool {
        [
            self.rtt_ms,
            self.baseline_rtt_ms,
            self.jitter_ms,
            self.loss_pct,
            self.retransmit_pct,
            self.goodput_kbps,
            self.connect_success_pct,
        ]
        .iter()
        .all(|v| v.is_finite() && *v >= 0.0)
            && self.loss_pct <= 100.0
            && self.retransmit_pct <= 100.0
            && self.connect_success_pct <= 100.0
    }

    /// Deterministic severity heuristic (0 = healthy, 100 = severe). Not a calibrated probability.
    pub fn severity(&self) -> u8 {
        if !self.is_valid() {
            return 100;
        }
        let rtt_ratio = if self.baseline_rtt_ms > 0.0 {
            (self.rtt_ms / self.baseline_rtt_ms).max(0.0)
        } else {
            1.0
        };
        let rtt_score = ((rtt_ratio - 1.0).max(0.0) * 18.0).min(35.0);
        let loss_score = (self.loss_pct * 4.0).min(40.0);
        let jitter_score = (self.jitter_ms / 4.0).min(15.0);
        let retransmit_score = (self.retransmit_pct * 2.0).min(20.0);
        let success_score = ((100.0 - self.connect_success_pct) * 0.35).min(35.0);
        (rtt_score + loss_score + jitter_score + retransmit_score + success_score)
            .round()
            .clamp(0.0, 100.0) as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkMode {
    Normal,
    Watch,
    Degraded,
    Critical,
}

impl NetworkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Watch => "watch",
            Self::Degraded => "degraded",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Prediction {
    pub severity_now: u8,
    pub projected_severity: u8,
    pub trend_per_sample: f64,
    pub degradation_likely: bool,
    pub samples_used: usize,
}

#[derive(Clone, Debug)]
pub struct PredictiveEngine {
    history: VecDeque<u8>,
    horizon_samples: usize,
}

impl PredictiveEngine {
    pub fn new(horizon_samples: usize) -> Self {
        Self {
            history: VecDeque::with_capacity(MAX_HISTORY),
            horizon_samples: horizon_samples.clamp(1, 16),
        }
    }

    pub fn observe(&mut self, sample: NetworkSample) -> Prediction {
        let severity = sample.severity();
        if self.history.len() == MAX_HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(severity);
        let trend = linear_slope(&self.history);
        let projected = (severity as f64 + trend.max(0.0) * self.horizon_samples as f64)
            .round()
            .clamp(0.0, 100.0) as u8;
        let enough = self.history.len() >= 4;
        Prediction {
            severity_now: severity,
            projected_severity: projected,
            trend_per_sample: trend,
            degradation_likely: enough && projected >= 55 && (trend >= 1.5 || severity >= 75),
            samples_used: self.history.len(),
        }
    }

    pub fn observe_calibrated(
        &mut self,
        sample: NetworkSample,
        calibrator: &RiskCalibrator,
    ) -> CalibratedPrediction {
        let prediction = self.observe(sample);
        let degradation_probability = calibrator.probability(prediction.projected_severity as f64);
        CalibratedPrediction {
            prediction,
            degradation_probability,
        }
    }

    pub fn clear(&mut self) {
        self.history.clear();
    }
}

fn linear_slope(values: &VecDeque<u8>) -> f64 {
    let n = values.len();
    if n < 2 {
        return 0.0;
    }
    let nf = n as f64;
    let mean_x = (nf - 1.0) / 2.0;
    let mean_y = values.iter().map(|v| *v as f64).sum::<f64>() / nf;
    let mut numerator = 0.0;
    let mut denominator = 0.0;
    for (i, value) in values.iter().enumerate() {
        let dx = i as f64 - mean_x;
        numerator += dx * (*value as f64 - mean_y);
        denominator += dx * dx;
    }
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

#[derive(Clone, Debug)]
pub struct AdaptiveController {
    mode: NetworkMode,
    candidate: NetworkMode,
    candidate_streak: u8,
    last_transition: Option<Instant>,
    cooldown: Duration,
}

impl AdaptiveController {
    pub fn new(cooldown: Duration) -> Self {
        Self {
            mode: NetworkMode::Normal,
            candidate: NetworkMode::Normal,
            candidate_streak: 0,
            last_transition: None,
            cooldown,
        }
    }

    pub fn mode(&self) -> NetworkMode {
        self.mode
    }

    pub fn observe(&mut self, severity: u8, now: Instant) -> NetworkMode {
        let desired = match self.mode {
            NetworkMode::Normal => {
                if severity >= 45 { NetworkMode::Degraded }
                else if severity >= 25 { NetworkMode::Watch }
                else { NetworkMode::Normal }
            }
            NetworkMode::Watch => {
                if severity >= 70 { NetworkMode::Critical }
                else if severity >= 50 { NetworkMode::Degraded }
                else if severity < 15 { NetworkMode::Normal }
                else { NetworkMode::Watch }
            }
            NetworkMode::Degraded => {
                if severity >= 78 { NetworkMode::Critical }
                else if severity < 30 { NetworkMode::Watch }
                else { NetworkMode::Degraded }
            }
            NetworkMode::Critical => {
                if severity < 55 { NetworkMode::Degraded } else { NetworkMode::Critical }
            }
        };
        if desired == self.mode {
            self.candidate = desired;
            self.candidate_streak = 0;
            return self.mode;
        }
        if desired == self.candidate {
            self.candidate_streak = self.candidate_streak.saturating_add(1);
        } else {
            self.candidate = desired;
            self.candidate_streak = 1;
        }
        let required = if desired == NetworkMode::Critical { 3 } else { 2 };
        let cooldown_ok = self
            .last_transition
            .map(|t| now.saturating_duration_since(t) >= self.cooldown)
            .unwrap_or(true);
        if self.candidate_streak >= required && cooldown_ok {
            self.mode = desired;
            self.last_transition = Some(now);
            self.candidate_streak = 0;
        }
        self.mode
    }
}

#[derive(Clone, Debug, Default)]
pub struct PathProfile {
    pub observations: u64,
    pub ewma_severity: f64,
    pub ewma_rtt_ms: f64,
    pub ewma_goodput_kbps: f64,
    pub ewma_loss_pct: f64,
    pub ewma_jitter_ms: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PathRanking {
    pub path_id: String,
    pub score: f64,
    pub observations: u64,
}

fn path_quality_score(p: &PathProfile) -> f64 {
    let throughput = if p.ewma_goodput_kbps <= 0.0 {
        0.0
    } else {
        (p.ewma_goodput_kbps / (p.ewma_goodput_kbps + 2_000.0)) * 12.0
    };
    let evidence = (p.observations as f64 / 5.0).min(1.0);
    let raw = (100.0 - p.ewma_severity + throughput).clamp(0.0, 100.0);
    (raw * (0.70 + 0.30 * evidence)).clamp(0.0, 100.0)
}

#[derive(Clone, Debug, Default)]
pub struct PathIntelligence {
    paths: HashMap<String, PathProfile>,
}

impl PathIntelligence {
    pub fn observe(&mut self, path_id: &str, sample: NetworkSample) -> Option<PathRanking> {
        if !sample.is_valid() || path_id.is_empty() || path_id.len() > 96 {
            return None;
        }
        if !self.paths.contains_key(path_id) && self.paths.len() >= MAX_PATHS {
            return None;
        }
        let p = self.paths.entry(path_id.to_string()).or_default();
        let alpha = if p.observations == 0 { 1.0 } else { 0.2 };
        let sev = sample.severity() as f64;
        p.ewma_severity += alpha * (sev - p.ewma_severity);
        p.ewma_rtt_ms += alpha * (sample.rtt_ms - p.ewma_rtt_ms);
        p.ewma_goodput_kbps += alpha * (sample.goodput_kbps - p.ewma_goodput_kbps);
        p.ewma_loss_pct += alpha * (sample.loss_pct - p.ewma_loss_pct);
        p.ewma_jitter_ms += alpha * (sample.jitter_ms - p.ewma_jitter_ms);
        p.observations = p.observations.saturating_add(1);
        Some(PathRanking {
            path_id: path_id.to_string(),
            score: path_quality_score(p),
            observations: p.observations,
        })
    }

    pub fn score_for(&self, path_id: &str) -> Option<(f64, u64)> {
        self.paths.get(path_id).map(|p| (path_quality_score(p), p.observations))
    }

    pub fn rank(&self) -> Vec<PathRanking> {
        let mut out: Vec<_> = self
            .paths
            .iter()
            .map(|(id, p)| PathRanking {
                path_id: id.clone(),
                score: path_quality_score(p),
                observations: p.observations,
            })
            .collect();
        // v0.15.1: NaN-safe total order with deterministic tie-breaks.
        out.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| b.observations.cmp(&a.observations)).then_with(|| a.path_id.cmp(&b.path_id)));
        out
    }

    pub fn remove_path(&mut self, path_id: &str) -> bool { self.paths.remove(path_id).is_some() }
    pub fn len(&self) -> usize { self.paths.len() }
    pub fn is_empty(&self) -> bool { self.paths.is_empty() }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceValue {
    pub metric: &'static str,
    pub observed: f64,
    pub threshold: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecisionExplanation {
    pub mode: NetworkMode,
    pub severity: u8,
    pub reasons: Vec<&'static str>,
    pub evidence: Vec<EvidenceValue>,
    pub alternatives: Vec<&'static str>,
    pub action_advice: &'static str,
    pub executed: bool,
}

pub fn explain(sample: NetworkSample, mode: NetworkMode) -> DecisionExplanation {
    let mut reasons = Vec::new();
    let mut evidence = Vec::new();
    if sample.baseline_rtt_ms > 0.0 {
        let ratio = sample.rtt_ms / sample.baseline_rtt_ms;
        evidence.push(EvidenceValue { metric: "rtt_baseline_ratio", observed: ratio, threshold: 2.0 });
        if ratio > 2.0 { reasons.push("rtt_above_2x_baseline"); }
    }
    evidence.push(EvidenceValue { metric: "packet_loss_pct", observed: sample.loss_pct, threshold: 3.0 });
    if sample.loss_pct >= 3.0 { reasons.push("packet_loss_elevated"); }
    evidence.push(EvidenceValue { metric: "jitter_ms", observed: sample.jitter_ms, threshold: 50.0 });
    if sample.jitter_ms >= 50.0 { reasons.push("jitter_elevated"); }
    evidence.push(EvidenceValue { metric: "retransmit_pct", observed: sample.retransmit_pct, threshold: 3.0 });
    if sample.retransmit_pct >= 3.0 { reasons.push("retransmissions_elevated"); }
    evidence.push(EvidenceValue { metric: "connect_success_pct", observed: sample.connect_success_pct, threshold: 95.0 });
    if sample.connect_success_pct < 95.0 { reasons.push("connection_success_below_95pct"); }
    if reasons.is_empty() { reasons.push("no_strong_fault_evidence"); }
    let (action_advice, alternatives) = match mode {
        NetworkMode::Normal => ("observe_only", vec!["keep_current_settings", "continue_measurement"]),
        NetworkMode::Watch => ("collect_more_samples", vec!["wait_for_confirmation", "avoid_disruptive_changes"]),
        NetworkMode::Degraded => ("consider_low_risk_reversible_tuning", vec!["bounded_frame_adjustment", "bounded_pacing"]),
        NetworkMode::Critical => ("request_operator_review_and_recovery_plan", vec!["operator_review", "verify_alternate_path_before_use"]),
    };
    DecisionExplanation { mode, severity: sample.severity(), reasons, evidence, alternatives, action_advice, executed: false }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResourceSnapshot {
    pub observations_used: usize,
    pub experiments_used: usize,
    pub estimated_bytes_used: usize,
}

#[derive(Clone, Debug)]
pub struct HardResourceBudget {
    max_observations: usize,
    max_experiments: usize,
    max_estimated_bytes: usize,
    snapshot: ResourceSnapshot,
}

impl HardResourceBudget {
    pub fn new(max_observations: usize, max_experiments: usize, max_estimated_bytes: usize) -> Self {
        Self {
            max_observations: max_observations.max(1),
            max_experiments: max_experiments.max(1),
            max_estimated_bytes: max_estimated_bytes.max(1024),
            snapshot: ResourceSnapshot { observations_used: 0, experiments_used: 0, estimated_bytes_used: 0 },
        }
    }
    pub fn reserve_observation(&mut self, estimated_bytes: usize) -> bool {
        if self.snapshot.observations_used >= self.max_observations
            || estimated_bytes > self.max_estimated_bytes.saturating_sub(self.snapshot.estimated_bytes_used)
        {
            return false;
        }
        self.snapshot.observations_used += 1;
        self.snapshot.estimated_bytes_used += estimated_bytes;
        true
    }
    pub fn reserve_experiment(&mut self) -> bool {
        if self.snapshot.experiments_used >= self.max_experiments { return false; }
        self.snapshot.experiments_used += 1;
        true
    }
    pub fn reserve_experiments(&mut self, count: usize) -> bool {
        if count == 0 || count > self.max_experiments.saturating_sub(self.snapshot.experiments_used) { return false; }
        self.snapshot.experiments_used += count;
        true
    }
    pub fn snapshot(&self) -> &ResourceSnapshot { &self.snapshot }
    pub fn reset_window(&mut self) {
        self.snapshot = ResourceSnapshot { observations_used: 0, experiments_used: 0, estimated_bytes_used: 0 };
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CalibrationExample {
    pub score: f64,
    pub degraded_within_horizon: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CalibrationMetrics {
    pub samples: usize,
    pub brier_score: f64,
    pub log_loss: f64,
    pub expected_calibration_error: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RiskCalibrator {
    a: f64,
    b: f64,
    fitted: bool,
    samples: usize,
}

impl Default for RiskCalibrator {
    fn default() -> Self { Self { a: 0.0, b: 0.0, fitted: false, samples: 0 } }
}

impl RiskCalibrator {
    pub fn fit(&mut self, examples: &[CalibrationExample]) -> bool {
        let positives = examples.iter().filter(|e| e.degraded_within_horizon).count();
        let negatives = examples.len().saturating_sub(positives);
        if examples.len() < 30
            || positives < 5
            || negatives < 5
            || examples.iter().any(|e| !e.score.is_finite() || !(0.0..=100.0).contains(&e.score))
        {
            self.fitted = false;
            self.samples = examples.len();
            return false;
        }
        let xs: Vec<f64> = examples.iter().map(|e| (e.score - 50.0) / 20.0).collect();
        let ys: Vec<f64> = examples.iter().map(|e| if e.degraded_within_horizon { 1.0 } else { 0.0 }).collect();
        let mut a = 0.0;
        let mut b = ((positives as f64 / negatives as f64).ln()).clamp(-4.0, 4.0);
        let lr = 0.03;
        for _ in 0..1200 {
            let mut ga = 0.0;
            let mut gb = 0.0;
            for (&x, &y) in xs.iter().zip(ys.iter()) {
                let z = (a * x + b).clamp(-20.0, 20.0);
                let p = 1.0 / (1.0 + (-z).exp());
                ga += (p - y) * x;
                gb += p - y;
            }
            let n = examples.len() as f64;
            a = (a - lr * (ga / n + 0.001 * a)).clamp(-12.0, 12.0);
            b = (b - lr * gb / n).clamp(-12.0, 12.0);
        }
        if !a.is_finite() || !b.is_finite() { self.fitted = false; return false; }
        self.a = a;
        self.b = b;
        self.samples = examples.len();
        self.fitted = true;
        true
    }

    pub fn probability(&self, score: f64) -> Option<f64> {
        if !self.fitted || !score.is_finite() || !(0.0..=100.0).contains(&score) { return None; }
        let x = (score - 50.0) / 20.0;
        let z = (self.a * x + self.b).clamp(-20.0, 20.0);
        Some((1.0 / (1.0 + (-z).exp())).clamp(0.001, 0.999))
    }

    pub fn evaluate(&self, holdout: &[CalibrationExample]) -> Option<CalibrationMetrics> {
        if !self.fitted || holdout.is_empty()
            || holdout.iter().any(|e| !e.score.is_finite() || !(0.0..=100.0).contains(&e.score))
        {
            return None;
        }
        let mut brier = 0.0;
        let mut log_loss = 0.0;
        let mut bins = [(0.0f64, 0.0f64, 0usize); 10];
        for e in holdout {
            let p = self.probability(e.score)?;
            let y = if e.degraded_within_horizon { 1.0 } else { 0.0 };
            brier += (p - y) * (p - y);
            log_loss -= y * p.ln() + (1.0 - y) * (1.0 - p).ln();
            let idx = ((p * 10.0).floor() as usize).min(9);
            bins[idx].0 += p;
            bins[idx].1 += y;
            bins[idx].2 += 1;
        }
        let n = holdout.len() as f64;
        let ece = bins.iter().filter(|b| b.2 > 0)
            .map(|b| (b.2 as f64 / n) * ((b.0 / b.2 as f64) - (b.1 / b.2 as f64)).abs()).sum();
        Some(CalibrationMetrics { samples: holdout.len(), brier_score: brier / n, log_loss: log_loss / n, expected_calibration_error: ece })
    }

    pub fn to_artifact_bytes(&self) -> Result<Vec<u8>, String> {
        if !self.fitted || !self.a.is_finite() || !self.b.is_finite() || self.samples < 30 {
            return Err("calibrator is not fitted".into());
        }
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(b"KTRISK01");
        out.extend_from_slice(&self.a.to_bits().to_be_bytes());
        out.extend_from_slice(&self.b.to_bits().to_be_bytes());
        out.extend_from_slice(&(self.samples as u64).to_be_bytes());
        Ok(out)
    }

    pub fn from_artifact_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() != 32 || &data[..8] != b"KTRISK01" {
            return Err("invalid risk calibrator artifact".into());
        }
        let a = f64::from_bits(u64::from_be_bytes(data[8..16].try_into().unwrap()));
        let b = f64::from_bits(u64::from_be_bytes(data[16..24].try_into().unwrap()));
        let samples = u64::from_be_bytes(data[24..32].try_into().unwrap());
        if !a.is_finite() || !b.is_finite() || a.abs() > 12.0 || b.abs() > 12.0
            || samples < 30 || samples > usize::MAX as u64
        {
            return Err("risk calibrator artifact outside safety limits".into());
        }
        Ok(Self { a, b, fitted: true, samples: samples as usize })
    }

    pub fn save_artifact_atomic(&self, path: &std::path::Path) -> Result<(), String> {
        let bytes = self.to_artifact_bytes()?;
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let tmp = path.with_extension(format!("risk-calibrator-{}-{stamp}.tmp", std::process::id()));
        let res = (|| -> Result<(), String> {
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)
                    .map_err(|e| format!("create calibrator temp: {e}"))?;
                f.write_all(&bytes).map_err(|e| format!("write calibrator: {e}"))?;
                f.sync_all().map_err(|e| format!("sync calibrator: {e}"))?;
            }
            #[cfg(not(unix))]
            std::fs::write(&tmp, &bytes).map_err(|e| format!("write calibrator: {e}"))?;
            std::fs::rename(&tmp, path).map_err(|e| format!("replace calibrator: {e}"))?;
            #[cfg(unix)]
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                if let Ok(dir) = std::fs::File::open(parent) { let _ = dir.sync_all(); }
            }
            Ok(())
        })();
        if res.is_err() { let _ = std::fs::remove_file(&tmp); }
        res
    }

    pub fn load_artifact(path: &std::path::Path) -> Result<Self, String> {
        let meta = std::fs::metadata(path).map_err(|e| format!("stat calibrator: {e}"))?;
        if meta.len() != 32 { return Err("risk calibrator artifact must be exactly 32 bytes".into()); }
        let data = std::fs::read(path).map_err(|e| format!("read calibrator: {e}"))?;
        Self::from_artifact_bytes(&data)
    }

    pub fn is_fitted(&self) -> bool { self.fitted }
    pub fn samples(&self) -> usize { self.samples }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CalibratedPrediction {
    pub prediction: Prediction,
    pub degradation_probability: Option<f64>,
}

/// Bounded collector automatically producing horizon-labeled `score\t0|1` rows from live telemetry.
#[derive(Clone, Debug)]
pub struct CalibrationCollector {
    horizon: Duration,
    sample_interval: Duration,
    last_recorded: Option<Instant>,
    pending: VecDeque<(Instant, f64, bool)>,
    resolved: VecDeque<CalibrationExample>,
}

impl CalibrationCollector {
    pub fn new(horizon: Duration, sample_interval: Duration) -> Self {
        Self {
            horizon: horizon.max(Duration::from_secs(1)),
            sample_interval,
            last_recorded: None,
            pending: VecDeque::with_capacity(64),
            resolved: VecDeque::with_capacity(128),
        }
    }

    pub fn observe(&mut self, projected_severity: f64, degraded_now: bool, now: Instant) {
        if !projected_severity.is_finite() || !(0.0..=100.0).contains(&projected_severity) { return; }
        if degraded_now {
            for entry in &mut self.pending {
                if now.saturating_duration_since(entry.0) <= self.horizon { entry.2 = true; }
            }
        }
        while let Some(&(ts, score, hit)) = self.pending.front() {
            if now.saturating_duration_since(ts) >= self.horizon {
                self.pending.pop_front();
                if self.resolved.len() >= MAX_RESOLVED_CALIBRATION { self.resolved.pop_front(); }
                self.resolved.push_back(CalibrationExample { score, degraded_within_horizon: hit });
            } else { break; }
        }
        let due = self.last_recorded.map(|t| now.saturating_duration_since(t) >= self.sample_interval).unwrap_or(true);
        if due {
            if self.pending.len() >= MAX_PENDING_CALIBRATION { self.pending.pop_front(); }
            self.pending.push_back((now, projected_severity, false));
            self.last_recorded = Some(now);
        }
    }

    pub fn resolved_len(&self) -> usize { self.resolved.len() }
    pub fn pending_len(&self) -> usize { self.pending.len() }
    pub fn resolved(&self) -> &VecDeque<CalibrationExample> { &self.resolved }

    pub fn export_tsv(&self) -> String {
        let mut out = String::with_capacity(self.resolved.len() * 10);
        for ex in &self.resolved {
            out.push_str(&format!("{:.1}\t{}\n", ex.score, if ex.degraded_within_horizon { 1 } else { 0 }));
        }
        out
    }
}

impl Default for CalibrationCollector {
    fn default() -> Self { Self::new(DEFAULT_CALIBRATION_HORIZON, Duration::from_secs(5)) }
}

#[derive(Clone, Debug, PartialEq)]
pub struct IntelligenceReport {
    pub prediction: Prediction,
    pub degradation_probability: Option<f64>,
    pub mode: NetworkMode,
    pub path: PathRanking,
    pub explanation: DecisionExplanation,
}

#[derive(Clone, Debug)]
pub struct NetworkIntelligence {
    predictors: HashMap<String, PredictiveEngine>,
    controllers: HashMap<String, AdaptiveController>,
    paths: PathIntelligence,
    budget: HardResourceBudget,
    calibrator: RiskCalibrator,
    collector: CalibrationCollector,
}

impl NetworkIntelligence {
    pub fn new() -> Self {
        let calibrator = match std::env::var_os("KHAYMALI_RISK_CALIBRATOR_PATH").map(std::path::PathBuf::from) {
            Some(path) => match RiskCalibrator::load_artifact(&path) {
                Ok(c) => c,
                Err(err) => { eprintln!("[intelligence] risk calibrator load failed; probabilities disabled: {err}"); RiskCalibrator::default() }
            },
            None => RiskCalibrator::default(),
        };
        Self {
            predictors: HashMap::new(),
            controllers: HashMap::new(),
            paths: PathIntelligence::default(),
            budget: HardResourceBudget::new(100_000, 256, 8 * 1024 * 1024),
            calibrator,
            collector: CalibrationCollector::default(),
        }
    }

    pub fn observe(&mut self, path_id: &str, sample: NetworkSample, now: Instant) -> Option<IntelligenceReport> {
        if !sample.is_valid() || path_id.is_empty() || path_id.len() > 96 { return None; }
        let est_bytes = std::mem::size_of::<NetworkSample>();
        if !self.budget.reserve_observation(est_bytes) {
            self.budget.reset_window();
            if !self.budget.reserve_observation(est_bytes) { return None; }
        }
        if !self.predictors.contains_key(path_id) && self.predictors.len() >= MAX_PATHS { return None; }
        if !self.controllers.contains_key(path_id) && self.controllers.len() >= MAX_PATHS { return None; }
        let calibrator = self.calibrator;
        let calibrated = self.predictors.entry(path_id.to_string()).or_insert_with(|| PredictiveEngine::new(4))
            .observe_calibrated(sample, &calibrator);
        let prediction = calibrated.prediction;
        let degradation_probability = calibrated.degradation_probability;
        let mode = self.controllers.entry(path_id.to_string()).or_insert_with(|| AdaptiveController::new(DEFAULT_COOLDOWN))
            .observe(prediction.projected_severity.max(prediction.severity_now), now);
        let path = self.paths.observe(path_id, sample)?;
        let explanation = explain(sample, mode);
        let degraded_now = matches!(mode, NetworkMode::Degraded | NetworkMode::Critical) || prediction.severity_now >= 65;
        self.collector.observe(prediction.projected_severity as f64, degraded_now, now);
        Some(IntelligenceReport { prediction, degradation_probability, mode, path, explanation })
    }

    pub fn fit_calibrator(&mut self, examples: &[CalibrationExample]) -> bool {
        let previous = self.calibrator;
        if !self.calibrator.fit(examples) { return false; }
        if let Some(path) = std::env::var_os("KHAYMALI_RISK_CALIBRATOR_PATH").map(std::path::PathBuf::from) {
            if self.calibrator.save_artifact_atomic(&path).is_err() { self.calibrator = previous; return false; }
        }
        true
    }

    pub fn reload_calibrator(&mut self) -> bool {
        let Some(path) = std::env::var_os("KHAYMALI_RISK_CALIBRATOR_PATH").map(std::path::PathBuf::from) else { return false; };
        let Ok(calibrator) = RiskCalibrator::load_artifact(&path) else { return false; };
        self.calibrator = calibrator;
        true
    }

    pub fn score_for_path(&self, path_id: &str) -> Option<(f64, u64)> { self.paths.score_for(path_id) }
    pub fn rank_paths(&self) -> Vec<PathRanking> { self.paths.rank() }
    pub fn calibration_samples(&self) -> usize { self.collector.resolved_len() }
    pub fn export_calibration_tsv(&self) -> String { self.collector.export_tsv() }
    pub fn remove_path(&mut self, path_id: &str) -> bool {
        let a = self.predictors.remove(path_id).is_some();
        let b = self.controllers.remove(path_id).is_some();
        let c = self.paths.remove_path(path_id);
        a || b || c
    }
    pub fn path_count(&self) -> usize { self.paths.len() }
    pub fn reset_budget_window(&mut self) { self.budget.reset_window(); }
}

impl Default for NetworkIntelligence { fn default() -> Self { Self::new() } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwinScenario { Clean, AddedLatency, RandomLoss, Jitter, Throttle, IntermittentOutage }

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DigitalTwinConfig {
    pub packet_size_bytes: usize,
    pub link_capacity_kbps: f64,
    pub offered_load_kbps: f64,
    pub queue_capacity_packets: usize,
    pub base_latency_ms: f64,
    pub random_seed: u64,
    pub outage_period_steps: usize,
    pub outage_length_steps: usize,
}

impl Default for DigitalTwinConfig {
    fn default() -> Self {
        Self {
            packet_size_bytes: 1200,
            link_capacity_kbps: 10_000.0,
            offered_load_kbps: 2_000.0,
            queue_capacity_packets: 64,
            base_latency_ms: 40.0,
            random_seed: 0x4b48_594d_414c_49,
            outage_period_steps: 40,
            outage_length_steps: 4,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DigitalTwinReport {
    pub scenario: TwinScenario,
    pub steps: usize,
    pub packets_generated: u64,
    pub packets_delivered: u64,
    pub packets_dropped: u64,
    pub mean_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub peak_queue_packets: usize,
    pub goodput_kbps: f64,
    pub mean_severity: f64,
}

fn next_rng(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *state
}

/// v0.15.1: seed-derived outage schedule (phase rng, period, length, first start step).
fn outage_schedule_start(cfg: &DigitalTwinConfig) -> (u64, usize, usize, usize) {
    let mut phase_rng = cfg.random_seed ^ 0x9e37_79b9_7f4a_7c15;
    let period = cfg.outage_period_steps.max(1);
    let outage_len = cfg.outage_length_steps.min(period);
    let start = (next_rng(&mut phase_rng) as usize) % period;
    (phase_rng, period, outage_len, start)
}

pub fn simulate_packet_twin(
    base: NetworkSample,
    scenario: TwinScenario,
    steps: usize,
    cfg: DigitalTwinConfig,
) -> Option<DigitalTwinReport> {
    if !base.is_valid() || cfg.packet_size_bytes == 0 || !cfg.link_capacity_kbps.is_finite()
        || cfg.link_capacity_kbps <= 0.0 || !cfg.offered_load_kbps.is_finite()
        || cfg.offered_load_kbps <= 0.0 || !cfg.base_latency_ms.is_finite()
        || cfg.base_latency_ms < 0.0 || cfg.queue_capacity_packets == 0
    {
        return None;
    }
    let steps = steps.clamp(1, 100_000);
    let packet_bits = cfg.packet_size_bytes as f64 * 8.0;
    let arrivals_per_step = (cfg.offered_load_kbps * 1000.0 / packet_bits / 10.0).max(0.01);
    let service_per_step = (cfg.link_capacity_kbps * 1000.0 / packet_bits / 10.0).max(0.01);

    let mut queue = 0.0f64;
    let mut arrival_credit = 0.0f64;
    let mut service_credit = 0.0f64;
    let mut rng = cfg.random_seed;
    let mut generated = 0u64;
    let mut delivered = 0u64;
    let mut dropped = 0u64;
    let mut peak_queue = 0usize;
    let mut latencies = Vec::with_capacity(steps);
    let mut severity_sum = 0.0;

    // v0.15.1: outage windows start at a seed-derived phase and each period is shifted by a seeded
    // jitter (<= 1/4 period), so strategies cannot overfit a fixed time grid. Deterministic per
    // seed; a separate generator keeps the packet loss/jitter sequence unchanged.
    let (mut phase_rng, period, outage_len, mut outage_start) = outage_schedule_start(&cfg);

    for i in 0..steps {
        if cfg.outage_period_steps > 0 && i >= outage_start + period {
            outage_start += period + (next_rng(&mut phase_rng) as usize) % (period / 4 + 1);
        }
        let outage = scenario == TwinScenario::IntermittentOutage && cfg.outage_period_steps > 0
            && i >= outage_start && i < outage_start + outage_len;
        let mut loss_pct = base.loss_pct;
        let mut capacity_scale = 1.0;
        let mut latency_add = 0.0;
        match scenario {
            TwinScenario::Clean => {}
            TwinScenario::AddedLatency => latency_add = 150.0,
            TwinScenario::RandomLoss => loss_pct = (loss_pct + if next_rng(&mut rng) % 100 < 8 { 8.0 } else { 1.0 }).min(100.0),
            TwinScenario::Jitter => latency_add = (next_rng(&mut rng) % 100) as f64,
            TwinScenario::Throttle => capacity_scale = 0.25,
            TwinScenario::IntermittentOutage => {}
        }

        arrival_credit += arrivals_per_step;
        let new_pkts = arrival_credit.floor() as u64;
        arrival_credit -= new_pkts as f64;
        generated += new_pkts;

        let mut step_dropped = 0u64;
        for _ in 0..new_pkts {
            if outage || (next_rng(&mut rng) % 10_000) < (loss_pct * 100.0) as u64 {
                dropped += 1;
                step_dropped += 1;
            } else if queue + 1.0 <= cfg.queue_capacity_packets as f64 {
                queue += 1.0;
            } else {
                dropped += 1;
                step_dropped += 1;
            }
        }
        peak_queue = peak_queue.max(queue.ceil() as usize);

        let effective_service = if outage { 0.0 } else { service_per_step * capacity_scale };
        service_credit = (service_credit + effective_service).min(effective_service);
        let served = service_credit.floor().min(queue).max(0.0);
        service_credit -= served;
        queue = (queue - served).max(0.0);
        delivered += served as u64;

        let eff_cap_kbps = (cfg.link_capacity_kbps * capacity_scale).max(1.0);
        let queue_delay = queue * packet_bits / (eff_cap_kbps * 1000.0) * 1000.0;
        let latency = cfg.base_latency_ms + latency_add + queue_delay;
        latencies.push(latency);

        let mut sample = base;
        sample.rtt_ms = latency;
        sample.loss_pct = if new_pkts > 0 { (step_dropped as f64 * 100.0 / new_pkts as f64).max(loss_pct) } else { loss_pct };
        if scenario == TwinScenario::Throttle { sample.goodput_kbps = sample.goodput_kbps.min(eff_cap_kbps); }
        if scenario == TwinScenario::Jitter { sample.jitter_ms += latency_add; }
        if outage { sample.connect_success_pct = 0.0; }
        severity_sum += sample.severity() as f64;
    }

    latencies.sort_by(|a, b| a.total_cmp(b));
    let mean_latency = latencies.iter().sum::<f64>() / latencies.len().max(1) as f64;
    let p95_idx = ((latencies.len() as f64 * 0.95).ceil() as usize).saturating_sub(1).min(latencies.len().saturating_sub(1));
    let elapsed_secs = steps as f64 / 10.0;
    let goodput_kbps = delivered as f64 * packet_bits / elapsed_secs.max(0.1) / 1000.0;
    Some(DigitalTwinReport {
        scenario, steps, packets_generated: generated, packets_delivered: delivered,
        packets_dropped: dropped, mean_latency_ms: mean_latency, p95_latency_ms: latencies[p95_idx],
        peak_queue_packets: peak_queue, goodput_kbps, mean_severity: severity_sum / steps as f64,
    })
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ExperimentObservation {
    pub scenario: TwinScenario,
    pub baseline_severity: f64,
    pub candidate_severity: f64,
    pub samples: usize,
}

#[derive(Clone, Debug)]
pub struct AdaptiveExperimentManager {
    observations: Vec<ExperimentObservation>,
    max_records: usize,
}

impl Default for AdaptiveExperimentManager {
    fn default() -> Self { Self { observations: Vec::with_capacity(MAX_EXPERIMENTS), max_records: MAX_EXPERIMENTS } }
}

impl AdaptiveExperimentManager {
    pub fn record(&mut self, observation: ExperimentObservation) -> bool {
        if observation.samples == 0 || !observation.baseline_severity.is_finite()
            || !observation.candidate_severity.is_finite() { return false; }
        if self.observations.len() == self.max_records { self.observations.remove(0); }
        self.observations.push(observation);
        true
    }

    pub fn next_scenario(&self) -> TwinScenario {
        let all = [TwinScenario::Clean, TwinScenario::AddedLatency, TwinScenario::RandomLoss,
            TwinScenario::Jitter, TwinScenario::Throttle, TwinScenario::IntermittentOutage];
        let mut best = all[0];
        let mut best_score = f64::NEG_INFINITY;
        let total = self.observations.len().max(1) as f64;
        for scenario in all {
            let rows: Vec<_> = self.observations.iter().filter(|o| o.scenario == scenario).collect();
            let score = if rows.is_empty() { 1_000.0 } else {
                let mean_gain = rows.iter().map(|o| o.baseline_severity - o.candidate_severity).sum::<f64>() / rows.len() as f64;
                mean_gain + (2.0 * total.ln() / rows.len() as f64).sqrt()
            };
            if score > best_score { best_score = score; best = scenario; }
        }
        best
    }

    pub fn run_next_scenario(&mut self, base: NetworkSample, steps: usize, cfg: DigitalTwinConfig, budget: &mut HardResourceBudget) -> Option<DigitalTwinReport> {
        if !budget.reserve_experiments(1) || !budget.reserve_observation(std::mem::size_of::<ExperimentObservation>()) { return None; }
        let scenario = self.next_scenario();
        let report = simulate_packet_twin(base, scenario, steps, cfg)?;
        let _ = self.record(ExperimentObservation { scenario, baseline_severity: base.severity() as f64, candidate_severity: report.mean_severity, samples: report.steps });
        Some(report)
    }

    pub fn compare_configs(&mut self, base: NetworkSample, scenario: TwinScenario, steps: usize, baseline_cfg: DigitalTwinConfig, candidate_cfg: DigitalTwinConfig, budget: &mut HardResourceBudget) -> Option<(DigitalTwinReport, DigitalTwinReport)> {
        if !budget.reserve_experiments(2) || !budget.reserve_observation(std::mem::size_of::<ExperimentObservation>()) { return None; }
        let candidate_cfg = DigitalTwinConfig { random_seed: baseline_cfg.random_seed, ..candidate_cfg };
        let baseline = simulate_packet_twin(base, scenario, steps, baseline_cfg)?;
        let candidate = simulate_packet_twin(base, scenario, steps, candidate_cfg)?;
        let _ = self.record(ExperimentObservation { scenario, baseline_severity: baseline.mean_severity, candidate_severity: candidate.mean_severity, samples: steps.max(1) });
        Some((baseline, candidate))
    }

    pub fn observations(&self) -> &[ExperimentObservation] { &self.observations }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> NetworkSample {
        NetworkSample { rtt_ms: 40.0, baseline_rtt_ms: 40.0, jitter_ms: 4.0, loss_pct: 0.0, retransmit_pct: 0.0, goodput_kbps: 5000.0, connect_success_pct: 100.0 }
    }

    #[test]
    fn predictor_and_controller_behave_with_hysteresis() {
        let mut p = PredictiveEngine::new(4);
        for loss in [0.0, 2.0, 5.0, 10.0] { let mut s = healthy(); s.loss_pct = loss; let _ = p.observe(s); }
        let mut s = healthy(); s.loss_pct = 15.0;
        let result = p.observe(s);
        assert!(result.trend_per_sample > 0.0 && result.projected_severity >= result.severity_now);

        let mut c = AdaptiveController::new(Duration::from_secs(1));
        let now = Instant::now();
        assert_eq!(c.observe(90, now), NetworkMode::Normal);
        assert_eq!(c.observe(90, now + Duration::from_secs(2)), NetworkMode::Degraded);
        assert_eq!(c.observe(90, now + Duration::from_secs(4)), NetworkMode::Degraded);
        assert_eq!(c.observe(90, now + Duration::from_secs(6)), NetworkMode::Degraded);
        assert_eq!(c.observe(90, now + Duration::from_secs(8)), NetworkMode::Critical);
    }

    #[test]
    fn path_registry_is_bounded_and_ranks_healthier_path_first() {
        let mut p = PathIntelligence::default();
        let mut bad = healthy(); bad.loss_pct = 15.0;
        p.observe("bad", bad).unwrap(); p.observe("good", healthy()).unwrap();
        assert_eq!(p.rank()[0].path_id, "good");
        for i in 0..MAX_PATHS { let _ = p.observe(&format!("p{i}"), healthy()); }
        assert!(p.len() <= MAX_PATHS);
    }

    #[test]
    fn v0151_outage_phase_depends_on_seed_but_is_deterministic() {
        let mk = |seed| DigitalTwinConfig { random_seed: seed, outage_period_steps: 40, outage_length_steps: 6, ..Default::default() };
        let a1 = simulate_packet_twin(healthy(), TwinScenario::IntermittentOutage, 400, mk(1)).unwrap();
        let a2 = simulate_packet_twin(healthy(), TwinScenario::IntermittentOutage, 400, mk(1)).unwrap();
        assert_eq!(a1, a2);
        let first = outage_schedule_start(&mk(1)).3;
        assert!((2..40u64).any(|s| outage_schedule_start(&mk(s)).3 != first), "outage phase must depend on the seed");
        assert!((1..40u64).all(|s| outage_schedule_start(&mk(s)).3 < 40));
    }

    #[test]
    fn packet_twin_builds_queue_under_throttle_and_is_deterministic() {
        let cfg = DigitalTwinConfig { link_capacity_kbps: 2_500.0, offered_load_kbps: 2_000.0, queue_capacity_packets: 16, ..Default::default() };
        let a = simulate_packet_twin(healthy(), TwinScenario::Throttle, 200, cfg).unwrap();
        let b = simulate_packet_twin(healthy(), TwinScenario::Throttle, 200, cfg).unwrap();
        assert_eq!(a, b);
        assert!(a.packets_generated > 200 && a.packets_dropped > 0);
        assert_eq!(a.peak_queue_packets, 16);
        assert!(a.p95_latency_ms >= a.mean_latency_ms);
    }

    #[test]
    fn calibration_collector_labels_horizon_and_exports_tsv() {
        let mut col = CalibrationCollector::new(Duration::from_secs(10), Duration::from_secs(2));
        let t0 = Instant::now();
        col.observe(20.0, false, t0);
        col.observe(75.0, false, t0 + Duration::from_secs(3));
        col.observe(85.0, true, t0 + Duration::from_secs(8));
        col.observe(15.0, false, t0 + Duration::from_secs(14));
        assert_eq!(col.resolved_len(), 2);
        let tsv = col.export_tsv();
        assert!(tsv.contains("20.0\t1\n") && tsv.contains("75.0\t1\n"));
    }

    #[test]
    fn platt_calibration_and_artifact_roundtrip() {
        let mut c = RiskCalibrator::default();
        let examples: Vec<_> = (0..40).map(|i| CalibrationExample {
            score: if i < 20 { 10.0 + i as f64 } else { 70.0 + (i - 20) as f64 },
            degraded_within_horizon: i >= 20,
        }).collect();
        assert!(c.fit(&examples));
        let bytes = c.to_artifact_bytes().unwrap();
        let restored = RiskCalibrator::from_artifact_bytes(&bytes).unwrap();
        assert!(restored.probability(90.0).unwrap() > restored.probability(10.0).unwrap());
        assert!(RiskCalibrator::default().probability(90.0).is_none());
        assert!(RiskCalibrator::from_artifact_bytes(&bytes[..31]).is_err());
        let metrics = restored.evaluate(&examples).unwrap();
        assert!(metrics.brier_score.is_finite() && metrics.log_loss.is_finite() && metrics.expected_calibration_error.is_finite());
    }

    #[test]
    fn unified_observer_and_experiments_respect_budget() {
        let mut intelligence = NetworkIntelligence::new();
        let now = Instant::now();
        assert!(intelligence.observe("path-a", healthy(), now).unwrap().degradation_probability.is_none());
        let examples: Vec<_> = (0..40).map(|i| CalibrationExample {
            score: if i < 20 { 10.0 + i as f64 } else { 70.0 + (i - 20) as f64 },
            degraded_within_horizon: i >= 20,
        }).collect();
        assert!(intelligence.fit_calibrator(&examples));
        assert!(intelligence.observe("path-a", healthy(), now + Duration::from_secs(1)).unwrap().degradation_probability.is_some());

        let mut manager = AdaptiveExperimentManager::default();
        let mut budget = HardResourceBudget::new(100, 3, 16_384);
        assert_eq!(manager.next_scenario(), TwinScenario::Clean);
        assert!(manager.run_next_scenario(healthy(), 100, DigitalTwinConfig::default(), &mut budget).is_some());
        let base_cfg = DigitalTwinConfig { link_capacity_kbps: 500.0, offered_load_kbps: 1_500.0, queue_capacity_packets: 8, ..Default::default() };
        let cand_cfg = DigitalTwinConfig { link_capacity_kbps: 3_000.0, offered_load_kbps: 1_500.0, queue_capacity_packets: 8, ..Default::default() };
        let (a, b) = manager.compare_configs(healthy(), TwinScenario::Throttle, 200, base_cfg, cand_cfg, &mut budget).unwrap();
        assert_eq!(a.packets_generated, b.packets_generated);
        assert!(b.goodput_kbps >= a.goodput_kbps);
        assert!(!budget.reserve_experiment());
    }
}
