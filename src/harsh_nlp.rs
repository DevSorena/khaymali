//! Compact Fixed-Weight Micro-NLP & Harsh-Network Controller (`src/harsh_nlp.rs`).
//!
//! Designed specifically for stabilizing Khaymali tunnels under severe censorship,
//! high packet loss, jitter spikes, MTU blackholes, and connection resets:
//!   * **Zero external dependencies & fixed weights** (~400 lines, deterministic O(1) inference).
//!   * Fuses numeric telemetry (`rtt_ms`, `base_rtt_ms`, `jitter_ms`, `loss_pct`,
//!     `retransmit_pct`, `disconnects_per_min`, `big_pkt_drop_ratio`, `goodput_kbps`)
//!     with lightweight keyword scoring on recent transport/kernel log lines.
//!   * Classifies 6 network regimes (`Clean`, `Congested`, `LossyBurst`, `MtuBlackhole`,
//!     `DpiReset`, `SevereThrottling`) and emits a concrete `TunnelAction`:
//!     `carrier`, `chunk_bytes`, `pacing_kbps`, `fec_parity_pct`, `mtu`.
//!   * **Production Safety Guardrails**:
//!       1. `PolicyMode::Shadow` by default (logs recommendations without mutating live tunnel).
//!       2. Post-action telemetry verification (`observe_post_action`).
//!       3. **Automatic rollback** if goodput drops > 15% OR loss increases > 3% OR RTT jumps > 35%.
//!       4. **Cooldown lockout** (default 180s) after rollback so the controller never flaps.

use crate::hjson::Json;
use anyhow::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyMode {
    Shadow,
    Active,
}

impl PolicyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyMode::Shadow => "shadow",
            PolicyMode::Active => "active",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "active" | "live" | "enforce" => PolicyMode::Active,
            _ => PolicyMode::Shadow,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HarshRegime {
    Clean,
    Congested,
    LossyBurst,
    MtuBlackhole,
    DpiReset,
    SevereThrottling,
}

impl HarshRegime {
    pub fn as_str(self) -> &'static str {
        match self {
            HarshRegime::Clean => "clean",
            HarshRegime::Congested => "congested",
            HarshRegime::LossyBurst => "lossy_burst",
            HarshRegime::MtuBlackhole => "mtu_blackhole",
            HarshRegime::DpiReset => "dpi_reset",
            HarshRegime::SevereThrottling => "severe_throttling",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TelemetrySnapshot {
    pub ts_unix: u64,
    pub rtt_ms: f32,
    pub base_rtt_ms: f32,
    pub jitter_ms: f32,
    pub loss_pct: f32,
    pub retransmit_pct: f32,
    pub disconnects_per_min: u32,
    pub big_pkt_drop_ratio: f32, // 0.0..=1.0 (e.g. >0.4 when large frames fail while small ones pass)
    pub goodput_kbps: f32,
    pub recent_log: String,
}

impl Default for TelemetrySnapshot {
    fn default() -> Self {
        Self {
            ts_unix: 0,
            rtt_ms: 45.0,
            base_rtt_ms: 40.0,
            jitter_ms: 3.0,
            loss_pct: 0.0,
            retransmit_pct: 0.0,
            disconnects_per_min: 0,
            big_pkt_drop_ratio: 0.0,
            goodput_kbps: 20_000.0,
            recent_log: String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelTuning {
    pub carrier: String,      // "tcp" | "wss" | "udp+fec" | "ssh" | "spoof" | "ktunnel"
    pub chunk_bytes: u32,     // 1024..=14336
    pub pacing_kbps: u32,     // 0 = uncapped, else kbps cap
    pub fec_parity_pct: u8,   // 0..=40
    pub mtu: u16,             // 1220..=1420
}

impl Default for TunnelTuning {
    fn default() -> Self {
        Self {
            carrier: "wss".into(),
            chunk_bytes: 14336,
            pacing_kbps: 0,
            fec_parity_pct: 0,
            mtu: 1380,
        }
    }
}

impl TunnelTuning {
    pub fn to_json(&self) -> Json {
        Json::obj()
            .set("carrier", self.carrier.clone())
            .set("chunk_bytes", self.chunk_bytes)
            .set("pacing_kbps", self.pacing_kbps)
            .set("fec_parity_pct", self.fec_parity_pct as u64)
            .set("mtu", self.mtu)
    }
}

#[derive(Clone, Debug)]
pub struct MicroNlpDecision {
    pub regime: HarshRegime,
    pub confidence: f32,
    pub recommended: TunnelTuning,
    pub applied: bool,
    pub reason: String,
}

impl MicroNlpDecision {
    pub fn to_json(&self) -> Json {
        Json::obj()
            .set("regime", self.regime.as_str())
            .set("confidence", (self.confidence as f64 * 1000.0).round() / 1000.0)
            .set("applied", self.applied)
            .set("reason", self.reason.clone())
            .set("recommended", self.recommended.to_json())
    }
}

// Fixed-weight linear model: 6 regimes x 8 normalized features + bias
// Features: [rtt_ratio, jitter_norm, loss_norm, retx_norm, disc_norm, mtu_drop, dpi_kw, throttle_kw]
const WEIGHTS: [[f32; 9]; 6] = [
    // 0: Clean
    [-2.0, -1.5, -4.0, -3.5, -2.5, -3.0, -3.0, -2.5, 2.2],
    // 1: Congested (high RTT bloat & jitter, moderate retransmit, low resets)
    [2.6, 2.2, 0.5, 1.4, -0.5, -1.0, -1.0, 0.8, -1.4],
    // 2: LossyBurst (packet loss + retransmits + jitter)
    [0.6, 1.4, 3.8, 3.0, 0.5, -0.5, -0.5, 0.5, -1.6],
    // 3: MtuBlackhole (big packet drop ratio + PMTU log cues)
    [0.4, 0.2, 0.8, 0.8, 0.2, 5.2, -0.5, 0.0, -1.8],
    // 4: DpiReset (disconnect burst + RST/TLS/EOF log cues)
    [0.2, 0.2, 0.4, 0.2, 3.6, -0.5, 4.5, 0.4, -1.9],
    // 5: SevereThrottling (extreme RTT + high loss + disconnects + throttle cues)
    [2.0, 1.8, 2.8, 2.2, 2.2, 0.5, 1.5, 3.8, -3.4],
];

const REGIMES: [HarshRegime; 6] = [
    HarshRegime::Clean,
    HarshRegime::Congested,
    HarshRegime::LossyBurst,
    HarshRegime::MtuBlackhole,
    HarshRegime::DpiReset,
    HarshRegime::SevereThrottling,
];

fn extract_features(s: &TelemetrySnapshot) -> [f32; 8] {
    let base = s.base_rtt_ms.max(5.0);
    let rtt_ratio = ((s.rtt_ms - base).max(0.0) / base).clamp(0.0, 4.0);
    let jitter_norm = (s.jitter_ms / 50.0).clamp(0.0, 3.0);
    let loss_norm = (s.loss_pct / 10.0).clamp(0.0, 4.0);
    let retx_norm = (s.retransmit_pct / 10.0).clamp(0.0, 4.0);
    let disc_norm = (s.disconnects_per_min as f32 / 5.0).clamp(0.0, 4.0);
    let mtu_drop = s.big_pkt_drop_ratio.clamp(0.0, 1.5);

    let log = s.recent_log.to_ascii_lowercase();
    let mut dpi_kw: f32 = 0.0;
    for kw in ["connection reset", "rst", "unexpected eof", "tls handshake", "broken pipe", "dpi", "filtered"] {
        if log.contains(kw) {
            dpi_kw += 0.5;
        }
    }
    let mut mtu_kw: f32 = 0.0;
    for kw in ["frag needed", "message too long", "emsgsize", "mtu", "blackhole", "stall"] {
        if log.contains(kw) {
            mtu_kw += 0.4;
        }
    }
    let mut thr_kw: f32 = 0.0;
    for kw in ["throttl", "quota", "timeout", "unreachable", "blackout", "severe"] {
        if log.contains(kw) {
            thr_kw += 0.5;
        }
    }
    [
        rtt_ratio,
        jitter_norm,
        loss_norm,
        retx_norm,
        disc_norm,
        (mtu_drop + mtu_kw).clamp(0.0, 2.0),
        dpi_kw.clamp(0.0, 2.0),
        thr_kw.clamp(0.0, 2.0),
    ]
}

fn softmax(logits: &[f32; 6]) -> [f32; 6] {
    let max_v = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut exps = [0.0f32; 6];
    let mut sum = 0.0f32;
    for i in 0..6 {
        exps[i] = (logits[i] - max_v).exp();
        sum += exps[i];
    }
    for e in &mut exps {
        *e /= sum.max(1e-6);
    }
    exps
}

/// Maps classified regime + current telemetry to concrete tunnel tuning parameters.
pub fn tuning_for_regime(regime: HarshRegime, s: &TelemetrySnapshot) -> TunnelTuning {
    match regime {
        HarshRegime::Clean => TunnelTuning {
            carrier: "wss".into(),
            chunk_bytes: 14336,
            pacing_kbps: 0,
            fec_parity_pct: 0,
            mtu: 1380,
        },
        HarshRegime::Congested => {
            let cap = (s.goodput_kbps * 0.85).clamp(1500.0, 80_000.0) as u32;
            TunnelTuning {
                carrier: "wss".into(),
                chunk_bytes: 8192,
                pacing_kbps: cap,
                fec_parity_pct: 5,
                mtu: 1340,
            }
        }
        HarshRegime::LossyBurst => {
            let fec = (s.loss_pct * 1.8).clamp(10.0, 35.0) as u8;
            TunnelTuning {
                carrier: "udp+fec".into(),
                chunk_bytes: 4096,
                pacing_kbps: (s.goodput_kbps * 0.9).clamp(1000.0, 60_000.0) as u32,
                fec_parity_pct: fec,
                mtu: 1280,
            }
        }
        HarshRegime::MtuBlackhole => TunnelTuning {
            carrier: "wss".into(),
            chunk_bytes: 2048,
            pacing_kbps: 0,
            fec_parity_pct: 5,
            mtu: 1220,
        },
        HarshRegime::DpiReset => TunnelTuning {
            carrier: "ssh".into(),
            chunk_bytes: 4096,
            pacing_kbps: 4000,
            fec_parity_pct: 10,
            mtu: 1280,
        },
        HarshRegime::SevereThrottling => TunnelTuning {
            carrier: "spoof".into(),
            chunk_bytes: 2048,
            pacing_kbps: 2000,
            fec_parity_pct: 30,
            mtu: 1240,
        },
    }
}

/// Stateful Micro-NLP controller with Shadow default, Auto-Rollback, and Cooldown Lockout.
pub struct HarshNlpController {
    pub mode: PolicyMode,
    pub min_confidence: f32,
    pub rollback_lockout_secs: u64,
    pub current: TunnelTuning,
    previous: Option<(TunnelTuning, TelemetrySnapshot)>,
    locked_until_unix: u64,
    pub rollbacks: u32,
}

impl Default for HarshNlpController {
    fn default() -> Self {
        Self::new(PolicyMode::Shadow)
    }
}

impl HarshNlpController {
    pub fn new(mode: PolicyMode) -> Self {
        Self {
            mode,
            min_confidence: 0.55,
            rollback_lockout_secs: 180,
            current: TunnelTuning::default(),
            previous: None,
            locked_until_unix: 0,
            rollbacks: 0,
        }
    }

    pub fn is_locked(&self, now_ts: u64) -> bool {
        now_ts < self.locked_until_unix
    }

    /// Pure O(1) fixed-weight inference without mutating controller state.
    pub fn classify(&self, snap: &TelemetrySnapshot) -> (HarshRegime, f32, TunnelTuning) {
        let f = extract_features(snap);
        let mut logits = [0.0f32; 6];
        for r in 0..6 {
            let mut acc = WEIGHTS[r][8];
            for k in 0..8 {
                acc += WEIGHTS[r][k] * f[k];
            }
            logits[r] = acc;
        }
        let probs = softmax(&logits);
        let mut best_i = 0;
        for i in 1..6 {
            if probs[i] > probs[best_i] {
                best_i = i;
            }
        }
        let regime = REGIMES[best_i];
        (regime, probs[best_i], tuning_for_regime(regime, snap))
    }

    /// Evaluates telemetry and applies tuning only when `PolicyMode::Active`, unlocked,
    /// and confidence >= `min_confidence`.
    pub fn evaluate(&mut self, snap: &TelemetrySnapshot) -> MicroNlpDecision {
        let (regime, conf, rec) = self.classify(snap);
        if self.is_locked(snap.ts_unix) {
            return MicroNlpDecision {
                regime,
                confidence: conf,
                recommended: rec,
                applied: false,
                reason: format!("locked until {} after previous rollback", self.locked_until_unix),
            };
        }
        if conf < self.min_confidence {
            return MicroNlpDecision {
                regime,
                confidence: conf,
                recommended: rec,
                applied: false,
                reason: format!("abstained: confidence {conf:.2} < {:.2}", self.min_confidence),
            };
        }
        if self.mode == PolicyMode::Shadow {
            return MicroNlpDecision {
                regime,
                confidence: conf,
                recommended: rec,
                applied: false,
                reason: "shadow mode (recommendation logged only)".into(),
            };
        }
        if rec == self.current {
            return MicroNlpDecision {
                regime,
                confidence: conf,
                recommended: rec,
                applied: false,
                reason: "already at optimal tuning".into(),
            };
        }
        self.previous = Some((self.current.clone(), snap.clone()));
        self.current = rec.clone();
        MicroNlpDecision {
            regime,
            confidence: conf,
            recommended: rec,
            applied: true,
            reason: format!("applied {} tuning", regime.as_str()),
        }
    }

    /// Checks whether the last applied action degraded tunnel performance.
    /// If degraded, restores the previous `TunnelTuning` immediately and engages lockout.
    pub fn verify_or_rollback(&mut self, post: &TelemetrySnapshot) -> Result<bool> {
        let Some((prev_tuning, pre)) = self.previous.clone() else {
            return Ok(false);
        };
        let goodput_dropped = pre.goodput_kbps > 100.0 && post.goodput_kbps < pre.goodput_kbps * 0.85;
        let loss_worse = post.loss_pct > pre.loss_pct + 3.0;
        let rtt_worse = pre.rtt_ms > 10.0 && post.rtt_ms > pre.rtt_ms * 1.35;
        if goodput_dropped || loss_worse || rtt_worse {
            self.current = prev_tuning;
            self.previous = None;
            self.rollbacks += 1;
            self.locked_until_unix = post.ts_unix.saturating_add(self.rollback_lockout_secs);
            return Ok(true);
        }
        // Action confirmed healthy -> clear rollback snapshot
        self.previous = None;
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn micro_nlp_classifies_all_harsh_regimes() {
        let ctl = HarshNlpController::default();

        let clean = TelemetrySnapshot::default();
        assert_eq!(ctl.classify(&clean).0, HarshRegime::Clean);

        let lossy = TelemetrySnapshot {
            loss_pct: 18.0,
            retransmit_pct: 15.0,
            jitter_ms: 45.0,
            rtt_ms: 95.0,
            ..Default::default()
        };
        let (r_loss, _, t_loss) = ctl.classify(&lossy);
        assert_eq!(r_loss, HarshRegime::LossyBurst);
        assert_eq!(t_loss.carrier, "udp+fec");
        assert!(t_loss.fec_parity_pct >= 15);

        let mtu = TelemetrySnapshot {
            big_pkt_drop_ratio: 0.9,
            recent_log: "EMSGSIZE mtu blackhole detected".into(),
            ..Default::default()
        };
        let (r_mtu, _, t_mtu) = ctl.classify(&mtu);
        assert_eq!(r_mtu, HarshRegime::MtuBlackhole);
        assert_eq!(t_mtu.mtu, 1220);

        let dpi = TelemetrySnapshot {
            disconnects_per_min: 14,
            recent_log: "TLS handshake unexpected EOF connection reset by peer (RST)".into(),
            ..Default::default()
        };
        let (r_dpi, _, t_dpi) = ctl.classify(&dpi);
        assert_eq!(r_dpi, HarshRegime::DpiReset);
        assert_eq!(t_dpi.carrier, "ssh");
    }

    #[test]
    fn shadow_default_active_apply_auto_rollback_and_lockout() {
        // 1. Default is Shadow mode: never mutates tuning
        let mut shadow = HarshNlpController::default();
        assert_eq!(shadow.mode, PolicyMode::Shadow);
        let harsh = TelemetrySnapshot {
            ts_unix: 1000,
            loss_pct: 16.0,
            retransmit_pct: 14.0,
            jitter_ms: 40.0,
            rtt_ms: 90.0,
            goodput_kbps: 10_000.0,
            ..Default::default()
        };
        let d_sh = shadow.evaluate(&harsh);
        assert!(!d_sh.applied);

        // 2. Active mode applies tuning
        let mut active = HarshNlpController::new(PolicyMode::Active);
        let orig = active.current.clone();
        let d_act = active.evaluate(&harsh);
        assert!(d_act.applied);
        assert_eq!(active.current.carrier, "udp+fec");

        // 3. Post-action degradation triggers immediate rollback + 180s lockout
        let worse = TelemetrySnapshot {
            ts_unix: 1020,
            loss_pct: 24.0,
            rtt_ms: 160.0,
            goodput_kbps: 4_000.0,
            ..harsh.clone()
        };
        assert!(active.verify_or_rollback(&worse).unwrap());
        assert_eq!(active.current, orig);
        assert_eq!(active.rollbacks, 1);
        assert!(active.is_locked(1100));
        assert!(!active.evaluate(&TelemetrySnapshot { ts_unix: 1100, ..harsh.clone() }).applied);
        assert!(!active.is_locked(1250));
    }
}
