//! Exit health tracking (SPEC §5):
//!   * EWMA RTT & Jitter + CUSUM positive RTT drift detector.
//!   * 3-state Circuit Breaker separating `Timeout` vs `Reset` via typed `io::ErrorKind` downcast.
//!   * Explicit state parity: `Snap.up` (`circuit == Closed`) and `Snap.selectable` (exact match
//!     with `pick()` eligibility, including `HalfOpen` probe-in-flight state).
//!   * Strict time-tick Hysteresis: first observation only records baseline timestamp (does NOT
//!     advance counter); every subsequent advance requires `>= hysteresis_interval` elapsed AND
//!     `>= 15%` improvement across 3 ticks with `samples >= 2`.
//!   * `diagnose()` is strictly advisory/read-only (never mutates routing, keys, or policy).

use crate::stats;
use crate::util::{now_unix, rand_range};
use std::sync::atomic::Ordering::Relaxed;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::sleep;

const HISTORY_CAP: usize = 60;
const CB_TIMEOUT_THRESHOLD: u32 = 3;
const CB_RESET_THRESHOLD: u32 = 2;
const HYSTERESIS_RATIO: f64 = 0.85;
const HYSTERESIS_WINS_NEEDED: u8 = 3;
const HYSTERESIS_TICK_INTERVAL: Duration = Duration::from_secs(10);
const MIN_SAMPLES_TO_PROMOTE: u32 = 2;
const CUSUM_SLACK_MS: f64 = 15.0;
const CUSUM_ALERT_THRESHOLD: f64 = 120.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    Timeout,
    Reset,
    Other,
}

/// Strictly advisory hints returned by `Exits::diagnose()`. Never executed automatically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdvisoryHint {
    HealthyPreferred(String),
    InvestigateResetOrDrift(String),
    AllCircuitsOpen { suggested_pool: usize },
    NoExitsConfigured,
}

struct St {
    addr: String,
    ewma_ms: f64,
    min_rtt_ms: f64,
    jitter_ms: f64,
    cusum: f64,
    samples: u32,
    fails: u32,
    timeout_fails: u32,
    reset_fails: u32,
    stalls: u32,
    circuit: CircuitState,
    down_until: Option<Instant>,
    half_open_probe_sent: bool,
    intel_score: Option<(f64, u64)>,
}

fn path_intel_active() -> bool {
    static ACTIVE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ACTIVE.get_or_init(|| {
        std::env::var("KHAYMALI_PATH_INTEL")
            .map(|v| v.eq_ignore_ascii_case("active") || v == "1")
            .unwrap_or(false)
    })
}

#[derive(Clone, Debug)]
pub struct Snap {
    pub addr: String,
    pub ewma_ms: f64,
    pub jitter_ms: f64,
    pub cusum: f64,
    pub fails: u32,
    pub timeout_fails: u32,
    pub reset_fails: u32,
    pub stalls: u32,
    pub circuit: CircuitState,
    /// True strictly when `circuit == CircuitState::Closed`.
    pub up: bool,
    /// Exact match with whether `pick()` can currently select this exit (false during Open cooldown
    /// AND false when a `HalfOpen` probe is already in flight).
    pub selectable: bool,
    pub half_open_probe_in_flight: bool,
}

#[derive(Clone, Debug)]
pub struct HealthRecord {
    pub ts: u64,
    pub addr: String,
    pub ewma_ms: f64,
    pub jitter_ms: f64,
    pub timeout_fails: u32,
    pub reset_fails: u32,
    pub up: bool,
    pub selectable: bool,
}

struct Inner {
    exits: Vec<St>,
    preferred: Option<String>,
    challenger: Option<String>,
    challenger_wins: u8,
    last_hysteresis_tick: Option<Instant>,
    hysteresis_interval: Duration,
    history: VecDeque<HealthRecord>,
}

pub struct Exits {
    inner: Mutex<Inner>,
}

impl Exits {
    pub fn new(addrs: Vec<String>) -> Arc<Exits> {
        Self::with_hysteresis_interval(addrs, HYSTERESIS_TICK_INTERVAL)
    }

    pub fn with_hysteresis_interval(addrs: Vec<String>, interval: Duration) -> Arc<Exits> {
        let preferred = addrs.first().cloned();
        let exits = addrs
            .into_iter()
            .map(|addr| St {
                addr,
                ewma_ms: 50.0,
                min_rtt_ms: 50.0,
                jitter_ms: 0.0,
                cusum: 0.0,
                samples: 0,
                fails: 0,
                timeout_fails: 0,
                reset_fails: 0,
                stalls: 0,
                circuit: CircuitState::Closed,
                down_until: None,
                half_open_probe_sent: false,
                intel_score: None,
            })
            .collect();
        Arc::new(Exits {
            inner: Mutex::new(Inner {
                exits,
                preferred,
                challenger: None,
                challenger_wins: 0,
                last_hysteresis_tick: None,
                hysteresis_interval: interval,
                history: VecDeque::with_capacity(HISTORY_CAP),
            }),
        })
    }

    fn score(s: &St) -> f64 {
        let base = s.ewma_ms
            + s.jitter_ms * 1.5
            + s.cusum * 0.5
            + s.timeout_fails as f64 * 350.0
            + s.reset_fails as f64 * 500.0
            + s.stalls as f64 * 250.0;
        Self::apply_intel_tiebreaker(base, s, path_intel_active())
    }

    fn apply_intel_tiebreaker(base: f64, s: &St, active: bool) -> f64 {
        if !active || s.circuit != CircuitState::Closed {
            return base;
        }
        let Some((intel_score, obs)) = s.intel_score else { return base; };
        if obs < 5 || !intel_score.is_finite() {
            return base;
        }
        let norm = ((50.0 - intel_score.clamp(0.0, 100.0)) / 50.0) * 0.20;
        stats::PATH_INTEL_ADJUSTMENTS.fetch_add(1, Relaxed);
        (base * (1.0 + norm)).max(1.0)
    }

    pub fn update_path_intel(&self, addr: &str, score: f64, observations: u64) {
        if !score.is_finite() { return; }
        let mut g = self.inner.lock().unwrap();
        if let Some(s) = g.exits.iter_mut().find(|s| s.addr == addr) {
            s.intel_score = Some((score.clamp(0.0, 100.0), observations));
        }
    }

    /// Single source of truth for selectability shared by `pick()` and `snapshot().selectable`.
    fn is_selectable_now(s: &St, now: Instant) -> bool {
        match s.circuit {
            CircuitState::Closed => true,
            CircuitState::Open => s.down_until.map_or(true, |t| t <= now),
            CircuitState::HalfOpen => !s.half_open_probe_sent,
        }
    }

    fn try_select(s: &mut St, now: Instant) -> bool {
        if !Self::is_selectable_now(s, now) {
            return false;
        }
        if s.circuit == CircuitState::Open {
            s.circuit = CircuitState::HalfOpen;
            s.half_open_probe_sent = false;
        }
        true
    }

    /// Periodic time-tick hysteresis evaluation. Respects `hysteresis_interval` strictly —
    /// rapid calls within one interval are ignored.
    pub fn evaluate_tick(&self) {
        self.evaluate_tick_at(Instant::now());
    }

    /// Time-injected tick evaluation (allows deterministic tests without bypassing interval checks).
    pub fn evaluate_tick_at(&self, now: Instant) {
        let mut g = self.inner.lock().unwrap();
        Self::evaluate_tick_locked(&mut g, now);
    }

    fn evaluate_tick_locked(g: &mut Inner, now: Instant) {
        // First observation only establishes baseline time; never counts as tick #1.
        let Some(last) = g.last_hysteresis_tick else {
            g.last_hysteresis_tick = Some(now);
            return;
        };
        if now.saturating_duration_since(last) < g.hysteresis_interval {
            return;
        }
        g.last_hysteresis_tick = Some(now);

        let closed: Vec<usize> = g
            .exits
            .iter()
            .enumerate()
            .filter(|(_, s)| s.circuit == CircuitState::Closed)
            .map(|(i, _)| i)
            .collect();
        if closed.is_empty() {
            return;
        }

        let tested: Vec<usize> = closed
            .iter()
            .copied()
            .filter(|&i| g.exits[i].samples >= MIN_SAMPLES_TO_PROMOTE)
            .collect();
        let pool = if tested.is_empty() { &closed } else { &tested };

        let best_idx = *pool
            .iter()
            .min_by(|&&a, &&b| {
                Self::score(&g.exits[a])
                    .partial_cmp(&Self::score(&g.exits[b]))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap();
        let best_addr = g.exits[best_idx].addr.clone();
        let best_score = Self::score(&g.exits[best_idx]);

        if let Some(pref_addr) = g.preferred.clone() {
            if let Some(&pref_idx) = closed.iter().find(|&&i| g.exits[i].addr == pref_addr) {
                if pref_idx == best_idx {
                    g.challenger = None;
                    g.challenger_wins = 0;
                } else {
                    let pref_score = Self::score(&g.exits[pref_idx]);
                    if best_score <= pref_score * HYSTERESIS_RATIO
                        && g.exits[best_idx].samples >= MIN_SAMPLES_TO_PROMOTE
                    {
                        if g.challenger.as_deref() == Some(best_addr.as_str()) {
                            g.challenger_wins = g.challenger_wins.saturating_add(1);
                        } else {
                            g.challenger = Some(best_addr.clone());
                            g.challenger_wins = 1;
                        }
                        if g.challenger_wins >= HYSTERESIS_WINS_NEEDED {
                            g.preferred = Some(best_addr);
                            g.challenger = None;
                            g.challenger_wins = 0;
                        }
                    } else {
                        g.challenger = None;
                        g.challenger_wins = 0;
                    }
                }
            } else {
                // Preferred exit is no longer Closed: fail over immediately
                g.preferred = Some(best_addr);
                g.challenger = None;
                g.challenger_wins = 0;
            }
        } else {
            g.preferred = Some(best_addr);
        }
    }

    pub fn pick(&self) -> Option<String> {
        self.pick_at(Instant::now())
    }

    pub fn pick_at(&self, now: Instant) -> Option<String> {
        let mut g = self.inner.lock().unwrap();
        Self::evaluate_tick_locked(&mut g, now);

        let mut selectable: Vec<usize> = Vec::new();
        for (i, s) in g.exits.iter_mut().enumerate() {
            if Self::try_select(s, now) {
                selectable.push(i);
            }
        }
        // Never stampede an Open circuit when all exits are unhealthy. Half-open
        // eligibility is granted by try_select() and remains single-flight per exit.
        if selectable.is_empty() {
            return None;
        }

        if selectable.len() > 1 && rand_range(0, 99) < 15 {
            let idx = selectable[rand_range(0, selectable.len() - 1)];
            if g.exits[idx].circuit == CircuitState::HalfOpen {
                g.exits[idx].half_open_probe_sent = true;
            }
            return Some(g.exits[idx].addr.clone());
        }

        let chosen_idx = if let Some(pref_addr) = g.preferred.as_deref() {
            selectable
                .iter()
                .copied()
                .find(|&i| g.exits[i].addr == pref_addr)
                .unwrap_or_else(|| {
                    *selectable
                        .iter()
                        .min_by(|&&a, &&b| {
                            Self::score(&g.exits[a])
                                .partial_cmp(&Self::score(&g.exits[b]))
                                .unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .unwrap()
                })
        } else {
            selectable[0]
        };

        if g.exits[chosen_idx].circuit == CircuitState::HalfOpen {
            g.exits[chosen_idx].half_open_probe_sent = true;
        }
        Some(g.exits[chosen_idx].addr.clone())
    }

    /// Best *other* selectable exit (for hedged dials). `None` if there is no alternative.
    pub fn pick_other(&self, not: &str) -> Option<String> {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap();
        let mut best: Option<usize> = None;
        for i in 0..g.exits.len() {
            if g.exits[i].addr == not || !Self::is_selectable_now(&g.exits[i], now) {
                continue;
            }
            best = match best {
                Some(b) if Self::score(&g.exits[b]) <= Self::score(&g.exits[i]) => Some(b),
                _ => Some(i),
            };
        }
        let i = best?;
        if !Self::try_select(&mut g.exits[i], now) {
            return None;
        }
        if g.exits[i].circuit == CircuitState::HalfOpen {
            g.exits[i].half_open_probe_sent = true;
        }
        Some(g.exits[i].addr.clone())
    }

    pub fn ok(&self, addr: &str, rtt: Duration) {
        let mut g = self.inner.lock().unwrap();
        let sample = rtt.as_secs_f64() * 1000.0;
        let mut rec = None;
        if let Some(s) = g.exits.iter_mut().find(|s| s.addr == addr) {
            if s.samples == 0 {
                s.ewma_ms = sample;
                s.min_rtt_ms = sample;
            } else {
                let diff = (sample - s.ewma_ms).abs();
                s.jitter_ms = s.jitter_ms * 0.75 + diff * 0.25;
                s.ewma_ms = s.ewma_ms * 0.7 + sample * 0.3;
                if sample < s.min_rtt_ms {
                    s.min_rtt_ms = sample;
                } else {
                    s.min_rtt_ms = s.min_rtt_ms * 0.995 + sample * 0.005;
                }
            }
            s.samples = s.samples.saturating_add(1);
            let drift = sample - s.min_rtt_ms - CUSUM_SLACK_MS;
            s.cusum = (s.cusum + drift).clamp(0.0, 500.0);
            s.fails = 0;
            s.timeout_fails = 0;
            s.reset_fails = 0;
            s.stalls = s.stalls.saturating_sub(1);
            s.circuit = CircuitState::Closed;
            s.down_until = None;
            s.half_open_probe_sent = false;
            rec = Some(HealthRecord {
                ts: now_unix(),
                addr: s.addr.clone(),
                ewma_ms: s.ewma_ms,
                jitter_ms: s.jitter_ms,
                timeout_fails: 0,
                reset_fails: 0,
                up: true,
                selectable: true,
            });
        }
        if let Some(r) = rec {
            if g.history.len() >= HISTORY_CAP {
                g.history.pop_front();
            }
            g.history.push_back(r);
        }
    }

    pub fn fail_kind(&self, addr: &str, kind: FailureKind) {
        self.fail_kind_at(addr, kind, Instant::now());
    }

    pub fn fail_kind_at(&self, addr: &str, kind: FailureKind, now: Instant) {
        let mut g = self.inner.lock().unwrap();
        let mut rec = None;
        if let Some(s) = g.exits.iter_mut().find(|s| s.addr == addr) {
            if s.circuit == CircuitState::Open
                && s.down_until.is_some_and(|t| t > now)
            {
                // Already in Open cooldown: do not escalate fails/down_until from concurrent workers.
            } else {
                s.fails = s.fails.saturating_add(1);
                match kind {
                    FailureKind::Timeout => s.timeout_fails = s.timeout_fails.saturating_add(1),
                    FailureKind::Reset => s.reset_fails = s.reset_fails.saturating_add(1),
                    FailureKind::Other => {}
                }
                let trip = match kind {
                    FailureKind::Reset => s.reset_fails >= CB_RESET_THRESHOLD || s.fails >= CB_TIMEOUT_THRESHOLD,
                    _ => s.fails >= CB_TIMEOUT_THRESHOLD,
                };
                if s.circuit == CircuitState::HalfOpen || trip {
                    s.circuit = CircuitState::Open;
                    let secs = (1u64 << s.fails.saturating_sub(1).min(4))
                        .min(crate::adapt::exit_cooldown_cap_secs());
                    s.down_until = Some(now + Duration::from_secs(secs));
                }
            }
            s.half_open_probe_sent = false;
            rec = Some(HealthRecord {
                ts: now_unix(),
                addr: s.addr.clone(),
                ewma_ms: s.ewma_ms,
                jitter_ms: s.jitter_ms,
                timeout_fails: s.timeout_fails,
                reset_fails: s.reset_fails,
                up: s.circuit == CircuitState::Closed,
                selectable: Self::is_selectable_now(s, now),
            });
        }
        if let Some(r) = rec {
            if g.history.len() >= HISTORY_CAP {
                g.history.pop_front();
            }
            g.history.push_back(r);
        }
    }

    /// Typed error classification walking `anyhow::Error::chain()` (zero fragile string matching).
    pub fn classify_error(err: &anyhow::Error) -> FailureKind {
        for cause in err.chain() {
            if cause.downcast_ref::<tokio::time::error::Elapsed>().is_some() {
                return FailureKind::Timeout;
            }
            if let Some(ioe) = cause.downcast_ref::<std::io::Error>() {
                return match ioe.kind() {
                    ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::BrokenPipe => FailureKind::Reset,
                    ErrorKind::TimedOut => FailureKind::Timeout,
                    _ => FailureKind::Other,
                };
            }
        }
        FailureKind::Other
    }

    /// Strictly advisory diagnostic snapshot for Control Plane / CLI (never executes changes).
    pub fn diagnose(&self, current_pool: usize) -> Vec<AdvisoryHint> {
        let g = self.inner.lock().unwrap();
        if g.exits.is_empty() {
            return vec![AdvisoryHint::NoExitsConfigured];
        }
        let mut hints = Vec::new();
        let open_count = g.exits.iter().filter(|s| s.circuit == CircuitState::Open).count();
        if open_count == g.exits.len() {
            hints.push(AdvisoryHint::AllCircuitsOpen {
                suggested_pool: (current_pool / 2).max(2),
            });
            return hints;
        }
        for s in &g.exits {
            if s.cusum >= CUSUM_ALERT_THRESHOLD || s.reset_fails >= CB_RESET_THRESHOLD {
                hints.push(AdvisoryHint::InvestigateResetOrDrift(s.addr.clone()));
            }
        }
        if let Some(pref) = &g.preferred {
            hints.push(AdvisoryHint::HealthyPreferred(pref.clone()));
        }
        hints
    }

    pub fn snapshot(&self) -> Vec<Snap> {
        self.snapshot_at(Instant::now())
    }

    pub fn snapshot_at(&self, now: Instant) -> Vec<Snap> {
        self.inner
            .lock()
            .unwrap()
            .exits
            .iter()
            .map(|s| Snap {
                addr: s.addr.clone(),
                ewma_ms: s.ewma_ms,
                jitter_ms: s.jitter_ms,
                cusum: s.cusum,
                fails: s.fails,
                timeout_fails: s.timeout_fails,
                reset_fails: s.reset_fails,
                stalls: s.stalls,
                circuit: s.circuit,
                up: s.circuit == CircuitState::Closed,
                selectable: Self::is_selectable_now(s, now),
                half_open_probe_in_flight: s.circuit == CircuitState::HalfOpen && s.half_open_probe_sent,
            })
            .collect()
    }

    pub fn history(&self) -> Vec<HealthRecord> {
        self.inner.lock().unwrap().history.iter().cloned().collect()
    }

    pub fn preferred(&self) -> Option<String> {
        self.inner.lock().unwrap().preferred.clone()
    }

    /// Record a mid-stream stall on an exit to penalize its score without immediately
    /// tripping a hard failure unless resets/timeouts follow.
    pub fn record_stall(&self, addr: &str) {
        let mut g = self.inner.lock().unwrap();
        if let Some(s) = g.exits.iter_mut().find(|s| s.addr == addr) {
            s.stalls = s.stalls.saturating_add(1).min(16);
        }
    }
}

/// Passive health loop: never sends bare TCP SYN/close probes (which give DPI scanner
/// fingerprints and falsely close circuits behind L7 filtering). Advances periodic
/// hysteresis ticks driven strictly by real transport outcomes.
pub async fn probe_loop(exits: Arc<Exits>, period: Duration) {
    loop {
        sleep(period).await;
        exits.evaluate_tick();
    }

    #[test]
    fn path_intel_tiebreaker_is_bounded_and_respects_circuit_state() {
        let mut s = St {
            addr: "1.1.1.1:4440".into(), ewma_ms: 100.0, min_rtt_ms: 100.0, jitter_ms: 0.0,
            cusum: 0.0, samples: 5, fails: 0, timeout_fails: 0, reset_fails: 0, stalls: 0,
            circuit: CircuitState::Closed, down_until: None, half_open_probe_sent: false,
            intel_score: Some((100.0, 10)),
        };
        assert!((Exits::apply_intel_tiebreaker(100.0, &s, false) - 100.0).abs() < 1e-6);
        assert!((Exits::apply_intel_tiebreaker(100.0, &s, true) - 80.0).abs() < 1e-6);
        s.intel_score = Some((0.0, 10));
        assert!((Exits::apply_intel_tiebreaker(100.0, &s, true) - 120.0).abs() < 1e-6);
        s.intel_score = Some((100.0, 3));
        assert!((Exits::apply_intel_tiebreaker(100.0, &s, true) - 100.0).abs() < 1e-6);
        s.intel_score = Some((100.0, 10)); s.circuit = CircuitState::Open;
        assert!((Exits::apply_intel_tiebreaker(100.0, &s, true) - 100.0).abs() < 1e-6);
    }
}
