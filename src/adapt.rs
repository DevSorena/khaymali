//! Adaptive control plane for hard network conditions.
//!
//! Three cooperating parts, all driven by the same sliding window of observed events:
//!
//! 1. **Decision engine** - classifies the path as `Normal / Degraded / Hostile / Blackout /
//!    Recovering` and turns that into a `Tuning` (dial timeouts, pool size, link max-age, backoff,
//!    hedged dials, acquire deadline). Escalation is immediate, de-escalation needs 3 calm ticks
//!    (no flapping), and a blackout is followed by a slow-start ramp (no thundering herd).
//! 2. **Pattern recovery** - fingerprints failures (`Sig`) and learns three repeatable patterns:
//!    links killed at a consistent age, periodic outages (period + length), and the dominant
//!    failure signature. Learned patterns survive restarts (small state file) and are used to
//!    rotate links *before* the usual kill age and to probe densely around the predicted end of an
//!    outage.
//! 3. **Bottleneck resolver** - detects `PoolStarved` (clients wait for links), `ExitSlow`
//!    (handshake RTT inflated), `StalePool` (pooled links found dead) and `SocksSaturated`. Pool
//!    starvation is resolved with AIMD growth of the dialer count; slow exits freeze growth so the
//!    tunnel never hammers an overloaded exit.
//!
//! Safety: this module only changes *performance knobs*. It never touches keys, authentication,
//! allowlists or the SSRF policy. `--no-adapt` restores the fixed behaviour exactly.
//! All time-dependent logic takes an injected `Instant`, so it is unit-tested deterministically.

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const WINDOW_SECS: u64 = 20;
/// "Recent" window used for blackout detection and growth gating: stale successes from before an
/// outage must not mask it.
pub const RECENT_SECS: u64 = 8;
const NB: usize = 64; // ring of 1-second buckets (must be >= WINDOW_SECS)
pub const TICK: Duration = Duration::from_secs(2);
const AGE_SAMPLE_TTL: Duration = Duration::from_secs(30 * 60);
const AGE_SAMPLE_CAP: usize = 64;
const EPISODE_CAP: usize = 8;
const STATE_MAX_AGE_SECS: u64 = 7 * 24 * 3600;

// ---------------------------------------------------------------------------------------------
// Process-wide gauges (read by stats::render and the control socket)
// ---------------------------------------------------------------------------------------------
pub static CONDITION: AtomicI64 = AtomicI64::new(0);
pub static POOL_TARGET: AtomicI64 = AtomicI64::new(0);
pub static BOTTLENECKS: AtomicI64 = AtomicI64::new(0);
pub static KILL_AGE_S: AtomicI64 = AtomicI64::new(-1);
pub static OUTAGE_PERIOD_S: AtomicI64 = AtomicI64::new(-1);
pub static OUTAGE_LEN_S: AtomicI64 = AtomicI64::new(-1);
pub static RECOVERIES: AtomicU64 = AtomicU64::new(0);
pub static BLACKOUT_SECS: AtomicU64 = AtomicU64::new(0);
pub static HEDGED_DIALS: AtomicU64 = AtomicU64::new(0);
pub static TRANSITIONS: AtomicU64 = AtomicU64::new(0);

static GLOBAL: OnceLock<Arc<Adapt>> = OnceLock::new();

pub fn install(a: Arc<Adapt>) {
    let _ = GLOBAL.set(a);
}

pub fn global() -> Option<Arc<Adapt>> {
    GLOBAL.get().cloned()
}

/// Record an event on the installed engine (no-op if none / disabled).
pub fn record_global(ev: Event) {
    if let Some(a) = GLOBAL.get() {
        a.record(ev);
    }
}

/// Current adaptive condition (`Normal` when no engine is installed).
pub fn condition_global() -> Condition {
    GLOBAL.get().map_or(Condition::Normal, |a| a.condition())
}

/// Longest time an exit's circuit may stay open after a failure. During a blackout every exit is
/// down anyway, so waiting up to 64 s before probing again only delays the recovery: cap it.
pub fn exit_cooldown_cap_secs() -> u64 {
    match condition_global() {
        Condition::Blackout | Condition::Recovering => 4,
        _ => 64,
    }
}

/// Backoff after a failed dial: adaptive if installed, otherwise plain doubling capped at 30 s.
pub fn next_backoff_global(cur: Duration) -> Duration {
    match GLOBAL.get() {
        Some(a) => a.next_backoff(cur, Instant::now()),
        None => (cur * 2).min(Duration::from_secs(30)),
    }
}

// ---------------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------------

/// Marker context attached to errors that come from the tunnel side of a link (as opposed to the
/// local SOCKS client or the destination), so a censor-style kill can be told apart from a user
/// closing a tab.
#[derive(Debug)]
pub struct TunnelSide;
impl std::fmt::Display for TunnelSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tunnel link")
    }
}
impl std::error::Error for TunnelSide {}

/// True only for *hard* tunnel-side deaths (RST / abort / timeout). A clean FIN without the
/// in-band end marker is usually the destination closing, so it is not counted.
pub fn is_hard_tunnel_death(e: &anyhow::Error) -> bool {
    if e.downcast_ref::<TunnelSide>().is_none() {
        return false;
    }
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::TimedOut
            )
        })
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Condition {
    Normal = 0,
    Degraded = 1,
    Hostile = 2,
    Blackout = 3,
    Recovering = 4,
}

impl Condition {
    pub fn as_str(self) -> &'static str {
        match self {
            Condition::Normal => "normal",
            Condition::Degraded => "degraded",
            Condition::Hostile => "hostile",
            Condition::Blackout => "blackout",
            Condition::Recovering => "recovering",
        }
    }
    fn severity(self) -> u8 {
        match self {
            Condition::Normal => 0,
            Condition::Degraded | Condition::Recovering => 1,
            Condition::Hostile => 2,
            Condition::Blackout => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Connect,
    Handshake,
}

/// Failure fingerprint of one dial attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Sig {
    /// No SYN-ACK in time: blackhole / IP block / total outage.
    ConnectTimeout = 0,
    /// TCP connected, then silence during the handshake: DPI byte-freeze / throttling.
    HandshakeStall = 1,
    /// Connection reset: active interference.
    EarlyReset = 2,
    /// Peer closed during the handshake (EOF).
    HandshakeClose = 3,
    /// Port actively refused: server/process down.
    Refused = 4,
    /// ENETUNREACH / EHOSTUNREACH: route problem.
    Unreachable = 5,
    Other = 6,
    /// Every exit's circuit breaker is open: nothing was even tried.
    CircuitOpen = 7,
}
const NSIG: usize = 8;
const ALL_SIGS: [Sig; NSIG] = [
    Sig::ConnectTimeout,
    Sig::HandshakeStall,
    Sig::EarlyReset,
    Sig::HandshakeClose,
    Sig::Refused,
    Sig::Unreachable,
    Sig::Other,
    Sig::CircuitOpen,
];

impl Sig {
    pub fn as_str(self) -> &'static str {
        match self {
            Sig::ConnectTimeout => "connect_timeout",
            Sig::HandshakeStall => "handshake_stall",
            Sig::EarlyReset => "early_reset",
            Sig::HandshakeClose => "handshake_close",
            Sig::Refused => "refused",
            Sig::Unreachable => "unreachable",
            Sig::Other => "other",
            Sig::CircuitOpen => "circuit_open",
        }
    }

    /// Typed classification (walks the error chain, no string matching).
    pub fn from_error(err: &anyhow::Error, stage: Stage) -> Sig {
        let timeout_sig = match stage {
            Stage::Connect => Sig::ConnectTimeout,
            Stage::Handshake => Sig::HandshakeStall,
        };
        for cause in err.chain() {
            if cause.downcast_ref::<tokio::time::error::Elapsed>().is_some() {
                return timeout_sig;
            }
            if let Some(io) = cause.downcast_ref::<std::io::Error>() {
                if matches!(io.raw_os_error(), Some(101) | Some(113)) {
                    return Sig::Unreachable;
                }
                return match io.kind() {
                    ErrorKind::ConnectionRefused => Sig::Refused,
                    ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe => Sig::EarlyReset,
                    ErrorKind::UnexpectedEof => Sig::HandshakeClose,
                    ErrorKind::TimedOut => timeout_sig,
                    _ => Sig::Other,
                };
            }
        }
        Sig::Other
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Event {
    DialOk { rtt: Duration },
    DialFail { sig: Sig },
    /// Time a client spent waiting for a pooled link, and whether it got one.
    Acquire { wait: Duration, ok: bool },
    /// A pooled link was dead/stale when used (idle-kill evidence).
    AcquireDead { age: Duration },
    /// An in-use link died with a hard tunnel-side error.
    LinkDied { age: Duration },
    /// An in-use link ended cleanly.
    LinkClean,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tuning {
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub pool_target: usize,
    pub max_age: Duration,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// 1 = single dial, 2 = hedged dial (two exits/attempts in parallel, first success wins).
    pub hedge: u8,
    pub acquire_deadline: Duration,
}

#[derive(Clone, Debug)]
pub struct AdaptCfg {
    pub enabled: bool,
    pub base_pool: usize,
    pub pool_max: usize,
    pub base_max_age: Duration,
    pub state_path: Option<String>,
}

pub const B_POOL_STARVED: u8 = 1;
pub const B_EXIT_SLOW: u8 = 2;
pub const B_STALE_POOL: u8 = 4;
pub const B_SOCKS_SATURATED: u8 = 8;

pub fn bottleneck_names(mask: u8) -> Vec<&'static str> {
    let mut v = Vec::new();
    if mask & B_POOL_STARVED != 0 {
        v.push("pool_starved");
    }
    if mask & B_EXIT_SLOW != 0 {
        v.push("exit_slow");
    }
    if mask & B_STALE_POOL != 0 {
        v.push("stale_pool");
    }
    if mask & B_SOCKS_SATURATED != 0 {
        v.push("socks_saturated");
    }
    v
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Learned {
    /// Links die at about this age (seconds): rotate before it.
    pub kill_age_s: Option<u32>,
    /// Outages start every ~period seconds.
    pub outage_period_s: Option<u32>,
    /// Outages last about this many seconds.
    pub outage_len_s: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Load {
    pub streams_active: i64,
    pub socks_cap: usize,
}

#[derive(Clone, Copy, Default)]
struct Bucket {
    sec: u64,
    used: bool,
    dial_ok: u32,
    dial_fail: u32,
    sig: [u32; NSIG],
    rtt_sum_ms: u64,
    acq: u32,
    acq_wait_ms: u64,
    acq_fail: u32,
    acq_dead: u32,
    died: u32,
    clean: u32,
}

#[derive(Default)]
struct Win {
    dial_ok: u32,
    dial_fail: u32,
    sig: [u32; NSIG],
    rtt_sum_ms: u64,
    acq: u32,
    acq_wait_ms: u64,
    acq_fail: u32,
    acq_dead: u32,
    died: u32,
    clean: u32,
}

struct Inner {
    t0: Instant,
    buckets: [Bucket; NB],
    cond: Condition,
    calm: u32,
    idle: u32,
    ramp: usize,
    rec_ticks: u32,
    extra_pool: usize,
    starved_free: u32,
    baseline_rtt_ms: f64,
    ages: VecDeque<(Instant, f64)>,
    outage_start: Option<Instant>,
    episodes: VecDeque<(Instant, f64)>,
    learned: Learned,
    dirty: bool,
    mask: u8,
    dominant: Option<Sig>,
    tuning: Tuning,
}

impl Inner {
    fn bucket_mut(&mut self, sec: u64) -> &mut Bucket {
        let b = &mut self.buckets[(sec % NB as u64) as usize];
        if !b.used || b.sec != sec {
            *b = Bucket::default();
            b.sec = sec;
            b.used = true;
        }
        b
    }

    fn window(&self, now_sec: u64) -> Win {
        self.window_n(now_sec, WINDOW_SECS)
    }

    fn window_n(&self, now_sec: u64, span: u64) -> Win {
        let mut w = Win::default();
        let from = now_sec.saturating_sub(span - 1);
        for s in from..=now_sec {
            let b = &self.buckets[(s % NB as u64) as usize];
            if !b.used || b.sec != s {
                continue;
            }
            w.dial_ok += b.dial_ok;
            w.dial_fail += b.dial_fail;
            for i in 0..NSIG {
                w.sig[i] += b.sig[i];
            }
            w.rtt_sum_ms += b.rtt_sum_ms;
            w.acq += b.acq;
            w.acq_wait_ms += b.acq_wait_ms;
            w.acq_fail += b.acq_fail;
            w.acq_dead += b.acq_dead;
            w.died += b.died;
            w.clean += b.clean;
        }
        w
    }

    fn forgive_failures(&mut self) {
        for b in self.buckets.iter_mut() {
            b.dial_fail = 0;
            b.sig = [0; NSIG];
            b.acq_fail = 0;
            b.acq_dead = 0;
            b.died = 0;
        }
    }

    fn push_age(&mut self, now: Instant, age: Duration) {
        if self.ages.len() >= AGE_SAMPLE_CAP {
            self.ages.pop_front();
        }
        self.ages.push_back((now, age.as_secs_f64()));
    }
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    if n == 0 {
        0.0
    } else if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// Returns the cluster centre if the samples are tightly grouped (median absolute deviation
/// within `rel_tol` of the median). This is what separates "a censor kills links at ~100 s" from
/// random deaths.
fn tight_cluster(samples: &[f64], min_n: usize, rel_tol: f64) -> Option<f64> {
    if samples.len() < min_n {
        return None;
    }
    let mut a = samples.to_vec();
    let m = median(&mut a);
    if m <= 0.0 {
        return None;
    }
    let mut d: Vec<f64> = samples.iter().map(|x| (x - m).abs()).collect();
    let mad = median(&mut d);
    (mad <= rel_tol * m).then_some(m)
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}
fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Pool target of a condition *without* bottleneck growth.
fn pool_for(base: usize, cond: Condition) -> usize {
    let base = base.max(1);
    match cond {
        Condition::Normal | Condition::Degraded | Condition::Recovering => base,
        Condition::Hostile => (base * 3 / 2).max(base + 1),
        Condition::Blackout => 2.min(base),
    }
}

fn compute_tuning(cfg: &AdaptCfg, g: &Inner) -> Tuning {
    let base = cfg.base_pool.max(1);
    let maxp = cfg.pool_max.max(base);
    let age0 = cfg.base_max_age;
    let (conn, hs, mut age, bmin, bmax, mut hedge, dl) = match g.cond {
        Condition::Normal => (secs(10), secs(10), age0, ms(500), secs(30), 1u8, secs(20)),
        Condition::Degraded => (secs(15), secs(15), age0.min(secs(90)), ms(500), secs(15), 1, secs(25)),
        Condition::Hostile => (secs(6), secs(6), age0.min(secs(45)), ms(250), secs(8), 2, secs(30)),
        Condition::Blackout => (secs(5), secs(5), age0, secs(1), secs(10), 2, secs(8)),
        Condition::Recovering => (secs(8), secs(8), age0, ms(250), secs(4), 2, secs(20)),
    };
    let (mut conn, mut hs, mut bmin) = (conn, hs, bmin);

    let mut pool = match g.cond {
        Condition::Recovering => g.ramp,
        Condition::Blackout => pool_for(base, g.cond),
        c => pool_for(base, c) + g.extra_pool,
    };

    // Learned: links die at a consistent age -> rotate before it.
    if let Some(k) = g.learned.kill_age_s {
        let safe = secs(((k as f64 * 0.75) as u64).max(15));
        age = age.min(safe);
    }
    // Idle-kill evidence (pooled links found dead): keep the pool fresh.
    if g.mask & B_STALE_POOL != 0 {
        age = age.min(secs(30)).max(secs(10));
    }
    // Dominant failure signature picks the recovery style.
    if g.cond != Condition::Normal {
        match g.dominant {
            Some(Sig::HandshakeStall) => {
                hs = hs.min(secs(5));
                hedge = hedge.max(2);
            }
            Some(Sig::EarlyReset) | Some(Sig::HandshakeClose) => hedge = hedge.max(2),
            Some(Sig::Refused) | Some(Sig::Unreachable) => bmin = bmin.max(secs(2)),
            Some(Sig::ConnectTimeout) => conn = conn.min(secs(8)),
            _ => {}
        }
    }
    pool = pool.clamp(1, maxp);
    Tuning {
        connect_timeout: conn,
        handshake_timeout: hs,
        pool_target: pool,
        max_age: age.max(secs(10)),
        backoff_min: bmin,
        backoff_max: bmax.max(bmin),
        hedge,
        acquire_deadline: dl,
    }
}

// ---------------------------------------------------------------------------------------------
// Adapt
// ---------------------------------------------------------------------------------------------

pub struct Adapt {
    cfg: AdaptCfg,
    inner: Mutex<Inner>,
}

impl Adapt {
    pub fn new(cfg: AdaptCfg) -> Arc<Adapt> {
        Self::with_clock(cfg, Instant::now())
    }

    pub fn with_clock(cfg: AdaptCfg, t0: Instant) -> Arc<Adapt> {
        let mut g = Inner {
            t0,
            buckets: [Bucket::default(); NB],
            cond: Condition::Normal,
            calm: 0,
            idle: 0,
            ramp: 1,
            rec_ticks: 0,
            extra_pool: 0,
            starved_free: 0,
            baseline_rtt_ms: 0.0,
            ages: VecDeque::new(),
            outage_start: None,
            episodes: VecDeque::new(),
            learned: Learned::default(),
            dirty: false,
            mask: 0,
            dominant: None,
            tuning: Tuning {
                connect_timeout: secs(10),
                handshake_timeout: secs(10),
                pool_target: cfg.base_pool.max(1),
                max_age: cfg.base_max_age,
                backoff_min: ms(500),
                backoff_max: secs(30),
                hedge: 1,
                acquire_deadline: secs(20),
            },
        };
        if cfg.enabled {
            if let Some(p) = &cfg.state_path {
                if let Some(l) = load_state(p) {
                    g.learned = l;
                }
            }
        }
        g.tuning = compute_tuning(&cfg, &g);
        let a = Arc::new(Adapt { cfg, inner: Mutex::new(g) });
        a.publish(&a.inner.lock().unwrap());
        a
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    pub fn tuning(&self) -> Tuning {
        self.inner.lock().unwrap().tuning
    }

    pub fn condition(&self) -> Condition {
        self.inner.lock().unwrap().cond
    }

    pub fn learned(&self) -> Learned {
        self.inner.lock().unwrap().learned
    }

    pub fn bottlenecks(&self) -> u8 {
        self.inner.lock().unwrap().mask
    }

    pub fn record(&self, ev: Event) {
        self.record_at(ev, Instant::now());
    }

    pub fn record_at(&self, ev: Event, now: Instant) {
        if !self.cfg.enabled {
            return;
        }
        let mut g = self.inner.lock().unwrap();
        let sec = now.saturating_duration_since(g.t0).as_secs();
        match ev {
            Event::AcquireDead { age } | Event::LinkDied { age } => g.push_age(now, age),
            _ => {}
        }
        let b = g.bucket_mut(sec);
        match ev {
            Event::DialOk { rtt } => {
                b.dial_ok += 1;
                b.rtt_sum_ms += rtt.as_millis() as u64;
            }
            Event::DialFail { sig } => {
                b.dial_fail += 1;
                b.sig[sig as usize] += 1;
            }
            Event::Acquire { wait, ok } => {
                b.acq += 1;
                b.acq_wait_ms += wait.as_millis() as u64;
                if !ok {
                    b.acq_fail += 1;
                }
            }
            Event::AcquireDead { .. } => b.acq_dead += 1,
            Event::LinkDied { .. } => b.died += 1,
            Event::LinkClean => b.clean += 1,
        }
    }

    /// Backoff to sleep after a failed dial. Exponential inside the condition's bounds, but dense
    /// (1 s) around the *predicted end* of an outage when a repeatable outage length is known.
    pub fn next_backoff(&self, cur: Duration, now: Instant) -> Duration {
        let g = self.inner.lock().unwrap();
        let t = g.tuning;
        let mut next = (cur * 2).clamp(t.backoff_min, t.backoff_max);
        if g.cond == Condition::Blackout {
            if let (Some(start), Some(len)) = (g.outage_start, g.learned.outage_len_s) {
                let el = now.saturating_duration_since(start).as_secs_f64();
                let len = len as f64;
                if el >= len * 0.8 - 2.0 && el <= len * 1.5 + 5.0 {
                    next = secs(1).max(t.backoff_min);
                }
            }
        }
        // +-20 % jitter so parallel dialers do not probe in lockstep.
        let j = crate::util::rand_range(80, 120) as f64 / 100.0;
        next.mul_f64(j).max(ms(100))
    }

    /// Seconds until the next outage is expected (only if a periodic pattern is known).
    pub fn predicted_next_outage_in(&self, now: Instant) -> Option<u64> {
        let g = self.inner.lock().unwrap();
        let period = g.learned.outage_period_s? as f64;
        let last = g.episodes.back()?.0;
        let since = now.saturating_duration_since(last).as_secs_f64();
        let mut left = period - since;
        while left < 0.0 {
            left += period;
        }
        Some(left as u64)
    }

    /// One control step (call every `TICK`). Returns human-readable log lines for transitions,
    /// learned patterns and bottleneck changes.
    pub fn tick_at(&self, now: Instant, load: Load) -> Vec<String> {
        let mut logs = Vec::new();
        if !self.cfg.enabled {
            return logs;
        }
        let mut g = self.inner.lock().unwrap();
        let now_sec = now.saturating_duration_since(g.t0).as_secs();
        let w = g.window(now_sec);
        let rw = g.window_n(now_sec, RECENT_SECS);
        let base = self.cfg.base_pool.max(1);
        let maxp = self.cfg.pool_max.max(base);

        let dials = w.dial_ok + w.dial_fail;
        let ended = w.died + w.clean;
        let events = dials + w.acq + w.acq_dead + ended;
        let rtt_avg = if w.dial_ok > 0 { w.rtt_sum_ms as f64 / w.dial_ok as f64 } else { 0.0 };
        if rtt_avg > 0.0 {
            if g.baseline_rtt_ms == 0.0 || rtt_avg < g.baseline_rtt_ms {
                g.baseline_rtt_ms = rtt_avg;
            } else if g.cond == Condition::Normal {
                g.baseline_rtt_ms = g.baseline_rtt_ms * 0.98 + rtt_avg * 0.02;
            }
        }
        let full_ratio = if dials > 0 { w.dial_fail as f64 / dials as f64 } else { 0.0 };
        let r_dials = rw.dial_ok + rw.dial_fail;
        // Prefer fresh evidence once there is enough of it, so a recent collapse is not diluted by
        // older successes (and a recovery is not dragged down by older failures).
        let fail_ratio = if r_dials >= 4 { rw.dial_fail as f64 / r_dials as f64 } else { full_ratio };
        let hostile_sigs = w.sig[Sig::HandshakeStall as usize]
            + w.sig[Sig::EarlyReset as usize]
            + w.sig[Sig::HandshakeClose as usize];
        let died_ratio = if ended > 0 { w.died as f64 / ended as f64 } else { 0.0 };

        let raw = if rw.dial_ok == 0 && rw.dial_fail >= 3 {
            Condition::Blackout
        } else if (dials >= 4 && fail_ratio >= 0.5)
            || (w.dial_fail >= 3 && hostile_sigs >= 3 && fail_ratio >= 0.25 && hostile_sigs as f64 >= 0.4 * w.dial_fail as f64)
            || (w.died >= 5 && died_ratio >= 0.3)
        {
            Condition::Hostile
        } else if (dials >= 4 && fail_ratio >= 0.15)
            || (g.baseline_rtt_ms > 0.0 && w.dial_ok >= 2 && rtt_avg >= 2.5 * g.baseline_rtt_ms)
            || (w.died >= 3 && died_ratio >= 0.15)
        {
            Condition::Degraded
        } else {
            Condition::Normal
        };

        g.dominant = if w.dial_fail >= 3 {
            ALL_SIGS
                .iter()
                .copied()
                .max_by_key(|s| w.sig[*s as usize])
                .filter(|s| w.sig[*s as usize] > 0)
        } else {
            None
        };

        // ---- decision engine: condition state machine -------------------------------------
        let prev = g.cond;
        let mut next = prev;
        if events == 0 {
            g.idle += 1;
            if g.idle >= 30 && prev != Condition::Normal && prev != Condition::Blackout {
                next = Condition::Normal;
                g.idle = 0;
            }
        } else {
            g.idle = 0;
            match prev {
                Condition::Blackout => {
                    if raw != Condition::Blackout {
                        next = Condition::Recovering;
                        g.rec_ticks = 0;
                        g.ramp = 2.min(pool_for(base, raw).max(1));
                    }
                }
                Condition::Recovering => {
                    if raw == Condition::Blackout {
                        next = Condition::Blackout;
                    } else {
                        g.rec_ticks += 1;
                        let target = pool_for(base, raw);
                        g.ramp = (g.ramp * 2).min(target).max(1);
                        if g.ramp >= target && g.rec_ticks >= 2 {
                            next = raw;
                            g.calm = 0;
                        }
                    }
                }
                _ => {
                    if raw == Condition::Blackout || raw.severity() > prev.severity() {
                        next = raw;
                        g.calm = 0;
                    } else if raw.severity() < prev.severity() {
                        g.calm += 1;
                        if g.calm >= 3 {
                            next = if prev == Condition::Hostile { Condition::Degraded } else { Condition::Normal };
                            g.calm = 0;
                        }
                    } else {
                        g.calm = 0;
                    }
                }
            }
        }
        if next == Condition::Blackout && prev != Condition::Blackout {
            g.outage_start = Some(now);
        }
        if prev == Condition::Blackout && next != Condition::Blackout {
            if let Some(s) = g.outage_start.take() {
                let dur = now.saturating_duration_since(s).as_secs_f64();
                if g.episodes.len() >= EPISODE_CAP {
                    g.episodes.pop_front();
                }
                g.episodes.push_back((s, dur));
                BLACKOUT_SECS.fetch_add(dur as u64, Relaxed);
                RECOVERIES.fetch_add(1, Relaxed);
                logs.extend(learn_outage(&mut g));
            }
            g.forgive_failures();
        }
        if next != prev {
            TRANSITIONS.fetch_add(1, Relaxed);
            logs.push(format!(
                "[adapt] condition {} -> {} (dials ok/fail {}/{}, rtt {:.0}ms, died {}/{}, dominant failure: {})",
                prev.as_str(),
                next.as_str(),
                w.dial_ok,
                w.dial_fail,
                rtt_avg,
                w.died,
                ended,
                g.dominant.map_or("none", |s| s.as_str()),
            ));
        }
        g.cond = next;

        // ---- bottleneck detection & resolution --------------------------------------------
        let wait_avg = if w.acq > 0 { w.acq_wait_ms as f64 / w.acq as f64 } else { 0.0 };
        // `starved_wait`: clients really waited for a link (scarcity -> grow the pool).
        // Plain acquire failures alone (dead path) are a blackout/hostility symptom, not scarcity.
        let starved_wait = w.acq >= 3 && wait_avg >= 300.0;
        let starved = starved_wait || (w.acq >= 3 && w.acq_fail >= 1);
        let exit_slow = g.baseline_rtt_ms > 0.0 && w.dial_ok >= 2 && rtt_avg >= 3.0 * g.baseline_rtt_ms;
        let stale = w.acq_dead >= 3;
        let socks_sat = load.socks_cap > 0 && (load.streams_active as f64) >= 0.85 * load.socks_cap as f64;
        let mut mask = 0u8;
        if starved {
            mask |= B_POOL_STARVED;
        }
        if exit_slow {
            mask |= B_EXIT_SLOW;
        }
        if stale {
            mask |= B_STALE_POOL;
        }
        if socks_sat {
            mask |= B_SOCKS_SATURATED;
        }
        let growth_ok = next != Condition::Blackout && next != Condition::Recovering && fail_ratio < 0.3 && !exit_slow;
        let extra_before = g.extra_pool;
        if starved_wait && growth_ok {
            let room = maxp.saturating_sub(pool_for(base, next) + g.extra_pool);
            g.extra_pool += (base / 2).max(2).min(room);
            g.starved_free = 0;
        } else if !starved_wait {
            g.starved_free += 1;
            if g.starved_free >= 10 && g.starved_free % 2 == 0 {
                g.extra_pool = g.extra_pool.saturating_sub(1);
            }
        }
        if mask != g.mask {
            let names = bottleneck_names(mask);
            logs.push(format!(
                "[adapt] bottleneck: {}",
                if names.is_empty() { "cleared".to_string() } else { names.join("+") }
            ));
            if mask & B_SOCKS_SATURATED != 0 {
                logs.push(format!(
                    "[adapt] SOCKS connections at {}/{} (>=85%): clients will start to be refused",
                    load.streams_active, load.socks_cap
                ));
            }
            if mask & B_EXIT_SLOW != 0 {
                logs.push("[adapt] exit handshake RTT >= 3x baseline: pool growth frozen (not hammering a slow exit)".to_string());
            }
        }
        if g.extra_pool != extra_before {
            logs.push(format!("[adapt] pool growth +{} (clients waited {:.0} ms for a link)", g.extra_pool - extra_before, wait_avg));
        }
        g.mask = mask;

        // ---- pattern learning --------------------------------------------------------------
        logs.extend(learn_age(&mut g, now));

        g.tuning = compute_tuning(&self.cfg, &g);
        self.publish(&g);
        logs
    }

    fn publish(&self, g: &Inner) {
        CONDITION.store(g.cond as i64, Relaxed);
        POOL_TARGET.store(g.tuning.pool_target as i64, Relaxed);
        BOTTLENECKS.store(g.mask as i64, Relaxed);
        KILL_AGE_S.store(g.learned.kill_age_s.map_or(-1, |v| v as i64), Relaxed);
        OUTAGE_PERIOD_S.store(g.learned.outage_period_s.map_or(-1, |v| v as i64), Relaxed);
        OUTAGE_LEN_S.store(g.learned.outage_len_s.map_or(-1, |v| v as i64), Relaxed);
    }

    /// If learned patterns changed, returns `(path, text)` to persist (IO is done by the caller,
    /// outside the lock).
    pub fn take_dirty_state(&self) -> Option<(String, String)> {
        let mut g = self.inner.lock().unwrap();
        if !g.dirty {
            return None;
        }
        g.dirty = false;
        let path = self.cfg.state_path.clone()?;
        Some((path, render_state(&g.learned)))
    }

    pub fn status_json(&self) -> String {
        let g = self.inner.lock().unwrap();
        let t = g.tuning;
        let opt = |v: Option<u32>| v.map_or("null".to_string(), |x| x.to_string());
        format!(
            "{{\"ok\":true,\"enabled\":{},\"condition\":\"{}\",\"dominant_failure\":{},\"bottlenecks\":[{}],\"learned\":{{\"kill_age_s\":{},\"outage_period_s\":{},\"outage_len_s\":{}}},\"tuning\":{{\"pool_target\":{},\"connect_timeout_ms\":{},\"handshake_timeout_ms\":{},\"max_age_s\":{},\"backoff_min_ms\":{},\"backoff_max_ms\":{},\"hedge\":{},\"acquire_deadline_ms\":{}}},\"recoveries\":{},\"blackout_seconds\":{}}}\n",
            self.cfg.enabled,
            g.cond.as_str(),
            g.dominant.map_or("null".to_string(), |s| format!("\"{}\"", s.as_str())),
            bottleneck_names(g.mask).iter().map(|n| format!("\"{n}\"")).collect::<Vec<_>>().join(","),
            opt(g.learned.kill_age_s),
            opt(g.learned.outage_period_s),
            opt(g.learned.outage_len_s),
            t.pool_target,
            t.connect_timeout.as_millis(),
            t.handshake_timeout.as_millis(),
            t.max_age.as_secs(),
            t.backoff_min.as_millis(),
            t.backoff_max.as_millis(),
            t.hedge,
            t.acquire_deadline.as_millis(),
            RECOVERIES.load(Relaxed),
            BLACKOUT_SECS.load(Relaxed),
        )
    }
}

/// Links die at a consistent age -> remember it (and forget it if later evidence contradicts it).
fn learn_age(g: &mut Inner, now: Instant) -> Vec<String> {
    while g.ages.front().is_some_and(|(t, _)| now.saturating_duration_since(*t) > AGE_SAMPLE_TTL) {
        g.ages.pop_front();
    }
    let vals: Vec<f64> = g.ages.iter().map(|(_, a)| *a).collect();
    let mut logs = Vec::new();
    let before = g.learned.kill_age_s;
    match tight_cluster(&vals, 6, 0.2) {
        Some(m) if m >= 3.0 => g.learned.kill_age_s = Some(m.round() as u32),
        None if vals.len() >= 12 => g.learned.kill_age_s = None,
        _ => {}
    }
    if g.learned.kill_age_s != before {
        g.dirty = true;
        match g.learned.kill_age_s {
            Some(k) => logs.push(format!("[adapt] pattern: links are killed at ~{k}s of age -> rotating links at {}s", ((k as f64 * 0.75) as u64).max(15))),
            None => logs.push("[adapt] pattern: link-kill age pattern no longer holds, forgotten".to_string()),
        }
    }
    logs
}

/// Periodic / repeatable outages -> remember period and length.
fn learn_outage(g: &mut Inner) -> Vec<String> {
    let before = g.learned;
    let lens: Vec<f64> = g.episodes.iter().map(|e| e.1).collect();
    if lens.len() >= 2 {
        let mut a = lens.clone();
        let m = median(&mut a);
        let mut d: Vec<f64> = lens.iter().map(|x| (x - m).abs()).collect();
        let mad = median(&mut d);
        g.learned.outage_len_s = (m >= 1.0 && mad <= 0.35 * m).then(|| m.round() as u32);
    }
    if g.episodes.len() >= 3 {
        let starts: Vec<Instant> = g.episodes.iter().map(|e| e.0).collect();
        let iv: Vec<f64> = starts.windows(2).map(|w| w[1].saturating_duration_since(w[0]).as_secs_f64()).collect();
        g.learned.outage_period_s = tight_cluster(&iv, 2, 0.25).filter(|p| *p >= 20.0).map(|p| p.round() as u32);
    }
    let mut logs = Vec::new();
    if g.learned != before {
        g.dirty = true;
        logs.push(format!(
            "[adapt] pattern: outage length ~{}s, period ~{}s -> dense probing around the predicted end",
            g.learned.outage_len_s.map_or("?".to_string(), |v| v.to_string()),
            g.learned.outage_period_s.map_or("none".to_string(), |v| v.to_string()),
        ));
    }
    logs
}

// ---------------------------------------------------------------------------------------------
// Persistence of learned patterns
// ---------------------------------------------------------------------------------------------

fn render_state(l: &Learned) -> String {
    let mut s = String::from("# khaymali learned patterns (safe to delete)\n");
    s.push_str(&format!("saved_unix={}\n", crate::util::now_unix()));
    if let Some(v) = l.kill_age_s {
        s.push_str(&format!("kill_age_s={v}\n"));
    }
    if let Some(v) = l.outage_period_s {
        s.push_str(&format!("outage_period_s={v}\n"));
    }
    if let Some(v) = l.outage_len_s {
        s.push_str(&format!("outage_len_s={v}\n"));
    }
    s
}

fn parse_state(text: &str, now_unix: u64) -> Option<Learned> {
    if text.len() > 4096 {
        return None;
    }
    let mut l = Learned::default();
    let mut saved = 0u64;
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let Ok(n) = v.trim().parse::<u64>() else { continue };
        match k.trim() {
            "saved_unix" => saved = n,
            "kill_age_s" if (3..=86_400).contains(&n) => l.kill_age_s = Some(n as u32),
            "outage_period_s" if (20..=86_400).contains(&n) => l.outage_period_s = Some(n as u32),
            "outage_len_s" if (1..=86_400).contains(&n) => l.outage_len_s = Some(n as u32),
            _ => {}
        }
    }
    if saved == 0 || now_unix.saturating_sub(saved) > STATE_MAX_AGE_SECS {
        return None;
    }
    Some(l)
}

fn load_state(path: &str) -> Option<Learned> {
    let text = std::fs::read_to_string(path).ok()?;
    parse_state(&text, crate::util::now_unix())
}

pub fn write_state_atomic(path: &str, text: &str) -> std::io::Result<()> {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

/// Background ticker: runs the control step, logs transitions and persists learned patterns.
pub fn spawn_ticker(a: Arc<Adapt>, socks_cap: usize) {
    if !a.enabled() {
        return;
    }
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(TICK);
        loop {
            iv.tick().await;
            let load = Load { streams_active: crate::stats::STREAMS_ACTIVE.load(Relaxed), socks_cap };
            for line in a.tick_at(Instant::now(), load) {
                eprintln!("{line}");
            }
            if let Some((p, t)) = a.take_dirty_state() {
                if let Err(e) = write_state_atomic(&p, &t) {
                    crate::stats::log_err_rl(&format!("[adapt] cannot save patterns to {p}: {e}"));
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> AdaptCfg {
        AdaptCfg { enabled: true, base_pool: 8, pool_max: 64, base_max_age: secs(120), state_path: None }
    }
    fn at(t0: Instant, s: u64) -> Instant {
        t0 + secs(s)
    }
    fn load() -> Load {
        Load::default()
    }
    fn fails(a: &Adapt, t0: Instant, s: u64, n: usize, sig: Sig) {
        for _ in 0..n {
            a.record_at(Event::DialFail { sig }, at(t0, s));
        }
    }
    fn oks(a: &Adapt, t0: Instant, s: u64, n: usize, rtt_ms: u64) {
        for _ in 0..n {
            a.record_at(Event::DialOk { rtt: ms(rtt_ms) }, at(t0, s));
        }
    }

    #[tokio::test]
    async fn signature_classification() {
        let rst = anyhow::Error::from(std::io::Error::from(ErrorKind::ConnectionReset));
        assert_eq!(Sig::from_error(&rst, Stage::Handshake), Sig::EarlyReset);
        let refused = anyhow::Error::from(std::io::Error::from(ErrorKind::ConnectionRefused));
        assert_eq!(Sig::from_error(&refused, Stage::Connect), Sig::Refused);
        let eof = anyhow::Error::from(std::io::Error::from(ErrorKind::UnexpectedEof));
        assert_eq!(Sig::from_error(&eof, Stage::Handshake), Sig::HandshakeClose);
        let route = anyhow::Error::from(std::io::Error::from_raw_os_error(101));
        assert_eq!(Sig::from_error(&route, Stage::Connect), Sig::Unreachable);
        let el = tokio::time::timeout(ms(1), std::future::pending::<()>()).await.unwrap_err();
        assert_eq!(Sig::from_error(&anyhow::Error::from(el), Stage::Connect), Sig::ConnectTimeout);
        let el = tokio::time::timeout(ms(1), std::future::pending::<()>()).await.unwrap_err();
        assert_eq!(Sig::from_error(&anyhow::Error::from(el), Stage::Handshake), Sig::HandshakeStall);
        assert_eq!(Sig::from_error(&anyhow::anyhow!("noise decrypt"), Stage::Handshake), Sig::Other);
    }

    #[test]
    fn hard_tunnel_death_needs_marker_and_hard_error() {
        use anyhow::Context;
        let io = |k| -> anyhow::Result<()> { Err(std::io::Error::from(k).into()) };
        let tunnel = io(ErrorKind::ConnectionReset).context(TunnelSide).unwrap_err();
        assert!(is_hard_tunnel_death(&tunnel));
        let clean_eof = io(ErrorKind::UnexpectedEof).context(TunnelSide).unwrap_err();
        assert!(!is_hard_tunnel_death(&clean_eof), "destination closing is not a censor kill");
        let client = io(ErrorKind::ConnectionReset).unwrap_err();
        assert!(!is_hard_tunnel_death(&client), "client-side resets are not tunnel deaths");
    }

    #[test]
    fn blackout_then_slow_start_recovery() {
        let t0 = Instant::now();
        let a = Adapt::with_clock(cfg(), t0);
        assert_eq!(a.condition(), Condition::Normal);
        fails(&a, t0, 1, 5, Sig::ConnectTimeout);
        a.tick_at(at(t0, 2), load());
        assert_eq!(a.condition(), Condition::Blackout);
        let t = a.tuning();
        assert_eq!(t.pool_target, 2, "blackout probes with a tiny pool instead of hammering");
        assert_eq!(t.acquire_deadline, secs(8), "clients must fail fast during a blackout");

        // path comes back
        oks(&a, t0, 5, 3, 80);
        a.tick_at(at(t0, 6), load());
        assert_eq!(a.condition(), Condition::Recovering);
        let mut targets = vec![a.tuning().pool_target];
        let mut s = 8;
        while a.condition() == Condition::Recovering && s < 40 {
            oks(&a, t0, s - 1, 3, 80);
            a.tick_at(at(t0, s), load());
            targets.push(a.tuning().pool_target);
            s += 2;
        }
        assert_eq!(a.condition(), Condition::Normal, "ramp finished: {targets:?}");
        assert!(targets.windows(2).all(|w| w[1] >= w[0]), "pool must ramp up monotonically: {targets:?}");
        assert_eq!(targets[0], 2);
        assert_eq!(a.tuning().pool_target, 8);
    }

    #[test]
    fn fresh_collapse_is_a_blackout_even_after_recent_successes() {
        // Found by tests/chaos.sh: successes from just before the outage sat in the 20 s window and
        // masked the blackout (and the starved pool even grew while the path was dead).
        let t0 = Instant::now();
        let a = Adapt::with_clock(cfg(), t0);
        oks(&a, t0, 1, 10, 60);
        a.tick_at(at(t0, 3), load());
        assert_eq!(a.condition(), Condition::Normal);
        for s in 10..=11u64 {
            fails(&a, t0, s, 3, Sig::Refused);
            for _ in 0..6 {
                a.record_at(Event::Acquire { wait: ms(800), ok: false }, at(t0, s));
            }
        }
        a.tick_at(at(t0, 12), load());
        assert_eq!(a.condition(), Condition::Blackout);
        assert_eq!(a.tuning().pool_target, 2, "no pool growth while the path is dead");
        assert!(a.tuning().backoff_min >= secs(1), "refused/unreachable -> do not hammer");
    }

    #[test]
    fn open_circuits_keep_the_blackout_alive_and_do_not_grow_the_pool() {
        // Found when merging into the LinkPool/burst-dial architecture: once every exit's circuit is
        // open, dials fail without being attempted. Those must still count as failures.
        let t0 = Instant::now();
        let a = Adapt::with_clock(cfg(), t0);
        oks(&a, t0, 1, 10, 60);
        for s in 10..=11u64 {
            fails(&a, t0, s, 2, Sig::CircuitOpen);
            for _ in 0..6 {
                a.record_at(Event::Acquire { wait: ms(0), ok: false }, at(t0, s));
            }
        }
        a.tick_at(at(t0, 12), load());
        assert_eq!(a.condition(), Condition::Blackout);
        assert_eq!(a.tuning().pool_target, 2, "failed acquires with zero wait are not scarcity");
    }

    #[test]
    fn hostile_resets_enable_hedging_and_fail_fast() {
        let t0 = Instant::now();
        let a = Adapt::with_clock(cfg(), t0);
        oks(&a, t0, 1, 4, 80);
        fails(&a, t0, 1, 6, Sig::EarlyReset);
        a.tick_at(at(t0, 2), load());
        assert_eq!(a.condition(), Condition::Hostile);
        let t = a.tuning();
        assert_eq!(t.hedge, 2);
        assert!(t.handshake_timeout <= secs(6));
        assert!(t.max_age <= secs(45));
        assert_eq!(t.pool_target, 12);
    }

    #[test]
    fn handshake_stall_signature_shortens_handshake_patience() {
        let t0 = Instant::now();
        let a = Adapt::with_clock(cfg(), t0);
        oks(&a, t0, 1, 4, 80);
        fails(&a, t0, 1, 6, Sig::HandshakeStall);
        a.tick_at(at(t0, 2), load());
        assert!(a.tuning().handshake_timeout <= secs(5), "waiting on a frozen handshake is wasted time");
    }

    #[test]
    fn deescalation_needs_three_calm_ticks() {
        let t0 = Instant::now();
        let a = Adapt::with_clock(cfg(), t0);
        oks(&a, t0, 1, 4, 80);
        fails(&a, t0, 1, 4, Sig::EarlyReset);
        a.tick_at(at(t0, 2), load());
        assert_eq!(a.condition(), Condition::Hostile);
        // 25 s later the window is clean
        for (i, s) in [30u64, 32, 34].iter().enumerate() {
            oks(&a, t0, s - 1, 4, 80);
            a.tick_at(at(t0, *s), load());
            if i < 2 {
                assert_eq!(a.condition(), Condition::Hostile, "tick {i}: must not flap");
            }
        }
        assert_eq!(a.condition(), Condition::Degraded);
    }

    #[test]
    fn learns_link_kill_age_and_rotates_before_it() {
        let t0 = Instant::now();
        let a = Adapt::with_clock(cfg(), t0);
        for (i, age) in [98u64, 101, 100, 103, 99, 102, 100, 97].iter().enumerate() {
            a.record_at(Event::LinkDied { age: secs(*age) }, at(t0, 1 + i as u64));
        }
        let logs = a.tick_at(at(t0, 10), load());
        let l = a.learned();
        assert_eq!(l.kill_age_s, Some(100), "{logs:?}");
        assert!(a.tuning().max_age <= secs(75), "rotate links before the kill age");
        assert!(a.take_dirty_state().is_none(), "no state path configured -> nothing to persist");
    }

    #[test]
    fn random_death_ages_are_not_a_pattern() {
        let t0 = Instant::now();
        let a = Adapt::with_clock(cfg(), t0);
        for (i, age) in [5u64, 190, 33, 71, 8, 140, 22, 99].iter().enumerate() {
            a.record_at(Event::LinkDied { age: secs(*age) }, at(t0, 1 + i as u64));
        }
        for _ in 0..100 {
            a.record_at(Event::LinkClean, at(t0, 5));
        }
        a.tick_at(at(t0, 10), load());
        assert_eq!(a.learned().kill_age_s, None);
        assert_eq!(a.tuning().max_age, secs(120));
    }

    #[test]
    fn learns_periodic_outage_and_probes_densely_near_its_end() {
        let t0 = Instant::now();
        let a = Adapt::with_clock(cfg(), t0);
        for k in 0..3u64 {
            let b = k * 60;
            fails(&a, t0, b + 1, 5, Sig::ConnectTimeout);
            a.tick_at(at(t0, b + 2), load());
            assert_eq!(a.condition(), Condition::Blackout, "outage {k}");
            oks(&a, t0, b + 21, 3, 80);
            a.tick_at(at(t0, b + 22), load());
            for s in [b + 24, b + 26, b + 28, b + 30, b + 32, b + 34, b + 36] {
                oks(&a, t0, s - 1, 3, 80);
                a.tick_at(at(t0, s), load());
            }
        }
        let l = a.learned();
        assert_eq!(l.outage_len_s, Some(20));
        assert_eq!(l.outage_period_s, Some(60));

        // 4th outage: probing is dense (~1 s) around the predicted end, sparse before it
        let b = 180u64;
        fails(&a, t0, b + 1, 5, Sig::ConnectTimeout);
        a.tick_at(at(t0, b + 2), load());
        assert_eq!(a.condition(), Condition::Blackout);
        let early = a.next_backoff(secs(8), at(t0, b + 3));
        let dense = a.next_backoff(secs(8), at(t0, b + 2 + 19));
        assert!(early >= ms(6400), "early in the outage keep exponential backoff, got {early:?}");
        assert!(dense <= ms(1300), "near the predicted end probe every ~1s, got {dense:?}");
        assert!(a.predicted_next_outage_in(at(t0, b + 30)).is_some());
    }

    #[test]
    fn pool_starvation_grows_pool_and_shrinks_when_calm() {
        let t0 = Instant::now();
        let a = Adapt::with_clock(cfg(), t0);
        let mut grown = 0;
        for s in 1..=8u64 {
            oks(&a, t0, s, 4, 60);
            for _ in 0..6 {
                a.record_at(Event::Acquire { wait: ms(700), ok: true }, at(t0, s));
            }
            a.tick_at(at(t0, s), load());
            grown = a.tuning().pool_target;
        }
        assert!(grown > 8, "starved pool must grow, got {grown}");
        assert!(grown <= 64, "bounded by pool_max");
        assert_ne!(a.bottlenecks() & B_POOL_STARVED, 0);
        for s in 40..=140u64 {
            oks(&a, t0, s, 2, 60);
            for _ in 0..4 {
                a.record_at(Event::Acquire { wait: ms(2), ok: true }, at(t0, s));
            }
            a.tick_at(at(t0, s), load());
        }
        assert_eq!(a.tuning().pool_target, 8, "shrinks back to the base pool");
        assert_eq!(a.bottlenecks() & B_POOL_STARVED, 0);
    }

    #[test]
    fn slow_exit_freezes_growth() {
        let t0 = Instant::now();
        let a = Adapt::with_clock(cfg(), t0);
        for s in 1..=6u64 {
            oks(&a, t0, s, 3, 50);
            a.tick_at(at(t0, s), load());
        }
        let before = a.tuning().pool_target;
        // the exit becomes ~10x slower AND clients start waiting
        for s in 30..=40u64 {
            oks(&a, t0, s, 3, 600);
            for _ in 0..6 {
                a.record_at(Event::Acquire { wait: ms(900), ok: true }, at(t0, s));
            }
            a.tick_at(at(t0, s), load());
        }
        assert_ne!(a.bottlenecks() & B_EXIT_SLOW, 0);
        assert!(a.tuning().pool_target <= before + 1, "must not pile more dials onto a slow exit");
    }

    #[test]
    fn stale_pool_shortens_link_age_and_socks_saturation_is_flagged() {
        let t0 = Instant::now();
        let a = Adapt::with_clock(cfg(), t0);
        for i in 0..4u64 {
            a.record_at(Event::AcquireDead { age: secs(50 + i * 25) }, at(t0, 1));
        }
        a.tick_at(at(t0, 2), Load { streams_active: 900, socks_cap: 1024 });
        let m = a.bottlenecks();
        assert_ne!(m & B_STALE_POOL, 0);
        assert_ne!(m & B_SOCKS_SATURATED, 0);
        assert!(a.tuning().max_age <= secs(30));
    }

    #[test]
    fn user_closing_tabs_is_not_hostility() {
        let t0 = Instant::now();
        let a = Adapt::with_clock(cfg(), t0);
        oks(&a, t0, 1, 10, 60);
        for _ in 0..200 {
            a.record_at(Event::LinkClean, at(t0, 1));
        }
        for _ in 0..4 {
            a.record_at(Event::LinkDied { age: secs(10) }, at(t0, 1));
        }
        a.tick_at(at(t0, 2), load());
        assert_eq!(a.condition(), Condition::Normal, "4 deaths among 204 sessions is noise");
    }

    #[test]
    fn disabled_is_inert_and_static() {
        let t0 = Instant::now();
        let mut c = cfg();
        c.enabled = false;
        let a = Adapt::with_clock(c, t0);
        fails(&a, t0, 1, 10, Sig::EarlyReset);
        assert!(a.tick_at(at(t0, 2), load()).is_empty());
        let t = a.tuning();
        assert_eq!(a.condition(), Condition::Normal);
        assert_eq!((t.pool_target, t.hedge, t.max_age), (8, 1, secs(120)));
    }

    #[test]
    fn state_roundtrip_and_rejects_stale_or_garbage() {
        let l = Learned { kill_age_s: Some(100), outage_period_s: Some(60), outage_len_s: Some(20) };
        let text = render_state(&l);
        let now = crate::util::now_unix();
        assert_eq!(parse_state(&text, now), Some(l));
        assert_eq!(parse_state(&text, now + STATE_MAX_AGE_SECS + 10), None, "old knowledge is dropped");
        assert_eq!(parse_state("kill_age_s=999999999\nsaved_unix=1", now), None);
        assert_eq!(parse_state(&"x".repeat(5000), now), None);
        let bad = format!("saved_unix={now}\nkill_age_s=1\noutage_period_s=5\n");
        assert_eq!(parse_state(&bad, now), Some(Learned::default()), "out-of-range values ignored");
    }

    #[test]
    fn learned_patterns_are_loaded_at_startup() {
        let dir = std::env::temp_dir().join(format!("khaymali-adapt-{}", crate::util::now_unix()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("adapt.state").to_string_lossy().to_string();
        let l = Learned { kill_age_s: Some(80), outage_period_s: None, outage_len_s: Some(15) };
        write_state_atomic(&p, &render_state(&l)).unwrap();
        let mut c = cfg();
        c.state_path = Some(p);
        let a = Adapt::new(c);
        assert_eq!(a.learned(), l);
        assert!(a.tuning().max_age <= secs(60), "a restart keeps the knowledge");
        let _ = std::fs::remove_dir_all(dir);
    }
}
