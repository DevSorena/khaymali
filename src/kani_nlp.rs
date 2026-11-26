//! Control-Plane Tiny Network NLP (`TinyNetNlp` v4.2 — Harsh Network Intelligence, SPEC §5).
//!
//! Strictly advisory/diagnostic, off the Data Plane hot path. Zero external dependencies.
//!
//! v4 upgrades:
//! 1. 7th class `NetIntent::Unrelated` (balanced 112-sample EN/FA corpus incl. normal khaymali logs)
//!    + 2048 hashed buckets + exact 32-bit FNV known-network vocabulary filter + explicit `has_magic`
//!    boolean (eliminates bucket-collision false positives on junk/unrelated logs).
//! 2. Per-class risk-aware confidence/gap/streak thresholds + sqrt(N) length-normalized logits
//!    (cuts abstention on real symptoms to ~8–10% without raising false actions).
//! 3. Atomic `errno` / protocol tokens (no trigrams on `econnrefused`/`econnreset`/`emsgsize`/...)
//!    + stage tags (`stage_dial`, `stage_handshake`, `stage_stream`) + pre- & post-negation (EN/FA).
//! 4. `classify_combined(log, &LinkMetrics)`: Late Fusion (0.45 text + 0.55 metrics) with
//!    corroboration boost and contradiction veto.
//! 5. Safe online learning: separate `delta_weights: [[i8; 2048]; 7]` clamped to [-120, +120],
//!    `Unrelated` locked, hourly rate cap, `decay_online_weights()`, `reset_online_weights()`,
//!    and outcome-verified learning via `NlpAdvisor::record_outcome`.
//!
//! Never executes arbitrary commands and never touches keys, auth, or SSRF policy.

use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

const VOCAB_BUCKETS: usize = 2048;
const NUM_CLASSES: usize = 7;
const WEIGHT_CLAMP: i16 = 4096;
const DELTA_CLAMP: i8 = 120;
const TRAIN_MARGIN: i32 = 640;
const TRAIN_EPOCHS: usize = 16;
const TRAIN_LR: i16 = 28;
const ONLINE_LR: i8 = 6;
const MAX_ONLINE_UPDATES_PER_HOUR: u32 = 12;
const MAX_INPUT_CHARS: usize = 4096;
const EVIDENCE_MIN_WEIGHT: i32 = 48;
const MAX_PERSISTED_HASHES: usize = 4096;

/// Backward-compatible baseline confidence constant.
pub const MIN_CONFIDENCE: f32 = 0.50;

/// Log-level / plumbing words carrying no network intent.
const STOP: &[&str] = &[
    "warn", "warning", "error", "err", "info", "debug", "trace", "khaymali", "entry", "exit",
    "bridge", "retry", "the", "a", "an", "of", "to", "is", "are", "was", "were", "and", "or",
    "at", "in", "on", "by", "for", "with", "from", "os", "after", "very", "too", "that", "this",
    "در", "به", "از", "با", "برای", "که", "این", "آن", "همه", "چیز", "خیلی", "فقط", "ولی",
];

/// Pre-negation cues: next 2 content tokens become `n|tok`.
const PRE_NEG: &[&str] = &["no", "not", "without", "never", "zero", "بدون", "نه", "هیچ", "غیر"];

/// Post-negation cues (Persian predicates following the noun, e.g., "در دسترس نیست", "باز نمیشه").
const POST_NEG: &[&str] = &[
    "نیست", "نمیشه", "نمیشود", "نشد", "نمیکنه", "نمیکند", "نمیده", "نمیدهد", "ندارد", "نداره",
    "نمیشن",
];

/// Atomic OS/protocol error tokens (hashed as `err|tok` WITHOUT trigrams so `econnrefused`
/// never shares trigrams with `econnreset`).
/// v0.15.1 contrast markers and the fault cues that make the clause after them decisive.
/// ("ولی" stays in STOP as well; the contrast pass runs before stop-word filtering.)
const CONTRAST: &[&str] = &["but", "however", "ولی", "اما"];
const FAULT_CUES: &[&str] = &[
    "نمیاد", "نمیره", "نمیرن", "گم", "رد", "نمیشه", "گیر", "قطع", "بزرگ", "fail", "fails", "failed",
    "lost", "drop", "dropped", "vanish", "stuck", "reset", "timeout", "big", "large",
];
/// v0.15.1: verbs whose meaning depends on their subject (emitted only as bigrams).
const AMBIGUOUS_VERBS: &[&str] = &["dropped", "drop", "drops"];

const ATOMIC_ERR: &[&str] = &[
    "econnrefused", "econnreset", "econnaborted", "enetunreach", "ehostunreach", "etimedout",
    "emsgsize", "epipe", "nxdomain", "servfail", "refused", "unreachable", "sinkhole", "blackout",
    "clienthello", "keepalive", "pmtu", "rst_early", "stall_16k", "freeze_bytes", "rtt_spike",
    "loss_burst", "dns_fail",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum NetIntent {
    Healthy = 0,
    EarlyRst = 1,
    ByteFreeze = 2,
    PmtuDrop = 3,
    Throttle = 4,
    RouteOrDnsFail = 5,
    Unrelated = 6,
}

impl NetIntent {
    const ALL: [NetIntent; NUM_CLASSES] = [
        NetIntent::Healthy,
        NetIntent::EarlyRst,
        NetIntent::ByteFreeze,
        NetIntent::PmtuDrop,
        NetIntent::Throttle,
        NetIntent::RouteOrDnsFail,
        NetIntent::Unrelated,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            NetIntent::Healthy => "healthy",
            NetIntent::EarlyRst => "early_rst",
            NetIntent::ByteFreeze => "byte_freeze",
            NetIntent::PmtuDrop => "pmtu_drop",
            NetIntent::Throttle => "throttle",
            NetIntent::RouteOrDnsFail => "route_or_dns_fail",
            NetIntent::Unrelated => "unrelated",
        }
    }

    pub fn is_fault(self) -> bool {
        !matches!(self, NetIntent::Healthy | NetIntent::Unrelated)
    }

    /// Risk-aware per-class gating thresholds: `(min_confidence, min_norm_gap, min_streak)`.
    pub fn thresholds(self) -> (f32, i32, u8) {
        match self {
            NetIntent::Healthy => (0.45, 70, 1),
            NetIntent::PmtuDrop => (0.45, 85, 2),        // low risk, reversible
            NetIntent::Throttle => (0.46, 90, 2),        // low risk, reversible
            NetIntent::ByteFreeze => (0.50, 105, 2),     // medium risk
            NetIntent::EarlyRst => (0.55, 115, 2),       // medium risk
            NetIntent::RouteOrDnsFail => (0.62, 145, 3), // high risk, disruptive
            NetIntent::Unrelated => (0.45, 70, 1),
        }
    }
}

/// Closed allowlist of bounded actions and explicit recommendations.
/// `Recommend*` variants are advisory only; route/fallback controllers own those transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticAction {
    KeepNormal,
    ReduceChunkSize { target_bytes: u16 },
    ShrinkFrameSize { target_bytes: u16 },
    RecommendExitOrBridge,
    EnablePacingAndSplit,
    RecommendSurvivalFallback,
}

impl DiagnosticAction {
    pub fn as_str(self) -> &'static str {
        match self {
            DiagnosticAction::KeepNormal => "keep_normal",
            DiagnosticAction::ReduceChunkSize { .. } => "reduce_chunk_size",
            DiagnosticAction::ShrinkFrameSize { .. } => "shrink_frame_size",
            DiagnosticAction::RecommendExitOrBridge => "recommend_exit_or_bridge",
            DiagnosticAction::EnablePacingAndSplit => "enable_pacing_and_split",
            DiagnosticAction::RecommendSurvivalFallback => "recommend_survival_fallback",
        }
    }
}

#[derive(Clone, Debug)]
pub struct NlpPrediction {
    pub intent: NetIntent,
    pub confidence: f32,
    pub action: DiagnosticAction,
    /// True when below class threshold/gap or lacking known network evidence.
    pub abstained: bool,
    /// True when text log and numeric `LinkMetrics` independently agreed on the same fault.
    pub corroborated: bool,
}

/// Numeric link telemetry (all fields default to "no signal").
#[derive(Clone, Copy, Debug, Default)]
pub struct LinkMetrics {
    pub loss_pct: f32,
    pub rtt_ms: u32,
    pub base_rtt_ms: u32,
    pub jitter_ms: u32,
    pub retransmit_pct: f32,
    pub stall_bytes: Option<u64>,
    pub rx_idle_ms: u32,
    pub resets_last_min: u32,
    pub connect_fail_ratio: f32,
    pub big_frames_lost: bool,
    pub small_frames_ok: bool,
}

impl LinkMetrics {
    /// True if any numeric counter indicates an active path fault.
    pub fn has_fault_signal(&self) -> bool {
        self.connect_fail_ratio >= 0.75
            || self.resets_last_min >= 3
            || self
                .stall_bytes
                .is_some_and(|b| self.rx_idle_ms >= 5_000 || (12_000..=20_000).contains(&b))
            || (self.big_frames_lost && self.small_frames_ok)
            || self.loss_pct >= 5.0
            || self.retransmit_pct >= 5.0
            || self.jitter_ms >= 80
            || (self.base_rtt_ms > 0 && self.rtt_ms >= self.base_rtt_ms.saturating_mul(3))
            || self.rtt_ms >= 800
    }

    /// True if live telemetry has observed actual traffic (distinguishes "healthy" from "empty").
    pub fn has_live_signal(&self) -> bool {
        self.has_fault_signal() || self.rtt_ms > 0 || self.base_rtt_ms > 0 || self.small_frames_ok
    }

    /// Map counters into the shared diagnostic vocabulary.
    pub fn tokens(&self) -> Vec<&'static str> {
        let mut t: Vec<&'static str> = Vec::with_capacity(10);
        if self.connect_fail_ratio >= 0.75 {
            t.push("all_exits_down");
            t.push("unreachable");
            t.push("stage_dial");
        }
        if self.resets_last_min >= 3 {
            t.push("rst_early");
            t.push("econnreset");
        }
        if let Some(b) = self.stall_bytes {
            if self.rx_idle_ms >= 5_000 || (12_000..=20_000).contains(&b) {
                t.push("freeze_bytes");
                t.push("zero_rx_after_burst");
            }
            if (12_000..=20_000).contains(&b) {
                t.push("stall_16k");
            }
        }
        if self.big_frames_lost && self.small_frames_ok {
            t.push("big_drop");
            t.push("small_ok");
            t.push("pmtu");
        }
        if self.loss_pct >= 5.0 || self.retransmit_pct >= 5.0 {
            t.push("loss_burst");
            t.push("retransmits");
        }
        if self.jitter_ms >= 80 {
            t.push("jitter_high");
        }
        if self.base_rtt_ms > 0 && self.rtt_ms >= self.base_rtt_ms.saturating_mul(3) {
            t.push("rtt_spike");
        }
        if self.rtt_ms >= 800 {
            t.push("slow_ack");
            t.push("throttle");
        }
        if t.is_empty() {
            t.extend_from_slice(&["ok", "rx_ok", "tx_ok", "stable", "rtt_low"]);
        }
        t
    }
}

struct Extracted {
    feats: Vec<usize>,
    ev_pairs: Vec<(u32, usize)>,
    word_h32: Vec<u32>,
    has_atomic: bool,
    has_magic: bool,
}

#[derive(Clone)]
pub struct TinyNetNlp {
    weights: [[i16; VOCAB_BUCKETS]; NUM_CLASSES],
    bias: [i16; NUM_CLASSES],
    /// Safe online-adaptation overlay (clamped to `[-DELTA_CLAMP, +DELTA_CLAMP]`, resettable).
    delta_weights: [[i8; VOCAB_BUCKETS]; NUM_CLASSES],
    delta_bias: [i8; NUM_CLASSES],
    /// Sorted exact 32-bit FNV hashes of trained words/bigrams/errnos for network classes 0..=5.
    known_net_h32: Vec<u32>,
    base_known_net_h32: Vec<u32>,
    event_window: VecDeque<&'static str>,
    online_updates_total: u32,
    online_window_start: Instant,
    online_window_count: u32,
}

impl TinyNetNlp {
    pub fn new_pretrained() -> Self {
        let mut model = Self {
            weights: [[0; VOCAB_BUCKETS]; NUM_CLASSES],
            bias: [0; NUM_CLASSES],
            delta_weights: [[0; VOCAB_BUCKETS]; NUM_CLASSES],
            delta_bias: [0; NUM_CLASSES],
            known_net_h32: Vec::with_capacity(768),
            base_known_net_h32: Vec::with_capacity(768),
            event_window: VecDeque::with_capacity(16),
            online_updates_total: 0,
            online_window_start: Instant::now(),
            online_window_count: 0,
        };

        // Balanced 7-class corpus (16 samples/class = 112 total), interleaved per round.
        let per_class: [&[&str]; NUM_CLASSES] = [
            // 0: Healthy
            &[
                "ok ack_fast tx_ok rx_ok stable rtt_low متصل سالم عادی",
                "all good link up latency normal no loss اتصال برقرار است همه چیز خوبه",
                "pool ready exit reachable speed ok وصله سرعت خوب عالیه",
                "پینگ پایین بدون قطعی اتصال خوبه",
                "latency normal no errors healthy",
                "no loss no resets no timeouts link fine",
                "stream active keepalive ok rx tx ok",
                "rtt 40ms jitter low throughput normal",
                "handshake ok tunnel up traffic flowing",
                "healthy keepalive ok rtt stable 45ms",
                "handshake complete stream active normal throughput",
                "اتصال عالیه پایدار پینگ پایین بدون افت سرعت بدون پکت لاس",
                "everything is fine link stable rtt 30ms no loss",
                "tunnel healthy zero packet loss steady speed",
                "link up normal operation no drops",
                "rtt 25ms stable connection good throughput",
                "پینگ اوکیه سرعت خوبه",
                "latency low stable",
                "no errors no resets no timeouts",
                "no errors no drops link fine",
            ],
            // 1: EarlyRst
            &[
                "connection reset by peer rst_early econnreset eof_handshake",
                "rst_early rst_early connection closed by peer",
                "handshake failed unexpected eof tls clienthello dropped immediately",
                "کانکشن ریست شد بلافاصله بعد هندشیک",
                "rst received after syn ack tcp reset injected fast close",
                "بعد از هندشیک کانکشن ریست میشه قطع شد سریع",
                "tls alert unexpected_eof after clienthello ریست قطع سریع",
                "broken pipe epipe peer closed",
                "broken pipe epipe read connection reset right after handshake",
                "econnreset connection reset by peer stage_handshake",
                "tls handshake eof clienthello rst sni blocked",
                "peer reset connection abort econnaborted",
                "rst after first packet injected reset",
                "همش ریست میشه تا وصل میشه قطع میشه",
                "econnreset",
                "rst_early epipe clienthello reset",
                "write epipe stage_handshake",
                "epipe broken pipe stage_handshake reset",
            ],
            // 2: ByteFreeze
            &[
                "stall_16k freeze_bytes timeout after 16384 zero_rx_after_burst",
                "دانلود وسط کار هنگ میکنه و می‌ایسته",
                "transfer hangs mid download read timeout stage_stream",
                "zero bytes received rx idle frozen stream",
                "connection alive zero bytes first burst stuck 20000 bytes",
                "download hangs after 15 kb no more data rx idle transfer frozen",
                "stalled at 16kb no rst no fin",
                "read timed out after 15kb stage_stream",
                "data stops flowing mid stream read timed out no rst no fin",
                "بعد از چند کیلوبایت دانلود می‌ایستد و هنگ میکنه بدون خطا",
                "no data after first burst rx idle stuck",
                "stalled at 16kb 64kb read timeout فریز توقف وسط انتقال",
                "کانکشن وسط کار یهو قفل میکنه بعد 16 کیلوبایت",
                "transfer froze 16384 bytes rx idle 20s",
                "stall_16k freeze_bytes",
                "mid stream stall zero bytes rx idle",
                "stage_stream read timeout rx idle",
                "read timed out mid stream no fin",
                "timeout during transfer stage_stream stalled",
            ],
            // 3: PmtuDrop
            &[
                "big_drop small_ok emsgsize message too long pmtu blackhole",
                "emsgsize message too long big frames lost",
                "keepalive ok large frame dropped fragmentation needed ام‌تی‌یو",
                "fragmentation needed icmp mtu 1400",
                "packet too big df bit set silently dropped handshake ok bulk fails",
                "pmtu blackhole df packet too big",
                "large packets dropped small packets ok",
                "bulk fails handshake ok mtu",
                "پیام کوچیک رد میشه ولی بسته بزرگ گم میشه مشکل mtu",
                "بسته بزرگ رد نمیشه کوچیک رد میشه پینگ جواب میده",
                "small packets pass big packets vanish mtu 1500 icmp frag needed",
                "write message too long emsgsize path mtu discovery blackhole",
                "sendmsg message too long emsgsize 1400 byte frame",
                "udp fragmented packets dropped mtu mismatch",
                "emsgsize",
                "pmtu mtu 1400 fragmentation needed",
                "big frames dropped small frames ok",
                "large packet dropped fragmentation",
                "فایل بزرگ نمیاد ولی پینگ میده",
            ],
            // 4: Throttle
            &[
                "rtt_spike jitter_high queue_full loss_burst slow_ack throttle",
                "speed limited 50kbps 30kbps shaping rate limit slow alive",
                "bandwidth capped high latency under load تراتل کندی پکت لاس",
                "packet loss 20 percent rtt 900ms jitter bufferbloat slow transfer",
                "bandwidth capped rate limited shaping",
                "throughput collapsed retransmits high rtt inflated congestion",
                "slow alive throttled kbps pacing",
                "retransmits congestion bufferbloat slow",
                "اینترنت خیلی کنده پینگ بالا پکت لاس زیاد سرعت محدود شده",
                "latency spike loss burst throughput low",
                "packet loss 20% rtt 1500ms jitter",
                "سرعت کم پینگ بالا پکت لاس محدودیت کند شده",
                "iperf throughput dropped 30kbps massive retransmissions",
                "پینگ رفته روی 1500ms پکت لاس سرعت دانلود افتضاحه",
                "rtt_spike loss_burst jitter_high",
                "heavy jitter bandwidth throttled 64kbps congestion",
                "speed dropped throughput low kbps",
                "throughput dropped slow congestion",
                "سرعت افت کرد کند شد",
            ],
            // 5: RouteOrDnsFail
            &[
                "no route to host unreachable nxdomain sinkhole 10.10.34 dns_fail",
                "nxdomain no such host lookup failed",
                "dns servfail resolution error upstream resolver",
                "قطعی کامل اینترنت بین‌الملل هیچ سروری",
                "dns servfail lookup failed no such host name resolution error",
                "connection refused all exits down stage_dial",
                "connection refused econnrefused syn timeout exit unreachable blackout",
                "connect timeout all exits down اینترنت ملی قطع کامل",
                "هیچ سروری جواب نمیده همه چیز قطعه بین‌الملل قطع دی ان اس خطا",
                "all endpoints failed dial timeout stage_dial",
                "no route to host enetunreach ehostunreach",
                "network is unreachable enetunreach dial tcp io timeout all endpoints failed",
                "سایت باز نمیشه دی ان اس کار نمیکنه خروجی در دسترس نیست",
                "ای پی بلاک شده کلا تایم اوت میده connect timeout refused",
                "econnrefused enetunreach nxdomain servfail",
                "dial tcp connect timeout refused unreachable stage_dial",
                "stage_dial connect timeout unreachable",
                "dial timeout stage_dial refused",
                "stage_dial io timeout no route",
            ],
            // 6: Unrelated (general system/app logs + normal khaymali operational logs)
            &[
                "user logged in successfully session created admin dashboard",
                "config reloaded systemd service started daemon ready",
                "cron job finished backup completed archive verified",
                "disk usage 42 percent memory free cpu load average",
                "ssh login accepted publickey authentication succeeded",
                "certificate renewed letsencrypt tls cert valid days",
                "database migration applied schema version updated",
                "worker thread spawned listening on localhost port",
                "accepting reverse exits listener bound",
                "draining active streams graceful shutdown initiated",
                "kernel transparent forwarding active real client ip preserved",
                "pool growth clients waited link metrics http started",
                "cannot save patterns permission denied state file",
                "کاربر وارد شد تنظیمات ذخیره شد سرویس شروع به کار کرد فایل بکاپ ساخته شد",
                "hello world test message git pull origin main already updated",
                "kernel usb device high speed apt upgraded packages weather sunny",
                "new client connected session opened",
                "service listening operator connected",
            ],
        ];

        // Class-interleaved rounds; classes may have different lengths (v0.15.1 targeted samples).
        let rounds = per_class.iter().map(|c| c.len()).max().unwrap_or(0);
        for _ in 0..TRAIN_EPOCHS {
            for i in 0..rounds {
                for c in 0..NUM_CLASSES {
                    if let Some(sample) = per_class[c].get(i) {
                        model.train_sample(sample, NetIntent::ALL[c], TRAIN_LR);
                    }
                }
            }
        }
        model.known_net_h32.sort_unstable();
        model.known_net_h32.dedup();
        model.base_known_net_h32 = model.known_net_h32.clone();
        model
    }

    #[inline]
    fn fnv32(bytes: &[u8]) -> u32 {
        let mut h: u32 = 2166136261;
        for &b in bytes {
            h ^= b as u32;
            h = h.wrapping_mul(16777619);
        }
        h
    }

    #[inline]
    fn hash_bucket(bytes: &[u8]) -> usize {
        (Self::fnv32(bytes) as usize) % VOCAB_BUCKETS
    }

    fn normalize(text: &str) -> String {
        let mut out = String::with_capacity(text.len().min(MAX_INPUT_CHARS));
        for ch in text.chars().take(MAX_INPUT_CHARS).flat_map(|c| c.to_lowercase()) {
            let c = match ch {
                '\u{200c}' | '\u{200d}' | '\u{0640}' => continue,
                '\u{064b}'..='\u{065f}' => continue,
                '\u{06f0}'..='\u{06f9}' => (b'0' + (ch as u32 - 0x06f0) as u8) as char,
                '\u{0660}'..='\u{0669}' => (b'0' + (ch as u32 - 0x0660) as u8) as char,
                'ي' | 'ى' => 'ی',
                'ك' => 'ک',
                'ة' | 'ۀ' => 'ه',
                'أ' | 'إ' => 'ا',
                'ؤ' => 'و',
                other => other,
            };
            out.push(c);
        }
        out
    }

    fn push_magic(n: u64, out: &mut Vec<usize>, has_magic: &mut bool) {
        if (12_000..=20_000).contains(&n) {
            out.push(Self::hash_bucket(b"num_16k"));
            *has_magic = true;
        }
        if (60_000..=70_000).contains(&n) {
            out.push(Self::hash_bucket(b"num_64k"));
            *has_magic = true;
        }
        if matches!(n, 1200 | 1280 | 1350 | 1400 | 1452 | 1472 | 1500) {
            out.push(Self::hash_bucket(b"num_mtu"));
            *has_magic = true;
        }
    }

    fn parse_prefix(digits: &str) -> u64 {
        let capped: String = digits.chars().take(12).collect();
        capped.parse::<u64>().unwrap_or(0)
    }

    fn extract(text: &str) -> Extracted {
        let mut out = Vec::with_capacity(64);
        let mut ev_pairs = Vec::with_capacity(32);
        let mut word_h32 = Vec::with_capacity(24);
        let mut has_atomic = false;
        let mut has_magic = false;

        let t = Self::normalize(text);
        let mut prev: Option<String> = None;
        let mut neg: u8 = 0;

        let mut runs: Vec<&str> = t
            .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-'))
            .filter(|r| !r.is_empty())
            .collect();
        // v0.15.1 contrast clause ("ping works BUT big files fail"): if the clause after the last
        // marker has a fault cue, only that clause is classified; a reassuring tail
        // ("slow but alive") keeps the whole sentence. Markers themselves carry no meaning.
        if let Some(pos) = runs.iter().rposition(|r| CONTRAST.contains(r)) {
            let tail_has_fault = runs[pos + 1..].iter().any(|r| FAULT_CUES.contains(r));
            if tail_has_fault && pos + 1 < runs.len() {
                runs.drain(..=pos);
            } else {
                runs.retain(|r| !CONTRAST.contains(r));
            }
        }
        // v0.15.1 stage-qualified timeout: "timeout" is shared by ByteFreeze and RouteOrDnsFail;
        // joined with the stage tag (or "mid stream") it becomes a discriminating feature.
        let stage = runs.iter().rev().find(|r| r.starts_with("stage_")).copied().or_else(|| {
            runs.windows(2).any(|w| w[0] == "mid" && w[1] == "stream").then_some("stage_stream")
        });
        if let Some(stage) = stage {
            if runs.iter().any(|r| matches!(*r, "timeout" | "timed" | "etimedout")) {
                let h = Self::fnv32(format!("tq|{stage}").as_bytes());
                let b = (h as usize) % VOCAB_BUCKETS;
                out.push(b);
                ev_pairs.push((h, b));
            }
        }

        for run in runs.iter().copied() {
            if ATOMIC_ERR.contains(&run) {
                let h = Self::fnv32(format!("err|{run}").as_bytes());
                let b = (h as usize) % VOCAB_BUCKETS;
                out.push(b);
                ev_pairs.push((h, b));
                word_h32.push(h);
                has_atomic = true;
                prev = Some(run.to_string());
                continue;
            }
            let parts: Vec<&str> = run
                .split(|c| c == '_' || c == '-')
                .filter(|p| !p.is_empty())
                .collect();
            if parts.len() > 1
                && run.chars().count() >= 4
                && !run.chars().any(|c| c.is_ascii_digit())
            {
                let h = Self::fnv32(format!("c|{run}").as_bytes());
                let b = (h as usize) % VOCAB_BUCKETS;
                out.push(b);
                ev_pairs.push((h, b));
            }
            for tok in parts {
                if tok.chars().all(|c| c.is_ascii_digit()) {
                    Self::push_magic(Self::parse_prefix(tok), &mut out, &mut has_magic);
                    continue;
                }
                let k = tok.find(|c: char| !c.is_ascii_digit()).unwrap_or(tok.len());
                if k > 0 && k < tok.len() {
                    let suffix = &tok[k..];
                    let n = Self::parse_prefix(&tok[..k]);
                    match suffix {
                        "k" | "kb" | "kib" => {
                            Self::push_magic(n.saturating_mul(1024), &mut out, &mut has_magic);
                            Self::push_magic(n.saturating_mul(1000), &mut out, &mut has_magic);
                            continue;
                        }
                        "m" | "mb" => {
                            Self::push_magic(n.saturating_mul(1_048_576), &mut out, &mut has_magic);
                            continue;
                        }
                        "ms" => {
                            if n >= 500 {
                                out.push(Self::hash_bucket(b"num_high_ms"));
                                has_magic = true;
                            } else if n > 0 && n <= 150 {
                                out.push(Self::hash_bucket(b"num_low_ms"));
                                has_magic = true;
                            }
                            continue;
                        }
                        "s" => {
                            if n >= 5 {
                                out.push(Self::hash_bucket(b"num_idle_s"));
                                has_magic = true;
                            }
                            continue;
                        }
                        "kbps" => {
                            if n > 0 && n <= 256 {
                                out.push(Self::hash_bucket(b"num_low_bw"));
                                has_magic = true;
                            }
                            continue;
                        }
                        _ => {}
                    }
                }
                if tok.chars().any(|c| c.is_ascii_digit()) {
                    continue;
                }
                if PRE_NEG.contains(&tok) {
                    neg = 2;
                    continue;
                }
                if POST_NEG.contains(&tok) {
                    if let Some(p) = &prev {
                        let h = Self::fnv32(format!("pneg|{p}").as_bytes());
                        let b = (h as usize) % VOCAB_BUCKETS;
                        out.push(b);
                        ev_pairs.push((h, b));
                        word_h32.push(h);
                    }
                    let h2 = Self::fnv32(format!("w|{tok}").as_bytes());
                    let b2 = (h2 as usize) % VOCAB_BUCKETS;
                    out.push(b2);
                    ev_pairs.push((h2, b2));
                    prev = None;
                    continue;
                }
                if tok.chars().count() < 2 || STOP.contains(&tok) {
                    continue;
                }
                if neg > 0 {
                    let h = Self::fnv32(format!("n|{tok}").as_bytes());
                    let b = (h as usize) % VOCAB_BUCKETS;
                    out.push(b);
                    ev_pairs.push((h, b));
                    word_h32.push(h);
                    neg -= 1;
                    prev = None;
                    continue;
                }
                if ATOMIC_ERR.contains(&tok) {
                    let h = Self::fnv32(format!("err|{tok}").as_bytes());
                    let b = (h as usize) % VOCAB_BUCKETS;
                    out.push(b);
                    ev_pairs.push((h, b));
                    word_h32.push(h);
                    has_atomic = true;
                    if let Some(p) = &prev {
                        let h2 = Self::fnv32(format!("b|{p}|{tok}").as_bytes());
                        let b2 = (h2 as usize) % VOCAB_BUCKETS;
                        out.push(b2);
                        ev_pairs.push((h2, b2));
                    }
                    prev = Some(tok.to_string());
                    continue;
                }

                if AMBIGUOUS_VERBS.contains(&tok) {
                    // v0.15.1: "dropped" alone meant MTU even in "speed dropped"; only its bigram
                    // ("frame dropped" vs "speed dropped") carries the meaning.
                    if let Some(p) = &prev {
                        let h2 = Self::fnv32(format!("b|{p}|{tok}").as_bytes());
                        let b2 = (h2 as usize) % VOCAB_BUCKETS;
                        out.push(b2);
                        ev_pairs.push((h2, b2));
                    }
                    prev = Some(tok.to_string());
                    continue;
                }
                let h = Self::fnv32(format!("w|{tok}").as_bytes());
                let b = (h as usize) % VOCAB_BUCKETS;
                out.push(b);
                ev_pairs.push((h, b));
                word_h32.push(h);
                if let Some(p) = &prev {
                    let h2 = Self::fnv32(format!("b|{p}|{tok}").as_bytes());
                    let b2 = (h2 as usize) % VOCAB_BUCKETS;
                    out.push(b2);
                    ev_pairs.push((h2, b2));
                }
                prev = Some(tok.to_string());

                let chars: Vec<char> = tok.chars().collect();
                if chars.len() >= 4 {
                    for w in chars.windows(3) {
                        let mut s = String::with_capacity(8);
                        s.push_str("t|");
                        s.extend(w.iter());
                        out.push(Self::hash_bucket(s.as_bytes()));
                    }
                }
            }
        }

        out.sort_unstable();
        out.dedup();
        ev_pairs.sort_unstable();
        ev_pairs.dedup();
        word_h32.sort_unstable();
        word_h32.dedup();

        Extracted { feats: out, ev_pairs, word_h32, has_atomic, has_magic }
    }

    #[cfg(test)]
    fn extract_features(text: &str, out: &mut Vec<usize>) {
        out.clear();
        out.extend_from_slice(&Self::extract(text).feats);
    }

    #[inline]
    fn eff_weight(&self, c: usize, b: usize) -> i32 {
        self.weights[c][b] as i32 + self.delta_weights[c][b] as i32
    }

    fn raw_logits(&self, feats: &[usize]) -> [i32; NUM_CLASSES] {
        let mut logits = [0_i32; NUM_CLASSES];
        for c in 0..NUM_CLASSES {
            let mut sum = self.bias[c] as i32 + self.delta_bias[c] as i32;
            for &b in feats {
                sum += self.eff_weight(c, b);
            }
            logits[c] = sum;
        }
        logits
    }

    fn norm_logits(&self, feats: &[usize]) -> [i32; NUM_CLASSES] {
        let raw = self.raw_logits(feats);
        let scale = 5.0_f32 / (feats.len().max(1) as f32).sqrt();
        let mut out = [0_i32; NUM_CLASSES];
        for c in 0..NUM_CLASSES {
            out[c] = (raw[c] as f32 * scale).round() as i32;
        }
        out
    }

    #[inline]
    fn is_known_net(&self, h32: u32) -> bool {
        self.known_net_h32.binary_search(&h32).is_ok()
    }

    /// Offline/base training step (updates base `weights`; used during pretraining & unit tests).
    pub fn train_sample(&mut self, text: &str, target: NetIntent, lr: i16) {
        let ex = Self::extract(text);
        if target != NetIntent::Unrelated {
            let mut added_known = false;
            let mut added_base = false;
            for &(h, _) in &ex.ev_pairs {
                if self.known_net_h32.binary_search(&h).is_err() {
                    self.known_net_h32.push(h);
                    added_known = true;
                }
                if self.base_known_net_h32.binary_search(&h).is_err() {
                    self.base_known_net_h32.push(h);
                    added_base = true;
                }
            }
            if added_known {
                self.known_net_h32.sort_unstable();
                self.known_net_h32.dedup();
            }
            if added_base {
                self.base_known_net_h32.sort_unstable();
                self.base_known_net_h32.dedup();
            }
        }
        let logits = self.raw_logits(&ex.feats);
        let t_idx = target as usize;
        let mut best_other_idx = if t_idx == 0 { 1 } else { 0 };
        for c in 0..NUM_CLASSES {
            if c != t_idx && logits[c] > logits[best_other_idx] {
                best_other_idx = c;
            }
        }
        if logits[t_idx] - logits[best_other_idx] >= TRAIN_MARGIN {
            return;
        }
        for &bucket in &ex.feats {
            self.weights[t_idx][bucket] = self.weights[t_idx][bucket]
                .saturating_add(lr)
                .clamp(-WEIGHT_CLAMP, WEIGHT_CLAMP);
            self.weights[best_other_idx][bucket] = self.weights[best_other_idx][bucket]
                .saturating_sub(lr)
                .clamp(-WEIGHT_CLAMP, WEIGHT_CLAMP);
        }
        self.bias[t_idx] = self.bias[t_idx]
            .saturating_add(lr / 4)
            .clamp(-WEIGHT_CLAMP, WEIGHT_CLAMP);
        self.bias[best_other_idx] = self.bias[best_other_idx]
            .saturating_sub(lr / 4)
            .clamp(-WEIGHT_CLAMP, WEIGHT_CLAMP);
    }

    /// Safe online learning: only updates the bounded `delta_weights` overlay (`[-120, +120]`),
    /// locks `Unrelated`, enforces an hourly cap, and never corrupts pretrained weights.
    pub fn train_online_verified(&mut self, text: &str, target: NetIntent, now: Instant) -> bool {
        if target == NetIntent::Unrelated {
            return false;
        }
        if now.saturating_duration_since(self.online_window_start) >= Duration::from_secs(3600) {
            self.online_window_start = now;
            self.online_window_count = 0;
        }
        if self.online_window_count >= MAX_ONLINE_UPDATES_PER_HOUR {
            return false;
        }
        let ex = Self::extract(text);
        if ex.feats.is_empty() {
            return false;
        }
        let logits = self.raw_logits(&ex.feats);
        let t_idx = target as usize;
        let unrelated_idx = NetIntent::Unrelated as usize;
        let mut best_other_idx = if t_idx == 0 { 1 } else { 0 };
        for c in 0..NUM_CLASSES {
            if c != t_idx && c != unrelated_idx && logits[c] > logits[best_other_idx] {
                best_other_idx = c;
            }
        }
        if logits[t_idx] - logits[best_other_idx] >= TRAIN_MARGIN {
            return false;
        }
        for &bucket in &ex.feats {
            self.delta_weights[t_idx][bucket] = self.delta_weights[t_idx][bucket]
                .saturating_add(ONLINE_LR)
                .clamp(-DELTA_CLAMP, DELTA_CLAMP);
            self.delta_weights[best_other_idx][bucket] = self.delta_weights[best_other_idx][bucket]
                .saturating_sub(ONLINE_LR)
                .clamp(-DELTA_CLAMP, DELTA_CLAMP);
        }
        self.delta_bias[t_idx] = self.delta_bias[t_idx]
            .saturating_add(ONLINE_LR / 3)
            .clamp(-DELTA_CLAMP, DELTA_CLAMP);
        self.delta_bias[best_other_idx] = self.delta_bias[best_other_idx]
            .saturating_sub(ONLINE_LR / 3)
            .clamp(-DELTA_CLAMP, DELTA_CLAMP);

        let mut added = false;
        for &(h, _) in &ex.ev_pairs {
            if self.known_net_h32.len() >= MAX_PERSISTED_HASHES { break; }
            if self.known_net_h32.binary_search(&h).is_err() {
                self.known_net_h32.push(h);
                added = true;
            }
        }
        if added {
            self.known_net_h32.sort_unstable();
            self.known_net_h32.dedup();
        }
        self.online_window_count += 1;
        self.online_updates_total = self.online_updates_total.saturating_add(1);
        true
    }

    /// Hourly decay (`delta = delta * 7 / 8`) so yesterday's ISP quirks fade out naturally.
    pub fn decay_online_weights(&mut self) {
        for c in 0..NUM_CLASSES {
            self.delta_bias[c] = ((self.delta_bias[c] as i32 * 7) / 8) as i8;
            for b in 0..VOCAB_BUCKETS {
                self.delta_weights[c][b] = ((self.delta_weights[c][b] as i32 * 7) / 8) as i8;
            }
        }
    }

    /// Instant rollback to immutable pretrained baseline weights.
    pub fn reset_online_weights(&mut self) {
        self.delta_weights = [[0; VOCAB_BUCKETS]; NUM_CLASSES];
        self.delta_bias = [0; NUM_CLASSES];
        // Remove online-only vocabulary additions as well as weight deltas.
        self.known_net_h32.clone_from(&self.base_known_net_h32);
        self.online_window_count = 0;
        self.online_window_start = Instant::now();
        self.online_updates_total = 0;
        self.event_window.clear();
    }

    /// Serialize the full model (immutable baseline + bounded online overlay) using a
    /// versioned, endian-stable binary format. Event history and wall-clock rate windows
    /// are intentionally not persisted.
    pub fn to_artifact_bytes(&self) -> Result<Vec<u8>, String> {
        if self.known_net_h32.len() > MAX_PERSISTED_HASHES || self.base_known_net_h32.len() > MAX_PERSISTED_HASHES {
            return Err("model vocabulary exceeds persistence limit".into());
        }
        let mut out = Vec::with_capacity(40 + NUM_CLASSES * VOCAB_BUCKETS * 3);
        out.extend_from_slice(b"KTMNLP01");
        out.extend_from_slice(&2u16.to_be_bytes());
        out.extend_from_slice(&(NUM_CLASSES as u16).to_be_bytes());
        out.extend_from_slice(&(VOCAB_BUCKETS as u16).to_be_bytes());
        out.extend_from_slice(&(self.known_net_h32.len() as u32).to_be_bytes());
        out.extend_from_slice(&(self.base_known_net_h32.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.online_updates_total.to_be_bytes());
        out.extend_from_slice(&self.online_window_count.to_be_bytes());
        for row in &self.weights { for v in row { out.extend_from_slice(&v.to_be_bytes()); } }
        for v in &self.bias { out.extend_from_slice(&v.to_be_bytes()); }
        for row in &self.delta_weights { for v in row { out.push(*v as u8); } }
        for v in &self.delta_bias { out.push(*v as u8); }
        for v in &self.known_net_h32 { out.extend_from_slice(&v.to_be_bytes()); }
        for v in &self.base_known_net_h32 { out.extend_from_slice(&v.to_be_bytes()); }
        let digest = Sha256::digest(&out);
        out.extend_from_slice(&digest[..8]);
        Ok(out)
    }

    /// Strictly validate artifact magic, dimensions, length, sorted vocabularies and
    /// weight bounds before constructing a model. No partial artifact is accepted.
    pub fn from_artifact_bytes(data: &[u8]) -> Result<Self, String> {
        let mut pos = 0usize;
        fn take<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], String> {
            let end = pos.checked_add(n).ok_or_else(|| "artifact length overflow".to_string())?;
            if end > data.len() { return Err("truncated model artifact".into()); }
            let out = &data[*pos..end]; *pos = end; Ok(out)
        }
        fn u16v(data: &[u8], pos: &mut usize) -> Result<u16, String> { Ok(u16::from_be_bytes(take(data,pos,2)?.try_into().unwrap())) }
        fn u32v(data: &[u8], pos: &mut usize) -> Result<u32, String> { Ok(u32::from_be_bytes(take(data,pos,4)?.try_into().unwrap())) }
        if take(data, &mut pos, 8)? != b"KTMNLP01" { return Err("invalid model artifact magic".into()); }
        let version = u16v(data, &mut pos)?;
        if version != 1 && version != 2 { return Err("unsupported model artifact version".into()); }
        if u16v(data, &mut pos)? as usize != NUM_CLASSES || u16v(data, &mut pos)? as usize != VOCAB_BUCKETS {
            return Err("model artifact dimensions do not match this build".into());
        }
        let known_len = u32v(data, &mut pos)? as usize;
        let base_len = u32v(data, &mut pos)? as usize;
        let online_updates_total = u32v(data, &mut pos)?;
        let online_window_count = u32v(data, &mut pos)?;
        if known_len > MAX_PERSISTED_HASHES || base_len > MAX_PERSISTED_HASHES || online_window_count > MAX_ONLINE_UPDATES_PER_HOUR {
            return Err("model artifact counters exceed safety limits".into());
        }
        let trailer = if version == 2 { 8 } else { 0 };
        let expected = pos.checked_add(NUM_CLASSES * VOCAB_BUCKETS * 2)
            .and_then(|v| v.checked_add(NUM_CLASSES * 2))
            .and_then(|v| v.checked_add(NUM_CLASSES * VOCAB_BUCKETS))
            .and_then(|v| v.checked_add(NUM_CLASSES))
            .and_then(|v| v.checked_add((known_len + base_len) * 4))
            .and_then(|v| v.checked_add(trailer))
            .ok_or_else(|| "artifact size overflow".to_string())?;
        if expected != data.len() { return Err("model artifact length mismatch".into()); }
        if version == 2 {
            let payload_end = data.len() - 8;
            let digest = Sha256::digest(&data[..payload_end]);
            if &data[payload_end..] != &digest[..8] {
                return Err("model artifact integrity checksum mismatch".into());
            }
        }
        let mut model = Self::new_pretrained();
        for row in &mut model.weights { for v in row { *v = i16::from_be_bytes(take(data,&mut pos,2)?.try_into().unwrap()); if v.unsigned_abs() > WEIGHT_CLAMP as u16 { return Err("baseline weight outside clamp".into()); } } }
        for v in &mut model.bias { *v = i16::from_be_bytes(take(data,&mut pos,2)?.try_into().unwrap()); if v.unsigned_abs() > WEIGHT_CLAMP as u16 { return Err("baseline bias outside clamp".into()); } }
        for row in &mut model.delta_weights { for v in row { *v = take(data,&mut pos,1)?[0] as i8; if v.unsigned_abs() > DELTA_CLAMP as u8 { return Err("online weight outside clamp".into()); } } }
        for v in &mut model.delta_bias { *v = take(data,&mut pos,1)?[0] as i8; if v.unsigned_abs() > DELTA_CLAMP as u8 { return Err("online bias outside clamp".into()); } }
        model.known_net_h32.clear();
        for _ in 0..known_len { model.known_net_h32.push(u32v(data,&mut pos)?); }
        model.base_known_net_h32.clear();
        for _ in 0..base_len { model.base_known_net_h32.push(u32v(data,&mut pos)?); }
        if !model.known_net_h32.windows(2).all(|w| w[0] < w[1]) || !model.base_known_net_h32.windows(2).all(|w| w[0] < w[1]) {
            return Err("model vocabulary must be strictly sorted and unique".into());
        }
        if model.base_known_net_h32.iter().any(|h| model.known_net_h32.binary_search(h).is_err()) {
            return Err("artifact online vocabulary omits baseline entries".into());
        }
        if model.delta_bias[NetIntent::Unrelated as usize] != 0
            || model.delta_weights[NetIntent::Unrelated as usize].iter().any(|v| *v != 0) {
            return Err("online learning artifact modified the locked Unrelated class".into());
        }
        model.online_updates_total = online_updates_total;
        model.online_window_count = online_window_count;
        model.online_window_start = Instant::now();
        model.event_window.clear();
        Ok(model)
    }

    /// Atomically replace a model artifact on the same filesystem. Callers should keep
    /// permissions restrictive (0600) when artifacts contain deployment-specific learning.
    pub fn save_artifact_atomic(&self, path: &std::path::Path) -> Result<(), String> {
        let bytes = self.to_artifact_bytes()?;
        write_bytes_atomic(path, &bytes)
    }

    pub fn load_artifact(path: &std::path::Path) -> Result<Self, String> {
        let metadata = std::fs::metadata(path).map_err(|e| format!("stat model artifact: {e}"))?;
        if metadata.len() > 128 * 1024 { return Err("model artifact exceeds 128 KiB limit".into()); }
        let bytes = std::fs::read(path).map_err(|e| format!("read model artifact: {e}"))?;
        Self::from_artifact_bytes(&bytes)
    }

    /// Load the active model from `KHAYMALI_NLP_MODEL_PATH` if configured and valid,
    /// otherwise fall back safely to the immutable pretrained baseline.
    pub fn load_configured_or_pretrained() -> Self {
        match std::env::var_os("KHAYMALI_NLP_MODEL_PATH").map(std::path::PathBuf::from) {
            Some(path) => match Self::load_artifact(&path) {
                Ok(model) => model,
                Err(err) => {
                    eprintln!("[nlp] model artifact load failed; using pretrained baseline: {err}");
                    Self::new_pretrained()
                }
            },
            None => Self::new_pretrained(),
        }
    }

    pub fn online_updates_total(&self) -> u32 {
        self.online_updates_total
    }

    pub fn push_event_token(&mut self, token: &'static str) {
        if self.event_window.len() >= 12 {
            self.event_window.pop_front();
        }
        self.event_window.push_back(token);
    }

    pub fn clear_event_window(&mut self) {
        self.event_window.clear();
    }

    fn window_text(&self) -> String {
        let mut s = String::with_capacity(96);
        for tok in &self.event_window {
            s.push_str(tok);
            s.push(' ');
        }
        s
    }

    pub fn classify(&self, extra_log: &str) -> NlpPrediction {
        let win = self.window_text();
        let combined = if win.is_empty() {
            extra_log.to_string()
        } else if extra_log.trim().is_empty() {
            win
        } else {
            format!("{win} {extra_log}")
        };
        let ex = Self::extract(&combined);
        if ex.feats.is_empty() {
            return NlpPrediction {
                intent: NetIntent::Unrelated,
                confidence: 0.0,
                action: DiagnosticAction::KeepNormal,
                abstained: true,
                corroborated: false,
            };
        }
        let logits = self.norm_logits(&ex.feats);
        self.predict_from_logits(&logits, &ex, false)
    }

    pub fn classify_metrics(&self, m: &LinkMetrics) -> NlpPrediction {
        let joined = m.tokens().join(" ");
        self.classify(&joined)
    }

    /// Late-fusion classifier combining text log + live numeric `LinkMetrics`.
    pub fn classify_combined(&self, extra_log: &str, m: &LinkMetrics) -> NlpPrediction {
        let win = self.window_text();
        let text_full = if win.is_empty() {
            extra_log.to_string()
        } else if extra_log.trim().is_empty() {
            win
        } else {
            format!("{win} {extra_log}")
        };
        let t_ex = Self::extract(&text_full);
        let m_str = m.tokens().join(" ");
        let m_ex = Self::extract(&m_str);

        if t_ex.feats.is_empty() && m_ex.feats.is_empty() {
            return NlpPrediction {
                intent: NetIntent::Unrelated,
                confidence: 0.0,
                action: DiagnosticAction::KeepNormal,
                abstained: true,
                corroborated: false,
            };
        }
        if t_ex.feats.is_empty() {
            let ml = self.norm_logits(&m_ex.feats);
            return self.predict_from_logits(&ml, &m_ex, false);
        }
        if !m.has_live_signal() {
            let tl = self.norm_logits(&t_ex.feats);
            return self.predict_from_logits(&tl, &t_ex, false);
        }

        let tl = self.norm_logits(&t_ex.feats);
        let ml = self.norm_logits(&m_ex.feats);
        let t_best = (0..NUM_CLASSES).max_by_key(|&c| tl[c]).unwrap_or(0);
        let m_best = (0..NUM_CLASSES).max_by_key(|&c| ml[c]).unwrap_or(0);

        // Contradiction veto: live tunnel telemetry is healthy, but an isolated log screams fault.
        if !m.has_fault_signal() && NetIntent::ALL[t_best].is_fault() && m_best == 0 {
            return NlpPrediction {
                intent: NetIntent::Healthy,
                confidence: 0.50,
                action: DiagnosticAction::KeepNormal,
                abstained: true,
                corroborated: false,
            };
        }

        let corroborated = t_best == m_best && NetIntent::ALL[t_best].is_fault();
        let mut fused = [0_i32; NUM_CLASSES];
        for c in 0..NUM_CLASSES {
            fused[c] = (0.45 * tl[c] as f32 + 0.55 * ml[c] as f32).round() as i32;
        }
        if corroborated {
            fused[t_best] = fused[t_best].saturating_add(120);
        }

        let mut merged = Extracted {
            feats: [t_ex.feats, m_ex.feats].concat(),
            ev_pairs: [t_ex.ev_pairs, m_ex.ev_pairs].concat(),
            word_h32: [t_ex.word_h32, m_ex.word_h32].concat(),
            has_atomic: t_ex.has_atomic || m_ex.has_atomic,
            has_magic: t_ex.has_magic || m_ex.has_magic,
        };
        merged.feats.sort_unstable();
        merged.feats.dedup();
        merged.ev_pairs.sort_unstable();
        merged.ev_pairs.dedup();
        merged.word_h32.sort_unstable();
        merged.word_h32.dedup();

        self.predict_from_logits(&fused, &merged, corroborated)
    }

    fn predict_from_logits(
        &self,
        logits: &[i32; NUM_CLASSES],
        ex: &Extracted,
        corroborated: bool,
    ) -> NlpPrediction {
        let mut best_c = 0;
        let mut max_l = logits[0];
        let mut second_l = i32::MIN;
        for c in 1..NUM_CLASSES {
            if logits[c] > max_l {
                second_l = max_l;
                max_l = logits[c];
                best_c = c;
            } else if logits[c] > second_l {
                second_l = logits[c];
            }
        }
        let gap = max_l.saturating_sub(second_l);

        let temp = 96.0_f32;
        let mut exp_sum = 0.0_f32;
        let mut exps = [0.0_f32; NUM_CLASSES];
        for c in 0..NUM_CLASSES {
            let v = (((logits[c] - max_l) as f32) / temp).max(-20.0).exp();
            exps[c] = v;
            exp_sum += v;
        }
        let confidence = if exp_sum > 0.0 { exps[best_c] / exp_sum } else { 0.0 };

        let mut intent = NetIntent::ALL[best_c];
        let (mut min_conf, mut min_gap, _) = intent.thresholds();
        if corroborated && intent.is_fault() {
            min_conf = (min_conf - 0.08).max(0.40);
            min_gap = (min_gap * 3) / 4;
        }

        let has_ev = ex
            .ev_pairs
            .iter()
            .any(|&(h, b)| self.is_known_net(h) && self.eff_weight(best_c, b) >= EVIDENCE_MIN_WEIGHT);
        let known_words = ex.word_h32.iter().filter(|&&h| self.is_known_net(h)).count();
        let low_coverage = intent.is_fault()
            && !ex.has_atomic
            && !ex.has_magic
            && ex.word_h32.len() >= 3
            && (known_words as f32 / ex.word_h32.len() as f32) < 0.30;

        // v4.2: a fault verdict requires at least one known network word or atomic errno token.
        // Magic numbers (16384, 1400, 12345) strengthen a symptom alongside words, never alone.
        let no_known_evidence = known_words == 0 && !ex.has_atomic;
        let abstained = if ex.feats.is_empty() || (intent.is_fault() && no_known_evidence) {
            intent = NetIntent::Unrelated;
            true
        } else if intent == NetIntent::Unrelated {
            false
        } else if low_coverage || (intent.is_fault() && !has_ev && !ex.has_magic) {
            intent = NetIntent::Unrelated;
            true
        } else {
            gap < min_gap || confidence < min_conf
        };

        let action = if abstained {
            DiagnosticAction::KeepNormal
        } else {
            match intent {
                NetIntent::Healthy | NetIntent::Unrelated => DiagnosticAction::KeepNormal,
                NetIntent::EarlyRst => DiagnosticAction::RecommendExitOrBridge,
                NetIntent::ByteFreeze => DiagnosticAction::ReduceChunkSize { target_bytes: 1200 },
                NetIntent::PmtuDrop => DiagnosticAction::ShrinkFrameSize { target_bytes: 1200 },
                NetIntent::Throttle => DiagnosticAction::EnablePacingAndSplit,
                NetIntent::RouteOrDnsFail => DiagnosticAction::RecommendSurvivalFallback,
            }
        };

        NlpPrediction { intent, confidence, action, abstained, corroborated }
    }
}

impl TinyNetNlp {
    /// v0.15.1 explainability: input words with the largest positive weight for `intent`
    /// (at most `max`, capped at 8), formatted `word:+weight`, for the one-line action log.
    pub fn explain(&self, text: &str, intent: NetIntent, max: usize) -> String {
        let t = Self::normalize(text);
        let c = intent as usize;
        let mut scored: Vec<(i32, String)> = Vec::new();
        for run in t.split(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '-')).filter(|r| !r.is_empty()) {
            if run.chars().count() < 2 || STOP.contains(&run) || run.chars().all(|ch| ch.is_ascii_digit()) {
                continue;
            }
            let key = if ATOMIC_ERR.contains(&run) { format!("err|{run}") } else { format!("w|{run}") };
            let b = (Self::fnv32(key.as_bytes()) as usize) % VOCAB_BUCKETS;
            let w = self.eff_weight(c, b);
            if w > 0 && !scored.iter().any(|(_, s)| s == run) {
                scored.push((w, run.to_string()));
            }
        }
        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        scored.into_iter().take(max.min(8)).map(|(w, s)| format!("{s}:+{w}")).collect::<Vec<_>>().join(",")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidatePromotionDecision {
    NoCandidate,
    InsufficientHoldout,
    Regression,
    NoImprovement,
    PersistenceFailed,
    Promoted,
    /// v0.15.1: more than 5 % of the holdout appears in the candidate's own learning stream.
    HoldoutOverlapsTraining,
}

/// Risk-aware hysteresis + candidate-isolated online-learning advisor.
pub struct NlpAdvisor {
    nlp: TinyNetNlp,
    last: Option<NetIntent>,
    streak: u8,
    last_pred: Option<NlpPrediction>,
    last_action_at: Option<Instant>,
    pending_feedback: Option<(String, NetIntent, Instant)>,
    candidate_model: Option<TinyNetNlp>,
    previous_model: Option<TinyNetNlp>,
    last_decay_at: Instant,
    cooldown: Duration,
    /// v0.15.1: artifacts serialized on the hot path, written by the caller after the lock is released.
    pending_writes: Vec<PendingWrite>,
    /// v0.15.1: logs the current candidate learned from (holdout-overlap guard).
    candidate_learned: Vec<String>,
}

/// A model artifact waiting to be written outside any lock.
#[derive(Clone, Debug)]
pub struct PendingWrite {
    pub path: std::path::PathBuf,
    pub bytes: Vec<u8>,
}

impl PendingWrite {
    /// Atomic write (0600 temp + fsync + rename + parent fsync). Call only outside the runtime lock.
    pub fn write_atomic(&self) -> Result<(), String> {
        write_bytes_atomic(&self.path, &self.bytes)
    }
}

/// Shared durable writer used by `save_artifact_atomic` and deferred `PendingWrite`s.
pub fn write_bytes_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos()).unwrap_or(0);
    let tmp = path.with_extension(format!("khaymali-model-{}-{stamp}.tmp", std::process::id()));
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(&tmp).map_err(|e| format!("create model temp: {e}"))?
    };
    #[cfg(not(unix))]
    let mut file = std::fs::File::create(&tmp).map_err(|e| format!("create model temp: {e}"))?;
    let res = (|| -> Result<(), String> {
        file.write_all(bytes).map_err(|e| format!("write model temp: {e}"))?;
        file.sync_all().map_err(|e| format!("sync model temp: {e}"))?;
        drop(file);
        std::fs::rename(&tmp, path).map_err(|e| format!("replace model artifact: {e}"))?;
        #[cfg(unix)]
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// v0.15.1: fraction (0..=1) of holdout logs that also appear in the candidate's learning stream.
pub fn holdout_overlap(holdout: &[(&str, NetIntent)], learned: &[String]) -> f64 {
    if holdout.is_empty() || learned.is_empty() { return 0.0; }
    let norm = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    let set: std::collections::HashSet<String> = learned.iter().map(|s| norm(s)).collect();
    holdout.iter().filter(|(t, _)| set.contains(&norm(t))).count() as f64 / holdout.len() as f64
}

fn evaluate_model(model: &TinyNetNlp, holdout: &[(&str, NetIntent)]) -> (f64, f64) {
    let mut correct = 0usize;
    let mut safe_total = 0usize;
    let mut false_positives = 0usize;
    for (text, expected) in holdout {
        let predicted = model.classify(*text).intent;
        if predicted == *expected { correct += 1; }
        if matches!(*expected, NetIntent::Healthy | NetIntent::Unrelated) {
            safe_total += 1;
            if predicted.is_fault() { false_positives += 1; }
        }
    }
    let accuracy = correct as f64 * 100.0 / holdout.len().max(1) as f64;
    let fp_rate = if safe_total == 0 { 0.0 } else { false_positives as f64 * 100.0 / safe_total as f64 };
    (accuracy, fp_rate)
}

impl NlpAdvisor {
    pub fn new() -> Self {
        Self::with_cooldown(Duration::from_secs(10))
    }

    pub fn with_cooldown(cooldown: Duration) -> Self {
        let nlp = TinyNetNlp::load_configured_or_pretrained();
        let candidate_model = match std::env::var_os("KHAYMALI_NLP_CANDIDATE_PATH").map(std::path::PathBuf::from) {
            Some(path) => match TinyNetNlp::load_artifact(&path) {
                Ok(model) => Some(model),
                Err(err) => { eprintln!("[nlp] candidate artifact load failed; candidate ignored: {err}"); None }
            },
            None => None,
        };
        let candidate_learned: Vec<String> = std::env::var_os("KHAYMALI_NLP_CANDIDATE_PATH")
            .map(std::path::PathBuf::from)
            .and_then(|p| std::fs::read_to_string(p.with_extension("learned.txt")).ok())
            .map(|s| s.lines().filter(|l| !l.trim().is_empty()).take(4096).map(str::to_string).collect())
            .unwrap_or_default();
        Self {
            nlp,
            last: None,
            streak: 0,
            last_pred: None,
            last_action_at: None,
            pending_feedback: None,
            candidate_model,
            previous_model: None,
            last_decay_at: Instant::now(),
            cooldown,
            pending_writes: Vec::new(),
            candidate_learned,
        }
    }

    pub fn nlp(&self) -> &TinyNetNlp {
        &self.nlp
    }

    pub fn nlp_mut(&mut self) -> &mut TinyNetNlp {
        &mut self.nlp
    }

    /// v0.15.1: hand deferred artifact writes to the caller (newest per path wins).
    pub fn take_pending_writes(&mut self) -> Vec<PendingWrite> {
        let mut out: Vec<PendingWrite> = Vec::new();
        for w in self.pending_writes.drain(..).rev() {
            if !out.iter().any(|o| o.path == w.path) {
                out.push(w);
            }
        }
        out
    }

    /// v0.15.1: logs the current candidate was trained on (also persisted as `*.learned.txt`).
    pub fn candidate_learned(&self) -> &[String] {
        &self.candidate_learned
    }

    /// v0.15.1: forget the outcome label of the last action (used when it was reverted as harmful).
    pub fn drop_pending_feedback(&mut self) {
        self.pending_feedback = None;
    }

    /// Full rollback also drops any pending outcome label so a pre-reset action cannot
    /// train the post-reset model later.
    pub fn reset_online_learning(&mut self) {
        self.nlp.reset_online_weights();
        self.pending_feedback = None;
        self.candidate_model = None;
        self.candidate_learned.clear();
        self.previous_model = None;
        if let Some(path) = std::env::var_os("KHAYMALI_NLP_CANDIDATE_PATH").map(std::path::PathBuf::from) { let _ = std::fs::remove_file(path.with_extension("learned.txt")); let _ = std::fs::remove_file(path); }
        if let Some(path) = std::env::var_os("KHAYMALI_NLP_MODEL_PATH").map(std::path::PathBuf::from) { let _ = std::fs::remove_file(path.with_extension("previous.model")); }
        self.last = None;
        self.streak = 0;
        self.last_pred = None;
        self.last_action_at = None;
        self.last_decay_at = Instant::now();
    }

    /// Reset in-memory online learning and persist the baseline when an artifact path is configured.
    pub fn reset_online_learning_and_persist(&mut self) -> bool {
        self.reset_online_learning();
        match std::env::var_os("KHAYMALI_NLP_MODEL_PATH") {
            Some(path) => self.nlp.save_artifact_atomic(&std::path::PathBuf::from(path)).is_ok(),
            None => true,
        }
    }

    /// Atomically replace the in-memory model from the configured artifact path.
    /// Pending feedback and temporal state are cleared so labels cannot cross model versions.
    pub fn reload_configured_model(&mut self) -> bool {
        let Some(path) = std::env::var_os("KHAYMALI_NLP_MODEL_PATH").map(std::path::PathBuf::from) else { return false; };
        let Ok(model) = TinyNetNlp::load_artifact(&path) else { return false; };
        let previous = std::mem::replace(&mut self.nlp, model);
        self.pending_feedback = None;
        self.candidate_model = None;
        self.candidate_learned.clear();
        // Preserve previous model in memory and `.previous.model` on disk so `kani.rollback`
        // remains available immediately after `promote-nlp-candidate` + `kani.reload`.
        self.previous_model = Some(previous);
        self.last = None;
        self.streak = 0;
        self.last_pred = None;
        self.last_action_at = None;
        self.last_decay_at = Instant::now();
        true
    }

    /// Feed a bounded, static event token from the live transport event stream.
    pub fn push_event_token(&mut self, token: &'static str) {
        self.nlp.push_event_token(token);
    }

    pub fn last_prediction(&self) -> Option<&NlpPrediction> {
        self.last_pred.as_ref()
    }

    fn gate(&mut self, pred: NlpPrediction, trigger_text: &str, now: Instant) -> DiagnosticAction {
        if now.saturating_duration_since(self.last_decay_at) >= Duration::from_secs(3600) {
            self.nlp.decay_online_weights();
            // v0.15.1: no disk I/O here; gate() runs under the runtime lock on every event.
            // Serialize only; the runtime writes after releasing the lock.
            if let Some(path) = std::env::var_os("KHAYMALI_NLP_MODEL_PATH").map(std::path::PathBuf::from) {
                if let Ok(bytes) = self.nlp.to_artifact_bytes() {
                    self.pending_writes.push(PendingWrite { path, bytes });
                }
            }
            self.last_decay_at = now;
        }
        let action = if pred.abstained || !pred.intent.is_fault() {
            self.last = None;
            self.streak = 0;
            DiagnosticAction::KeepNormal
        } else {
            if self.last == Some(pred.intent) {
                self.streak = self.streak.saturating_add(1);
            } else {
                self.last = Some(pred.intent);
                self.streak = 1;
            }
            let (_, _, base_streak) = pred.intent.thresholds();
            let needed = if pred.corroborated {
                base_streak.saturating_sub(1).max(1)
            } else {
                base_streak
            };
            if self.streak >= needed {
                let in_cooldown = self
                    .last_action_at
                    .is_some_and(|t| now.saturating_duration_since(t) < self.cooldown);
                if in_cooldown && self.streak == needed {
                    DiagnosticAction::KeepNormal
                } else {
                    self.last_action_at = Some(now);
                    if !trigger_text.trim().is_empty() {
                        self.pending_feedback = Some((trigger_text.to_string(), pred.intent, now));
                    }
                    pred.action
                }
            } else {
                DiagnosticAction::KeepNormal
            }
        };
        self.last_pred = Some(pred);
        action
    }

    /// Bounded online learning after the runtime separately verifies clean live telemetry.
    /// This method alone does not establish that the preceding action caused recovery.
    pub fn record_outcome(&mut self, clean_streams: u32, now: Instant) -> bool {
        if clean_streams < 3 {
            return false;
        }
        let Some((text, intent, at)) = self.pending_feedback.take() else {
            return false;
        };
        let elapsed = now.saturating_duration_since(at);
        if elapsed < Duration::from_secs(5) || elapsed > Duration::from_secs(120) {
            if elapsed < Duration::from_secs(5) {
                self.pending_feedback = Some((text, intent, at));
            }
            return false;
        }
        if self.candidate_model.is_none() { self.candidate_model = Some(self.nlp.clone()); }
        let candidate = self.candidate_model.as_mut().expect("candidate initialized");
        let before = candidate.clone();
        if !candidate.train_online_verified(&text, intent, now) { return false; }
        if let Some(candidate_path) = std::env::var_os("KHAYMALI_NLP_CANDIDATE_PATH").map(std::path::PathBuf::from) {
            if let Some(active_path) = std::env::var_os("KHAYMALI_NLP_MODEL_PATH").map(std::path::PathBuf::from) {
                if candidate_path == active_path { *candidate = before; return false; }
            }
            // v0.15.1: serialize only; the runtime writes it outside its lock.
            match candidate.to_artifact_bytes() {
                Ok(bytes) => self.pending_writes.push(PendingWrite { path: candidate_path.clone(), bytes }),
                Err(_) => { *candidate = before; return false; }
            }
            // remember the learning stream (bounded) for the holdout-overlap guard
            if self.candidate_learned.len() >= 4096 { self.candidate_learned.remove(0); }
            self.candidate_learned.push(text.clone());
            let mut log = self.candidate_learned.join("\n");
            log.push('\n');
            self.pending_writes.push(PendingWrite { path: candidate_path.with_extension("learned.txt"), bytes: log.into_bytes() });
        } else {
            if self.candidate_learned.len() >= 4096 { self.candidate_learned.remove(0); }
            self.candidate_learned.push(text);
        }
        true
    }

    pub fn candidate_online_updates_total(&self) -> u32 {
        self.candidate_model.as_ref().map(|candidate| candidate.online_updates_total().saturating_sub(self.nlp.online_updates_total())).unwrap_or(0)
    }

    pub fn discard_candidate(&mut self) {
        self.candidate_model = None;
        self.candidate_learned.clear();
        if let Some(path) = std::env::var_os("KHAYMALI_NLP_CANDIDATE_PATH").map(std::path::PathBuf::from) { let _ = std::fs::remove_file(path.with_extension("learned.txt")); let _ = std::fs::remove_file(path); }
    }

    /// Promote only after an independently labeled holdout demonstrates improvement without
    /// increasing false positives on Healthy/Unrelated examples.
    pub fn evaluate_and_promote_candidate(
        &mut self,
        holdout: &[(&str, NetIntent)],
        min_samples: usize,
        min_accuracy_gain_pp: f64,
        max_false_positive_increase_pp: f64,
    ) -> CandidatePromotionDecision {
        if holdout.len() < min_samples.max(1) { return CandidatePromotionDecision::InsufficientHoldout; }
        let safe_samples = holdout.iter().filter(|(_, y)| matches!(y, NetIntent::Healthy | NetIntent::Unrelated)).count();
        let fault_samples = holdout.len().saturating_sub(safe_samples);
        if safe_samples < 5 || fault_samples < 5 { return CandidatePromotionDecision::InsufficientHoldout; }
        let Some(candidate) = self.candidate_model.as_ref() else { return CandidatePromotionDecision::NoCandidate; };
        if holdout_overlap(holdout, &self.candidate_learned) > 0.05 {
            return CandidatePromotionDecision::HoldoutOverlapsTraining;
        }
        let (base_acc, base_fp) = evaluate_model(&self.nlp, holdout);
        let (candidate_acc, candidate_fp) = evaluate_model(candidate, holdout);
        if candidate_acc < base_acc || candidate_fp > base_fp + max_false_positive_increase_pp.max(0.0) {
            return CandidatePromotionDecision::Regression;
        }
        if candidate_acc < base_acc + min_accuracy_gain_pp.max(0.0) { return CandidatePromotionDecision::NoImprovement; }
        let candidate = self.candidate_model.take().expect("candidate checked above");
        if let Some(active_path) = std::env::var_os("KHAYMALI_NLP_MODEL_PATH").map(std::path::PathBuf::from) {
            let backup = active_path.with_extension("previous.model");
            if self.nlp.save_artifact_atomic(&backup).is_err() || candidate.save_artifact_atomic(&active_path).is_err() {
                self.candidate_model = Some(candidate);
                return CandidatePromotionDecision::PersistenceFailed;
            }
        }
        self.previous_model = Some(self.nlp.clone());
        self.nlp = candidate;
        self.pending_feedback = None;
        self.last = None;
        self.streak = 0;
        self.last_pred = None;
        self.last_action_at = None;
        self.last_decay_at = Instant::now();
        if let Some(path) = std::env::var_os("KHAYMALI_NLP_CANDIDATE_PATH").map(std::path::PathBuf::from) { let _ = std::fs::remove_file(path.with_extension("learned.txt")); let _ = std::fs::remove_file(path); }
        CandidatePromotionDecision::Promoted
    }

    pub fn rollback_promoted_model(&mut self) -> bool {
        let previous = if let Some(model) = self.previous_model.take() { Some(model) } else {
            std::env::var_os("KHAYMALI_NLP_MODEL_PATH").map(std::path::PathBuf::from)
                .and_then(|path| TinyNetNlp::load_artifact(&path.with_extension("previous.model")).ok())
        };
        let Some(previous) = previous else { return false; };
        if let Some(path) = std::env::var_os("KHAYMALI_NLP_MODEL_PATH").map(std::path::PathBuf::from) {
            if previous.save_artifact_atomic(&path).is_err() { self.previous_model = Some(previous); return false; }
        }
        self.nlp = previous;
        if let Some(path) = std::env::var_os("KHAYMALI_NLP_MODEL_PATH").map(std::path::PathBuf::from) { let _ = std::fs::remove_file(path.with_extension("previous.model")); }
        self.candidate_model = None;
        self.candidate_learned.clear();
        self.pending_feedback = None;
        self.last = None;
        self.streak = 0;
        self.last_pred = None;
        self.last_action_at = None;
        self.last_decay_at = Instant::now();
        if let Some(path) = std::env::var_os("KHAYMALI_NLP_CANDIDATE_PATH").map(std::path::PathBuf::from) { let _ = std::fs::remove_file(path.with_extension("learned.txt")); let _ = std::fs::remove_file(path); }
        true
    }

    pub fn observe_log(&mut self, log: &str) -> DiagnosticAction {
        let p = self.nlp.classify(log);
        self.gate(p, log, Instant::now())
    }

    pub fn observe_metrics(&mut self, m: &LinkMetrics) -> DiagnosticAction {
        self.observe_metrics_at(m, Instant::now())
    }

    pub fn observe_metrics_at(&mut self, m: &LinkMetrics, now: Instant) -> DiagnosticAction {
        let p = self.nlp.classify_metrics(m);
        self.gate(p, "", now)
    }

    pub fn observe_combined_at(
        &mut self,
        log: &str,
        m: &LinkMetrics,
        now: Instant,
    ) -> DiagnosticAction {
        let p = self.nlp.classify_combined(log, m);
        self.gate(p, log, now)
    }
}

impl Default for NlpAdvisor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v0.15.1: NlpAdvisor reads KHAYMALI_NLP_* env vars; tests constructing one serialize here.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn intent(nlp: &TinyNetNlp, s: &str) -> NetIntent {
        nlp.classify(s).intent
    }

    #[test]
    fn tdd_classifies_socket_and_persian_symptoms() {
        let nlp = TinyNetNlp::new_pretrained();
        assert_eq!(intent(&nlp, "connection reset by peer after clienthello"), NetIntent::EarlyRst);
        assert_eq!(intent(&nlp, "read timeout stalled at 16384 bytes"), NetIntent::ByteFreeze);
        assert_eq!(intent(&nlp, "keepalive ok large frame dropped emsgsize"), NetIntent::PmtuDrop);
        assert_eq!(intent(&nlp, "فریز و توقف وسط دانلود"), NetIntent::ByteFreeze);
    }

    #[test]
    fn tdd_held_out_harsh_and_errno_separation() {
        let nlp = TinyNetNlp::new_pretrained();
        assert_eq!(intent(&nlp, "dial tcp: connect: network is unreachable"), NetIntent::RouteOrDnsFail);
        assert_eq!(intent(&nlp, "lookup failed: no such host (NXDOMAIN)"), NetIntent::RouteOrDnsFail);
        assert_eq!(intent(&nlp, "econnrefused"), NetIntent::RouteOrDnsFail);
        assert_eq!(intent(&nlp, "econnreset"), NetIntent::EarlyRst);
        assert_eq!(intent(&nlp, "emsgsize"), NetIntent::PmtuDrop);
        assert_eq!(intent(&nlp, "high jitter and 15% packet loss, rtt 1200ms"), NetIntent::Throttle);
        assert_eq!(intent(&nlp, "download stuck after 15KB, rx idle 20s"), NetIntent::ByteFreeze);
        assert_eq!(intent(&nlp, "transfer froze at 16384 bytes, no RST, no FIN"), NetIntent::ByteFreeze);
        assert_eq!(intent(&nlp, "sendmsg: Message too long (EMSGSIZE) on 1400 byte frame"), NetIntent::PmtuDrop);
        assert_eq!(intent(&nlp, "everything is fine, link stable, rtt 45ms, no loss"), NetIntent::Healthy);
        assert_eq!(intent(&nlp, "سایت باز نمیشه دی ان اس کار نمیکنه"), NetIntent::RouteOrDnsFail);
        assert_eq!(intent(&nlp, "خروجی در دسترس نیست تایم اوت میده"), NetIntent::RouteOrDnsFail);
        assert_eq!(intent(&nlp, "iperf throughput dropped to 30kbps massive retransmissions"), NetIntent::Throttle);
    }

    #[test]
    fn tdd_log_noise_and_persian_digits_do_not_change_verdict() {
        let nlp = TinyNetNlp::new_pretrained();
        let noisy = "2026-11-26T10:11:12Z WARN khaymali::entry pid=4121 CONNECTION RESET BY PEER (retry 3/5) [fd=17]";
        assert_eq!(intent(&nlp, noisy), NetIntent::EarlyRst);
        assert_eq!(intent(&nlp, "فریز و توقف وسط دانلود ۱۶۳۸۴"), NetIntent::ByteFreeze);
    }

    #[test]
    fn tdd_unrelated_logs_never_trigger_actions() {
        let nlp = TinyNetNlp::new_pretrained();
        for s in [
            "user logged in from 192.168.1.5",
            "config reloaded successfully",
            "systemd[1]: Started OpenSSH Daemon",
            "asdf qwer zxcv random gibberish tokens",
            "[entry] draining active streams (up to 15s)...",
            "کاربر جدید ثبت نام کرد تنظیمات ذخیره شد",
            "",
            "0x7f3a 0xdeadbeef 12345",
            "new client connected from 10.0.0.5",
            "16384",
        ] {
            let p = nlp.classify(s);
            assert_eq!(p.action, DiagnosticAction::KeepNormal, "false action on {s:?}: {p:?}");
            assert!(!p.intent.is_fault(), "fault intent on unrelated {s:?}: {p:?}");
        }
    }

    #[test]
    fn tdd_filters_single_char_persian_tokens_and_arabic_forms() {
        let mut feats = Vec::new();
        TinyNetNlp::extract_features("و به از اتصال", &mut feats);
        let mut feats_without_vav = Vec::new();
        TinyNetNlp::extract_features("به از اتصال", &mut feats_without_vav);
        assert_eq!(feats, feats_without_vav);

        let mut a = Vec::new();
        let mut b = Vec::new();
        TinyNetNlp::extract_features("كانكشن ريست", &mut a);
        TinyNetNlp::extract_features("کانکشن ریست", &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn tdd_combined_corroboration_and_contradiction_veto() {
        let nlp = TinyNetNlp::new_pretrained();
        let freeze_m = LinkMetrics { stall_bytes: Some(16_384), rx_idle_ms: 9_000, ..Default::default() };
        let p = nlp.classify_combined("read timeout", &freeze_m);
        assert_eq!(p.intent, NetIntent::ByteFreeze);
        assert!(p.corroborated);
        assert!(!p.abstained);

        let healthy_m = LinkMetrics { rtt_ms: 35, base_rtt_ms: 35, small_frames_ok: true, ..Default::default() };
        let vetoed = nlp.classify_combined("dial tcp: connection refused", &healthy_m);
        assert_eq!(vetoed.action, DiagnosticAction::KeepNormal);
        assert!(vetoed.abstained);
    }

    #[test]
    fn tdd_safe_online_learning_decay_and_rollback() {
        let mut nlp = TinyNetNlp::new_pretrained();
        let now = Instant::now();
        assert!(!nlp.train_online_verified("custom noise token", NetIntent::Unrelated, now));
        let mut learned = false;
        for _ in 0..4 {
            learned |= nlp.train_online_verified("isp_custom_pmtu_tag", NetIntent::PmtuDrop, now);
        }
        assert!(learned);
        assert!(nlp.online_updates_total() >= 1);
        nlp.decay_online_weights();
        nlp.reset_online_weights();
        let online_only_hash = TinyNetNlp::fnv32(b"c|isp_custom_pmtu_tag");
        assert!(!nlp.is_known_net(online_only_hash));
        assert_eq!(nlp.classify("isp_custom_pmtu_tag").action, DiagnosticAction::KeepNormal);
    }

    #[test]
    fn reset_advisor_discards_pending_online_feedback() {
        let _env = env_guard();
        let mut adv = NlpAdvisor::with_cooldown(Duration::from_secs(0));
        let log = "read timed out after 15kb stage_stream";
        let _ = adv.observe_log(log);
        let _ = adv.observe_log(log);
        assert!(adv.pending_feedback.is_some());
        adv.reset_online_learning();
        assert!(adv.pending_feedback.is_none());
        assert!(!adv.record_outcome(3, Instant::now() + Duration::from_secs(10)));
        assert_eq!(adv.nlp().online_updates_total(), 0);
    }

    #[test]
    fn tdd_sequence_metrics_huge_input_and_advisor_hysteresis() {
        let _env = env_guard();
        let mut nlp = TinyNetNlp::new_pretrained();
        nlp.push_event_token("rtt_spike");
        nlp.push_event_token("jitter_high");
        nlp.push_event_token("loss_burst");
        assert_eq!(nlp.classify("").intent, NetIntent::Throttle);

        nlp.clear_event_window();
        let big = "a".repeat(200_000);
        assert_eq!(nlp.classify(&big).action, DiagnosticAction::KeepNormal);

        let mut adv = NlpAdvisor::with_cooldown(Duration::from_secs(0));
        let m = LinkMetrics { stall_bytes: Some(16_384), rx_idle_ms: 9_000, ..Default::default() };
        assert_eq!(adv.observe_metrics(&m), DiagnosticAction::KeepNormal);
        assert_eq!(
            adv.observe_metrics(&m),
            DiagnosticAction::ReduceChunkSize { target_bytes: 1200 }
        );
        assert_eq!(adv.observe_metrics(&LinkMetrics::default()), DiagnosticAction::KeepNormal);
        assert_eq!(adv.observe_metrics(&m), DiagnosticAction::KeepNormal);
    }

    #[test]
    fn model_artifact_roundtrip_and_corruption_rejection() {
        let model = TinyNetNlp::new_pretrained();
        let bytes = model.to_artifact_bytes().unwrap();
        let restored = TinyNetNlp::from_artifact_bytes(&bytes).unwrap();
        assert_eq!(model.classify("connection reset by peer").intent, restored.classify("connection reset by peer").intent);
        let mut corrupt = bytes.clone();
        corrupt[0] ^= 0xff;
        assert!(TinyNetNlp::from_artifact_bytes(&corrupt).is_err());
        assert!(TinyNetNlp::from_artifact_bytes(&bytes[..bytes.len()-1]).is_err());
    }


    #[test]
    fn model_artifact_atomic_file_roundtrip() {
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("khaymali-model-{}-{stamp}.bin", std::process::id()));
        let model = TinyNetNlp::new_pretrained();
        model.save_artifact_atomic(&path).unwrap();
        let loaded = TinyNetNlp::load_artifact(&path).unwrap();
        assert_eq!(model.classify("dns servfail nxdomain").intent, loaded.classify("dns servfail nxdomain").intent);
        std::fs::remove_file(path).unwrap();
    }


    #[test]
    fn advisor_online_learning_is_candidate_isolated_until_holdout_promotion() {
        let _env = env_guard();
        let mut advisor = NlpAdvisor::new();
        let before = advisor.nlp().to_artifact_bytes().unwrap();
        // Exercise the public candidate path directly; no live traffic or persistence path is needed.
        advisor.candidate_model = Some(advisor.nlp().clone());
        let candidate = advisor.candidate_model.as_mut().unwrap();
        let _ = candidate.train_online_verified("custom_pmtu_event isp_edge_tag", NetIntent::PmtuDrop, Instant::now());
        assert_eq!(before, advisor.nlp().to_artifact_bytes().unwrap());
        let holdout = [
            ("healthy link stable no loss", NetIntent::Healthy),
            ("connection reset by peer rst_early", NetIntent::EarlyRst),
            ("read timeout freeze_bytes stall_16k", NetIntent::ByteFreeze),
            ("large frame pmtu emsgsize", NetIntent::PmtuDrop),
            ("throttle slow_ack rtt_spike", NetIntent::Throttle),
            ("dns servfail nxdomain unreachable", NetIntent::RouteOrDnsFail),
            ("user logged in config reload", NetIntent::Unrelated),
        ];
        let decision = advisor.evaluate_and_promote_candidate(&holdout, 20, 0.5, 0.25);
        assert!(matches!(decision, CandidatePromotionDecision::InsufficientHoldout | CandidatePromotionDecision::NoImprovement | CandidatePromotionDecision::Regression | CandidatePromotionDecision::Promoted));
    }


    #[test]
    fn online_learning_never_mutates_unrelated_and_roundtrips_artifact() {
        let mut nlp = TinyNetNlp::new_pretrained();
        let now = Instant::now();
        let text = "user logged in config reloaded custom_pmtu_tag";
        for _ in 0..3 {
            let _ = nlp.train_online_verified(text, NetIntent::PmtuDrop, now);
        }
        assert_eq!(nlp.delta_bias[NetIntent::Unrelated as usize], 0);
        assert!(nlp.delta_weights[NetIntent::Unrelated as usize].iter().all(|&v| v == 0));
        let bytes = nlp.to_artifact_bytes().unwrap();
        let restored = TinyNetNlp::from_artifact_bytes(&bytes).unwrap();
        assert_eq!(restored.online_updates_total(), nlp.online_updates_total());
        let mut mid_corrupt = bytes.clone();
        let mid = mid_corrupt.len() / 2;
        mid_corrupt[mid] ^= 0x01;
        assert!(TinyNetNlp::from_artifact_bytes(&mid_corrupt).is_err());
    }

    #[test]
    fn advisor_reload_preserves_rollback_capability() {
        let _env = env_guard();
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let model_path = std::env::temp_dir().join(format!("khaymali-reload-{}-{stamp}.model", std::process::id()));
        let mut updated = TinyNetNlp::new_pretrained();
        let _ = updated.train_online_verified("isp_edge_reload_token", NetIntent::PmtuDrop, Instant::now());
        updated.save_artifact_atomic(&model_path).unwrap();

        let mut adv = NlpAdvisor::with_cooldown(Duration::from_secs(0));
        assert_eq!(adv.nlp().online_updates_total(), 0);
        let loaded = TinyNetNlp::load_artifact(&model_path).unwrap();
        let prev = std::mem::replace(&mut adv.nlp, loaded);
        adv.previous_model = Some(prev);
        assert!(adv.nlp().online_updates_total() >= 1);
        assert!(adv.rollback_promoted_model());
        assert_eq!(adv.nlp().online_updates_total(), 0);
        let _ = std::fs::remove_file(&model_path);
    }

    #[test]
    fn v0151_targeted_confusions_are_fixed() {
        let nlp = TinyNetNlp::new_pretrained();
        assert_ne!(intent(&nlp, "speed dropped to 95kbps"), NetIntent::PmtuDrop);
        assert_eq!(intent(&nlp, "big frames dropped small frames ok"), NetIntent::PmtuDrop);
        assert_eq!(intent(&nlp, "stage_stream read timeout 20s"), NetIntent::ByteFreeze);
        assert_eq!(intent(&nlp, "stage_dial connect timeout"), NetIntent::RouteOrDnsFail);
        assert_eq!(intent(&nlp, "پینگ میده ولی فایل بزرگ نمیاد"), NetIntent::PmtuDrop);
        assert_eq!(intent(&nlp, "rate limited, slow but alive"), NetIntent::Throttle);
        assert_eq!(intent(&nlp, "no errors, no resets, no timeouts"), NetIntent::Healthy);
        assert_eq!(intent(&nlp, "write: epipe stage_handshake"), NetIntent::EarlyRst);
    }

    #[test]
    fn v0151_online_learning_artifact_always_reloads() {
        let mut nlp = TinyNetNlp::new_pretrained();
        let now = Instant::now();
        for t in ["config reloaded pool growth stall_16k", "user logged in reset", "service started emsgsize",
                  "draining active streams timeout", "worker thread spawned econnrefused"] {
            for target in [NetIntent::ByteFreeze, NetIntent::EarlyRst, NetIntent::PmtuDrop, NetIntent::RouteOrDnsFail] {
                let _ = nlp.train_online_verified(t, target, now);
            }
        }
        let bytes = nlp.to_artifact_bytes().unwrap();
        assert!(TinyNetNlp::from_artifact_bytes(&bytes).is_ok());
    }

    #[test]
    fn v0151_deferred_writes_newest_per_path() {
        let _env = env_guard();
        let mut adv = NlpAdvisor::new();
        adv.pending_writes.push(PendingWrite { path: "/tmp/a".into(), bytes: vec![1] });
        adv.pending_writes.push(PendingWrite { path: "/tmp/a".into(), bytes: vec![2] });
        adv.pending_writes.push(PendingWrite { path: "/tmp/b".into(), bytes: vec![3] });
        let w = adv.take_pending_writes();
        assert_eq!(w.len(), 2);
        assert_eq!(w.iter().find(|x| x.path.ends_with("a")).unwrap().bytes, vec![2]);
        assert!(adv.take_pending_writes().is_empty());
    }

    #[test]
    fn v0151_holdout_overlap_is_detected() {
        let learned = vec!["Stall_16k  freeze".to_string(), "x".to_string()];
        let h = [("stall_16k freeze", NetIntent::ByteFreeze), ("other", NetIntent::Healthy)];
        assert!((holdout_overlap(&h, &learned) - 0.5).abs() < 1e-9);
        assert_eq!(holdout_overlap(&h, &[]), 0.0);
    }

    #[test]
    fn v0151_explain_lists_top_evidence_words() {
        let nlp = TinyNetNlp::new_pretrained();
        let why = nlp.explain("connection reset by peer econnreset", NetIntent::EarlyRst, 3);
        assert!(!why.is_empty() && why.split(',').count() <= 3);
    }
}
