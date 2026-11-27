//! Autopilot (`src/autopilot.rs`): moves a dead tunnel to a carrier that works.
//!
//! A *carrier* is one way to reach the Exit: plain `HOST:PORT` (tcp, optionally camouflaged),
//! `udp://`, `ktunnel://` or `auto://`. Give the Entry one `--exit` per carrier the Exit really
//! listens on, then add `--autopilot`. When nothing has worked for `down_min` minutes it:
//!   1. checks the limits (cooldown, runs per 24 h, quiet hours),
//!   2. path-tests every allowed carrier (a real dial + Noise handshake) or, with
//!      `--ap-no-path-test`, walks them in order,
//!   3. moves the tunnel to the fastest one that got through (`Exits::force`) and waits up to
//!      45 s for a real link on it; if none appears the previous choice is restored and that
//!      carrier is tried last for the next 6 hours; at most 3 carriers per run.
//! Every run is written to a small history file and sent to the alert channels.
//!
//! A tunnel that has never been seen up since start is left alone (you may still be setting it
//! up), and traffic still flowing counts as "up" even when new dials fail (traffic beats ping).

use crate::alerts::Alerts;
use crate::health::Exits;
use crate::stats;
use crate::util::now_unix;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const VERIFY_WINDOW: Duration = Duration::from_secs(45);
pub const PENALTY_SECS: u64 = 6 * 3600;
pub const MAX_TRIES_PER_RUN: usize = 3;
const HISTORY_CAP: usize = 100;

#[derive(Clone, Debug)]
pub struct Limits {
    pub down_min: u64,
    pub cooldown_min: u64,
    pub per_day: u32,
    pub path_test: bool,
    /// Quiet hours `(from, to)` in server time (0-23); `from > to` wraps midnight.
    pub quiet: Option<(u8, u8)>,
    /// Allowed carriers: any of `tcp`, `udp`, `ktunnel`, `auto`. Empty = all.
    pub allowed: Vec<String>,
    /// Minutes east of UTC used for quiet hours (`KHAYMALI_TZ_OFFSET_MIN`, e.g. 210 for Iran).
    pub tz_offset_min: i64,
    /// Only watch and alert (down / up); never switch carriers.
    pub monitor_only: bool,
    /// How long a moved tunnel has to show a real link before it is rolled back.
    pub verify: Duration,
    /// How often the monitor looks at the tunnel.
    pub tick: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { down_min: 5, cooldown_min: 30, per_day: 6, path_test: true, quiet: None, allowed: vec![], tz_offset_min: 0, monitor_only: false, verify: VERIFY_WINDOW, tick: Duration::from_secs(10) }
    }
}

pub fn carrier_of(addr: &str) -> &'static str {
    if addr.starts_with("udp://") {
        "udp"
    } else if addr.starts_with("ktunnel://") {
        "ktunnel"
    } else if addr.starts_with("wss://") {
        "wss"
    } else if addr.starts_with("ws://") {
        "ws"
    } else if addr.starts_with("ssh://") {
        "ssh"
    } else if addr.starts_with("spoof://") {
        "spoof"
    } else if addr.starts_with("auto://") {
        "auto"
    } else {
        "tcp"
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub ts: u64,
    pub kind: String,
    pub detail: String,
}

#[derive(Default, Clone, Debug)]
pub struct State {
    pub events: VecDeque<Event>,
    pub runs: Vec<u64>,
    pub failed: HashMap<String, u64>,
}

fn esc(s: &str) -> String {
    s.replace(['|', '\n', '\r'], " ")
}

impl State {
    pub fn push(&mut self, kind: &str, detail: &str) {
        if self.events.len() >= HISTORY_CAP {
            self.events.pop_front();
        }
        self.events.push_back(Event { ts: now_unix(), kind: kind.into(), detail: esc(detail) });
    }

    pub fn to_text(&self) -> String {
        let mut o = String::new();
        for e in &self.events {
            o.push_str(&format!("E|{}|{}|{}\n", e.ts, e.kind, e.detail));
        }
        for r in &self.runs {
            o.push_str(&format!("R|{r}\n"));
        }
        let mut f: Vec<_> = self.failed.iter().collect();
        f.sort();
        for (a, t) in f {
            o.push_str(&format!("F|{}|{t}\n", esc(a)));
        }
        o
    }

    pub fn from_text(s: &str) -> State {
        let mut st = State::default();
        for l in s.lines() {
            let p: Vec<&str> = l.splitn(4, '|').collect();
            match p.as_slice() {
                ["E", ts, k, d] => {
                    if let Ok(ts) = ts.parse() {
                        st.events.push_back(Event { ts, kind: (*k).into(), detail: (*d).into() });
                    }
                }
                ["R", ts] => {
                    if let Ok(t) = ts.parse() {
                        st.runs.push(t)
                    }
                }
                ["F", a, t] => {
                    if let Ok(t) = t.parse() {
                        st.failed.insert((*a).into(), t);
                    }
                }
                _ => {}
            }
        }
        while st.events.len() > HISTORY_CAP {
            st.events.pop_front();
        }
        st
    }

    pub fn load(path: &str) -> State {
        std::fs::read_to_string(path).map(|s| State::from_text(&s)).unwrap_or_default()
    }

    pub fn save(&self, path: &str) {
        let tmp = format!("{path}.tmp");
        if std::fs::write(&tmp, self.to_text()).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Run,
    Wait(String),
}

pub fn local_hour(now: u64, tz_offset_min: i64) -> u8 {
    (((now as i64 + tz_offset_min * 60).rem_euclid(86400)) / 3600) as u8
}

pub fn in_quiet(hour: u8, quiet: Option<(u8, u8)>) -> bool {
    match quiet {
        None => false,
        Some((a, b)) if a == b => false,
        Some((a, b)) if a < b => hour >= a && hour < b,
        Some((a, b)) => hour >= a || hour < b,
    }
}

/// Should a run start now? Mirrors what an operator would check before touching a tunnel.
pub fn decide(l: &Limits, st: &State, now: u64, down_secs: u64, seen_up: bool) -> Verdict {
    if !seen_up {
        return Verdict::Wait("tunnel not seen up yet (still being set up)".into());
    }
    let need = l.down_min * 60;
    if down_secs < need {
        return Verdict::Wait(format!("down for {} of {} minutes", down_secs / 60, l.down_min));
    }
    if in_quiet(local_hour(now, l.tz_offset_min), l.quiet) {
        return Verdict::Wait("quiet hours".into());
    }
    if let Some(last) = st.runs.iter().max() {
        let next = last + l.cooldown_min * 60;
        if now < next {
            return Verdict::Wait(format!("next run in {} minutes", (next - now).div_ceil(60)));
        }
    }
    let in_day = st.runs.iter().filter(|&&t| now.saturating_sub(t) < 86400).count() as u32;
    if in_day >= l.per_day {
        return Verdict::Wait(format!("daily limit reached ({}/{})", in_day, l.per_day));
    }
    Verdict::Run
}

/// Allowed carriers only; a carrier that failed within 6 h goes last.
pub fn order_candidates(l: &Limits, st: &State, now: u64, addrs: &[String]) -> Vec<String> {
    let mut ok: Vec<String> = addrs
        .iter()
        .filter(|a| l.allowed.is_empty() || l.allowed.iter().any(|c| c == carrier_of(a)))
        .cloned()
        .collect();
    let penalised = |a: &String| st.failed.get(a).is_some_and(|t| now.saturating_sub(*t) < PENALTY_SECS);
    ok.sort_by_key(penalised); // stable: keeps configured order inside each group
    ok
}

/// Fastest first among path-test results; failures are dropped.
pub fn rank_path_test(results: Vec<(String, Option<Duration>)>) -> Vec<String> {
    let mut good: Vec<(String, Duration)> = results.into_iter().filter_map(|(a, r)| r.map(|d| (a, d))).collect();
    good.sort_by(|a, b| a.1.cmp(&b.1));
    good.into_iter().map(|(a, _)| a).collect()
}

fn traffic_total() -> i64 {
    stats::BYTES_DOWN.load(Relaxed) as i64
}

/// The runner. `probe(addr)` must do a real dial + handshake and return its duration.
pub async fn run<F, Fut>(exits: Arc<Exits>, l: Limits, state_path: Option<String>, alerts: Option<Arc<Alerts>>, probe: F)
where
    F: Fn(String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<Duration>> + Send + 'static,
{
    let probe = Arc::new(probe);
    let mut st = state_path.as_deref().map(State::load).unwrap_or_default();
    let save = |st: &State| {
        if let Some(p) = &state_path {
            st.save(p);
        }
    };
    let say = |kind: &str, msg: &str| {
        let alerts = alerts.clone();
        let line = format!("[autopilot] {kind}: {msg}");
        eprintln!("{line}");
        if let Some(a) = alerts {
            a.send(&line);
        }
    };
    let (mut down_since, mut seen_up, mut was_down, mut last_traffic) = (None::<Instant>, false, false, traffic_total());
    let mut last_wait = String::new();
    let all_addrs: Vec<String> = exits.snapshot().into_iter().map(|s| s.addr).collect();
    if !l.monitor_only && all_addrs.len() < 2 {
        eprintln!("[autopilot] WARNING: only one --exit configured; give one --exit per carrier (tcp, udp://, ktunnel://) so there is something to switch to");
    }
    if l.monitor_only {
        eprintln!("[autopilot] monitor only: alerts on down/up, no carrier switching");
    } else {
        eprintln!(
        "[autopilot] on: down>{}m cooldown {}m max {}/day path-test={} carriers={:?}",
        l.down_min, l.cooldown_min, l.per_day, l.path_test,
        if l.allowed.is_empty() { vec!["all".to_string()] } else { l.allowed.clone() }
        );
    }
    loop {
        tokio::time::sleep(l.tick).await;
        let snap = exits.snapshot();
        let t = traffic_total();
        let moving = t != last_traffic;
        last_traffic = t;
        let up = snap.iter().any(|s| s.up) || moving;
        if up {
            if was_down {
                st.push("recovered", "tunnel is up again");
                save(&st);
                say("recovered", "tunnel is up again");
            }
            seen_up = true;
            was_down = false;
            down_since = None;
            last_wait.clear();
            continue;
        }
        let since = *down_since.get_or_insert_with(Instant::now);
        if !was_down && seen_up {
            was_down = true;
            say("down", "no carrier is answering");
        }
        let now = now_unix();
        match decide(&l, &st, now, since.elapsed().as_secs(), seen_up) {
            Verdict::Wait(why) => {
                let bucket = why.split(" of ").next().unwrap_or("").to_string();
                if bucket != last_wait {
                    eprintln!("[autopilot] waiting: {why}");
                    last_wait = bucket;
                }
            }
            Verdict::Run if l.monitor_only => {}
            Verdict::Run => {
                let cands = order_candidates(&l, &st, now, &all_addrs);
                st.runs.push(now);
                st.runs.retain(|&r| now.saturating_sub(r) < 86400 * 2);
                if cands.is_empty() {
                    st.push("skipped", "no allowed carrier configured");
                    save(&st);
                    say("skipped", "no allowed carrier configured");
                    continue;
                }
                // 2. path test (or configured order)
                let order = if l.path_test {
                    let mut hs = Vec::new();
                    for a in cands.clone() {
                        let (p, a2) = (probe.clone(), a.clone());
                        hs.push((a, tokio::spawn(async move { tokio::time::timeout(Duration::from_secs(10), p(a2)).await })));
                    }
                    let mut res = Vec::new();
                    for (a, h) in hs {
                        let r = match h.await {
                            Ok(Ok(Ok(d))) => Some(d),
                            _ => None,
                        };
                        res.push((a, r));
                    }
                    let detail: Vec<String> = res
                        .iter()
                        .map(|(a, r)| match r {
                            Some(d) => format!("{} {}ms", carrier_of(a), d.as_millis()),
                            None => format!("{} blocked", carrier_of(a)),
                        })
                        .collect();
                    st.push("path_test", &detail.join(", "));
                    let ranked = rank_path_test(res);
                    if ranked.is_empty() {
                        st.push("failed", "no allowed carrier got through the path test");
                        save(&st);
                        say("failed", "no allowed carrier got through the path test");
                        continue;
                    }
                    ranked
                } else {
                    cands
                };
                // 3. move, verify 45 s, roll back
                let mut tried = Vec::new();
                let mut done = false;
                for a in order.into_iter().take(MAX_TRIES_PER_RUN) {
                    let prev = exits.forced();
                    exits.force(Some(a.clone()));
                    let deadline = Instant::now() + l.verify;
                    let mut connected = false;
                    while Instant::now() < deadline {
                        tokio::time::sleep(l.tick.min(Duration::from_secs(3))).await;
                        if exits.snapshot().iter().any(|s| s.addr == a && s.up) {
                            connected = true;
                            break;
                        }
                        // the dialers only retry after their backoff; nudge a real attempt
                        if let Ok(Ok(d)) = tokio::time::timeout(Duration::from_secs(10), probe(a.clone())).await {
                            exits.ok(&a, d);
                        }
                    }
                    if connected {
                        st.push("switched", &format!("moved to {}", carrier_of(&a)));
                        save(&st);
                        say("switched", &format!("tunnel moved to carrier {} ({a})", carrier_of(&a)));
                        done = true;
                        break;
                    }
                    exits.force(prev);
                    st.failed.insert(a.clone(), now_unix());
                    tried.push(carrier_of(&a));
                }
                if !done {
                    let m = format!("tried {}: did not connect, previous choice restored", tried.join(", "));
                    st.push("failed", &m);
                    save(&st);
                    say("failed", &m);
                } else {
                    down_since = None;
                    was_down = false;
                }
            }
        }
    }
}

pub fn status_text(path: &str) -> String {
    let st = State::load(path);
    if st.events.is_empty() && st.runs.is_empty() {
        return format!("autopilot: no history in {path}\n");
    }
    let now = now_unix();
    let mut o = format!("autopilot history ({path}), newest last; runs in last 24h: {}\n", st.runs.iter().filter(|&&t| now.saturating_sub(t) < 86400).count());
    for e in &st.events {
        o.push_str(&format!("  {}  {:<10} {}\n", e.ts, e.kind, e.detail));
    }
    for (a, t) in &st.failed {
        if now.saturating_sub(*t) < PENALTY_SECS {
            o.push_str(&format!("  penalised (tried last for {}h): {a}\n", PENALTY_SECS / 3600));
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim() -> Limits {
        Limits::default()
    }

    #[test]
    fn waits_until_down_long_enough_and_seen_up() {
        let st = State::default();
        assert!(matches!(decide(&lim(), &st, 1000, 9999, false), Verdict::Wait(m) if m.contains("not seen up")));
        assert!(matches!(decide(&lim(), &st, 1000, 120, true), Verdict::Wait(m) if m.contains("2 of 5")));
        assert_eq!(decide(&lim(), &st, 1000, 301, true), Verdict::Run);
    }

    #[test]
    fn cooldown_and_daily_limit() {
        let now = 1_000_000;
        let mut st = State::default();
        st.runs.push(now - 600); // 10 min ago, cooldown 30
        assert!(matches!(decide(&lim(), &st, now, 9999, true), Verdict::Wait(m) if m.contains("next run in 20")));
        let mut l = lim();
        l.cooldown_min = 1;
        st.runs = (1..=6).map(|i| now - i * 3000).collect();
        assert!(matches!(decide(&l, &st, now, 9999, true), Verdict::Wait(m) if m.contains("daily limit")));
        l.per_day = 7;
        assert_eq!(decide(&l, &st, now, 9999, true), Verdict::Run);
    }

    #[test]
    fn quiet_hours_wrap_midnight() {
        assert!(in_quiet(23, Some((22, 6))) && in_quiet(3, Some((22, 6))) && !in_quiet(12, Some((22, 6))));
        assert!(in_quiet(3, Some((2, 5))) && !in_quiet(5, Some((2, 5))));
        assert!(!in_quiet(3, None));
        assert_eq!(local_hour(0, 210), 3); // 03:30 in Iran at unix 0
        let mut l = lim();
        l.quiet = Some((2, 5));
        l.tz_offset_min = 210;
        assert!(matches!(decide(&l, &State::default(), 0, 9999, true), Verdict::Wait(m) if m == "quiet hours"));
    }

    #[test]
    fn candidates_respect_allowed_and_penalty() {
        let addrs: Vec<String> = ["1.1.1.1:443", "udp://1.1.1.1:444", "ktunnel://1.1.1.1:445"].map(String::from).to_vec();
        let mut l = lim();
        let mut st = State::default();
        st.failed.insert("1.1.1.1:443".into(), 1000);
        assert_eq!(order_candidates(&l, &st, 2000, &addrs), vec!["udp://1.1.1.1:444", "ktunnel://1.1.1.1:445", "1.1.1.1:443"]);
        assert_eq!(order_candidates(&l, &st, 1000 + PENALTY_SECS + 1, &addrs)[0], "1.1.1.1:443"); // penalty expired
        l.allowed = vec!["udp".into(), "tcp".into()];
        assert_eq!(order_candidates(&l, &State::default(), 0, &addrs), vec!["1.1.1.1:443", "udp://1.1.1.1:444"]);
    }

    #[test]
    fn path_test_ranks_fastest_and_drops_blocked() {
        let r = vec![
            ("tcp".to_string(), Some(Duration::from_millis(90))),
            ("udp".to_string(), None),
            ("kt".to_string(), Some(Duration::from_millis(30))),
        ];
        assert_eq!(rank_path_test(r), vec!["kt", "tcp"]);
    }

    #[test]
    fn state_roundtrip_and_cap() {
        let mut st = State::default();
        for i in 0..150 {
            st.push("path_test", &format!("a|b\nc {i}"));
        }
        st.runs = vec![5, 6];
        st.failed.insert("udp://x:1".into(), 77);
        let back = State::from_text(&st.to_text());
        assert_eq!(back.events.len(), HISTORY_CAP);
        assert_eq!(back.runs, vec![5, 6]);
        assert_eq!(back.failed.get("udp://x:1"), Some(&77));
        assert!(back.events.back().unwrap().detail.contains("c 149"));
    }

    use crate::health::FailureKind;

    fn two_exits() -> Arc<Exits> {
        let e = Exits::new(vec!["1.1.1.1:443".into(), "udp://1.1.1.1:444".into()]);
        e.ok("1.1.1.1:443", Duration::from_millis(20)); // seen up once
        e
    }
    fn open_all(e: &Exits) {
        for a in ["1.1.1.1:443", "udp://1.1.1.1:444"] {
            for _ in 0..3 {
                e.fail_kind(a, FailureKind::Timeout);
            }
        }
    }
    fn fast() -> Limits {
        Limits { down_min: 0, cooldown_min: 1, tick: Duration::from_millis(40), verify: Duration::from_millis(600), ..Limits::default() }
    }
    fn tmp(n: &str) -> String {
        format!("{}/khaymali-ap-test-{}-{n}", std::env::temp_dir().display(), std::process::id())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_moves_a_dead_tunnel_to_the_fastest_working_carrier() {
        let e = two_exits();
        let path = tmp("move");
        let probe = |a: String| async move {
            if a.starts_with("udp://") { Ok(Duration::from_millis(30)) } else { Err(anyhow::anyhow!("blocked")) }
        };
        let h = tokio::spawn(run(e.clone(), fast(), Some(path.clone()), None, probe));
        tokio::time::sleep(Duration::from_millis(200)).await; // monitor sees it up
        open_all(&e);
        let mut st = State::default();
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            st = State::load(&path);
            if st.events.iter().any(|x| x.kind == "switched") {
                break;
            }
        }
        h.abort();
        let kinds: Vec<_> = st.events.iter().map(|x| x.kind.as_str()).collect();
        assert!(kinds.contains(&"path_test") && kinds.contains(&"switched"), "{kinds:?}");
        assert_eq!(e.forced().as_deref(), Some("udp://1.1.1.1:444"));
        let pt = st.events.iter().find(|x| x.kind == "path_test").unwrap();
        assert!(pt.detail.contains("udp 30ms") && pt.detail.contains("tcp blocked"), "{}", pt.detail);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_rolls_back_and_penalises_when_nothing_connects() {
        let e = two_exits();
        let path = tmp("fail");
        // the path test passes for tcp, but the real link never comes up and the nudge probe fails
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n2 = n.clone();
        let probe = move |a: String| {
            let first = n2.fetch_add(1, Relaxed) < 2; // the two path-test probes
            async move {
                if first && a == "1.1.1.1:443" { Ok(Duration::from_millis(10)) } else { Err(anyhow::anyhow!("no")) }
            }
        };
        e.force(Some("keep-me".into())); // an earlier choice must come back after rollback
        let h = tokio::spawn(run(e.clone(), fast(), Some(path.clone()), None, probe));
        tokio::time::sleep(Duration::from_millis(200)).await;
        open_all(&e);
        let mut st = State::default();
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            st = State::load(&path);
            if st.events.iter().any(|x| x.kind == "failed") {
                break;
            }
        }
        h.abort();
        assert!(st.events.iter().any(|x| x.kind == "failed" && x.detail.contains("restored")), "{:?}", st.events);
        assert_eq!(e.forced().as_deref(), Some("keep-me"), "previous choice restored");
        assert!(st.failed.contains_key("1.1.1.1:443"), "failed carrier is penalised");
        assert!(!st.events.iter().any(|x| x.kind == "switched"));
        let _ = std::fs::remove_file(path);
    }
}
