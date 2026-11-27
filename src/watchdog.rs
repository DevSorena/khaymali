//! Decoy Parity Watchdog + Khaymali 3-Layer Tunnel Health & Per-Tunnel Watchdog (`src/watchdog.rs`).

use crate::alerts::Alerts;
use crate::health::Exits;
use crate::stats;
use std::collections::HashMap;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

pub fn spawn_decoy_watchdog(fallback_addr: String, period: Duration) {
    tokio::spawn(async move {
        loop {
            let t0 = Instant::now();
            match timeout(Duration::from_secs(5), TcpStream::connect(&fallback_addr)).await {
                Ok(Ok(_)) => {
                    stats::DECOY_UP.store(1, Relaxed);
                    stats::DECOY_RTT_MS.store(t0.elapsed().as_millis() as u64, Relaxed);
                }
                _ => {
                    stats::DECOY_UP.store(0, Relaxed);
                    stats::log_err_rl(&format!("[watchdog] WARNING: decoy {fallback_addr} unreachable"));
                }
            }
            sleep(period).await;
        }
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthVerdict {
    Pass,
    Fail,
    Unreachable,
}

impl HealthVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Unreachable => "UNREACHABLE",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ThreeLayerHealth {
    pub service_ok: bool,
    pub session_ok: bool,
    pub data_ok: bool,
    pub data_rtt_ms: f64,
    pub verdict: HealthVerdict,
    pub detail: String,
}

pub fn evaluate_three_layers(
    service_ok: bool,
    session_ok: bool,
    data_ok: bool,
    data_rtt_ms: f64,
    data_timed_out: bool,
) -> ThreeLayerHealth {
    let (verdict, detail) = if !service_ok {
        (HealthVerdict::Fail, "service not running".to_string())
    } else if !session_ok {
        (HealthVerdict::Unreachable, "no live Noise session to Exit".to_string())
    } else if data_ok {
        (HealthVerdict::Pass, format!("service + session + data OK ({data_rtt_ms:.1}ms)"))
    } else if data_timed_out {
        (HealthVerdict::Unreachable, "data probe timed out".to_string())
    } else {
        (HealthVerdict::Fail, "session up but data probe refused".to_string())
    };
    ThreeLayerHealth { service_ok, session_ok, data_ok, data_rtt_ms, verdict, detail }
}

pub async fn check_three_layer_live(exits: &Exits, probe_addr: Option<&str>) -> ThreeLayerHealth {
    let snaps = exits.snapshot();
    let session_ok = snaps.iter().any(|s| s.up) || stats::LINKS_READY.load(Relaxed) > 0;
    let service_ok = true;
    let Some(addr) = probe_addr else {
        return evaluate_three_layers(service_ok, session_ok, session_ok, 0.0, false);
    };
    let t0 = Instant::now();
    match timeout(Duration::from_secs(4), TcpStream::connect(addr)).await {
        Ok(Ok(_)) => {
            evaluate_three_layers(service_ok, session_ok, true, t0.elapsed().as_secs_f64() * 1000.0, false)
        }
        Ok(Err(_)) => evaluate_three_layers(service_ok, session_ok, false, 0.0, false),
        Err(_) => evaluate_three_layers(service_ok, session_ok, false, 0.0, true),
    }
}

pub fn watchdog_backoff(attempts: u32) -> Duration {
    let mins = match attempts {
        0 => 0,
        1 => 3,
        2 => 6,
        3 => 12,
        4 => 24,
        _ => 30,
    };
    Duration::from_secs(mins * 60)
}

#[derive(Default)]
struct PerLinkState {
    seen_up: bool,
    down_since: Option<Instant>,
    alerted_down: bool,
    restarts: u32,
    last_action: Option<Instant>,
}

pub async fn run_link_watchdog(
    exits: Arc<Exits>,
    fail_threshold: Duration,
    alerts: Option<Arc<Alerts>>,
) {
    let mut map: HashMap<String, PerLinkState> = HashMap::new();
    loop {
        sleep(Duration::from_secs(15)).await;
        let now = Instant::now();
        for snap in exits.snapshot() {
            let st = map.entry(snap.addr.clone()).or_default();
            if snap.up {
                if st.alerted_down {
                    let down_secs = st
                        .down_since
                        .map(|t| now.saturating_duration_since(t).as_secs())
                        .unwrap_or(0);
                    let msg = format!(
                        "[watchdog] Exit {} RECOVERED after {}s (rtt={:.1}ms)",
                        snap.addr, down_secs, snap.ewma_ms
                    );
                    eprintln!("{msg}");
                    if let Some(a) = &alerts {
                        a.send(&msg);
                    }
                }
                st.seen_up = true;
                st.down_since = None;
                st.alerted_down = false;
                st.restarts = 0;
            } else if st.seen_up {
                let since = *st.down_since.get_or_insert(now);
                let down_for = now.saturating_duration_since(since);
                if down_for >= fail_threshold && !st.alerted_down {
                    st.alerted_down = true;
                    let msg = format!(
                        "[watchdog] Exit {} DOWN for {}s (timeouts={}, resets={})",
                        snap.addr,
                        down_for.as_secs(),
                        snap.timeout_fails,
                        snap.reset_fails
                    );
                    eprintln!("{msg}");
                    if let Some(a) = &alerts {
                        a.send(&msg);
                    }
                }
                let need_wait = watchdog_backoff(st.restarts.saturating_add(1));
                let can_act = st
                    .last_action
                    .map(|t| now.saturating_duration_since(t) >= need_wait)
                    .unwrap_or(down_for >= fail_threshold);
                if can_act {
                    st.restarts = st.restarts.saturating_add(1);
                    st.last_action = Some(now);
                    stats::WATCHDOG_EVENTS.fetch_add(1, Relaxed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_layer_verdict_and_exponential_backoff() {
        assert_eq!(evaluate_three_layers(true, true, true, 12.5, false).verdict, HealthVerdict::Pass);
        assert_eq!(evaluate_three_layers(false, true, true, 0.0, false).verdict, HealthVerdict::Fail);
        assert_eq!(evaluate_three_layers(true, false, false, 0.0, false).verdict, HealthVerdict::Unreachable);
        assert_eq!(evaluate_three_layers(true, true, false, 0.0, true).verdict, HealthVerdict::Unreachable);
        assert_eq!(evaluate_three_layers(true, true, false, 0.0, false).verdict, HealthVerdict::Fail);
        assert_eq!(watchdog_backoff(1), Duration::from_secs(180));
        assert_eq!(watchdog_backoff(2), Duration::from_secs(360));
        assert_eq!(watchdog_backoff(3), Duration::from_secs(720));
        assert_eq!(watchdog_backoff(8), Duration::from_secs(1800));
    }
}
