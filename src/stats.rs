//! Process-wide atomic counters, race-free single-AtomicU64 CAS log rate limiter,
//! and bounded Prometheus-style metrics endpoint.

use crate::health::Exits;
use crate::util::now_unix;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering, Ordering::Relaxed};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

const MAX_METRICS_CONNS: usize = 32;
pub const MAX_ERR_LOGS_PER_SEC: u32 = 10;

pub static LINKS_READY: AtomicI64 = AtomicI64::new(0);
pub static STREAMS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static STREAMS_ACTIVE: AtomicI64 = AtomicI64::new(0);
pub static UDP_ASSOC: AtomicI64 = AtomicI64::new(0);
pub static UDP_FORWARDS_ACTIVE: AtomicI64 = AtomicI64::new(0);
pub static BYTES_UP: AtomicU64 = AtomicU64::new(0);
pub static BYTES_DOWN: AtomicU64 = AtomicU64::new(0);
pub static LINK_FAIL: AtomicU64 = AtomicU64::new(0);
pub static CAMO_OK: AtomicU64 = AtomicU64::new(0);
pub static CAMO_FALLBACK: AtomicU64 = AtomicU64::new(0);
pub static CLOCK_SKEW_DROPPED: AtomicU64 = AtomicU64::new(0);
pub static POOL_KEEPALIVE_DROPPED: AtomicU64 = AtomicU64::new(0);
pub static ADAPTIVE_ACTIONS: AtomicU64 = AtomicU64::new(0);
pub static ADAPTIVE_CHUNK_BYTES: AtomicUsize = AtomicUsize::new(14 * 1024);
pub static MUX_CARRIERS_ACTIVE: AtomicI64 = AtomicI64::new(0);
pub static MUX_STREAMS_OPENED: AtomicU64 = AtomicU64::new(0);
pub static RESUMABLE_SESSIONS_ACTIVE: AtomicI64 = AtomicI64::new(0);
pub static SESSIONS_RESUMED: AtomicU64 = AtomicU64::new(0);
pub static SESSION_RETRANSMITS: AtomicU64 = AtomicU64::new(0);
pub static L3_PACKETS_TX: AtomicU64 = AtomicU64::new(0);
pub static L3_PACKETS_RX: AtomicU64 = AtomicU64::new(0);
pub static REKEY_ROTATIONS: AtomicU64 = AtomicU64::new(0);
pub static UDP_TRANSPORT_SESSIONS: AtomicI64 = AtomicI64::new(0);
pub static KTUNNEL_SESSIONS_ACTIVE: AtomicI64 = AtomicI64::new(0);
pub static KTUNNEL_FLOWS_ACTIVE: AtomicI64 = AtomicI64::new(0);
pub static UDP_RETRANSMITS: AtomicU64 = AtomicU64::new(0);
pub static UDP_FEC_RECOVERED: AtomicU64 = AtomicU64::new(0);
pub static UDP_FEC_GROUP_K: AtomicU64 = AtomicU64::new(0);
pub static REVERSE_EXITS_CONNECTED: AtomicI64 = AtomicI64::new(0);
pub static WS_SESSIONS_ACTIVE: AtomicI64 = AtomicI64::new(0);
pub static WSS_SESSIONS_ACTIVE: AtomicI64 = AtomicI64::new(0);
pub static SSH_CARRIER_SESSIONS: AtomicI64 = AtomicI64::new(0);
pub static WATCHDOG_EVENTS: AtomicU64 = AtomicU64::new(0);
pub static FALLBACK_ACTIVE: AtomicI64 = AtomicI64::new(0);
pub static FALLBACK_EVICTED: AtomicU64 = AtomicU64::new(0);
pub static BRIDGE_REPLAY_DROPPED: AtomicU64 = AtomicU64::new(0);
pub static BRIDGE_HS_REJECTED: AtomicU64 = AtomicU64::new(0);
pub static LOGS_SUPPRESSED: AtomicU64 = AtomicU64::new(0);
pub static DECOY_UP: AtomicI64 = AtomicI64::new(-1);
pub static DECOY_RTT_MS: AtomicU64 = AtomicU64::new(0);
pub static NLP_LAST_INTENT: AtomicI64 = AtomicI64::new(0);
pub static NLP_ACTIONS: AtomicU64 = AtomicU64::new(0);
/// v0.15.1 NLP safety-envelope counters.
pub static NLP_REVERTS: AtomicU64 = AtomicU64::new(0);
pub static NLP_RATE_LIMITED: AtomicU64 = AtomicU64::new(0);
pub static NLP_PERSIST_FAILURES: AtomicU64 = AtomicU64::new(0);
pub static NLP_RECOMMENDATIONS: AtomicU64 = AtomicU64::new(0);
pub static NLP_ABSTENTIONS: AtomicU64 = AtomicU64::new(0);
pub static NLP_ONLINE_UPDATES: AtomicU64 = AtomicU64::new(0);
pub static NLP_CANDIDATE_UPDATES: AtomicU64 = AtomicU64::new(0);
// Latest bounded LinkMetrics snapshot used for combined NLP replay/auditing.
pub static NLP_LINK_LOSS_PER_MILLE: AtomicU64 = AtomicU64::new(0);
pub static NLP_LINK_RTT_MS: AtomicU64 = AtomicU64::new(0);
pub static NLP_LINK_BASE_RTT_MS: AtomicU64 = AtomicU64::new(0);
pub static NLP_LINK_JITTER_MS: AtomicU64 = AtomicU64::new(0);
pub static NLP_LINK_RETRANSMIT_TENTHS: AtomicU64 = AtomicU64::new(0);
pub static NLP_LINK_HAS_STALL: AtomicU64 = AtomicU64::new(0);
pub static NLP_LINK_STALL_BYTES: AtomicU64 = AtomicU64::new(0);
pub static NLP_LINK_RX_IDLE_MS: AtomicU64 = AtomicU64::new(0);
pub static NLP_LINK_RESETS_LAST_MIN: AtomicU64 = AtomicU64::new(0);
pub static NLP_LINK_CONNECT_FAIL_PER_MILLE: AtomicU64 = AtomicU64::new(0);
pub static NLP_LINK_BIG_FRAMES_LOST: AtomicU64 = AtomicU64::new(0);
pub static NLP_LINK_SMALL_FRAMES_OK: AtomicU64 = AtomicU64::new(0);
pub static INTELLIGENCE_MODE: AtomicI64 = AtomicI64::new(0); // 0 normal, 1 watch, 2 degraded, 3 critical
pub static INTELLIGENCE_PREDICTED_SEVERITY: AtomicU64 = AtomicU64::new(0);
pub static INTELLIGENCE_PROJECTED_SEVERITY: AtomicU64 = AtomicU64::new(0);
pub static INTELLIGENCE_DEGRADATION_LIKELY: AtomicU64 = AtomicU64::new(0);
pub static INTELLIGENCE_PATH_SCORE_TENTHS: AtomicU64 = AtomicU64::new(0);
pub static INTELLIGENCE_GOODPUT_BPS: AtomicU64 = AtomicU64::new(0);
pub static INTELLIGENCE_JITTER_TENTHS_MS: AtomicU64 = AtomicU64::new(0);
pub static INTELLIGENCE_RISK_PROB_MILLI: AtomicU64 = AtomicU64::new(0);
pub static INTELLIGENCE_RISK_CALIBRATED: AtomicU64 = AtomicU64::new(0);
pub static INTELLIGENCE_CALIBRATION_SAMPLES: AtomicU64 = AtomicU64::new(0);
pub static PATH_INTEL_ADJUSTMENTS: AtomicU64 = AtomicU64::new(0);
pub static UDP_LOSS_PER_MILLE: AtomicU64 = AtomicU64::new(0);

/// Packs `(unix_sec_u32 << 32) | count_u32` into a single AtomicU64 for race-free CAS rate limiting.
static LOG_RATE_STATE: AtomicU64 = AtomicU64::new(0);

/// Race-free lock-free CAS slot acquisition (exact cap per second across all threads).
pub fn try_acquire_log_slot(state: &AtomicU64, sec: u32, max_per_sec: u32) -> bool {
    loop {
        let cur = state.load(Relaxed);
        let cur_sec = (cur >> 32) as u32;
        let cur_cnt = (cur & 0xffff_ffff) as u32;
        let next = if cur_sec != sec {
            if max_per_sec == 0 {
                return false;
            }
            ((sec as u64) << 32) | 1
        } else if cur_cnt < max_per_sec {
            ((sec as u64) << 32) | ((cur_cnt + 1) as u64)
        } else {
            return false;
        };
        if state
            .compare_exchange_weak(cur, next, Ordering::AcqRel, Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

/// Separate 2 lines/s budget for NLP explanation logs (cannot starve error logs).
static NLP_LOG_RATE_STATE: AtomicU64 = AtomicU64::new(0);

/// v0.15.1: print one NLP explanation line if this second's budget allows it.
pub fn log_nlp(msg: &str) {
    let sec = (now_unix() & 0xffff_ffff) as u32;
    if try_acquire_log_slot(&NLP_LOG_RATE_STATE, sec, 2) {
        eprintln!("{msg}");
    } else {
        LOGS_SUPPRESSED.fetch_add(1, Relaxed);
    }
}

pub fn log_err_rl(msg: &str) {
    let sec = (now_unix() & 0xffff_ffff) as u32;
    if try_acquire_log_slot(&LOG_RATE_STATE, sec, MAX_ERR_LOGS_PER_SEC) {
        eprintln!("{msg}");
    } else {
        LOGS_SUPPRESSED.fetch_add(1, Relaxed);
    }
}

pub fn render(exits: Option<&Exits>) -> String {
    let mut s = String::new();
    let mut line = |name: &str, v: i64| s.push_str(&format!("khaymali_{name} {v}\n"));
    line("links_ready", LINKS_READY.load(Relaxed));
    line("streams_total", STREAMS_TOTAL.load(Relaxed) as i64);
    line("streams_active", STREAMS_ACTIVE.load(Relaxed));
    line("udp_associations_active", UDP_ASSOC.load(Relaxed));
    line("udp_forwards_active", UDP_FORWARDS_ACTIVE.load(Relaxed));
    line("bytes_up_total", BYTES_UP.load(Relaxed) as i64);
    line("bytes_down_total", BYTES_DOWN.load(Relaxed) as i64);
    line("link_failures_total", LINK_FAIL.load(Relaxed) as i64);
    line("camo_accepted_total", CAMO_OK.load(Relaxed) as i64);
    line("camo_fallback_total", CAMO_FALLBACK.load(Relaxed) as i64);
    line("clock_skew_dropped_total", CLOCK_SKEW_DROPPED.load(Relaxed) as i64);
    line("pool_keepalive_dropped_total", POOL_KEEPALIVE_DROPPED.load(Relaxed) as i64);
    line("adapt_condition", crate::adapt::CONDITION.load(Relaxed)); // 0 normal 1 degraded 2 hostile 3 blackout 4 recovering
    line("adapt_pool_target", crate::adapt::POOL_TARGET.load(Relaxed));
    line("adapt_bottleneck_mask", crate::adapt::BOTTLENECKS.load(Relaxed)); // 1 pool_starved 2 exit_slow 4 stale_pool 8 socks_saturated
    line("adapt_pattern_kill_age_seconds", crate::adapt::KILL_AGE_S.load(Relaxed));
    line("adapt_pattern_outage_period_seconds", crate::adapt::OUTAGE_PERIOD_S.load(Relaxed));
    line("adapt_pattern_outage_length_seconds", crate::adapt::OUTAGE_LEN_S.load(Relaxed));
    line("adapt_recoveries_total", crate::adapt::RECOVERIES.load(Relaxed) as i64);
    line("adapt_blackout_seconds_total", crate::adapt::BLACKOUT_SECS.load(Relaxed) as i64);
    line("adapt_hedged_dials_total", crate::adapt::HEDGED_DIALS.load(Relaxed) as i64);
    line("adapt_transitions_total", crate::adapt::TRANSITIONS.load(Relaxed) as i64);
    line("adaptive_actions_total", ADAPTIVE_ACTIONS.load(Relaxed) as i64);
    line("adaptive_chunk_bytes", ADAPTIVE_CHUNK_BYTES.load(Relaxed) as i64);
    line("nlp_last_intent", NLP_LAST_INTENT.load(Relaxed));
    line("nlp_actions_total", NLP_ACTIONS.load(Relaxed) as i64);
    line("nlp_reverts_total", NLP_REVERTS.load(Relaxed) as i64);
    line("nlp_rate_limited_total", NLP_RATE_LIMITED.load(Relaxed) as i64);
    line("nlp_persist_failures_total", NLP_PERSIST_FAILURES.load(Relaxed) as i64);
    line("nlp_recommendations_total", NLP_RECOMMENDATIONS.load(Relaxed) as i64);
    line("nlp_abstentions_total", NLP_ABSTENTIONS.load(Relaxed) as i64);
    line("nlp_online_updates_total", NLP_ONLINE_UPDATES.load(Relaxed) as i64);
    line("nlp_candidate_updates_total", NLP_CANDIDATE_UPDATES.load(Relaxed) as i64);
    line("nlp_link_loss_per_mille", NLP_LINK_LOSS_PER_MILLE.load(Relaxed) as i64);
    line("nlp_link_rtt_ms", NLP_LINK_RTT_MS.load(Relaxed) as i64);
    line("nlp_link_base_rtt_ms", NLP_LINK_BASE_RTT_MS.load(Relaxed) as i64);
    line("nlp_link_jitter_ms", NLP_LINK_JITTER_MS.load(Relaxed) as i64);
    line("nlp_link_retransmit_tenths_pct", NLP_LINK_RETRANSMIT_TENTHS.load(Relaxed) as i64);
    line("nlp_link_has_stall", NLP_LINK_HAS_STALL.load(Relaxed) as i64);
    line("nlp_link_stall_bytes", NLP_LINK_STALL_BYTES.load(Relaxed) as i64);
    line("nlp_link_rx_idle_ms", NLP_LINK_RX_IDLE_MS.load(Relaxed) as i64);
    line("nlp_link_resets_last_min", NLP_LINK_RESETS_LAST_MIN.load(Relaxed) as i64);
    line("nlp_link_connect_fail_per_mille", NLP_LINK_CONNECT_FAIL_PER_MILLE.load(Relaxed) as i64);
    line("nlp_link_big_frames_lost", NLP_LINK_BIG_FRAMES_LOST.load(Relaxed) as i64);
    line("nlp_link_small_frames_ok", NLP_LINK_SMALL_FRAMES_OK.load(Relaxed) as i64);
    line("intelligence_mode", INTELLIGENCE_MODE.load(Relaxed));
    line("intelligence_predicted_severity", INTELLIGENCE_PREDICTED_SEVERITY.load(Relaxed) as i64);
    line("intelligence_projected_severity", INTELLIGENCE_PROJECTED_SEVERITY.load(Relaxed) as i64);
    line("intelligence_degradation_likely", INTELLIGENCE_DEGRADATION_LIKELY.load(Relaxed) as i64);
    line("intelligence_path_score_tenths", INTELLIGENCE_PATH_SCORE_TENTHS.load(Relaxed) as i64);
    line("intelligence_measured_goodput_kbps", (INTELLIGENCE_GOODPUT_BPS.load(Relaxed) / 1000) as i64);
    line("intelligence_measured_jitter_tenths_ms", INTELLIGENCE_JITTER_TENTHS_MS.load(Relaxed) as i64);
    line("intelligence_degradation_probability_milli", INTELLIGENCE_RISK_PROB_MILLI.load(Relaxed) as i64);
    line("intelligence_risk_calibrated", INTELLIGENCE_RISK_CALIBRATED.load(Relaxed) as i64);
    line("intelligence_calibration_samples", INTELLIGENCE_CALIBRATION_SAMPLES.load(Relaxed) as i64);
    line("path_intel_adjustments_total", PATH_INTEL_ADJUSTMENTS.load(Relaxed) as i64);
    line("udp_loss_per_mille", UDP_LOSS_PER_MILLE.load(Relaxed) as i64);
    line("mux_carriers_active", MUX_CARRIERS_ACTIVE.load(Relaxed));
    line("mux_streams_opened_total", MUX_STREAMS_OPENED.load(Relaxed) as i64);
    line("resumable_sessions_active", RESUMABLE_SESSIONS_ACTIVE.load(Relaxed));
    line("sessions_resumed_total", SESSIONS_RESUMED.load(Relaxed) as i64);
    line("session_retransmits_total", SESSION_RETRANSMITS.load(Relaxed) as i64);
    line("l3_packets_tx_total", L3_PACKETS_TX.load(Relaxed) as i64);
    line("l3_packets_rx_total", L3_PACKETS_RX.load(Relaxed) as i64);
    line("rekey_rotations_total", REKEY_ROTATIONS.load(Relaxed) as i64);
    line("udp_transport_sessions_active", UDP_TRANSPORT_SESSIONS.load(Relaxed));
    line("ktunnel_sessions_active", KTUNNEL_SESSIONS_ACTIVE.load(Relaxed));
    line("ktunnel_flows_active", KTUNNEL_FLOWS_ACTIVE.load(Relaxed));
    line("udp_retransmits_total", UDP_RETRANSMITS.load(Relaxed) as i64);
    line("udp_fec_recovered_total", UDP_FEC_RECOVERED.load(Relaxed) as i64);
    line("udp_fec_group_size", UDP_FEC_GROUP_K.load(Relaxed) as i64);
    line("reverse_exits_connected", REVERSE_EXITS_CONNECTED.load(Relaxed));
    line("ws_sessions_active", WS_SESSIONS_ACTIVE.load(Relaxed));
    line("wss_sessions_active", WSS_SESSIONS_ACTIVE.load(Relaxed));
    line("ssh_carrier_sessions_active", SSH_CARRIER_SESSIONS.load(Relaxed));
    line("watchdog_events_total", WATCHDOG_EVENTS.load(Relaxed) as i64);
    line("fallback_active", FALLBACK_ACTIVE.load(Relaxed));
    line("fallback_evicted_total", FALLBACK_EVICTED.load(Relaxed) as i64);
    line("bridge_replay_dropped_total", BRIDGE_REPLAY_DROPPED.load(Relaxed) as i64);
    line("bridge_handshake_rejected_total", BRIDGE_HS_REJECTED.load(Relaxed) as i64);
    line("logs_suppressed_total", LOGS_SUPPRESSED.load(Relaxed) as i64);
    let decoy_up = DECOY_UP.load(Relaxed);
    if decoy_up >= 0 {
        line("decoy_up", decoy_up);
        line("decoy_rtt_ms", DECOY_RTT_MS.load(Relaxed) as i64);
    }
    if let Some(e) = exits {
        for x in e.snapshot() {
            s.push_str(&format!(
                "khaymali_exit_up{{addr=\"{}\"}} {}\nkhaymali_exit_selectable{{addr=\"{}\"}} {}\nkhaymali_exit_rtt_ms{{addr=\"{}\"}} {:.1}\nkhaymali_exit_jitter_ms{{addr=\"{}\"}} {:.1}\nkhaymali_exit_timeout_failures{{addr=\"{}\"}} {}\nkhaymali_exit_reset_failures{{addr=\"{}\"}} {}\nkhaymali_exit_stalls{{addr=\"{}\"}} {}\nkhaymali_exit_cusum{{addr=\"{}\"}} {:.1}\n",
                x.addr, x.up as u8, x.addr, x.selectable as u8, x.addr, x.ewma_ms, x.addr, x.jitter_ms, x.addr, x.timeout_fails, x.addr, x.reset_fails, x.addr, x.stalls, x.addr, x.cusum
            ));
        }
    }
    s
}

pub async fn serve(addr: String, exits: Option<Arc<Exits>>) {
    let l = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => return eprintln!("[metrics] cannot bind {addr}: {e}"),
    };
    eprintln!("[metrics] http://{addr}/metrics");
    let sem = Arc::new(Semaphore::new(MAX_METRICS_CONNS));
    loop {
        let Ok((mut c, _)) = l.accept().await else { continue };
        let Ok(permit) = sem.clone().try_acquire_owned() else {
            drop(c);
            continue;
        };
        let exits = exits.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut buf = [0u8; 512];
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), c.read(&mut buf)).await;
            let body = render(exits.as_deref());
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                c.write_all(resp.as_bytes()),
            )
            .await;
        });
    }
}
