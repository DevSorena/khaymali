//! Alert-only Decoy Parity Watchdog (SPEC §3.2).
//! Periodically verifies Decoy reachability and RTT, exporting metrics without mutating config.

use crate::stats;
use std::sync::atomic::Ordering::Relaxed;
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
