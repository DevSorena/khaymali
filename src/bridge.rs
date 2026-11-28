//! Bridge node: untrusted outbound-only relay between Entry and Exit.
//! Uses `Transport` abstraction for Bridge -> Exit, aligned 16 KiB relay buffers
//! (`copy_bidirectional_with_sizes`), secret-bound Channel Binding `HKDF(h, cb_secret)`
//! for Entry <-> Bridge, and live `AdaptiveRuntime` recovery telemetry (SPEC §2.2, §3.1).

use crate::adapt::{self, Adapt, AdaptCfg, Event, Sig, Stage};
use crate::camo::CamoCfg;
use crate::control::{self, ControlState};
use crate::health::{self, Exits, FailureKind};
use crate::link;
use crate::recovery::{AdaptiveRuntime, TransportEvent};
use crate::stats;
use crate::transport::{self, AutoTransport, CamoTransport, TcpTransport, Transport};
use crate::util::*;
use anyhow::{Context, Result};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::copy_bidirectional_with_sizes;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const BRIDGE_COPY_BUF: usize = 16 * 1024;

pub struct BridgeCfg {
    pub key: Vec<u8>,
    pub entry: String,
    pub entry_pub: Vec<u8>,
    pub exits: Vec<String>,
    pub pool: usize,
    pub camo: Option<CamoCfg>,
    pub metrics: Option<String>,
    pub control: Option<String>,
    pub adapt: bool,
    pub adapt_state: Option<String>,
}

pub async fn run(cfg: BridgeCfg) -> Result<()> {
    let has_multi = transport::needs_multi_transport(&cfg.exits);
    let tx_impl: Arc<dyn Transport> = if has_multi {
        if transport::requires_carrier_secret(&cfg.exits) && cfg.camo.is_none() {
            anyhow::bail!("udp://, ktunnel://, and wss:// exits require --camo-secret");
        }
        let udp_auth_key = cfg.camo.as_ref().map(|c| c.secret.clone()).unwrap_or_default();
        Arc::new(AutoTransport {
            camo: cfg.camo.clone(),
            udp_auth_key,
            connect_timeout: Duration::from_secs(20),
        })
    } else {
        match &cfg.camo {
            Some(c) => Arc::new(CamoTransport {
                cfg: c.clone(),
                connect_timeout: Duration::from_secs(20),
            }),
            None => Arc::new(TcpTransport {
                connect_timeout: Duration::from_secs(10),
            }),
        }
    };
    // Adaptive timeouts/backoff. A bridge has no link pool to resize (each worker holds one
    // long-lived relay), so the decision engine + pattern-aware backoff apply, not pool growth.
    let adapt = Adapt::new(AdaptCfg {
        enabled: cfg.adapt,
        base_pool: cfg.pool.max(1),
        pool_max: cfg.pool.max(1),
        base_max_age: Duration::from_secs(120),
        state_path: cfg.adapt_state.clone(),
    });
    adapt::install(adapt.clone());
    adapt::spawn_ticker(adapt, 0);
    eprintln!(
        "[bridge] {} workers: entry={} exits={:?} transport={}",
        cfg.pool,
        cfg.entry,
        cfg.exits,
        tx_impl.name()
    );
    let exits = Exits::new(cfg.exits.clone());
    let adaptive = AdaptiveRuntime::new(cfg.pool.max(1) * 4);
    tokio::spawn(health::probe_loop(exits.clone(), Duration::from_secs(20)));
    if let Some(m) = cfg.metrics.clone() {
        tokio::spawn(stats::serve(m, Some(exits.clone())));
    }
    let ctl = ControlState::with_runtime(
        "bridge",
        tx_impl.name(),
        Some(exits.clone()),
        None,
        Some(adaptive.clone()),
        vec![cfg.entry_pub.clone()],
    );
    if let Some(sock) = cfg.control.clone() {
        tokio::spawn(control::serve(sock, ctl.clone()));
    }

    let cfg = Arc::new(cfg);
    let mut hs = vec![];
    for _ in 0..cfg.pool.max(1) {
        let (cfg, exits, tx_impl, adaptive, ctl) = (
            cfg.clone(),
            exits.clone(),
            tx_impl.clone(),
            adaptive.clone(),
            ctl.clone(),
        );
        hs.push(tokio::spawn(async move {
            let mut backoff = Duration::from_millis(300);
            while !ctl.is_draining() {
                let t0 = Instant::now();
                match once(&cfg, &exits, tx_impl.as_ref(), &adaptive).await {
                    Ok(()) => backoff = Duration::from_millis(300),
                    Err(e) => {
                        stats::LINK_FAIL.fetch_add(1, Relaxed);
                        stats::log_err_rl(&format!("[bridge] {e}"));
                        backoff = if t0.elapsed() > Duration::from_secs(20) {
                            Duration::from_millis(300)
                        } else {
                            adapt::next_backoff_global(backoff)
                        };
                    }
                }
                let wait = AdaptiveRuntime::jittered_backoff(backoff);
                tokio::select! {
                    _ = sleep(wait) => {}
                    _ = ctl.drain_notify.notified() => break,
                }
            }
        }));
    }
    for h in hs {
        let _ = h.await;
    }
    Ok(())
}

async fn connect_exit(
    exits: &Exits,
    tx_impl: &dyn Transport,
    adaptive: &AdaptiveRuntime,
    connect_timeout: Duration,
) -> Result<(String, BoxRw)> {
    let addr = exits.pick().context("no selectable exits available")?;
    let t0 = Instant::now();
    let res = match timeout(connect_timeout, tx_impl.dial(&addr)).await {
        Ok(r) => r,
        Err(el) => Err(anyhow::Error::from(el)),
    };
    match &res {
        Ok(_) => {
            let rtt = t0.elapsed();
            exits.ok(&addr, rtt);
            adaptive.record_with_path(TransportEvent::ConnectOk { rtt_ms: rtt.as_millis() as u32 }, 0, &addr);
            if let Some((score, obs)) = adaptive.path_score(&addr) { exits.update_path_intel(&addr, score, obs); }
        }
        Err(e) => {
            let kind = Exits::classify_error(e);
            exits.fail_kind(&addr, kind);
            let ev = match kind {
                FailureKind::Timeout => TransportEvent::HandshakeTimeout,
                FailureKind::Reset => TransportEvent::EarlyReset { bytes_transferred: 0 },
                FailureKind::Other => TransportEvent::ConnectFail,
            };
            adaptive.record_with_path(ev, 0, &addr);
            if let Some((score, obs)) = adaptive.path_score(&addr) { exits.update_path_intel(&addr, score, obs); }
        }
    }
    let stream = res.with_context(|| format!("exit {addr}"))?;
    Ok((addr, stream))
}

async fn once(
    cfg: &BridgeCfg,
    exits: &Exits,
    tx_impl: &dyn Transport,
    adaptive: &AdaptiveRuntime,
) -> Result<()> {
    // Authenticate with Entry first. Exit camouflage/handshake starts only after Entry
    // accepted the Bridge, avoiding an idle Exit-side handshake timeout on slow Entry paths.
    let t0 = Instant::now();
    let (ct, ht) = adapt::global().map_or((Duration::from_secs(10), Duration::from_secs(10)), |a| {
        let t = a.tuning();
        (t.connect_timeout, t.handshake_timeout)
    });
    let mut stage = Stage::Connect;
    // Floor timeouts so adaptive shrinking never creates a handshake timeout death spiral
    // on high-latency / lossy Camo paths.
    let entry_ct = ct.max(Duration::from_secs(15));
    let entry_ht = ht.max(Duration::from_secs(12));
    let exit_ct = if cfg.camo.is_some() {
        ct.max(Duration::from_secs(20))
    } else {
        ct.max(Duration::from_secs(15))
    };
    let setup = async {
        let mut e = timeout(entry_ct, TcpStream::connect(&cfg.entry)).await??;
        stage = Stage::Handshake;
        link::tune(&e);
        let (hs_hash, cb_secret) =
            timeout(entry_ht, link::auth_initiate(&mut e, &cfg.key, &cfg.entry_pub)).await??;
        let keys = transport::derive_channel_binding_keys(&hs_hash, &cb_secret);
        let bound_e = transport::wrap_bound_stream(Box::new(e), keys.b2e, keys.e2b);
        stage = Stage::Connect;
        let (exit_addr, x) = connect_exit(exits, tx_impl, adaptive, exit_ct).await?;
        Ok::<_, anyhow::Error>((bound_e, exit_addr, x))
    }
    .await;
    let (mut bound_e, exit_addr, mut x) = match setup {
        Ok(v) => {
            adapt::record_global(Event::DialOk { rtt: t0.elapsed() });
            v
        }
        Err(e) => {
            adapt::record_global(Event::DialFail { sig: Sig::from_error(&e, stage) });
            return Err(e);
        }
    };
    let (from_entry, from_exit) =
        copy_bidirectional_with_sizes(&mut bound_e, &mut x, BRIDGE_COPY_BUF, BRIDGE_COPY_BUF)
            .await?;
    let total = from_entry.saturating_add(from_exit);
    if total == 0 {
        exits.fail_kind(&exit_addr, FailureKind::Reset);
        adaptive.record_with_path(TransportEvent::EarlyReset { bytes_transferred: 0 }, 0, &exit_addr);
        anyhow::bail!("bridge relay to {exit_addr} closed without transferring data");
    }
    adaptive.record_with_path(TransportEvent::StreamOk { bytes: total }, 0, &exit_addr);
    if let Some((score, obs)) = adaptive.path_score(&exit_addr) { exits.update_path_intel(&exit_addr, score, obs); }
    Ok(())
}
