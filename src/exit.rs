//! Exit node: terminates Noise links (TCP, TCP+Camo, and reliable UDP carriers), serves
//! multiplexed carriers (`[3]`), legacy TCP (`[1]`), dual-stack IPv4/IPv6 UDP (`[2]`), and
//! Layer-3 TUN/GRE/IPIP packet tunnels (`[4]`), enforcing anti-SSRF / anti-DNS-rebinding and
//! per-peer quotas (SPEC §3.2, §4.1, §4.2).

use crate::camo::{self, CamoCfg, Replay};
use crate::control::{self, ControlState};
use crate::fallback::{FallbackLimiter, FALLBACK_MAX_TOTAL};
use crate::ktunnel::KtunnelListener;
use crate::l3::{self, L3Mode, TunConfig, DEFAULT_TUN_MTU};
use crate::link::{self, Link};
use crate::mux;
use crate::session_resume::{SessionRegistry, DEFAULT_SESSION_DETACH_TTL};
use crate::stats;
use crate::udp;
use crate::transport::{AutoTransport, CamoTransport, TcpTransport, Transport};
use crate::udp_transport::UdpCarrierListener;
use crate::util::*;
use crate::watchdog;
use crate::ws_transport::WsCarrierListener;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};

pub const MAX_EXIT_CONNS: usize = 4096;
pub const MAX_CONNS_PER_PEER: usize = 1024;
const DRAIN_WINDOW: Duration = Duration::from_secs(15);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ExitCfg {
    pub listen: String,
    pub udp_listen: Option<String>,
    pub ktunnel_listen: Option<String>,
    pub ws_listen: Option<String>,
    pub wss_listen: Option<String>,
    pub key: Vec<u8>,
    pub allowed: Vec<Vec<u8>>,
    pub allow_private: bool,
    pub camo: Option<CamoCfg>,
    pub control: Option<String>,
    pub tun: Option<String>,
    pub tun_cidr: Option<String>,
    pub reverse_entry: Option<String>,
    pub reverse_pool: usize,
}

struct PeerQuota {
    max_per_peer: usize,
    counts: Mutex<HashMap<Vec<u8>, usize>>,
}

struct PeerGuard {
    key: Vec<u8>,
    quota: Arc<PeerQuota>,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        let mut m = self.quota.counts.lock().unwrap();
        if let Some(c) = m.get_mut(&self.key) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                m.remove(&self.key);
            }
        }
    }
}

impl PeerQuota {
    fn new(max_per_peer: usize) -> Arc<Self> {
        Arc::new(Self {
            max_per_peer,
            counts: Mutex::new(HashMap::new()),
        })
    }

    fn acquire(self: &Arc<Self>, peer_pub: &[u8]) -> Option<PeerGuard> {
        let mut m = self.counts.lock().unwrap();
        let entry = m.entry(peer_pub.to_vec()).or_insert(0);
        if *entry >= self.max_per_peer {
            return None;
        }
        *entry += 1;
        Some(PeerGuard {
            key: peer_pub.to_vec(),
            quota: self.clone(),
        })
    }
}

pub async fn run(cfg: ExitCfg) -> Result<()> {
    let l = TcpListener::bind(&cfg.listen).await?;
    let transport_name = match (cfg.camo.is_some(), cfg.udp_listen.is_some()) {
        (true, true) => "tcp+camo/udp",
        (true, false) => "tcp+camo",
        (false, true) => "tcp/udp",
        (false, false) => "tcp",
    };
    eprintln!(
        "[exit] listening on {} ({} allowed entry key(s), max_conns={}, camouflage {}, udp={}, ws={}, wss={}, tun={})",
        cfg.listen,
        cfg.allowed.len(),
        MAX_EXIT_CONNS,
        if cfg.camo.is_some() { "ON" } else { "off" },
        cfg.udp_listen.as_deref().unwrap_or("off"),
        cfg.ws_listen.as_deref().unwrap_or("off"),
        cfg.wss_listen.as_deref().unwrap_or("off"),
        cfg.tun.as_deref().unwrap_or("off"),
    );

    if let Some(fb) = cfg.camo.as_ref().and_then(|c| c.fallback.clone()) {
        watchdog::spawn_decoy_watchdog(fb, Duration::from_secs(3600));
    }

    let ctl = ControlState::with_runtime("exit", transport_name, None, None, None, cfg.allowed.clone());
    if let Some(sock) = cfg.control.clone() {
        tokio::spawn(control::serve(sock, ctl.clone()));
    }

    let cfg = Arc::new(cfg);
    let replay = Arc::new(Replay::new());
    let fb_limiter = FallbackLimiter::default_limiter();
    let preauth_sem = Arc::new(Semaphore::new(MAX_EXIT_CONNS + FALLBACK_MAX_TOTAL * 2));
    let conn_sem = Arc::new(Semaphore::new(MAX_EXIT_CONNS));
    let peer_quota = PeerQuota::new(MAX_CONNS_PER_PEER);
    let session_reg = Arc::new(SessionRegistry::new());
    {
        let sr_sweep = session_reg.clone();
        let ctl_sweep = ctl.clone();
        tokio::spawn(async move {
            while !ctl_sweep.is_draining() {
                sleep(Duration::from_secs(10)).await;
                sr_sweep.sweep_expired(DEFAULT_SESSION_DETACH_TTL);
            }
        });
    }

    if let Some(rev_entry) = cfg.reverse_entry.clone() {
        let workers = cfg.reverse_pool.clamp(1, 32);
        let has_special = crate::transport::needs_multi_transport(std::slice::from_ref(&rev_entry));
        let tx_impl: Arc<dyn Transport> = if has_special {
            let auth_key = cfg
                .camo
                .as_ref()
                .map(|c| c.secret.clone())
                .unwrap_or_default();
            Arc::new(AutoTransport {
                camo: cfg.camo.clone(),
                udp_auth_key: auth_key,
                connect_timeout: Duration::from_secs(10),
            })
        } else if let Some(c) = cfg.camo.clone() {
            Arc::new(CamoTransport {
                cfg: c,
                connect_timeout: Duration::from_secs(10),
            })
        } else {
            Arc::new(TcpTransport {
                connect_timeout: Duration::from_secs(10),
            })
        };
        eprintln!(
            "[exit] reverse-dial mode -> {rev_entry} (workers={workers}, transport={})",
            tx_impl.name()
        );
        for _ in 0..workers {
            let (cfg_r, pq_r, sr_r, ctl_r, tx_r, target_r) = (
                cfg.clone(),
                peer_quota.clone(),
                session_reg.clone(),
                ctl.clone(),
                tx_impl.clone(),
                rev_entry.clone(),
            );
            tokio::spawn(async move {
                let mut backoff = Duration::from_millis(300);
                while !ctl_r.is_draining() {
                    match timeout(Duration::from_secs(10), tx_r.dial(&target_r)).await {
                        Ok(Ok(stream)) => {
                            backoff = Duration::from_millis(300);
                            stats::REVERSE_EXITS_CONNECTED.fetch_add(1, Relaxed);
                            let res = handle_stream(stream, &cfg_r, &pq_r, &sr_r).await;
                            stats::REVERSE_EXITS_CONNECTED.fetch_sub(1, Relaxed);
                            if let Err(e) = res {
                                stats::log_err_rl(&format!("[exit] reverse-entry {target_r}: {e}"));
                            }
                        }
                        Ok(Err(e)) => {
                            stats::log_err_rl(&format!("[exit] reverse-dial {target_r}: {e}"));
                        }
                        Err(_) => {
                            stats::log_err_rl(&format!("[exit] reverse-dial {target_r}: timeout"));
                        }
                    }
                    tokio::select! {
                        _ = sleep(backoff) => {}
                        _ = ctl_r.drain_notify.notified() => break,
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(15));
                }
            });
        }
    }

    if let Some(ktun_addr) = cfg.ktunnel_listen.clone() {
        let ktun_key = cfg
            .camo
            .as_ref()
            .map(|c| c.secret.clone())
            .ok_or_else(|| anyhow::anyhow!("--ktunnel-listen requires --camo-secret"))?;
        let mut kl = KtunnelListener::bind(&ktun_addr, ktun_key).await?;
        eprintln!("[exit] Multi-Flow FakeTLS-Mux (ktunnel) listening on {ktun_addr}");
        let (cfg_k, conn_sem_k, peer_quota_k, ctl_k, sreg_k) = (
            cfg.clone(),
            conn_sem.clone(),
            peer_quota.clone(),
            ctl.clone(),
            session_reg.clone(),
        );
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = ctl_k.drain_notify.notified() => break,
                    res = kl.accept() => {
                        let Some((stream, peer)) = res else { break };
                        let Ok(permit) = conn_sem_k.clone().try_acquire_owned() else {
                            continue;
                        };
                        let (cfg_c, pq_c, sr_c) = (cfg_k.clone(), peer_quota_k.clone(), sreg_k.clone());
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = handle_stream(stream, &cfg_c, &pq_c, &sr_c).await {
                                stats::log_err_rl(&format!("[exit] ktunnel {peer}: {e}"));
                            }
                        });
                    }
                }
            }
        });
    }

    if let Some(ws_addr) = cfg.ws_listen.clone() {
        let ws_key = cfg.camo.as_ref().map(|c| c.secret.clone()).unwrap_or_default();
        let wl = Arc::new(WsCarrierListener::bind(&ws_addr, ws_key, None).await?);
        eprintln!("[exit] WS (RFC 6455) carrier listening on {ws_addr}");
        let (cfg_w, conn_sem_w, peer_quota_w, ctl_w, sreg_w) = (
            cfg.clone(), conn_sem.clone(), peer_quota.clone(), ctl.clone(), session_reg.clone(),
        );
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = ctl_w.drain_notify.notified() => break,
                    res = wl.accept() => {
                        let Ok((tcp, peer)) = res else { continue };
                        let Ok(permit) = conn_sem_w.clone().try_acquire_owned() else { drop(tcp); continue; };
                        let (wl_c, cfg_c, pq_c, sr_c) = (wl.clone(), cfg_w.clone(), peer_quota_w.clone(), sreg_w.clone());
                        tokio::spawn(async move {
                            let _permit = permit;
                            match wl_c.handshake(tcp, peer.ip()).await {
                                Ok(Some(stream)) => {
                                    if let Err(e) = handle_stream(stream, &cfg_c, &pq_c, &sr_c).await {
                                        stats::log_err_rl(&format!("[exit] ws {peer}: {e}"));
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => stats::log_err_rl(&format!("[exit] ws handshake {peer}: {e}")),
                            }
                        });
                    }
                }
            }
        });
    }

    if let Some(wss_addr) = cfg.wss_listen.clone() {
        let camo_wss = cfg.camo.clone().ok_or_else(|| anyhow::anyhow!("--wss-listen requires --camo-secret"))?;
        let wss_key = camo_wss.secret.clone();
        let wl = Arc::new(WsCarrierListener::bind(&wss_addr, wss_key, Some(camo_wss)).await?);
        eprintln!("[exit] WSS (Camo TLS + RFC 6455) carrier listening on {wss_addr}");
        let (cfg_w, conn_sem_w, peer_quota_w, ctl_w, sreg_w) = (
            cfg.clone(), conn_sem.clone(), peer_quota.clone(), ctl.clone(), session_reg.clone(),
        );
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = ctl_w.drain_notify.notified() => break,
                    res = wl.accept() => {
                        let Ok((tcp, peer)) = res else { continue };
                        let Ok(permit) = conn_sem_w.clone().try_acquire_owned() else { drop(tcp); continue; };
                        let (wl_c, cfg_c, pq_c, sr_c) = (wl.clone(), cfg_w.clone(), peer_quota_w.clone(), sreg_w.clone());
                        tokio::spawn(async move {
                            let _permit = permit;
                            match wl_c.handshake(tcp, peer.ip()).await {
                                Ok(Some(stream)) => {
                                    if let Err(e) = handle_stream(stream, &cfg_c, &pq_c, &sr_c).await {
                                        stats::log_err_rl(&format!("[exit] wss {peer}: {e}"));
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => stats::log_err_rl(&format!("[exit] wss handshake {peer}: {e}")),
                            }
                        });
                    }
                }
            }
        });
    }

    if let Some(udp_addr) = cfg.udp_listen.clone() {
        let udp_key = cfg
            .camo
            .as_ref()
            .map(|c| c.secret.clone())
            .ok_or_else(|| anyhow::anyhow!("--udp-listen requires --camo-secret"))?;
        let mut ul = UdpCarrierListener::bind(&udp_addr, udp_key).await?;
        eprintln!("[exit] UDP carrier listening on {udp_addr}");
        let (cfg_u, conn_sem_u, peer_quota_u, ctl_u, sreg_u) = (
            cfg.clone(),
            conn_sem.clone(),
            peer_quota.clone(),
            ctl.clone(),
            session_reg.clone(),
        );
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = ctl_u.drain_notify.notified() => break,
                    res = ul.accept() => {
                        let Some((stream, peer)) = res else { break };
                        let Ok(permit) = conn_sem_u.clone().try_acquire_owned() else {
                            continue;
                        };
                        let (cfg_c, pq_c, sr_c) = (cfg_u.clone(), peer_quota_u.clone(), sreg_u.clone());
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = handle_stream(stream, &cfg_c, &pq_c, &sr_c).await {
                                stats::log_err_rl(&format!("[exit] udp {peer}: {e}"));
                            }
                        });
                    }
                }
            }
        });
    }

    loop {
        tokio::select! {
            _ = ctl.drain_notify.notified() => {
                eprintln!("[exit] draining active streams (up to {}s)...", DRAIN_WINDOW.as_secs());
                let deadline = Instant::now() + DRAIN_WINDOW;
                while stats::STREAMS_ACTIVE.load(Relaxed) > 0 && Instant::now() < deadline {
                    sleep(Duration::from_millis(100)).await;
                }
                return Ok(());
            }
            res = l.accept() => {
                let (s, peer) = res?;
                let Ok(pre_permit) = preauth_sem.clone().try_acquire_owned() else {
                    drop(s);
                    continue;
                };
                let (cfg, replay, fb_limiter, conn_sem, peer_quota, sreg) = (
                    cfg.clone(),
                    replay.clone(),
                    fb_limiter.clone(),
                    conn_sem.clone(),
                    peer_quota.clone(),
                    session_reg.clone(),
                );
                tokio::spawn(async move {
                    let _pre_permit = pre_permit;
                    if let Err(e) = handle(s, peer.ip(), &cfg, &replay, &fb_limiter, &conn_sem, &peer_quota, &sreg).await {
                        stats::log_err_rl(&format!("[exit] {peer}: {e}"));
                    }
                });
            }
        }
    }
}

async fn handle(
    s: TcpStream,
    peer_ip: IpAddr,
    cfg: &ExitCfg,
    replay: &Replay,
    fb_limiter: &Arc<FallbackLimiter>,
    conn_sem: &Arc<Semaphore>,
    peer_quota: &Arc<PeerQuota>,
    session_reg: &Arc<SessionRegistry>,
) -> Result<()> {
    link::tune(&s);
    let stream: BoxRw = match &cfg.camo {
        Some(c) => match camo::server(s, peer_ip, c, replay, fb_limiter).await? {
            Some(st) => st,
            None => return Ok(()),
        },
        None => Box::new(s),
    };

    let Ok(_conn_permit) = conn_sem.clone().try_acquire_owned() else {
        bail!("exit connection capacity reached");
    };

    handle_stream(stream, cfg, peer_quota, session_reg).await
}

async fn handle_stream(
    stream: BoxRw,
    cfg: &ExitCfg,
    peer_quota: &Arc<PeerQuota>,
    session_reg: &Arc<SessionRegistry>,
) -> Result<()> {
    let mut lk: Link =
        timeout(Duration::from_secs(10), link::respond(stream, &cfg.key, &cfg.allowed)).await??;

    let _peer_guard = match lk.peer_pub() {
        Some(pk) => match peer_quota.acquire(pk) {
            Some(g) => Some(g),
            None => bail!("per-peer connection limit reached"),
        },
        None => None,
    };

    loop {
        let req = timeout(Duration::from_secs(30 * 60), lk.recv()).await??;
        match req.first() {
            Some(0) => {
                lk.send(&[0]).await?;
                continue;
            }
            Some(1) => return handle_tcp(lk, &req[1..], cfg.allow_private).await,
            Some(2) => {
                let sock_v4 = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = lk.send(&[1]).await;
                        bail!("udp v4 bind failed: {e}");
                    }
                };
                let sock_v6 = udp::bind_udp_v6_only().ok();
                lk.send(&[0]).await?;
                return udp::exit_relay_dual(lk, sock_v4, sock_v6, cfg.allow_private).await;
            }
            Some(3) => {
                lk.send(&[0]).await?;
                return mux::serve_exit_with_registry(lk, cfg.allow_private, session_reg.clone()).await;
            }
            Some(4) => {
                // Layer-3 IP TUN bridge (`[4, mode_byte]`)
                let mode = match req.get(1).copied().unwrap_or(0) {
                    1 => L3Mode::Gre,
                    2 => L3Mode::Ipip,
                    _ => L3Mode::Tun,
                };
                return handle_l3_tun(lk, cfg, mode).await;
            }
            _ => bail!("bad request type"),
        }
    }
}

#[cfg(target_os = "linux")]
async fn handle_l3_tun(mut lk: Link, cfg: &ExitCfg, mode: L3Mode) -> Result<()> {
    let Some(if_name) = cfg.tun.clone() else {
        let _ = lk.send(&[1]).await;
        bail!("L3 TUN tunnel requested by peer, but Exit was not started with --tun <IFNAME>");
    };
    let tun_cfg = TunConfig {
        if_name,
        mode,
        local_cidr: cfg
            .tun_cidr
            .clone()
            .unwrap_or_else(|| "10.200.0.1/30".to_string()),
        peer_ip: IpAddr::V4(Ipv4Addr::new(10, 200, 0, 2)),
        mtu: DEFAULT_TUN_MTU,
        allow_private_routes: cfg.allow_private,
        routes: Vec::new(),
        gre_key: None,
    };
    let tun_dev = match l3::LinuxTunDevice::open(&tun_cfg) {
        Ok(d) => d,
        Err(e) => {
            let _ = lk.send(&[1]).await;
            return Err(e);
        }
    };
    lk.send(&[0]).await?;
    l3::bridge_tun_over_link(tun_dev, lk, tun_cfg).await
}

#[cfg(not(target_os = "linux"))]
async fn handle_l3_tun(mut lk: Link, _cfg: &ExitCfg, _mode: L3Mode) -> Result<()> {
    let _ = lk.send(&[1]).await;
    l3::run_tun_not_supported().await
}

async fn handle_tcp(mut lk: Link, addr: &[u8], allow_private: bool) -> Result<()> {
    let target = match timeout(Duration::from_secs(10), connect(addr, allow_private)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            let _ = lk.send(&[1]).await;
            bail!("connect failed: {e}");
        }
        Err(_) => {
            let _ = lk.send(&[1]).await;
            bail!("connect timeout");
        }
    };
    link::tune(&target);
    lk.send(&[0]).await?;
    lk.pipe(target).await
}

async fn connect(addr: &[u8], allow_private: bool) -> Result<TcpStream> {
    let (host, port, _) = parse_addr(addr)?;
    let addrs = resolve_validated(&host, port, allow_private, DNS_TIMEOUT).await?;
    let mut last = None;
    for sa in addrs {
        match TcpStream::connect(sa).await {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e.into()),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no addresses reachable")))
}
