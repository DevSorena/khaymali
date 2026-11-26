//! Entry node: local SOCKS5 server (CONNECT + IPv4/IPv6 UDP ASSOCIATE), L4 TCP & UDP Port
//! Forwards (with optional PROXY Protocol v2), lock-free-wakeup `LinkPool` with idle PING/PONG
//! zombie sweeper, on-demand burst dialing, Turbo-Tunnel Live Session Resume (`SessionRegistry`),
//! and live `AdaptiveRuntime` recovery integration (SPEC §2.1, §4.2).

use crate::adapt::{self, Adapt, AdaptCfg, Condition, Event, Sig, Stage, Tuning};
use crate::camo::CamoCfg;
use crate::control::{self, ControlState};
use crate::forward::{self, ForwardMode, ForwardProto, ForwardRegistry, ForwardSpec};
use crate::l3::{KernelForwardRule, KernelTransparentForwarder};
use crate::health::{self, Exits, FailureKind};
use crate::link::{self, BridgeReplayCache, Link};
use crate::mux::{MuxCarrier, MuxOpenResult, ResumableOpenResult};
use crate::recovery::{AdaptiveRuntime, TransportEvent};
use crate::session_resume::{SessionRegistry, DEFAULT_SESSION_DETACH_TTL};
use crate::stats;
use crate::transport::{self, AutoTransport, CamoTransport, TcpTransport, Transport};
use crate::udp;
use crate::util::{ip_prefix_key, PrefixKey};
use anyhow::{bail, Result};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio::time::{sleep, timeout};

pub const MAX_BRIDGE_HANDSHAKES: usize = 32;
pub const MAX_BRIDGE_HS_PER_PREFIX: usize = 4;
pub const MAX_ACTIVE_BRIDGES: usize = 256;
pub const MAX_SOCKS_CONNS: usize = 1024;
pub const BRIDGE_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
pub const SOCKS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_WINDOW: Duration = Duration::from_secs(15);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Dual-cap Bridge handshake limiter: global cap + per-prefix (/64, /24) cap (SPEC §1.2, §8 Test #2).
pub struct BridgeHandshakeLimiter {
    max_total: usize,
    max_per_prefix: usize,
    state: StdMutex<(usize, HashMap<PrefixKey, usize>)>,
}

pub struct BridgeHsGuard {
    prefix: PrefixKey,
    limiter: Arc<BridgeHandshakeLimiter>,
}

impl Drop for BridgeHsGuard {
    fn drop(&mut self) {
        let mut g = self.limiter.state.lock().unwrap();
        g.0 = g.0.saturating_sub(1);
        if let Some(c) = g.1.get_mut(&self.prefix) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                g.1.remove(&self.prefix);
            }
        }
    }
}

impl BridgeHandshakeLimiter {
    pub fn new(max_total: usize, max_per_prefix: usize) -> Arc<Self> {
        Arc::new(Self {
            max_total: max_total.max(1),
            max_per_prefix: max_per_prefix.max(1).min(max_total.max(1)),
            state: StdMutex::new((0, HashMap::new())),
        })
    }

    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<BridgeHsGuard> {
        let prefix = ip_prefix_key(ip);
        let mut g = self.state.lock().unwrap();
        if g.0 >= self.max_total {
            stats::BRIDGE_HS_REJECTED.fetch_add(1, Relaxed);
            return None;
        }
        let entry = g.1.entry(prefix).or_insert(0);
        if *entry >= self.max_per_prefix {
            stats::BRIDGE_HS_REJECTED.fetch_add(1, Relaxed);
            return None;
        }
        *entry += 1;
        g.0 += 1;
        Some(BridgeHsGuard {
            prefix,
            limiter: self.clone(),
        })
    }
}

/// Bounded Link Pool with race-free `LINKS_READY` accounting, zero async-mutex contention
/// across `.await`, and idle keepalive inspection support.
struct LinkPool {
    cap: usize,
    q: StdMutex<VecDeque<Link>>,
    has_item: Notify,
    has_space: Notify,
}

impl LinkPool {
    fn new(cap: usize) -> Arc<Self> {
        stats::LINKS_READY.store(0, Relaxed);
        Arc::new(Self {
            cap: cap.max(1),
            q: StdMutex::new(VecDeque::with_capacity(cap.max(1))),
            has_item: Notify::new(),
            has_space: Notify::new(),
        })
    }

    fn try_push(&self, lk: Link) -> Result<(), Link> {
        let mut q = self.q.lock().unwrap();
        if q.len() >= self.cap {
            return Err(lk);
        }
        q.push_back(lk);
        stats::LINKS_READY.store(q.len() as i64, Relaxed);
        drop(q);
        self.has_item.notify_one();
        Ok(())
    }

    async fn push_wait(&self, mut lk: Link, ctl: &ControlState) -> bool {
        loop {
            let space = self.has_space.notified();
            tokio::pin!(space);
            space.as_mut().enable();
            match self.try_push(lk) {
                Ok(()) => return true,
                Err(back) => lk = back,
            }
            if ctl.is_draining() {
                return false;
            }
            tokio::select! {
                _ = space => {}
                _ = ctl.drain_notify.notified() => return false,
            }
        }
    }

    fn try_pop(&self) -> Option<Link> {
        let mut q = self.q.lock().unwrap();
        let l = q.pop_front();
        stats::LINKS_READY.store(q.len() as i64, Relaxed);
        drop(q);
        if l.is_some() {
            self.has_space.notify_one();
        }
        l
    }

    async fn pop(&self) -> Link {
        loop {
            let item = self.has_item.notified();
            tokio::pin!(item);
            item.as_mut().enable();
            if let Some(l) = self.try_pop() {
                return l;
            }
            item.await;
        }
    }

    fn evict_expired_and_pop_for_check(&self, max_age: Duration, check_after: Duration) -> Option<Link> {
        let mut q = self.q.lock().unwrap();
        let before = q.len();
        q.retain(|l| l.age() <= max_age);
        let mut candidate = None;
        if let Some(pos) = q.iter().position(|l| l.idle_since_check() >= check_after) {
            candidate = q.remove(pos);
        }
        let after = q.len();
        stats::LINKS_READY.store(after as i64, Relaxed);
        drop(q);
        if after < before {
            self.has_space.notify_waiters();
        }
        candidate
    }
}

struct DirectDialer {
    exits: Arc<Exits>,
    tx_impl: Arc<dyn Transport>,
    burst_sem: Arc<Semaphore>,
}

pub struct EntryCfg {
    pub socks: String,
    pub key: Vec<u8>,
    pub exit_pub: Vec<u8>,
    pub bridge_listen: Option<String>,
    pub allowed_bridges: Vec<Vec<u8>>,
    pub listen_exit: Option<String>,
    pub tun_if: Option<String>,
    pub exits: Vec<String>,
    pub pool: usize,
    pub max_age: Duration,
    pub camo: Option<CamoCfg>,
    pub metrics: Option<String>,
    pub control: Option<String>,
    pub require_channel_binding: bool,
    pub mux: bool,
    pub mux_carriers: usize,
    pub session_resume: bool,
    pub forwards: Vec<ForwardSpec>,
    /// Adaptive decision / pattern-recovery / bottleneck system (`--no-adapt` turns it off).
    pub adapt: bool,
    /// Upper bound for the adaptive dialer pool.
    pub pool_max: usize,
    /// File that persists learned patterns across restarts.
    pub adapt_state: Option<String>,
}

/// Pool of live multiplexed Noise carriers (each carrying up to 128 concurrent TCP streams
/// with automatic rekey rotation and Turbo-Tunnel live `SessionOwner` reattachment).
struct MuxPool {
    target_carriers: usize,
    carriers: StdMutex<Vec<Arc<MuxCarrier>>>,
    open_gate: Semaphore,
    session_reg: Arc<SessionRegistry>,
}

impl MuxPool {
    fn new(target_carriers: usize, session_reg: Arc<SessionRegistry>) -> Arc<Self> {
        Arc::new(Self {
            target_carriers: target_carriers.clamp(1, 16),
            carriers: StdMutex::new(Vec::new()),
            open_gate: Semaphore::new(4),
            session_reg,
        })
    }

    fn pick_least_loaded(&self) -> Option<Arc<MuxCarrier>> {
        let mut list = self.carriers.lock().unwrap();
        list.retain(|c| c.is_usable());
        list.iter().min_by_key(|c| c.load()).cloned()
    }

    fn insert(&self, c: Arc<MuxCarrier>) {
        let mut list = self.carriers.lock().unwrap();
        list.retain(|x| x.is_usable());
        if list.len() < self.target_carriers {
            list.push(c);
        }
    }

    fn needs_more(&self) -> bool {
        let mut list = self.carriers.lock().unwrap();
        list.retain(|c| c.is_usable());
        list.len() < self.target_carriers
    }

    async fn ensure_carrier(
        self: &Arc<Self>,
        pool: &LinkPool,
        cfg: &EntryCfg,
        direct: Option<&DirectDialer>,
        adaptive: &AdaptiveRuntime,
    ) -> Option<Arc<MuxCarrier>> {
        if let Some(carrier) = self.pick_least_loaded() {
            if !self.needs_more() || carrier.load() < 2 {
                return Some(carrier);
            }
        }
        if let Ok(_gate) = self.open_gate.try_acquire() {
            if let Acquired::Link(lk) = acquire(pool, cfg, direct, adaptive, &[3]).await {
                let c = MuxCarrier::spawn(lk, cfg.max_age);
                self.insert(c.clone());
                return Some(c);
            }
        }
        self.pick_least_loaded()
    }

    async fn open_resumable_tcp(
        self: &Arc<Self>,
        pool: &LinkPool,
        cfg: &EntryCfg,
        direct: Option<&DirectDialer>,
        adaptive: &AdaptiveRuntime,
        target_addr: &[u8],
    ) -> ResumableOpenResult {
        for _ in 0..2 {
            if let Some(carrier) = self.ensure_carrier(pool, cfg, direct, adaptive).await {
                match carrier
                    .open_resumable_stream(target_addr, &self.session_reg)
                    .await
                {
                    ResumableOpenResult::Opened(st) => return ResumableOpenResult::Opened(st),
                    ResumableOpenResult::Refused => return ResumableOpenResult::Refused,
                    ResumableOpenResult::CarrierDead => continue,
                }
            }
            break;
        }
        ResumableOpenResult::CarrierDead
    }

    async fn open_tcp(
        self: &Arc<Self>,
        pool: &LinkPool,
        cfg: &EntryCfg,
        direct: Option<&DirectDialer>,
        adaptive: &AdaptiveRuntime,
        target_addr: &[u8],
    ) -> MuxOpenResult {
        for _ in 0..2 {
            if let Some(carrier) = self.ensure_carrier(pool, cfg, direct, adaptive).await {
                match carrier.open_stream(target_addr).await {
                    MuxOpenResult::Opened(st) => return MuxOpenResult::Opened(st),
                    MuxOpenResult::Refused => return MuxOpenResult::Refused,
                    MuxOpenResult::CarrierDead => continue,
                }
            }
            break;
        }
        MuxOpenResult::CarrierDead
    }
}

pub async fn run(cfg: EntryCfg) -> Result<()> {
    if cfg.bridge_listen.is_none() && cfg.exits.is_empty() && cfg.listen_exit.is_none() {
        bail!("entry needs --bridge-listen, --listen-exit, and/or at least one --exit");
    }
    if cfg.bridge_listen.is_some() && cfg.allowed_bridges.is_empty() {
        bail!("--bridge-listen requires at least one --allow-bridge <bridge public key>");
    }
    let cfg = Arc::new(cfg);
    let base_pool = cfg.pool.max(1);
    let direct_mode = !cfg.exits.is_empty();
    let adapt = Adapt::new(AdaptCfg {
        enabled: cfg.adapt,
        base_pool,
        pool_max: cfg.pool_max.max(base_pool),
        base_max_age: cfg.max_age,
        state_path: cfg.adapt_state.clone(),
    });
    adapt::install(adapt.clone());
    adapt::spawn_ticker(adapt.clone(), MAX_SOCKS_CONNS);
    let dialers = if cfg.adapt && direct_mode { cfg.pool_max.max(base_pool) } else { base_pool };
    let pool = LinkPool::new(dialers);
    let exits = Exits::new(cfg.exits.clone());
    let fwd_reg = ForwardRegistry::new();
    let adaptive = AdaptiveRuntime::new(MAX_SOCKS_CONNS);
    let session_reg = Arc::new(SessionRegistry::new());

    let has_udp_exit = cfg.exits.iter().any(|e| e.starts_with("udp://") || e.starts_with("ktunnel://") || e.starts_with("auto://"));
    let transport_name = if !cfg.exits.is_empty() {
        match (has_udp_exit, cfg.camo.is_some(), cfg.mux) {
            (true, _, true) => "udp+mux",
            (true, _, false) => "udp+arq",
            (false, true, true) => "camo+mux",
            (false, true, false) => "tcp+camo",
            (false, false, true) => "tcp+mux",
            (false, false, false) => "tcp",
        }
    } else if cfg.require_channel_binding {
        if cfg.mux { "bridge+cb+mux" } else { "bridge+cb" }
    } else if cfg.mux {
        "bridge+mux"
    } else {
        "bridge"
    };
    let mux_pool: Option<Arc<MuxPool>> = if cfg.mux {
        Some(MuxPool::new(cfg.mux_carriers.max(1), session_reg.clone()))
    } else {
        None
    };

    let ctl = ControlState::with_runtime(
        "entry",
        transport_name,
        Some(exits.clone()),
        Some(fwd_reg.clone()),
        Some(adaptive.clone()),
        cfg.allowed_bridges.clone(),
    );

    if let Some(m) = cfg.metrics.clone() {
        tokio::spawn(stats::serve(m, Some(exits.clone())));
    }
    if let Some(sock) = cfg.control.clone() {
        tokio::spawn(control::serve(sock, ctl.clone()));
    }

    // Background idle pool keepalive sweeper: detects silently dropped NAT/DPI links
    // before any client stalls on acquire().
    {
        let (pool_sw, cfg_sw, adaptive_sw, ctl_sw) =
            (pool.clone(), cfg.clone(), adaptive.clone(), ctl.clone());
        tokio::spawn(async move {
            let check_after = (cfg_sw.max_age / 2)
                .min(Duration::from_secs(20))
                .max(Duration::from_secs(5));
            while !ctl_sw.is_draining() {
                tokio::select! {
                    _ = sleep(Duration::from_secs(8)) => {}
                    _ = ctl_sw.drain_notify.notified() => break,
                }
                for _ in 0..4 {
                    let Some(mut lk) = pool_sw.evict_expired_and_pop_for_check(cfg_sw.max_age, check_after) else {
                        break;
                    };
                    if lk.ping(KEEPALIVE_TIMEOUT).await {
                        adaptive_sw.record(TransportEvent::KeepaliveOk, 0);
                        let _ = pool_sw.try_push(lk);
                    } else {
                        stats::POOL_KEEPALIVE_DROPPED.fetch_add(1, Relaxed);
                        adaptive_sw.record(TransportEvent::KeepaliveFail, 0);
                    }
                }
            }
        });
    }

    if let Some(exit_bind) = cfg.listen_exit.clone() {
        let el = TcpListener::bind(&exit_bind).await?;
        eprintln!("[entry] accepting reverse-dialed exits on {exit_bind}");
        let (cfg_le, pool_le, ctl_le) = (cfg.clone(), pool.clone(), ctl.clone());
        let active_exit_sem = Arc::new(Semaphore::new(MAX_ACTIVE_BRIDGES));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = ctl_le.drain_notify.notified() => break,
                    res = el.accept() => {
                        let Ok((s, peer)) = res else { continue };
                        let Ok(permit) = active_exit_sem.clone().try_acquire_owned() else {
                            drop(s);
                            continue;
                        };
                        let (cfg_c, pool_c, ctl_c) = (cfg_le.clone(), pool_le.clone(), ctl_le.clone());
                        tokio::spawn(async move {
                            link::tune(&s);
                            match timeout(Duration::from_secs(10), link::initiate(Box::new(s), &cfg_c.key, &cfg_c.exit_pub)).await {
                                Ok(Ok(lk)) => {
                                    let lk = lk.with_permit(permit);
                                    stats::REVERSE_EXITS_CONNECTED.fetch_add(1, Relaxed);
                                    let pushed = pool_c.push_wait(lk, &ctl_c).await;
                                    if !pushed {
                                        stats::REVERSE_EXITS_CONNECTED.fetch_sub(1, Relaxed);
                                    }
                                }
                                _ => {
                                    stats::LINK_FAIL.fetch_add(1, Relaxed);
                                    stats::log_err_rl(&format!("[entry] reverse-exit {peer}: handshake failed"));
                                }
                            }
                        });
                    }
                }
            }
        });
    }

    if let Some(addr) = cfg.bridge_listen.clone() {
        let l = TcpListener::bind(&addr).await?;
        eprintln!(
            "[entry] accepting authenticated bridges on {addr} (hs_cap={MAX_BRIDGE_HANDSHAKES}, per_prefix={MAX_BRIDGE_HS_PER_PREFIX}, active_cap={MAX_ACTIVE_BRIDGES})"
        );
        let (cfg, pool, ctl) = (cfg.clone(), pool.clone(), ctl.clone());
        let hs_limiter = BridgeHandshakeLimiter::new(MAX_BRIDGE_HANDSHAKES, MAX_BRIDGE_HS_PER_PREFIX);
        let active_sem = Arc::new(Semaphore::new(MAX_ACTIVE_BRIDGES));
        let replay = Arc::new(BridgeReplayCache::new());
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = ctl.drain_notify.notified() => break,
                    res = l.accept() => {
                        match res {
                            Ok((s, peer)) => {
                                let Some(hs_guard) = hs_limiter.try_acquire(peer.ip()) else {
                                    drop(s);
                                    continue;
                                };
                                let (cfg, pool, active_sem, replay, ctl) =
                                    (cfg.clone(), pool.clone(), active_sem.clone(), replay.clone(), ctl.clone());
                                tokio::spawn(async move {
                                    if let Err(e) = accept_bridge(s, &cfg, &pool, &ctl, hs_guard, active_sem, &replay).await {
                                        stats::LINK_FAIL.fetch_add(1, Relaxed);
                                        stats::log_err_rl(&format!("[entry] bridge {peer}: {e}"));
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("[entry] accept error: {e}");
                                sleep(Duration::from_millis(200)).await;
                            }
                        }
                    }
                }
            }
        });
    }

    let direct_dialer: Option<Arc<DirectDialer>> = if !cfg.exits.is_empty() {
        let tx_impl: Arc<dyn Transport> = if has_udp_exit {
            let udp_auth_key = cfg
                .camo
                .as_ref()
                .map(|c| c.secret.clone())
                .ok_or_else(|| anyhow::anyhow!("udp:// and ktunnel:// exits require --camo-secret"))?;
            Arc::new(AutoTransport {
                camo: cfg.camo.clone(),
                udp_auth_key,
                connect_timeout: Duration::from_secs(10),
            })
        } else {
            match &cfg.camo {
                Some(c) => Arc::new(CamoTransport {
                    cfg: c.clone(),
                    connect_timeout: Duration::from_secs(10),
                }),
                None => Arc::new(TcpTransport {
                    connect_timeout: Duration::from_secs(10),
                }),
            }
        };
        eprintln!(
            "[entry] direct mode -> {:?} (pool {}, transport={}, session_resume={})",
            cfg.exits,
            cfg.pool,
            tx_impl.name(),
            cfg.mux && cfg.session_resume
        );
        tokio::spawn(health::probe_loop(exits.clone(), Duration::from_secs(20)));
        for idx in 0..dialers {
            let (cfg, pool, exits, tx_impl, adaptive, ctl, adapt) = (
                cfg.clone(),
                pool.clone(),
                exits.clone(),
                tx_impl.clone(),
                adaptive.clone(),
                ctl.clone(),
                adapt.clone(),
            );
            tokio::spawn(async move {
                let mut backoff = adapt.tuning().backoff_min;
                while !ctl.is_draining() {
                    if idx >= adapt.tuning().pool_target {
                        tokio::select! {
                            _ = sleep(Duration::from_millis(500)) => {}
                            _ = ctl.drain_notify.notified() => return,
                        }
                        continue;
                    }
                    match dial(&exits, &cfg, tx_impl.as_ref(), &adaptive).await {
                        Ok(l) => {
                            backoff = adapt.tuning().backoff_min;
                            if !pool.push_wait(l, &ctl).await {
                                return;
                            }
                        }
                        Err(e) => {
                            stats::LINK_FAIL.fetch_add(1, Relaxed);
                            stats::log_err_rl(&format!("[entry] dial: {e}"));
                            let wait = adapt.next_backoff(backoff, Instant::now());
                            tokio::select! {
                                _ = sleep(wait) => {}
                                _ = ctl.drain_notify.notified() => return,
                            }
                            backoff = wait;
                        }
                    }
                }
            });
        }
        Some(Arc::new(DirectDialer {
            exits: exits.clone(),
            tx_impl,
            burst_sem: Arc::new(Semaphore::new(256)),
        }))
    } else {
        None
    };

    // Turbo-Tunnel Live Session Resume supervisor: watches for detached SessionOwners when
    // a MuxCarrier dies or rotates and seamlessly reattaches them to healthy carriers.
    if let Some(mp) = mux_pool.clone() {
        let (pool_re, cfg_re, dir_re, adp_re, ctl_re, sreg_re) = (
            pool.clone(),
            cfg.clone(),
            direct_dialer.clone(),
            adaptive.clone(),
            ctl.clone(),
            session_reg.clone(),
        );
        tokio::spawn(async move {
            while !ctl_re.is_draining() {
                tokio::select! {
                    _ = sleep(Duration::from_millis(120)) => {}
                    _ = ctl_re.drain_notify.notified() => break,
                }
                sreg_re.sweep_expired(DEFAULT_SESSION_DETACH_TTL);
                let detached = sreg_re.detached_sessions();
                if detached.is_empty() {
                    continue;
                }
                if let Some(carrier) = mp
                    .ensure_carrier(&pool_re, &cfg_re, dir_re.as_deref(), &adp_re)
                    .await
                {
                    for owner in detached {
                        let next_epoch = owner.bump_epoch();
                        if carrier.attach_session(&owner, next_epoch, false).await.is_err() {
                            owner.detach_carrier();
                            break;
                        }
                    }
                }
            }
        });
    }

    let socks_sem = Arc::new(Semaphore::new(MAX_SOCKS_CONNS));

    // Optional L4 Port Forwards (`--forward SPEC`) supporting Userspace TCP/UDP & Kernel Transparent Source-IP Mode
    let mut kernel_rules: Vec<KernelForwardRule> = Vec::new();
    for spec in &cfg.forwards {
        let fstate = fwd_reg.register(spec.clone());
        if spec.mode == ForwardMode::KernelTransparent {
            for lport in spec.listen_start..=spec.listen_end {
                let (th, tp) = spec.target_for_listen_port(lport);
                let tip: std::net::Ipv4Addr = th
                    .parse()
                    .map_err(|_| anyhow::anyhow!("kernel transparent forward requires IPv4 target (got '{th}')"))?;
                kernel_rules.push(KernelForwardRule {
                    proto: spec.proto.as_str(),
                    listen_port: lport,
                    target_ip: tip,
                    target_port: tp,
                });
            }
            continue;
        }
        for lport in spec.listen_start..=spec.listen_end {
            let bind_addr = format!("{}:{lport}", spec.bind_ip);
            let (target_host, target_port) = spec.target_for_listen_port(lport);
            if spec.proto == ForwardProto::Tcp {
                let fl = TcpListener::bind(&bind_addr).await?;
                eprintln!(
                    "[entry] forward tcp {bind_addr} -> {target_host}:{target_port} (name={}, proxy_v2={})",
                    spec.name,
                    spec.proxy_v2
                );
                let (pool, cfg, direct, adaptive, ctl, fstate, sem) = (
                    pool.clone(),
                    cfg.clone(),
                    direct_dialer.clone(),
                    adaptive.clone(),
                    ctl.clone(),
                    fstate.clone(),
                    socks_sem.clone(),
                );
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = ctl.drain_notify.notified() => break,
                            res = fl.accept() => {
                                let Ok((c, peer)) = res else { continue };
                                if fstate.quota_reached() || !fstate.enabled.load(Relaxed) {
                                    drop(c);
                                    continue;
                                }
                                let Ok(permit) = sem.clone().try_acquire_owned() else {
                                    drop(c);
                                    continue;
                                };
                                let (pool, cfg, direct, adaptive, fstate, th) = (
                                    pool.clone(),
                                    cfg.clone(),
                                    direct.clone(),
                                    adaptive.clone(),
                                    fstate.clone(),
                                    target_host.clone(),
                                );
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    link::tune(&c);
                                    let Ok(req) = forward::encode_target_req(&th, target_port) else { return };
                                    if let Acquired::Link(lk) = acquire(&pool, &cfg, direct.as_deref(), &adaptive, &req).await {
                                        let user = fstate.register_user(peer);
                                        if let Err(e) = forward::pipe_forwarded_tcp_adaptive(lk, c, fstate, user, Some(adaptive)).await {
                                            stats::log_err_rl(&format!("[entry] forward tcp {peer}: {e}"));
                                        }
                                    }
                                });
                            }
                        }
                    }
                });
            } else {
                // Real L4 UDP Port Forward implementation
                let usock = Arc::new(UdpSocket::bind(&bind_addr).await?);
                let target_prefix = forward::encode_target_addr(&target_host, target_port)?;
                eprintln!(
                    "[entry] forward udp {bind_addr} -> {target_host}:{target_port} (name={}, proxy_v2={})",
                    spec.name,
                    spec.proxy_v2
                );
                let (pool, cfg, direct, adaptive, ctl, fstate, sem) = (
                    pool.clone(),
                    cfg.clone(),
                    direct_dialer.clone(),
                    adaptive.clone(),
                    ctl.clone(),
                    fstate.clone(),
                    socks_sem.clone(),
                );
                tokio::spawn(async move {
                    let sessions: Arc<StdMutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>> =
                        Arc::new(StdMutex::new(HashMap::new()));
                    let mut buf = vec![0u8; 65536];
                    loop {
                        tokio::select! {
                            _ = ctl.drain_notify.notified() => break,
                            res = usock.recv_from(&mut buf) => {
                                let Ok((n, peer)) = res else { continue };
                                if fstate.quota_reached() || !fstate.enabled.load(Relaxed) || n == 0 {
                                    continue;
                                }
                                let pkt = buf[..n].to_vec();
                                let existing = sessions.lock().unwrap().get(&peer).cloned();
                                if let Some(tx) = existing {
                                    let _ = tx.try_send(pkt);
                                    continue;
                                }
                                let Ok(permit) = sem.clone().try_acquire_owned() else {
                                    continue;
                                };
                                let (tx_pkt, rx_pkt) = mpsc::channel::<Vec<u8>>(64);
                                let _ = tx_pkt.try_send(pkt);
                                sessions.lock().unwrap().insert(peer, tx_pkt);
                                let (pool, cfg, direct, adaptive, fstate, usock_c, sessions_c, prefix_c) = (
                                    pool.clone(),
                                    cfg.clone(),
                                    direct.clone(),
                                    adaptive.clone(),
                                    fstate.clone(),
                                    usock.clone(),
                                    sessions.clone(),
                                    target_prefix.clone(),
                                );
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    if let Acquired::Link(lk) = acquire(&pool, &cfg, direct.as_deref(), &adaptive, &[2]).await {
                                        let user = fstate.register_user(peer);
                                        if let Err(e) = forward::relay_forwarded_udp(
                                            lk,
                                            usock_c,
                                            peer,
                                            prefix_c,
                                            rx_pkt,
                                            fstate,
                                            user,
                                        ).await {
                                            stats::log_err_rl(&format!("[entry] forward udp {peer}: {e}"));
                                        }
                                    }
                                    sessions_c.lock().unwrap().remove(&peer);
                                });
                            }
                        }
                    }
                });
            }
        }
    }

    #[cfg(target_os = "linux")]
    let _kernel_fwd_guard = if !kernel_rules.is_empty() {
        let tun_name = cfg.tun_if.as_deref().unwrap_or("khaymali0");
        let kfwd = KernelTransparentForwarder::new(tun_name, kernel_rules)?;
        kfwd.apply()?;
        eprintln!("[entry] kernel transparent forwarding active via {tun_name} (real client IP preserved)");
        Some(kfwd)
    } else {
        None
    };

    let l = TcpListener::bind(&cfg.socks).await?;
    eprintln!(
        "[entry] SOCKS5 (CONNECT + IPv4/IPv6 UDP ASSOCIATE) on {} (max_conns={MAX_SOCKS_CONNS})",
        cfg.socks
    );
    loop {
        tokio::select! {
            _ = ctl.drain_notify.notified() => {
                eprintln!("[entry] draining active streams (up to {}s)...", DRAIN_WINDOW.as_secs());
                let deadline = Instant::now() + DRAIN_WINDOW;
                while stats::STREAMS_ACTIVE.load(Relaxed) > 0 && Instant::now() < deadline {
                    sleep(Duration::from_millis(100)).await;
                }
                return Ok(());
            }
            res = l.accept() => {
                let (c, _) = res?;
                let active_now = stats::STREAMS_ACTIVE.load(Relaxed).max(0) as usize;
                let dynamic_cap = adaptive.current_concurrency_cap().min(MAX_SOCKS_CONNS);
                if active_now >= dynamic_cap {
                    drop(c);
                    continue;
                }
                let Ok(permit) = socks_sem.clone().try_acquire_owned() else {
                    drop(c);
                    continue;
                };
                let (pool, mux_p, cfg, direct, adaptive) = (
                    pool.clone(),
                    mux_pool.clone(),
                    cfg.clone(),
                    direct_dialer.clone(),
                    adaptive.clone(),
                );
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_socks(c, &pool, mux_p.as_ref(), &cfg, direct.as_deref(), adaptive).await {
                        stats::log_err_rl(&format!("[entry] socks: {e}"));
                    }
                });
            }
        }
    }
}

async fn dial_once(
    exits: &Exits,
    cfg: &EntryCfg,
    tx_impl: &dyn Transport,
    adaptive: &AdaptiveRuntime,
    addr: String,
    t: Tuning,
) -> Result<Link> {
    let t0 = Instant::now();
    let res: std::result::Result<Link, (anyhow::Error, Stage)> = async {
        let stream = match timeout(t.connect_timeout, tx_impl.dial(&addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err((e, Stage::Connect)),
            Err(el) => return Err((anyhow::Error::from(el), Stage::Connect)),
        };
        match timeout(t.handshake_timeout, link::initiate(stream, &cfg.key, &cfg.exit_pub)).await {
            Ok(Ok(l)) => Ok(l),
            Ok(Err(e)) => Err((e, Stage::Handshake)),
            Err(el) => Err((anyhow::Error::from(el), Stage::Handshake)),
        }
    }
    .await;
    match res {
        Ok(l) => {
            let rtt = t0.elapsed();
            exits.ok(&addr, rtt);
            adaptive.record_with_path(
                TransportEvent::ConnectOk { rtt_ms: rtt.as_millis() as u32 },
                stats::STREAMS_ACTIVE.load(Relaxed).max(0) as u32,
                &addr,
            );
            if let Some((score, obs)) = adaptive.path_score(&addr) {
                exits.update_path_intel(&addr, score, obs);
            }
            adapt::record_global(Event::DialOk { rtt });
            Ok(l)
        }
        Err((e, stage)) => {
            let kind = Exits::classify_error(&e);
            exits.fail_kind(&addr, kind);
            let ev = match kind {
                FailureKind::Timeout => TransportEvent::HandshakeTimeout,
                FailureKind::Reset => TransportEvent::EarlyReset { bytes_transferred: 0 },
                FailureKind::Other => TransportEvent::ConnectFail,
            };
            let stage_tag = match stage {
                Stage::Connect => "stage_dial",
                Stage::Handshake => "stage_handshake",
            };
            let diag_line = format!("dial {addr}: {e} {stage_tag}");
            adaptive.record_with_path_and_log(
                ev,
                stats::STREAMS_ACTIVE.load(Relaxed).max(0) as u32,
                &addr,
                Some(&diag_line),
            );
            if let Some((score, obs)) = adaptive.path_score(&addr) {
                exits.update_path_intel(&addr, score, obs);
            }
            adapt::record_global(Event::DialFail { sig: Sig::from_error(&e, stage) });
            Err(anyhow::anyhow!("exit {addr}: {e}"))
        }
    }
}

fn dial_tuning(cfg: &EntryCfg) -> Tuning {
    match adapt::global() {
        Some(a) => a.tuning(),
        None => Tuning {
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            pool_target: cfg.pool.max(1),
            max_age: cfg.max_age,
            backoff_min: Duration::from_millis(500),
            backoff_max: Duration::from_secs(30),
            hedge: 1,
            acquire_deadline: Duration::from_secs(20),
        },
    }
}

async fn dial(
    exits: &Exits,
    cfg: &EntryCfg,
    tx_impl: &dyn Transport,
    adaptive: &AdaptiveRuntime,
) -> Result<Link> {
    let t = dial_tuning(cfg);
    let Some(a1) = exits.pick() else {
        adapt::record_global(Event::DialFail { sig: Sig::CircuitOpen });
        bail!("no selectable exits")
    };
    if t.hedge < 2 {
        return dial_once(exits, cfg, tx_impl, adaptive, a1, t).await;
    }
    let a2 = exits.pick_other(&a1).unwrap_or_else(|| a1.clone());
    adapt::HEDGED_DIALS.fetch_add(1, Relaxed);
    let fa = dial_once(exits, cfg, tx_impl, adaptive, a1, t);
    let fb = dial_once(exits, cfg, tx_impl, adaptive, a2, t);
    tokio::pin!(fa);
    tokio::pin!(fb);
    tokio::select! {
        ra = &mut fa => match ra {
            Ok(l) => Ok(l),
            Err(ea) => match fb.await { Ok(l) => Ok(l), Err(_) => Err(ea) },
        },
        rb = &mut fb => match rb {
            Ok(l) => Ok(l),
            Err(eb) => match fa.await { Ok(l) => Ok(l), Err(_) => Err(eb) },
        },
    }
}

async fn accept_bridge(
    mut s: TcpStream,
    cfg: &EntryCfg,
    pool: &LinkPool,
    ctl: &ControlState,
    hs_guard: BridgeHsGuard,
    active_sem: Arc<Semaphore>,
    replay: &BridgeReplayCache,
) -> Result<()> {
    link::tune(&s);
    let auth_res = timeout(
        BRIDGE_AUTH_TIMEOUT,
        link::auth_respond(&mut s, &cfg.key, &cfg.allowed_bridges, replay, cfg.require_channel_binding),
    )
    .await;
    drop(hs_guard);
    let (_bridge_pub, hs_hash, maybe_cb_secret) = auth_res??;

    let Ok(active_permit) = active_sem.try_acquire_owned() else {
        bail!("active bridge capacity reached");
    };

    let stream = match maybe_cb_secret {
        Some(cb_secret) => {
            let keys = transport::derive_channel_binding_keys(&hs_hash, &cb_secret);
            transport::wrap_bound_stream(Box::new(s), keys.e2b, keys.b2e)
        }
        None => Box::new(s),
    };

    let lk = timeout(Duration::from_secs(10), link::initiate(stream, &cfg.key, &cfg.exit_pub))
        .await??
        .with_permit(active_permit);
    if !pool.push_wait(lk, ctl).await {
        bail!("pool closed or draining");
    }
    Ok(())
}

enum Acquired {
    Link(Link),
    Refused,
    Unavailable,
}

async fn acquire(
    pool: &LinkPool,
    cfg: &EntryCfg,
    direct: Option<&DirectDialer>,
    adaptive: &AdaptiveRuntime,
    req: &[u8],
) -> Acquired {
    acquire_within(pool, cfg, direct, adaptive, req, None).await
}

async fn acquire_within(
    pool: &LinkPool,
    cfg: &EntryCfg,
    direct: Option<&DirectDialer>,
    adaptive: &AdaptiveRuntime,
    req: &[u8],
    budget: Option<Duration>,
) -> Acquired {
    let mut t = dial_tuning(cfg);
    if let Some(b) = budget {
        t.acquire_deadline = t.acquire_deadline.min(b);
    }
    let mut waited = Duration::ZERO;
    let r = acquire_inner(pool, cfg, direct, adaptive, req, &t, &mut waited).await;
    adapt::record_global(Event::Acquire {
        wait: waited,
        ok: matches!(r, Acquired::Link(_) | Acquired::Refused),
    });
    r
}

async fn acquire_inner(
    pool: &LinkPool,
    cfg: &EntryCfg,
    direct: Option<&DirectDialer>,
    adaptive: &AdaptiveRuntime,
    req: &[u8],
    t: &Tuning,
    waited: &mut Duration,
) -> Acquired {
    let deadline = Instant::now() + t.acquire_deadline;
    let mut dead = 0;
    while dead < 6 {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Acquired::Unavailable;
        }
        let t_get = Instant::now();
        let allow_burst = adapt::condition_global() != Condition::Blackout;
        let got: Option<Link> = if let Some(l) = pool.try_pop() {
            Some(l)
        } else if let (true, Some(d)) = (allow_burst, direct) {
            if let Ok(bp) = d.burst_sem.clone().try_acquire_owned() {
                let dialed = timeout(
                    left.min(Duration::from_secs(8)),
                    dial(&d.exits, cfg, d.tx_impl.as_ref(), adaptive),
                )
                .await;
                drop(bp);
                match dialed {
                    Ok(Ok(l)) => Some(l),
                    _ => match timeout(left.min(Duration::from_millis(50)), pool.pop()).await {
                        Ok(l) => Some(l),
                        Err(_) => {
                            *waited += t_get.elapsed();
                            dead += 1;
                            continue;
                        }
                    },
                }
            } else {
                timeout(left, pool.pop()).await.ok()
            }
        } else {
            timeout(left, pool.pop()).await.ok()
        };
        *waited += t_get.elapsed();
        let Some(mut lk) = got else { return Acquired::Unavailable };

        let age = lk.age();
        if age > t.max_age {
            continue;
        }
        if lk.send(req).await.is_err() {
            dead += 1;
            adapt::record_global(Event::AcquireDead { age });
            adaptive.record(TransportEvent::EarlyReset { bytes_transferred: 0 }, 0);
            continue;
        }
        let resp_wait = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(10));
        match timeout(resp_wait, lk.recv()).await {
            Ok(Ok(r)) if r == [0] => return Acquired::Link(lk),
            Ok(Ok(r)) if r == [1] => return Acquired::Refused,
            other => {
                dead += 1;
                if matches!(other, Ok(Err(_))) {
                    adapt::record_global(Event::AcquireDead { age });
                }
                adaptive.record(
                    TransportEvent::MidStreamStall {
                        bytes_transferred: 0,
                        frame_size: adaptive.current_chunk_size(),
                    },
                    0,
                );
            }
        }
    }
    Acquired::Unavailable
}

async fn handle_socks(
    mut c: TcpStream,
    pool: &LinkPool,
    mux_pool: Option<&Arc<MuxPool>>,
    cfg: &EntryCfg,
    direct: Option<&DirectDialer>,
    adaptive: Arc<AdaptiveRuntime>,
) -> Result<()> {
    link::tune(&c);
    let (cmd, addr) = timeout(SOCKS_HANDSHAKE_TIMEOUT, socks_handshake(&mut c)).await??;
    match cmd {
        1 => {
            let t_open = Instant::now();
            let overall = dial_tuning(cfg).acquire_deadline;
            // 1. Turbo-Tunnel Live Resumable Mux path (survives carrier deaths without TCP RST)
            if let Some(mp) = mux_pool {
                if cfg.session_resume {
                    let opened = match timeout(
                        overall,
                        mp.open_resumable_tcp(pool, cfg, direct, &adaptive, &addr),
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(_) => ResumableOpenResult::CarrierDead,
                    };
                    match opened {
                        ResumableOpenResult::Opened(st) => {
                            reply(&mut c, 0, None).await;
                            let r = st.pipe_tcp(c, Some(adaptive)).await;
                            if r.is_ok() {
                                adapt::record_global(Event::LinkClean);
                            }
                            return r;
                        }
                        ResumableOpenResult::Refused => {
                            reply(&mut c, 5, None).await;
                            return Ok(());
                        }
                        ResumableOpenResult::CarrierDead => {}
                    }
                } else {
                    let opened =
                        match timeout(overall, mp.open_tcp(pool, cfg, direct, &adaptive, &addr)).await
                        {
                            Ok(r) => r,
                            Err(_) => MuxOpenResult::CarrierDead,
                        };
                    match opened {
                        MuxOpenResult::Opened(st) => {
                            reply(&mut c, 0, None).await;
                            let r = st.pipe_tcp(c, Some(adaptive)).await;
                            if r.is_ok() {
                                adapt::record_global(Event::LinkClean);
                            }
                            return r;
                        }
                        MuxOpenResult::Refused => {
                            reply(&mut c, 5, None).await;
                            return Ok(());
                        }
                        MuxOpenResult::CarrierDead => {}
                    }
                }
            }
            // 2. Fallback to dedicated single-stream Link
            let mut req = vec![1u8];
            req.extend_from_slice(&addr);
            let left = overall.saturating_sub(t_open.elapsed()).max(Duration::from_millis(500));
            match acquire_within(pool, cfg, direct, &adaptive, &req, Some(left)).await {
                Acquired::Link(lk) => {
                    reply(&mut c, 0, None).await;
                    let age0 = lk.age();
                    let t_pipe = Instant::now();
                    let r = lk.pipe_adaptive(c, Some(adaptive)).await;
                    match &r {
                        Ok(()) => adapt::record_global(Event::LinkClean),
                        Err(e) if adapt::is_hard_tunnel_death(e) => {
                            adapt::record_global(Event::LinkDied { age: age0 + t_pipe.elapsed() })
                        }
                        Err(_) => {}
                    }
                    r
                }
                Acquired::Refused => {
                    reply(&mut c, 5, None).await;
                    Ok(())
                }
                Acquired::Unavailable => {
                    reply(&mut c, 1, None).await;
                    bail!("no link available")
                }
            }
        }
        3 => {
            let local = c.local_addr()?;
            let sock = UdpSocket::bind((local.ip(), 0)).await?;
            let bnd = sock.local_addr()?;
            let client_ip = c.peer_addr()?.ip();
            match acquire(pool, cfg, direct, &adaptive, &[2]).await {
                Acquired::Link(lk) => {
                    reply(&mut c, 0, Some(bnd)).await;
                    udp::entry_relay(sock, lk, c, client_ip).await
                }
                _ => {
                    reply(&mut c, 1, None).await;
                    bail!("no link available for UDP")
                }
            }
        }
        _ => {
            reply(&mut c, 7, None).await;
            bail!("unsupported SOCKS command {cmd}")
        }
    }
}

async fn reply(c: &mut TcpStream, code: u8, bnd: Option<SocketAddr>) {
    let mut m = Vec::with_capacity(22);
    match bnd {
        Some(SocketAddr::V6(v6)) => {
            m.extend_from_slice(&[5, code, 0, 4]);
            m.extend_from_slice(&v6.ip().octets());
            m.extend_from_slice(&v6.port().to_be_bytes());
        }
        Some(SocketAddr::V4(v4)) => {
            m.extend_from_slice(&[5, code, 0, 1]);
            m.extend_from_slice(&v4.ip().octets());
            m.extend_from_slice(&v4.port().to_be_bytes());
        }
        None => {
            m.extend_from_slice(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
    }
    let _ = c.write_all(&m).await;
}

pub async fn socks_handshake(c: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut h = [0u8; 2];
    c.read_exact(&mut h).await?;
    if h[0] != 5 || h[1] == 0 {
        bail!("not SOCKS5");
    }
    let mut methods = vec![0u8; h[1] as usize];
    c.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        let _ = c.write_all(&[5, 0xff]).await;
        bail!("SOCKS5 client did not offer no-auth method");
    }
    c.write_all(&[5, 0]).await?;

    let mut r = [0u8; 4];
    c.read_exact(&mut r).await?;
    if r[0] != 5 {
        bail!("bad SOCKS5 request version");
    }
    let mut addr = vec![r[3]];
    match r[3] {
        1 => {
            let mut b = [0u8; 4];
            c.read_exact(&mut b).await?;
            addr.extend_from_slice(&b);
        }
        3 => {
            let mut n = [0u8; 1];
            c.read_exact(&mut n).await?;
            if n[0] == 0 {
                reply(c, 8, None).await;
                bail!("empty domain");
            }
            let mut b = vec![0u8; n[0] as usize];
            c.read_exact(&mut b).await?;
            addr.push(n[0]);
            addr.extend_from_slice(&b);
        }
        4 => {
            let mut b = [0u8; 16];
            c.read_exact(&mut b).await?;
            addr.extend_from_slice(&b);
        }
        _ => {
            reply(c, 8, None).await;
            bail!("bad address type");
        }
    }
    let mut p = [0u8; 2];
    c.read_exact(&mut p).await?;
    addr.extend_from_slice(&p);
    Ok((r[1], addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn neg_bridge_handshake_prefix_flood_bounded() {
        let lim = BridgeHandshakeLimiter::new(8, 2);
        let g1 = lim.try_acquire("2001:4860:4860:1::1".parse().unwrap()).unwrap();
        let g2 = lim.try_acquire("2001:4860:4860:1::2".parse().unwrap()).unwrap();
        assert!(lim.try_acquire("2001:4860:4860:1::3".parse().unwrap()).is_none());
        let g_clean = lim.try_acquire("198.51.100.5".parse().unwrap());
        assert!(g_clean.is_some());
        drop(g1);
        assert!(lim.try_acquire("2001:4860:4860:1::4".parse().unwrap()).is_some());
        drop(g2);
    }

    #[tokio::test]
    async fn neg_socks5_slowloris_and_malformed() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            assert!(timeout(Duration::from_millis(120), socks_handshake(&mut s)).await.is_err());

            let (mut s2, _) = l.accept().await.unwrap();
            assert!(socks_handshake(&mut s2).await.is_err());

            let (mut s3, _) = l.accept().await.unwrap();
            assert!(socks_handshake(&mut s3).await.is_err());
        });

        let mut c1 = TcpStream::connect(addr).await.unwrap();
        c1.write_all(&[5]).await.unwrap();
        sleep(Duration::from_millis(160)).await;
        drop(c1);

        let mut c2 = TcpStream::connect(addr).await.unwrap();
        c2.write_all(&[5, 1, 2]).await.unwrap();
        let mut rep = [0u8; 2];
        c2.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep, [5, 0xff]);

        let mut c3 = TcpStream::connect(addr).await.unwrap();
        c3.write_all(b"GET / HTTP/1.1
").await.unwrap();
        drop(c3);

        srv.await.unwrap();
    }
}
