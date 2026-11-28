//! Isolated Fallback Registry with IP + prefix (/64 IPv6, /24 IPv4) quotas,
//! conditional Idle LRU eviction, and half-close FIN mirroring (SPEC §3.2).

use crate::stats;
use crate::util::{ip_prefix_key, PrefixKey};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;

pub const FALLBACK_MAX_TOTAL: usize = 256;
pub const FALLBACK_MAX_PER_IP: usize = 24;
pub const FALLBACK_MAX_PER_PREFIX: usize = 38; // ~15% per IPv6 /64 or IPv4 /24

struct FallbackEntry {
    ip: IpAddr,
    prefix: PrefixKey,
    _created_ms: u64,
    last_active_ms: Arc<AtomicU64>,
    evict: Arc<Notify>,
}

/// Real Fallback Registry tracking active fallback sockets for conditional Idle LRU eviction.
pub struct FallbackLimiter {
    max_total: usize,
    max_per_ip: usize,
    max_per_prefix: usize,
    base: Instant,
    next_id: AtomicU64,
    active: Mutex<HashMap<u64, FallbackEntry>>,
}

pub struct FallbackLease {
    id: u64,
    limiter: Arc<FallbackLimiter>,
    last_active_ms: Arc<AtomicU64>,
    evict: Arc<Notify>,
}

impl FallbackLease {
    pub fn touch(&self) {
        let ms = self.limiter.base.elapsed().as_millis() as u64;
        self.last_active_ms.store(ms, Relaxed);
    }

    pub fn evicted(&self) -> tokio::sync::futures::Notified<'_> {
        self.evict.notified()
    }
}

impl Drop for FallbackLease {
    fn drop(&mut self) {
        let mut map = self.limiter.active.lock().unwrap();
        map.remove(&self.id);
        stats::FALLBACK_ACTIVE.store(map.len() as i64, Relaxed);
    }
}

impl FallbackLimiter {
    pub fn new(max_total: usize, max_per_ip: usize, max_per_prefix: usize) -> Arc<Self> {
        let mt = max_total.max(1);
        Arc::new(Self {
            max_total: mt,
            max_per_ip: max_per_ip.max(1).min(mt),
            max_per_prefix: max_per_prefix.max(1).min(mt),
            base: Instant::now(),
            next_id: AtomicU64::new(1),
            active: Mutex::new(HashMap::new()),
        })
    }

    pub fn default_limiter() -> Arc<Self> {
        Self::new(FALLBACK_MAX_TOTAL, FALLBACK_MAX_PER_IP, FALLBACK_MAX_PER_PREFIX)
    }

    fn evict_oldest_matching(
        map: &mut HashMap<u64, FallbackEntry>,
        pred: impl Fn(&FallbackEntry) -> bool,
    ) -> bool {
        if let Some((&victim_id, _)) = map
            .iter()
            .filter(|(_, e)| pred(e))
            .min_by_key(|(_, e)| e.last_active_ms.load(Relaxed))
        {
            if let Some(victim) = map.remove(&victim_id) {
                victim.evict.notify_one();
                stats::FALLBACK_EVICTED.fetch_add(1, Relaxed);
                return true;
            }
        }
        false
    }

    pub fn acquire(self: &Arc<Self>, ip: IpAddr) -> FallbackLease {
        let prefix = ip_prefix_key(ip);
        let mut map = self.active.lock().unwrap();

        let ip_count = map.values().filter(|e| e.ip == ip).count();
        let prefix_count = map.values().filter(|e| e.prefix == prefix).count();

        if ip_count >= self.max_per_ip {
            Self::evict_oldest_matching(&mut map, |e| e.ip == ip);
        } else if prefix_count >= self.max_per_prefix {
            Self::evict_oldest_matching(&mut map, |e| e.prefix == prefix);
        } else if map.len() >= self.max_total {
            let mut counts: HashMap<PrefixKey, usize> = HashMap::new();
            for e in map.values() {
                *counts.entry(e.prefix).or_insert(0) += 1;
            }
            if let Some((&top_prefix, _)) = counts.iter().max_by_key(|(_, &c)| c) {
                Self::evict_oldest_matching(&mut map, |e| e.prefix == top_prefix);
            }
        }

        let id = self.next_id.fetch_add(1, Relaxed);
        let now_ms = self.base.elapsed().as_millis() as u64;
        let last_active_ms = Arc::new(AtomicU64::new(now_ms));
        let evict = Arc::new(Notify::new());
        map.insert(
            id,
            FallbackEntry {
                ip,
                prefix,
                _created_ms: now_ms,
                last_active_ms: last_active_ms.clone(),
                evict: evict.clone(),
            },
        );
        stats::FALLBACK_ACTIVE.store(map.len() as i64, Relaxed);

        FallbackLease {
            id,
            limiter: self.clone(),
            last_active_ms,
            evict,
        }
    }

    pub fn count_for_prefix(&self, prefix: PrefixKey) -> usize {
        self.active.lock().unwrap().values().filter(|e| e.prefix == prefix).count()
    }

    pub fn active_count(&self) -> usize {
        self.active.lock().unwrap().len()
    }
}

/// When the peer aborted (RST), close our side the same way so plain-HTTP probes
/// cannot distinguish the tunnel from the decoy by FIN vs RST.
fn abort_with_rst<S: AsRef<TcpStream>>(sock: &S) {
    let _ = socket2::SockRef::from(sock.as_ref()).set_linger(Some(Duration::from_secs(0)));
}

fn is_reset(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
    )
}

/// Zero artificial timeout in normal mode; mirrors both half-close FIN directions 1:1.
/// Closes cleanly ONLY if `lease` is evicted under saturation.
pub async fn mirror_bidirectional(c: TcpStream, d: TcpStream, lease: &FallbackLease) {
    let (mut cr, mut cw) = c.into_split();
    let (mut dr, mut dw) = d.into_split();

    let c_to_d = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match cr.read(&mut buf).await {
                Ok(0) => {
                    let _ = dw.shutdown().await;
                    break;
                }
                Ok(n) => {
                    lease.touch();
                    if dw.write_all(&buf[..n]).await.is_err() {
                        let _ = dw.shutdown().await;
                        break;
                    }
                }
                Err(e) => {
                    if is_reset(&e) {
                        abort_with_rst(&dw);
                    } else {
                        let _ = dw.shutdown().await;
                    }
                    return true;
                }
            }
        }
        false
    };

    let d_to_c = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match dr.read(&mut buf).await {
                Ok(0) => {
                    let _ = cw.shutdown().await;
                    break;
                }
                Ok(n) => {
                    lease.touch();
                    if cw.write_all(&buf[..n]).await.is_err() {
                        let _ = cw.shutdown().await;
                        break;
                    }
                }
                Err(e) => {
                    if is_reset(&e) {
                        abort_with_rst(&cw);
                    } else {
                        let _ = cw.shutdown().await;
                    }
                    return true;
                }
            }
        }
        false
    };

    tokio::pin!(c_to_d);
    tokio::pin!(d_to_c);
    tokio::select! {
        rst = &mut c_to_d => {
            if !rst {
                tokio::select! {
                    _ = &mut d_to_c => {}
                    _ = lease.evicted() => {}
                }
            }
        }
        rst = &mut d_to_c => {
            if !rst {
                tokio::select! {
                    _ = &mut c_to_d => {}
                    _ = lease.evicted() => {}
                }
            }
        }
        _ = lease.evicted() => {}
    }
}
