//! UDP relay over a link (SOCKS5 UDP ASSOCIATE + L4 UDP Forward) with strict anti-SSRF,
//! anti-DNS-rebinding, client-IP isolation, dual-stack IPv4/IPv6 support, bounded TTL DNS cache,
//! and zero-allocation hot-path buffers (SPEC §4.1).

use crate::link::{Link, CHUNK};
use crate::stats;
use crate::util::*;
use anyhow::Result;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::sleep;

const IDLE: Duration = Duration::from_secs(120);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

struct Activity {
    base: Instant,
    last: AtomicU64,
}

impl Activity {
    fn new() -> Arc<Activity> {
        Arc::new(Activity { base: Instant::now(), last: AtomicU64::new(0) })
    }
    fn touch(&self) {
        self.last.store(self.base.elapsed().as_secs(), Relaxed);
    }
    async fn idle(&self) {
        loop {
            sleep(Duration::from_secs(10)).await;
            if self.base.elapsed().as_secs().saturating_sub(self.last.load(Relaxed)) > IDLE.as_secs() {
                return;
            }
        }
    }
}

struct AssocGuard;
impl AssocGuard {
    fn new() -> AssocGuard {
        stats::UDP_ASSOC.fetch_add(1, Relaxed);
        AssocGuard
    }
}
impl Drop for AssocGuard {
    fn drop(&mut self) {
        stats::UDP_ASSOC.fetch_sub(1, Relaxed);
    }
}

fn encode_sockaddr_into(sa: SocketAddr, out: &mut Vec<u8>) {
    out.clear();
    match sa.ip() {
        IpAddr::V4(a) => {
            out.push(1);
            out.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            out.push(4);
            out.extend_from_slice(&a.octets());
        }
    }
    out.extend_from_slice(&sa.port().to_be_bytes());
}

/// Bind an IPv6-only UDP socket (`IPV6_V6ONLY = true`) for dual-stack Exit UDP relay.
pub fn bind_udp_v6_only() -> Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_only_v6(true)?;
    sock.set_nonblocking(true)?;
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    sock.bind(&SockAddr::from(addr))?;
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(UdpSocket::from_std(std_sock)?)
}

/// Resolve and validate UDP destination atomically (anti-SSRF + anti-DNS-rebinding).
/// Supports both IPv4 and IPv6 public targets (preferring IPv4 when both exist).
pub async fn resolve_udp_target(host: &str, port: u16, allow_private: bool) -> Option<SocketAddr> {
    let addrs = resolve_validated(host, port, allow_private, DNS_TIMEOUT).await.ok()?;
    if let Some(v4) = addrs.iter().find(|a| a.is_ipv4()) {
        return Some(*v4);
    }
    addrs.into_iter().next()
}

pub async fn entry_relay(sock: UdpSocket, link: Link, mut control: TcpStream, client_ip: IpAddr) -> Result<()> {
    let _g = AssocGuard::new();
    let sock = Arc::new(sock);
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let act = Activity::new();
    let (mut lr, mut lw) = link.split();

    let up = {
        let (sock, client, act) = (sock.clone(), client.clone(), act.clone());
        async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, src) = sock.recv_from(&mut buf).await?;
                // Strict client-IP isolation: drop datagrams from any other sender
                if src.ip() != client_ip || n < 4 || buf[2] != 0 {
                    continue;
                }
                *client.lock().unwrap() = Some(src);
                let msg = &buf[3..n];
                if addr_len(msg).is_none() || msg.len() > CHUNK {
                    continue;
                }
                act.touch();
                stats::BYTES_UP.fetch_add(msg.len() as u64, Relaxed);
                lw.send(msg).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };
    let down = {
        let (sock, client, act) = (sock.clone(), client.clone(), act.clone());
        async move {
            let mut plain = vec![0u8; CHUNK + 64];
            let mut out = Vec::with_capacity(3 + CHUNK);
            loop {
                let n = lr.recv_into(&mut plain).await?;
                if n == 0 {
                    return Ok::<(), anyhow::Error>(());
                }
                let dst = *client.lock().unwrap();
                if let Some(dst) = dst {
                    out.clear();
                    out.extend_from_slice(&[0, 0, 0]);
                    out.extend_from_slice(&plain[..n]);
                    act.touch();
                    stats::BYTES_DOWN.fetch_add(n as u64, Relaxed);
                    let _ = sock.send_to(&out, dst).await;
                }
            }
        }
    };
    let watch = async move {
        let mut b = [0u8; 64];
        while control.read(&mut b).await.map(|n| n > 0).unwrap_or(false) {}
    };
    tokio::select! {
        r = up => r,
        r = down => r,
        _ = watch => Ok(()),
        _ = act.idle() => Ok(()),
    }
}

pub async fn exit_relay(link: Link, sock: UdpSocket, allow_private: bool) -> Result<()> {
    exit_relay_dual(link, sock, None, allow_private).await
}

pub async fn exit_relay_dual(
    link: Link,
    sock_v4: UdpSocket,
    sock_v6: Option<UdpSocket>,
    allow_private: bool,
) -> Result<()> {
    let _g = AssocGuard::new();
    let sock_v4 = Arc::new(sock_v4);
    let sock_v6 = sock_v6.map(Arc::new);
    let act = Activity::new();
    let (mut lr, mut lw) = link.split();

    let up = {
        let (sock_v4, sock_v6, act) = (sock_v4.clone(), sock_v6.clone(), act.clone());
        async move {
            let mut cache: HashMap<(String, u16), (SocketAddr, Instant)> = HashMap::new();
            let mut plain = vec![0u8; CHUNK + 64];
            loop {
                let mlen = lr.recv_into(&mut plain).await?;
                if mlen == 0 {
                    return Ok::<(), anyhow::Error>(());
                }
                let m = &plain[..mlen];
                let Ok((host, port, n)) = parse_addr(m) else { continue };
                let key = (host, port);
                let now = Instant::now();
                let cached = cache
                    .get(&key)
                    .filter(|(_, ts)| now.saturating_duration_since(*ts) < DNS_CACHE_TTL)
                    .map(|(sa, _)| *sa);
                let sa = match cached {
                    Some(sa) => sa,
                    None => {
                        let Some(sa) = resolve_udp_target(&key.0, key.1, allow_private).await else {
                            continue;
                        };
                        if cache.len() >= 256 {
                            cache.retain(|_, (_, ts)| now.saturating_duration_since(*ts) < DNS_CACHE_TTL);
                            if cache.len() >= 256 {
                                cache.clear();
                            }
                        }
                        cache.insert(key.clone(), (sa, now));
                        sa
                    }
                };
                if !allow_private && is_private(sa.ip()) {
                    continue;
                }
                act.touch();
                if sa.is_ipv4() {
                    let _ = sock_v4.send_to(&m[n..], sa).await;
                } else if let Some(ref s6) = sock_v6 {
                    let _ = s6.send_to(&m[n..], sa).await;
                }
            }
        }
    };

    let down = {
        let (sock_v4, sock_v6, act) = (sock_v4.clone(), sock_v6.clone(), act.clone());
        async move {
            let mut buf4 = vec![0u8; 65536];
            let mut buf6 = vec![0u8; 65536];
            let mut msg = Vec::with_capacity(CHUNK);
            loop {
                let (n, src, is_v6) = if let Some(ref s6) = sock_v6 {
                    tokio::select! {
                        r = sock_v4.recv_from(&mut buf4) => {
                            let (n, src) = r?;
                            (n, src, false)
                        }
                        r = s6.recv_from(&mut buf6) => {
                            let (n, src) = r?;
                            (n, src, true)
                        }
                    }
                } else {
                    let (n, src) = sock_v4.recv_from(&mut buf4).await?;
                    (n, src, false)
                };
                encode_sockaddr_into(src, &mut msg);
                let payload = if is_v6 { &buf6[..n] } else { &buf4[..n] };
                if msg.len() + payload.len() > CHUNK {
                    continue;
                }
                msg.extend_from_slice(payload);
                act.touch();
                lw.send(&msg).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };

    tokio::select! {
        r = up => r,
        r = down => r,
        _ = act.idle() => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn neg_udp_ssrf_targets_blocked() {
        for h in [
            "127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254",
            "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.5", "64:ff9b::10.0.0.1",
            "fc00::1", "fe80::1", "ff02::1",
        ] {
            assert!(resolve_udp_target(h, 53, false).await.is_none(), "UDP target {h} must be blocked");
        }
        assert!(resolve_udp_target("1.1.1.1", 53, false).await.is_some());
        assert!(resolve_udp_target("2606:4700:4700::1111", 53, false).await.is_some());
        assert!(resolve_udp_target("127.0.0.1", 53, true).await.is_some());
    }
}
