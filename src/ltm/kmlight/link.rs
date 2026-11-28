//! TUN ↔ UDP forwarding — performance-oriented hot path.
//!
//! Design goals (parity with the old Go light tunnel + main Khaymali habits):
//!   * 16 MiB UDP socket buffers so bursts are not silently dropped
//!   * No per-packet heap allocation
//!   * Peer address published once (Atomic) — no Mutex on the data path
//!   * Non-blocking I/O with short parks instead of 1s read timeouts
//!   * Header stamp is a flat memcpy + 2-byte tag (already cheap)

use super::config::KmLightConfig;
use super::frame::{Framer, HEADER_LEN};
use super::tun::TunDevice;
use anyhow::{Context, Result};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Outer UDP payload budget. Inner MTU is cfg.mtu; we only need a little headroom.
const MAX_PKT: usize = 2048;
const SOCK_BUF: usize = 16 * 1024 * 1024;

pub struct Link {
    pub cfg: KmLightConfig,
    pub tun: TunDevice,
    pub fr: Framer,
    pub sock: UdpSocket,
    /// Packed SocketAddr bits for the learned server-side peer (0 = none).
    /// Layout: high 32 = IPv4 octets, low 32 = port << 16 | family marker.
    peer_v4: AtomicU64,
    peer_set: AtomicBool,
}

impl Link {
    pub fn run(cfg: KmLightConfig) -> Result<()> {
        let fr = Framer::new(&cfg.secret);
        let tun = TunDevice::open(&cfg.tun_name)?;
        super::tun::bring_up(&cfg, &tun.name)?;
        eprintln!(
            "khaymali-light {}: interface {} up ({}/{} mtu {} role {})",
            env!("CARGO_PKG_VERSION"),
            tun.name,
            cfg.tun_ip,
            cfg.prefix,
            cfg.mtu,
            cfg.role
        );

        let sock = if cfg.role == "server" {
            let addr = if cfg.listen.is_empty() {
                "0.0.0.0:2096".to_string()
            } else {
                cfg.listen.clone()
            };
            let s = UdpSocket::bind(&addr).with_context(|| format!("bind {addr}"))?;
            eprintln!("listening on {addr}");
            s
        } else {
            let remote: SocketAddr = cfg.remote.parse().context("parse remote")?;
            let s = if !cfg.local.is_empty() {
                let local: SocketAddr = format!("{}:0", cfg.local).parse()?;
                let s = UdpSocket::bind(local)?;
                s.connect(remote)?;
                s
            } else {
                let s = UdpSocket::bind("0.0.0.0:0")?;
                s.connect(remote)?;
                s
            };
            eprintln!("target {}", cfg.remote);
            s
        };

        tune_socket(&sock)?;
        // Non-blocking: hot loops park briefly on EAGAIN instead of 1s timeout latency.
        sock.set_nonblocking(true)?;

        let link = Arc::new(Link {
            cfg,
            tun,
            fr,
            sock,
            peer_v4: AtomicU64::new(0),
            peer_set: AtomicBool::new(false),
        });

        let l1 = Arc::clone(&link);
        thread::Builder::new()
            .name("kmlight-tun2net".into())
            .spawn(move || {
                if let Err(e) = tun_to_net(l1) {
                    eprintln!("tun→net: {e}");
                }
            })?;

        let l2 = Arc::clone(&link);
        if l2.cfg.role == "client" && l2.cfg.keepalive > 0 {
            thread::Builder::new()
                .name("kmlight-ka".into())
                .spawn(move || keepalive_loop(l2))?;
        }

        net_to_tun(link)
    }

    fn set_peer_v4(&self, addr: SocketAddr) {
        if let SocketAddr::V4(v4) = addr {
            let ip = u32::from(*v4.ip());
            let packed = ((ip as u64) << 32) | (v4.port() as u64);
            self.peer_v4.store(packed, Ordering::Release);
            self.peer_set.store(true, Ordering::Release);
        }
    }

    fn get_peer_v4(&self) -> Option<SocketAddr> {
        if !self.peer_set.load(Ordering::Acquire) {
            return None;
        }
        let packed = self.peer_v4.load(Ordering::Acquire);
        let ip = Ipv4Addr::from(((packed >> 32) as u32).to_be_bytes());
        let port = (packed & 0xffff) as u16;
        Some(SocketAddr::from((ip, port)))
    }
}

use std::net::Ipv4Addr;

fn tune_socket(sock: &UdpSocket) -> Result<()> {
    let _ = sock.set_read_timeout(None);
    let _ = sock.set_write_timeout(None);
    // Best-effort large buffers (kernel may clamp to net.core.rmem_max / wmem_max).
    let fd = sock.as_raw_fd();
    unsafe {
        let buf = SOCK_BUF as libc::c_int;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &buf as *const _ as *const _,
            std::mem::size_of_val(&buf) as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &buf as *const _ as *const _,
            std::mem::size_of_val(&buf) as libc::socklen_t,
        );
        // Double-request so Linux allows up to 2x (common pattern for raising effective size).
        let buf2 = (SOCK_BUF * 2) as libc::c_int;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &buf2 as *const _ as *const _,
            std::mem::size_of_val(&buf2) as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &buf2 as *const _ as *const _,
            std::mem::size_of_val(&buf2) as libc::socklen_t,
        );
    }
    Ok(())
}

fn park_brief() {
    thread::sleep(Duration::from_micros(50));
}

fn tun_to_net(link: Arc<Link>) -> Result<()> {
    let fd = link.tun.as_raw_fd();
    let mut buf = vec![0u8; HEADER_LEN + MAX_PKT];
    // Cap read to configured MTU so we never oversize outer datagrams needlessly.
    let max_inner = (link.cfg.mtu as usize).min(MAX_PKT);
    loop {
        let n = unsafe { libc::read(fd, buf[HEADER_LEN..].as_mut_ptr() as *mut _, max_inner) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == std::io::ErrorKind::WouldBlock {
                park_brief();
                continue;
            }
            break;
        }
        if n == 0 {
            break;
        }
        let n = n as usize;
        if link.cfg.role == "server" && !link.peer_set.load(Ordering::Acquire) {
            continue;
        }
        link.fr.stamp(&mut buf[..HEADER_LEN]);
        let pkt = &buf[..HEADER_LEN + n];
        if link.cfg.role == "client" {
            match link.sock.send(pkt) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => park_brief(),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    eprintln!("udp send: {e}");
                    park_brief();
                }
            }
        } else if let Some(peer) = link.get_peer_v4() {
            match link.sock.send_to(pkt, peer) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => park_brief(),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    eprintln!("udp send_to: {e}");
                    park_brief();
                }
            }
        }
    }
    Ok(())
}

fn net_to_tun(link: Arc<Link>) -> Result<()> {
    let mut buf = vec![0u8; HEADER_LEN + MAX_PKT];
    let fd = link.tun.as_raw_fd();
    loop {
        let res = link.sock.recv_from(&mut buf);
        let (n, src) = match res {
            Ok(v) => v,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                park_brief();
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if !link.fr.valid(&buf[..n]) {
            continue;
        }
        if link.cfg.role == "server" {
            // Learn / refresh peer without locking the hot path.
            link.set_peer_v4(src);
        }
        if n == HEADER_LEN {
            continue; // keepalive
        }
        let payload = &buf[HEADER_LEN..n];
        let w = unsafe { libc::write(fd, payload.as_ptr() as *const _, payload.len()) };
        if w < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                eprintln!("tun write: {err}");
            }
        }
    }
}

fn keepalive_loop(link: Arc<Link>) {
    let mut hdr = [0u8; HEADER_LEN];
    let period = Duration::from_secs(link.cfg.keepalive.max(1));
    loop {
        thread::sleep(period);
        link.fr.stamp(&mut hdr);
        let _ = link.sock.send(&hdr);
    }
}
