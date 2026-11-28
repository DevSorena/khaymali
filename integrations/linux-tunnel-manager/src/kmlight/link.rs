//! TUN ↔ UDP forwarding loop.

use super::config::KmLightConfig;
use super::frame::{Framer, HEADER_LEN};
use super::tun::TunDevice;
use crate::system::Result;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const MAX_PKT: usize = 65535;

pub struct Link {
    pub cfg: KmLightConfig,
    pub tun: TunDevice,
    pub fr: Framer,
    pub sock: UdpSocket,
    peer: Mutex<Option<SocketAddr>>,
}

impl Link {
    pub fn run(cfg: KmLightConfig) -> Result<()> {
        let fr = Framer::new(&cfg.secret);
        let tun = TunDevice::open(&cfg.tun_name)?;
        super::tun::bring_up(&cfg, &tun.name)?;
        eprintln!(
            "khaymali-light {}: interface {} is up ({}/{} mtu {}, role {})",
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
            let s = UdpSocket::bind(&addr)?;
            eprintln!("listening on {addr}");
            s
        } else {
            let remote: SocketAddr = cfg.remote.parse()?;
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
        let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));

        let link = Arc::new(Link {
            cfg,
            tun,
            fr,
            sock,
            peer: Mutex::new(None),
        });

        let l1 = Arc::clone(&link);
        thread::spawn(move || {
            if let Err(e) = tun_to_net(l1) {
                eprintln!("tun→net: {e}");
            }
        });

        let l2 = Arc::clone(&link);
        if l2.cfg.role == "client" && l2.cfg.keepalive > 0 {
            thread::spawn(move || keepalive_loop(l2));
        }

        net_to_tun(link)
    }
}

fn tun_to_net(link: Arc<Link>) -> Result<()> {
    let fd = link.tun.as_raw_fd();
    let mut buf = vec![0u8; HEADER_LEN + MAX_PKT];
    loop {
        let n = unsafe {
            libc::read(fd, buf[HEADER_LEN..].as_mut_ptr() as *mut _, MAX_PKT)
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if n == 0 {
            break;
        }
        let n = n as usize;
        if link.cfg.role == "server" && link.peer.lock().unwrap().is_none() {
            continue;
        }
        link.fr.stamp(&mut buf[..HEADER_LEN]);
        let pkt = &buf[..HEADER_LEN + n];
        if link.cfg.role == "client" {
            let _ = link.sock.send(pkt);
        } else if let Some(peer) = *link.peer.lock().unwrap() {
            let _ = link.sock.send_to(pkt, peer);
        }
    }
    Ok(())
}

fn net_to_tun(link: Arc<Link>) -> Result<()> {
    let mut buf = vec![0u8; HEADER_LEN + MAX_PKT];
    let fd = link.tun.as_raw_fd();
    loop {
        let (n, src) = match link.sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(e) => return Err(e.into()),
        };
        if !link.fr.valid(&buf[..n]) {
            continue;
        }
        if link.cfg.role == "server" {
            *link.peer.lock().unwrap() = Some(src);
        }
        if n == HEADER_LEN {
            continue;
        }
        let payload = &buf[HEADER_LEN..n];
        unsafe {
            libc::write(fd, payload.as_ptr() as *const _, payload.len());
        }
    }
}

fn keepalive_loop(link: Arc<Link>) {
    let mut hdr = [0u8; HEADER_LEN];
    loop {
        thread::sleep(Duration::from_secs(link.cfg.keepalive.max(1)));
        link.fr.stamp(&mut hdr);
        let _ = link.sock.send(&hdr);
    }
}
