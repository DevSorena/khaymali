//! Linux TUN (IFF_TUN | IFF_NO_PI).

use super::config::KmLightConfig;
use crate::sysrun;
use anyhow::{bail, Context, Result};
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;

#[repr(C)]
struct IfReq {
    name: [u8; 16],
    flags: i16,
    _pad: [u8; 22],
}

pub struct TunDevice {
    file: std::fs::File,
    pub name: String,
}

impl TunDevice {
    pub fn open(name: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .context("open /dev/net/tun")?;
        let mut req = IfReq {
            name: [0; 16],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        let nb = name.as_bytes();
        let n = nb.len().min(15);
        req.name[..n].copy_from_slice(&nb[..n]);
        let rc = unsafe {
            libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &mut req as *mut _ as *mut libc::c_void)
        };
        if rc < 0 {
            bail!("TUNSETIFF: {}", io::Error::last_os_error());
        }
        // Non-blocking TUN reads so the forwarder can park instead of blocking forever
        // when paired with a quiet peer (optional; ignored if fails).
        unsafe {
            let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
            if flags >= 0 {
                let _ = libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        let end = req.name.iter().position(|&b| b == 0).unwrap_or(16);
        let if_name = String::from_utf8_lossy(&req.name[..end]).into_owned();
        Ok(TunDevice { file, name: if_name })
    }

    pub fn as_raw_fd(&self) -> i32 {
        self.file.as_raw_fd()
    }
}

impl Read for TunDevice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}
impl Write for TunDevice {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

pub fn bring_up(cfg: &KmLightConfig, dev: &str) -> Result<()> {
    let _ = sysrun::run(&cmd(&["ip", "addr", "flush", "dev", dev]));
    let out = sysrun::run(&cmd(&[
        "ip", "addr", "add", &format!("{}/{}", cfg.tun_ip, cfg.prefix), "dev", dev,
    ]));
    if !out.ok {
        bail!("addr add: {}", out.stderr.trim());
    }
    // Clamp MTU to a fragmentation-safe range for UDP+header overhead (37 B stamp).
    let mtu = cfg.mtu.clamp(1280, 1400);
    let _ = sysrun::run(&cmd(&["ip", "link", "set", "dev", dev, "mtu", &mtu.to_string()]));
    let out = sysrun::run(&cmd(&["ip", "link", "set", "dev", dev, "up"]));
    if !out.ok {
        bail!("link up: {}", out.stderr.trim());
    }
    // Large txqueuelen absorbs userspace bursts before qdisc drops.
    let _ = sysrun::run(&cmd(&["ip", "link", "set", "dev", dev, "txqueuelen", "10000"]));
    let _ = sysrun::run(&cmd(&[
        "ip", "route", "replace", &format!("{}/32", cfg.peer_ip), "dev", dev, "src", &cfg.tun_ip,
    ]));
    let _ = sysrun::run(&cmd(&["sysctl", "-w", "net.ipv4.ip_forward=1"]));
    let _ = sysrun::run(&cmd(&["sysctl", "-w", &format!("net.ipv4.conf.{dev}.rp_filter=0")]));
    // Raise host UDP buffer caps so the 16MiB SO_*BUF requests can stick.
    let _ = sysrun::run(&cmd(&["sysctl", "-w", "net.core.rmem_max=16777216"]));
    let _ = sysrun::run(&cmd(&["sysctl", "-w", "net.core.wmem_max=16777216"]));
    let _ = sysrun::run(&cmd(&["sysctl", "-w", "net.core.rmem_default=1048576"]));
    let _ = sysrun::run(&cmd(&["sysctl", "-w", "net.core.wmem_default=1048576"]));
    Ok(())
}
