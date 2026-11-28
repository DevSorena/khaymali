//! Linux TUN device (IFF_TUN | IFF_NO_PI).

use crate::system::{run_cmd, run_cmd_quiet, Result};
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
            .open("/dev/net/tun")?;

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
            return Err(format!("TUNSETIFF failed: {}", io::Error::last_os_error()).into());
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

pub fn bring_up(cfg: &super::config::KmLightConfig, dev: &str) -> Result<()> {
    let _ = run_cmd(&["ip", "addr", "flush", "dev", dev]);
    run_cmd(&[
        "ip", "addr", "add",
        &format!("{}/{}", cfg.tun_ip, cfg.prefix),
        "dev", dev,
    ])?;
    run_cmd(&["ip", "link", "set", "dev", dev, "mtu", &cfg.mtu.to_string()])?;
    run_cmd(&["ip", "link", "set", "dev", dev, "up"])?;
    run_cmd_quiet(&["ip", "link", "set", "dev", dev, "txqueuelen", "10000"]);
    run_cmd_quiet(&[
        "ip", "route", "replace",
        &format!("{}/32", cfg.peer_ip),
        "dev", dev, "src", &cfg.tun_ip,
    ]);
    run_cmd_quiet(&["sysctl", "-w", "net.ipv4.ip_forward=1"]);
    run_cmd_quiet(&["sysctl", "-w", &format!("net.ipv4.conf.{dev}.rp_filter=0")]);
    Ok(())
}
