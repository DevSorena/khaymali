//! Classic kernel tunnels via `ip` / `wg` (through sysrun).

use crate::sysrun;
use anyhow::{bail, Context, Result};
use super::config::MODULES;

fn cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

fn run(args: &[&str]) -> Result<()> {
    let out = sysrun::run(&cmd(args));
    if !out.ok {
        bail!("{}: {}", args.join(" "), out.stderr.trim());
    }
    Ok(())
}

fn run_ok(args: &[&str]) -> bool {
    sysrun::run(&cmd(args)).ok
}

fn stdout(args: &[&str]) -> Option<String> {
    let out = sysrun::run(&cmd(args));
    if out.ok {
        Some(out.stdout.trim().to_string())
    } else {
        None
    }
}

pub struct TunnelDriver;

impl TunnelDriver {
    pub fn ensure_modules() {
        for m in MODULES {
            let _ = sysrun::run(&cmd(&["modprobe", m]));
        }
    }

    pub fn cleanup_interface(dev: &str) {
        let _ = sysrun::run(&cmd(&["ip", "link", "del", "dev", dev]));
    }

    pub fn setup(
        proto: &str,
        dev: &str,
        local_bind: &str,
        remote_ip: &str,
        my_ip: &str,
        peer_ip: &str,
        mtu: u32,
        port: Option<u16>,
    ) -> Result<()> {
        Self::ensure_modules();
        match proto {
            "ipip" => Self::setup_simple("ipip", dev, local_bind, remote_ip, my_ip, peer_ip, mtu),
            "gre" => Self::setup_simple("gre", dev, local_bind, remote_ip, my_ip, peer_ip, mtu),
            "gretap" => Self::setup_simple("gretap", dev, local_bind, remote_ip, my_ip, peer_ip, mtu),
            "sit" => Self::setup_simple("sit", dev, local_bind, remote_ip, my_ip, peer_ip, mtu),
            "vxlan" => Self::setup_vxlan(dev, local_bind, remote_ip, my_ip, peer_ip, mtu, port.unwrap_or(4789)),
            "geneve" => Self::setup_geneve(dev, local_bind, remote_ip, my_ip, peer_ip, mtu, port.unwrap_or(6081)),
            "wireguard" => Self::setup_wireguard(dev, my_ip, mtu),
            "l2tp" => Self::setup_l2tp(dev, local_bind, remote_ip, my_ip, peer_ip, mtu, port.unwrap_or(5000)),
            other => bail!("unsupported protocol: {other}"),
        }
    }

    fn setup_simple(
        kind: &str, dev: &str, local: &str, remote: &str, my_ip: &str, peer_ip: &str, mtu: u32,
    ) -> Result<()> {
        Self::cleanup_interface(dev);
        run(&["ip", "link", "add", "name", dev, "type", kind, "local", local, "remote", remote])
            .with_context(|| format!("create {kind} {dev}"))?;
        if kind != "gretap" {
            run(&["ip", "addr", "add", &format!("{my_ip}/30"), "dev", dev])?;
        }
        run(&["ip", "link", "set", "dev", dev, "mtu", &mtu.to_string(), "up"])?;
        if kind != "gretap" {
            let _ = run_ok(&["ip", "route", "replace", &format!("{peer_ip}/32"), "dev", dev]);
        }
        Ok(())
    }

    fn setup_vxlan(
        dev: &str, local: &str, remote: &str, my_ip: &str, peer_ip: &str, mtu: u32, port: u16,
    ) -> Result<()> {
        Self::cleanup_interface(dev);
        let iface = default_iface().unwrap_or_else(|| "eth0".into());
        run(&[
            "ip", "link", "add", dev, "type", "vxlan",
            "id", "42", "local", local, "remote", remote,
            "dstport", &port.to_string(), "dev", &iface,
        ])?;
        run(&["ip", "addr", "add", &format!("{my_ip}/30"), "dev", dev])?;
        run(&["ip", "link", "set", "dev", dev, "mtu", &mtu.to_string(), "up"])?;
        let _ = run_ok(&["ip", "route", "replace", &format!("{peer_ip}/32"), "dev", dev]);
        Ok(())
    }

    fn setup_geneve(
        dev: &str, local: &str, remote: &str, my_ip: &str, peer_ip: &str, mtu: u32, port: u16,
    ) -> Result<()> {
        Self::cleanup_interface(dev);
        run(&[
            "ip", "link", "add", "name", dev, "type", "geneve",
            "id", "42", "remote", remote, "local", local, "dstport", &port.to_string(),
        ])?;
        run(&["ip", "addr", "add", &format!("{my_ip}/30"), "dev", dev])?;
        run(&["ip", "link", "set", "dev", dev, "mtu", &mtu.to_string(), "up"])?;
        let _ = run_ok(&["ip", "route", "replace", &format!("{peer_ip}/32"), "dev", dev]);
        Ok(())
    }

    fn setup_wireguard(dev: &str, my_ip: &str, mtu: u32) -> Result<()> {
        let _ = run_ok(&["modprobe", "wireguard"]);
        Self::cleanup_interface(dev);
        run(&["ip", "link", "add", "dev", dev, "type", "wireguard"])?;
        run(&["ip", "addr", "add", &format!("{my_ip}/30"), "dev", dev])?;
        run(&["ip", "link", "set", "dev", dev, "mtu", &mtu.to_string(), "up"])?;
        Ok(())
    }

    fn setup_l2tp(
        dev: &str, local: &str, remote: &str, my_ip: &str, peer_ip: &str, mtu: u32, port: u16,
    ) -> Result<()> {
        Self::cleanup_interface(dev);
        let _ = run_ok(&["ip", "l2tp", "del", "tunnel", "tunnel_id", "1"]);
        run(&[
            "ip", "l2tp", "add", "tunnel",
            "tunnel_id", "1", "peer_tunnel_id", "1",
            "encap", "udp", "local", local, "remote", remote,
            "udp_sport", &port.to_string(), "udp_dport", &port.to_string(),
        ])?;
        run(&[
            "ip", "l2tp", "add", "session",
            "tunnel_id", "1", "session_id", "1", "peer_session_id", "1", "name", dev,
        ])?;
        run(&["ip", "addr", "add", &format!("{my_ip}/30"), "dev", dev])?;
        run(&["ip", "link", "set", "dev", dev, "mtu", &mtu.to_string(), "up"])?;
        let _ = run_ok(&["ip", "route", "replace", &format!("{peer_ip}/32"), "dev", dev]);
        Ok(())
    }
}

fn default_iface() -> Option<String> {
    stdout(&["ip", "route", "show", "default"]).and_then(|s| {
        s.split_whitespace().skip_while(|t| *t != "dev").nth(1).map(|s| s.to_string())
    })
}

pub fn primary_ip() -> Option<String> {
    let iface = default_iface()?;
    stdout(&["ip", "-4", "-o", "addr", "show", "dev", &iface]).and_then(|s| {
        s.split_whitespace()
            .find(|t| t.contains('/'))
            .map(|t| t.split('/').next().unwrap_or(t).to_string())
    })
}
