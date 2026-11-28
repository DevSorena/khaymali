//! Create / tear down classic kernel tunnels via `ip` / `wg`.

use crate::system::{load_modules, modprobe, run_cmd, run_cmd_ok, run_cmd_quiet, Result};
use crate::config::MODULES;

pub struct TunnelDriver;

impl TunnelDriver {
    pub fn ensure_modules() {
        load_modules(MODULES);
    }

    pub fn cleanup_interface(dev: &str) {
        run_cmd_quiet(&["ip", "link", "del", "dev", dev]);
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
            "gre" | "eoip" => Self::setup_simple("gre", dev, local_bind, remote_ip, my_ip, peer_ip, mtu),
            "gretap" => Self::setup_simple("gretap", dev, local_bind, remote_ip, my_ip, peer_ip, mtu),
            "sit" => Self::setup_simple("sit", dev, local_bind, remote_ip, my_ip, peer_ip, mtu),
            "vxlan" => Self::setup_vxlan(dev, local_bind, remote_ip, my_ip, peer_ip, mtu, port.unwrap_or(4789)),
            "geneve" => Self::setup_geneve(dev, local_bind, remote_ip, my_ip, peer_ip, mtu, port.unwrap_or(6081)),
            "wireguard" => Self::setup_wireguard(dev, my_ip, mtu, port.unwrap_or(51820)),
            "l2tp" => Self::setup_l2tp(dev, local_bind, remote_ip, my_ip, peer_ip, mtu, port.unwrap_or(5000)),
            other => Err(format!("unsupported protocol: {other}").into()),
        }
    }

    fn setup_simple(
        kind: &str, dev: &str, local: &str, remote: &str, my_ip: &str, peer_ip: &str, mtu: u32,
    ) -> Result<()> {
        Self::cleanup_interface(dev);
        run_cmd(&["ip", "link", "add", "name", dev, "type", kind, "local", local, "remote", remote])?;
        if kind != "gretap" {
            run_cmd(&["ip", "addr", "add", &format!("{my_ip}/30"), "dev", dev])?;
        }
        run_cmd(&["ip", "link", "set", "dev", dev, "mtu", &mtu.to_string(), "up"])?;
        if kind != "gretap" {
            run_cmd_ok(&["ip", "route", "replace", &format!("{peer_ip}/32"), "dev", dev]);
        }
        Ok(())
    }

    fn setup_vxlan(
        dev: &str, local: &str, remote: &str, my_ip: &str, peer_ip: &str, mtu: u32, port: u16,
    ) -> Result<()> {
        Self::cleanup_interface(dev);
        let iface = crate::netinfo::default_iface().unwrap_or_else(|| "eth0".into());
        run_cmd(&[
            "ip", "link", "add", dev, "type", "vxlan",
            "id", "42", "local", local, "remote", remote,
            "dstport", &port.to_string(), "dev", &iface,
        ])?;
        run_cmd(&["ip", "addr", "add", &format!("{my_ip}/30"), "dev", dev])?;
        run_cmd(&["ip", "link", "set", "dev", dev, "mtu", &mtu.to_string(), "up"])?;
        run_cmd_ok(&["ip", "route", "replace", &format!("{peer_ip}/32"), "dev", dev]);
        Ok(())
    }

    fn setup_geneve(
        dev: &str, local: &str, remote: &str, my_ip: &str, peer_ip: &str, mtu: u32, port: u16,
    ) -> Result<()> {
        Self::cleanup_interface(dev);
        run_cmd(&[
            "ip", "link", "add", "name", dev, "type", "geneve",
            "id", "42", "remote", remote, "local", local, "dstport", &port.to_string(),
        ])?;
        run_cmd(&["ip", "addr", "add", &format!("{my_ip}/30"), "dev", dev])?;
        run_cmd(&["ip", "link", "set", "dev", dev, "mtu", &mtu.to_string(), "up"])?;
        run_cmd_ok(&["ip", "route", "replace", &format!("{peer_ip}/32"), "dev", dev]);
        Ok(())
    }

    fn setup_wireguard(dev: &str, my_ip: &str, mtu: u32, port: u16) -> Result<()> {
        modprobe("wireguard");
        Self::cleanup_interface(dev);
        run_cmd(&["ip", "link", "add", "dev", dev, "type", "wireguard"])?;
        run_cmd(&["ip", "addr", "add", &format!("{my_ip}/30"), "dev", dev])?;
        run_cmd(&["ip", "link", "set", "dev", dev, "mtu", &mtu.to_string(), "up"])?;
        let _ = port;
        Ok(())
    }

    fn setup_l2tp(
        dev: &str, local: &str, remote: &str, my_ip: &str, peer_ip: &str, mtu: u32, port: u16,
    ) -> Result<()> {
        Self::cleanup_interface(dev);
        run_cmd_quiet(&["ip", "l2tp", "del", "tunnel", "tunnel_id", "1"]);
        run_cmd(&[
            "ip", "l2tp", "add", "tunnel",
            "tunnel_id", "1", "peer_tunnel_id", "1",
            "encap", "udp", "local", local, "remote", remote,
            "udp_sport", &port.to_string(), "udp_dport", &port.to_string(),
        ])?;
        run_cmd(&[
            "ip", "l2tp", "add", "session",
            "tunnel_id", "1", "session_id", "1", "peer_session_id", "1", "name", dev,
        ])?;
        run_cmd(&["ip", "addr", "add", &format!("{my_ip}/30"), "dev", dev])?;
        run_cmd(&["ip", "link", "set", "dev", dev, "mtu", &mtu.to_string(), "up"])?;
        run_cmd_ok(&["ip", "route", "replace", &format!("{peer_ip}/32"), "dev", dev]);
        Ok(())
    }
}
