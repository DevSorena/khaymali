//! Persist and restore classic tunnels across reboots.

use super::config::{ensure_state_dir, tunnels_file, RESTORE_SERVICE, RESTORE_UNIT};
use super::drivers::TunnelDriver;
use crate::sysrun;
use anyhow::{Context, Result};
use std::fs;

#[derive(Debug, Clone)]
pub struct SavedTunnel {
    pub proto: String,
    pub dev: String,
    pub local: String,
    pub remote: String,
    pub my_ip: String,
    pub peer_ip: String,
    pub mtu: u32,
    pub port: Option<u16>,
}

fn get_str(obj: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let i = obj.find(&pat)?;
    let rest = obj[i + pat.len()..].trim_start();
    if !rest.starts_with(':') {
        return None;
    }
    let rest = rest[1..].trim_start();
    if rest.starts_with('"') {
        let rest = &rest[1..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    } else {
        let end = rest
            .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
            .unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

pub fn load_tunnels() -> Vec<SavedTunnel> {
    let Ok(data) = fs::read_to_string(tunnels_file()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for chunk in data.split('{').skip(1) {
        let obj = format!("{{{chunk}");
        let dev = get_str(&obj, "dev").unwrap_or_default();
        if dev.is_empty() {
            continue;
        }
        out.push(SavedTunnel {
            proto: get_str(&obj, "proto").unwrap_or_default(),
            dev,
            local: get_str(&obj, "local").unwrap_or_default(),
            remote: get_str(&obj, "remote").unwrap_or_default(),
            my_ip: get_str(&obj, "my_ip").unwrap_or_default(),
            peer_ip: get_str(&obj, "peer_ip").unwrap_or_default(),
            mtu: get_str(&obj, "mtu").and_then(|s| s.parse().ok()).unwrap_or(1400),
            port: get_str(&obj, "port").and_then(|s| {
                if s == "null" {
                    None
                } else {
                    s.parse().ok()
                }
            }),
        });
    }
    out
}

pub fn save_tunnels(list: &[SavedTunnel]) -> Result<()> {
    ensure_state_dir().context("create state dir")?;
    let mut parts = Vec::new();
    for t in list {
        let port = t
            .port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "null".into());
        parts.push(format!(
            "{{\"proto\":\"{}\",\"dev\":\"{}\",\"local\":\"{}\",\"remote\":\"{}\",\"my_ip\":\"{}\",\"peer_ip\":\"{}\",\"mtu\":{},\"port\":{}}}",
            t.proto, t.dev, t.local, t.remote, t.my_ip, t.peer_ip, t.mtu, port
        ));
    }
    fs::write(tunnels_file(), format!("[{}]", parts.join(",")))?;
    Ok(())
}

pub fn add_tunnel(t: SavedTunnel) -> Result<()> {
    let mut list = load_tunnels();
    list.retain(|x| x.dev != t.dev);
    list.push(t);
    save_tunnels(&list)
}

pub fn restore_all() -> Result<()> {
    for t in load_tunnels() {
        println!("[*] Restoring {} ({})", t.dev, t.proto);
        if let Err(e) = TunnelDriver::setup(
            &t.proto, &t.dev, &t.local, &t.remote, &t.my_ip, &t.peer_ip, t.mtu, t.port,
        ) {
            eprintln!("[!] restore {}: {e}", t.dev);
        }
    }
    Ok(())
}

pub fn install_restore_service() -> Result<()> {
    let unit = "\
[Unit]
Description=Restore Khaymali classic tunnels
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/khaymali tunnels-restore
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
";
    fs::write(RESTORE_UNIT, unit)?;
    let _ = sysrun::run(&["systemctl".into(), "daemon-reload".into()]);
    let out = sysrun::run(&["systemctl".into(), "enable".into(), RESTORE_SERVICE.into()]);
    if !out.ok {
        bail_svc(&out.stderr)?;
    }
    println!("[+] {RESTORE_SERVICE} enabled.");
    Ok(())
}

fn bail_svc(err: &str) -> Result<()> {
    anyhow::bail!("systemctl enable failed: {}", err.trim())
}
