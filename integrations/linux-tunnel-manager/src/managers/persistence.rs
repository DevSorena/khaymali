use crate::config::{tunnels_file, ensure_state_dir, RESTORE_SERVICE, RESTORE_UNIT};
use crate::json_min;
use crate::system::{run_cmd, Result};
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

pub fn load_tunnels() -> Vec<SavedTunnel> {
    let Ok(data) = fs::read_to_string(tunnels_file()) else {
        return Vec::new();
    };
    // Minimal array parser: split objects
    let mut out = Vec::new();
    for chunk in data.split('{').skip(1) {
        let obj = format!("{{{chunk}");
        let g = |k: &str| json_min::get_str(&obj, k).unwrap_or("").to_string();
        if g("dev").is_empty() {
            continue;
        }
        out.push(SavedTunnel {
            proto: g("proto"),
            dev: g("dev"),
            local: g("local"),
            remote: g("remote"),
            my_ip: g("my_ip"),
            peer_ip: g("peer_ip"),
            mtu: json_min::get_u64(&obj, "mtu").unwrap_or(1400) as u32,
            port: json_min::get_u64(&obj, "port").map(|v| v as u16),
        });
    }
    out
}

pub fn save_tunnels(list: &[SavedTunnel]) -> Result<()> {
    ensure_state_dir()?;
    let mut parts = Vec::new();
    for t in list {
        let port = t.port.map(|p| p.to_string()).unwrap_or_else(|| "null".into());
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
        if let Err(e) = crate::protocols::drivers::TunnelDriver::setup(
            &t.proto, &t.dev, &t.local, &t.remote, &t.my_ip, &t.peer_ip, t.mtu, t.port,
        ) {
            eprintln!("[!] restore {}: {e}", t.dev);
        }
    }
    Ok(())
}

pub fn install_restore_service() -> Result<()> {
    let unit = "[Unit]\nDescription=Restore Khaymali Manager tunnels\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/khaymali-manager --restore\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n";
    fs::write(RESTORE_UNIT, unit)?;
    run_cmd(&["systemctl", "daemon-reload"])?;
    run_cmd(&["systemctl", "enable", RESTORE_SERVICE])?;
    println!("[+] {RESTORE_SERVICE} enabled.");
    Ok(())
}
