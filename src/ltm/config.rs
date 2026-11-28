//! Paths and constants for the integrated tunnel manager.

use std::path::{Path, PathBuf};

pub const SYNC_PORT: u16 = 9876;
pub const KMLIGHT_BENCH_PORT: u16 = 2096;
pub const KMLIGHT_DIR: &str = "/etc/khaymali-light";
pub const KMLIGHT_CONFIG: &str = "/etc/khaymali-light/config.json";
pub const KMLIGHT_SERVICE: &str = "khaymali-light";
pub const KMLIGHT_UNIT: &str = "/etc/systemd/system/khaymali-light.service";
pub const RESTORE_SERVICE: &str = "khaymali-tunnels-restore";
pub const RESTORE_UNIT: &str = "/etc/systemd/system/khaymali-tunnels-restore.service";

pub const MODULES: &[&str] = &[
    "ip_gre", "ip_tunnel", "gretap", "ipip", "tunnel4", "vxlan", "geneve",
    "sit", "l2tp_core", "l2tp_netlink", "l2tp_ip", "l2tp_eth", "wireguard",
];

pub fn state_dir() -> PathBuf {
    if Path::new("/etc").is_dir() {
        PathBuf::from("/etc/khaymali/tunnels")
    } else {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join(".khaymali/tunnels"))
            .unwrap_or_else(|| PathBuf::from("/tmp/khaymali-tunnels"))
    }
}

pub fn tunnels_file() -> PathBuf {
    state_dir().join("tunnels.json")
}

pub fn ensure_state_dir() -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir())
}
