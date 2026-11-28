//! Shared constants and on-disk state locations.

use std::path::{Path, PathBuf};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const SYNC_PORT: u16 = 9876;
pub const STREAM_PORT: u16 = 5201;
pub const TEST_DURATION: u64 = 5;
pub const SUBNET_LOCAL: &str = "10.99.1.1";
pub const SUBNET_REMOTE: &str = "10.99.1.2";

pub const INSTALL_DIR: &str = "/opt/khaymali-manager";

pub const KMLIGHT_BIN: &str = "/usr/local/bin/khaymali-light";
pub const KMLIGHT_DIR: &str = "/etc/khaymali-light";
pub const KMLIGHT_CONFIG: &str = "/etc/khaymali-light/config.json";
pub const KMLIGHT_SERVICE: &str = "khaymali-light";
pub const KMLIGHT_UNIT: &str = "/etc/systemd/system/khaymali-light.service";
pub const KMLIGHT_BENCH_PORT: u16 = 2096;

pub const RESTORE_SERVICE: &str = "ltm-restore";
pub const RESTORE_UNIT: &str = "/etc/systemd/system/ltm-restore.service";

pub const MODULES: &[&str] = &[
    "ip_gre", "ip_tunnel", "gretap", "ipip", "tunnel4", "vxlan", "geneve",
    "sit", "l2tp_core", "l2tp_netlink", "l2tp_ip", "l2tp_eth", "wireguard",
];

pub fn state_dir() -> PathBuf {
    if Path::new("/etc").is_dir() {
        PathBuf::from("/etc/khaymali-manager")
    } else {
        dirs_fallback()
    }
}

fn dirs_fallback() -> PathBuf {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".ltm"))
        .unwrap_or_else(|| PathBuf::from("/tmp/ltm"))
}

pub fn tunnels_file() -> PathBuf {
    state_dir().join("tunnels.json")
}

pub fn port_fwd_file() -> PathBuf {
    state_dir().join("port_forward.json")
}

pub fn ensure_state_dir() -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir())
}
