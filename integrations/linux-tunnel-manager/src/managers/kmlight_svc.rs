use crate::config::{KMLIGHT_BIN, KMLIGHT_CONFIG, KMLIGHT_DIR, KMLIGHT_SERVICE, KMLIGHT_UNIT};
use crate::kmlight::config::KmLightConfig;
use crate::system::{run_cmd, run_cmd_ok, run_cmd_quiet, Result};
use std::fs;
use std::path::Path;

pub fn build_core() -> bool {
    if Path::new(KMLIGHT_BIN).exists() {
        return true;
    }
    if run_cmd_ok(&["which", "khaymali-light"]) {
        return true;
    }
    eprintln!("[!] khaymali-light not found. Build: cargo build --release --bin khaymali-light");
    false
}

pub fn save_config(cfg: &KmLightConfig) -> Result<()> {
    fs::create_dir_all(KMLIGHT_DIR)?;
    cfg.save(Path::new(KMLIGHT_CONFIG))?;
    Ok(())
}

pub fn install_service() -> Result<()> {
    let unit = format!(
        "[Unit]\nDescription=Khaymali Light tunnel\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={bin} --config {cfg}\nRestart=always\nRestartSec=2\nLimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n",
        bin = KMLIGHT_BIN,
        cfg = KMLIGHT_CONFIG,
    );
    fs::write(KMLIGHT_UNIT, unit)?;
    run_cmd(&["systemctl", "daemon-reload"])?;
    run_cmd(&["systemctl", "enable", "--now", KMLIGHT_SERVICE])?;
    println!("[+] {KMLIGHT_SERVICE} enabled and started.");
    Ok(())
}

pub fn service_status() {
    run_cmd_quiet(&["systemctl", "status", KMLIGHT_SERVICE, "--no-pager"]);
}

pub fn service_restart() {
    run_cmd_quiet(&["systemctl", "restart", KMLIGHT_SERVICE]);
}

pub fn service_stop() {
    run_cmd_quiet(&["systemctl", "stop", KMLIGHT_SERVICE]);
    run_cmd_quiet(&["systemctl", "disable", KMLIGHT_SERVICE]);
}

pub fn gen_secret() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("{:x}{:x}", t, t.wrapping_mul(0x9e37))
}
