use super::config::KmLightConfig;
use crate::ltm::config::{KMLIGHT_CONFIG, KMLIGHT_DIR, KMLIGHT_SERVICE, KMLIGHT_UNIT};
use crate::sysrun;
use anyhow::{bail, Result};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn save_config(cfg: &KmLightConfig) -> Result<()> {
    fs::create_dir_all(KMLIGHT_DIR)?;
    cfg.save(Path::new(KMLIGHT_CONFIG))?;
    Ok(())
}

pub fn install_service() -> Result<()> {
    // Prefer the main binary: `khaymali light --config ...`
    let bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "/usr/local/bin/khaymali".into());
    let unit = format!(
        "\
[Unit]
Description=Khaymali Light tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin} light --config {cfg}
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
",
        bin = bin,
        cfg = KMLIGHT_CONFIG,
    );
    fs::write(KMLIGHT_UNIT, unit)?;
    let _ = sysrun::run(&["systemctl".into(), "daemon-reload".into()]);
    let out = sysrun::run(&[
        "systemctl".into(),
        "enable".into(),
        "--now".into(),
        KMLIGHT_SERVICE.into(),
    ]);
    if !out.ok {
        bail!("enable service: {}", out.stderr.trim());
    }
    println!("[+] {KMLIGHT_SERVICE} enabled and started.");
    Ok(())
}

pub fn service_status() {
    let _ = sysrun::run(&[
        "systemctl".into(),
        "status".into(),
        KMLIGHT_SERVICE.into(),
        "--no-pager".into(),
    ]);
}

pub fn service_restart() {
    let _ = sysrun::run(&["systemctl".into(), "restart".into(), KMLIGHT_SERVICE.into()]);
}

pub fn service_stop() {
    let _ = sysrun::run(&["systemctl".into(), "stop".into(), KMLIGHT_SERVICE.into()]);
    let _ = sysrun::run(&["systemctl".into(), "disable".into(), KMLIGHT_SERVICE.into()]);
}

pub fn gen_secret() -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}{:x}", t, t.wrapping_mul(0x9e37))
}
