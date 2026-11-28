//! Root checks and command runners (std only).

use std::io;
use std::process::{Command, Stdio};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub fn check_root() -> Result<()> {
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        return Err("Root privileges required. Run with sudo.".into());
    }
    Ok(())
}

pub fn run_cmd(args: &[&str]) -> Result<String> {
    let out = Command::new(args[0])
        .args(&args[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("{} failed: {}", args.join(" "), err.trim()).into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn run_cmd_ok(args: &[&str]) -> bool {
    run_cmd(args).is_ok()
}

pub fn run_cmd_quiet(args: &[&str]) {
    let _ = Command::new(args[0])
        .args(&args[1..])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub fn have(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn modprobe(module: &str) {
    run_cmd_quiet(&["modprobe", module]);
}

pub fn load_modules(modules: &[&str]) {
    for m in modules {
        modprobe(m);
    }
}

pub fn install_deps() {
    println!("[*] Checking common tools...");
    if have("apt-get") {
        run_cmd_quiet(&[
            "apt-get", "install", "-y", "-qq",
            "iproute2", "iptables", "iperf3", "wireguard-tools",
        ]);
    } else if have("dnf") {
        run_cmd_quiet(&["dnf", "install", "-y", "-q", "iproute", "iptables", "iperf3", "wireguard-tools"]);
    }
    println!("[+] Done.");
}

pub fn optimize_sysctl() {
    println!("[*] Applying network sysctl tuning...");
    let settings = [
        ("net.core.rmem_max", "16777216"),
        ("net.core.wmem_max", "16777216"),
        ("net.ipv4.tcp_congestion_control", "bbr"),
        ("net.ipv4.ip_forward", "1"),
    ];
    for (k, v) in settings {
        run_cmd_quiet(&["sysctl", "-w", &format!("{k}={v}")]);
    }
    println!("[+] Sysctl applied.");
}

pub fn io_err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.into())
}
