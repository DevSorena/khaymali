//! SSH Port-Forward Engine & Bagher Restricted Key Lock (`src/sshfwd.rs`).
//!
//! Full Rust port of Khaymali's `sshfwd.go`:
//!   * `SshFwdConfig` persistence (`sshfwd.json`) supporting direct SSH reverse/local
//!     forwarding (`-R`/`-L`) and Bagher SSH carrier modes.
//!   * Restricted `authorized_keys` lock (`command="/bin/false",restrict,port-forwarding`
//!     plus per-port `permitopen="127.0.0.1:P"`) and `upgrade_bagher_key_locks`.
//!   * Hardened OpenSSH systemd units (`ServerAliveInterval=15`, `ServerAliveCountMax=3`,
//!     `ExitOnForwardFailure=yes`, `BatchMode=yes`, `StrictHostKeyChecking=accept-new`).
//!   * Companion `frps` config generator when SSH wraps FRP control/data.

use crate::hjson::{self, Json};
use crate::sysrun;
use anyhow::{bail, Result};

pub const BAGHER_KEY_LOCK: &str = r#"command="/bin/false",restrict,port-forwarding"#;

#[derive(Clone, Debug)]
pub struct SshFwdConfig {
    pub enabled: bool,
    pub mode: String, // "direct" | "reverse" | "bagher-frp"
    pub remote_host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub key_path: String,
    pub frp_port: u16,
    pub ports: Vec<u16>,
    pub compression: bool,
}

impl Default for SshFwdConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "reverse".into(),
            remote_host: String::new(),
            ssh_port: 22,
            ssh_user: "root".into(),
            key_path: "/etc/khaymali/sshfwd_ed25519".into(),
            frp_port: 7000,
            ports: Vec::new(),
            compression: false,
        }
    }
}

impl SshFwdConfig {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.mode.as_str(), "direct" | "reverse" | "bagher-frp") {
            bail!("invalid sshfwd mode '{}' (expected direct|reverse|bagher-frp)", self.mode);
        }
        if self.remote_host.trim().is_empty() {
            bail!("sshfwd remote_host is required");
        }
        if self.ssh_port == 0 {
            bail!("sshfwd ssh_port must be > 0");
        }
        if self.ports.is_empty() && self.mode != "bagher-frp" {
            bail!("sshfwd requires at least one forwarded port");
        }
        Ok(())
    }

    pub fn to_json(&self) -> Json {
        Json::obj()
            .set("enabled", self.enabled)
            .set("mode", self.mode.clone())
            .set("remote_host", self.remote_host.clone())
            .set("ssh_port", self.ssh_port)
            .set("ssh_user", self.ssh_user.clone())
            .set("key_path", self.key_path.clone())
            .set("frp_port", self.frp_port)
            .set("ports", self.ports.clone())
            .set("compression", self.compression)
    }

    pub fn from_json(j: &Json) -> Self {
        let mut c = Self::default();
        c.enabled = j.bool_of("enabled");
        let m = j.str_of("mode");
        if !m.is_empty() {
            c.mode = m;
        }
        c.remote_host = j.str_of("remote_host");
        if j.u64_of("ssh_port") > 0 {
            c.ssh_port = j.u64_of("ssh_port") as u16;
        }
        let u = j.str_of("ssh_user");
        if !u.is_empty() {
            c.ssh_user = u;
        }
        let k = j.str_of("key_path");
        if !k.is_empty() {
            c.key_path = k;
        }
        if j.u64_of("frp_port") > 0 {
            c.frp_port = j.u64_of("frp_port") as u16;
        }
        c.ports = j
            .arr_of("ports")
            .into_iter()
            .filter_map(|v| v.as_f64().map(|n| n as u16))
            .filter(|&p| p > 0)
            .collect();
        c.compression = j.bool_of("compression");
        c
    }

    pub fn save(&self, path: &str) -> Result<()> {
        hjson::write_atomic(path, self.to_json().to_string_pretty().as_bytes())
    }

    pub fn load(path: &str) -> Result<Option<Self>> {
        Ok(hjson::read_json_file(path)?.map(|j| Self::from_json(&j)))
    }

    /// Renders the systemd unit for `ssh-fwd.service`.
    pub fn render_service_unit(&self) -> Result<String> {
        self.validate()?;
        let mut args = vec![
            "/usr/bin/ssh".to_string(),
            "-N".into(),
            "-T".into(),
            "-i".into(),
            self.key_path.clone(),
            "-p".into(),
            self.ssh_port.to_string(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            "ServerAliveInterval=15".into(),
            "-o".into(),
            "ServerAliveCountMax=3".into(),
            "-o".into(),
            "ExitOnForwardFailure=yes".into(),
            "-o".into(),
            "TCPKeepAlive=yes".into(),
        ];
        if self.compression {
            args.push("-C".into());
        }
        match self.mode.as_str() {
            "direct" => {
                for &p in &self.ports {
                    args.push("-L".into());
                    args.push(format!("0.0.0.0:{p}:127.0.0.1:{p}"));
                }
            }
            "reverse" => {
                for &p in &self.ports {
                    args.push("-R".into());
                    args.push(format!("0.0.0.0:{p}:127.0.0.1:{p}"));
                }
            }
            "bagher-frp" => {
                args.push("-L".into());
                args.push(format!("127.0.0.1:{}:127.0.0.1:{}", self.frp_port, self.frp_port));
            }
            _ => {}
        }
        args.push(format!("{}@{}", self.ssh_user, self.remote_host));

        Ok(format!(
            "[Unit]\nDescription=Khaymali SSH Port Forward ({})\nAfter=network-online.target\nWants=network-online.target\n\n\
[Service]\nType=simple\nExecStart={}\nRestart=always\nRestartSec=3\nLimitNOFILE=65535\n\n\
[Install]\nWantedBy=multi-user.target\n",
            self.mode,
            args.join(" ")
        ))
    }

    pub fn render_frps_companion_toml(&self, token: &str) -> String {
        format!(
            "bindAddr = \"127.0.0.1\"\nbindPort = {}\nauth.method = \"token\"\nauth.token = \"{token}\"\ntransport.tcpMux = true\n",
            self.frp_port
        )
    }
}

/// Formats a locked-down `authorized_keys` line restricting the key strictly to port forwarding.
pub fn format_authorized_key_line(pub_key: &str, mode: &str, frp_port: u16, ports: &[u16]) -> Result<String> {
    let pk = pub_key.trim();
    if pk.is_empty() || pk.contains('\n') || pk.contains('\r') {
        bail!("invalid SSH public key");
    }
    let mut opts = vec![BAGHER_KEY_LOCK.to_string()];
    if mode == "bagher-frp" && frp_port > 0 {
        opts.push(format!("permitopen=\"127.0.0.1:{frp_port}\""));
    } else if mode == "direct" {
        for &p in ports {
            if p > 0 {
                opts.push(format!("permitopen=\"127.0.0.1:{p}\""));
            }
        }
    }
    Ok(format!("{} {pk} # khaymali-bagher", opts.join(",")))
}

/// Upgrades legacy unlocked `# khaymali-bagher` keys in `authorized_keys` text.
pub fn upgrade_bagher_key_locks(authorized_keys: &str) -> (String, usize) {
    let mut upgraded = 0usize;
    let mut out = Vec::new();
    for line in authorized_keys.lines() {
        let t = line.trim();
        if (t.contains("# khaymali-bagher"))
            && !t.starts_with(BAGHER_KEY_LOCK)
        {
            // Strip any old options before ssh-ed25519 / ssh-rsa / ecdsa-
            if let Some(pos) = t
                .find("ssh-ed25519 ")
                .or_else(|| t.find("ssh-rsa "))
                .or_else(|| t.find("ecdsa-sha2-"))
            {
                out.push(format!("{BAGHER_KEY_LOCK} {}", &t[pos..]));
                upgraded += 1;
                continue;
            }
        }
        out.push(line.to_string());
    }
    let mut res = out.join("\n");
    if !res.is_empty() {
        res.push('\n');
    }
    (res, upgraded)
}

pub fn apply_sshfwd(cfg: &SshFwdConfig, unit_dir: &str) -> Result<()> {
    let unit = cfg.render_service_unit()?;
    sysrun::install_unit(unit_dir, "khaymali-sshfwd.service", &unit, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sshfwd_unit_and_restricted_key_lock() {
        let cfg = SshFwdConfig {
            enabled: true,
            mode: "reverse".into(),
            remote_host: "198.51.100.10".into(),
            ssh_port: 2222,
            ssh_user: "tunnel".into(),
            key_path: "/etc/khaymali/id_ed25519".into(),
            frp_port: 7000,
            ports: vec![443, 8443],
            compression: true,
        };
        let unit = cfg.render_service_unit().unwrap();
        assert!(unit.contains("-R 0.0.0.0:443:127.0.0.1:443"));
        assert!(unit.contains("-R 0.0.0.0:8443:127.0.0.1:8443"));
        assert!(unit.contains("ExitOnForwardFailure=yes"));

        let line = format_authorized_key_line("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest", "direct", 7000, &[443]).unwrap();
        assert!(line.starts_with(BAGHER_KEY_LOCK));
        assert!(line.contains("permitopen=\"127.0.0.1:443\""));

        let legacy = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIold # khaymali-bagher\n";
        let (up, n) = upgrade_bagher_key_locks(legacy);
        assert_eq!(n, 1);
        assert!(up.starts_with(BAGHER_KEY_LOCK));
    }
}
