//! Bagher SSH Tunnel Carrier (`ssh://[USER@]HOST[:SSH_PORT]/REMOTE_PORT`, `src/ssh_carrier.rs`).
//!
//! Ported from Khaymali's `bagher_carrier.go` & `bagher_links.go`:
//!   * Carries Khaymali Noise_IK links inside SSH when only SSH passes the firewall.
//!   * Solves OpenSSH `ssh -N` Nagle latency spike by opening a lightweight session exec so
//!     `sshd` immediately enables `TCP_NODELAY` on the carrier socket.
//!   * Supports IPv6 bracketed `known_hosts`, reverse-forward (`-R`) generation, and multi-link
//!     port conflict checking.

use crate::link;
use crate::stats;
use crate::util::BoxRw;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::TcpListener as StdTcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshCarrierSpec {
    pub user: String,
    pub host: String,
    pub ssh_port: u16,
    pub remote_target_port: u16,
    pub identity_file: Option<String>,
    pub known_hosts: Option<String>,
    pub strict_host_key: bool,
    pub alive_interval_secs: u16,
    pub alive_count_max: u16,
}

impl SshCarrierSpec {
    pub fn parse(raw: &str) -> Result<Self> {
        let rest = raw.strip_prefix("ssh://").unwrap_or(raw).trim();
        if rest.is_empty() {
            bail!("empty ssh:// carrier URI");
        }
        let (main_part, query) = match rest.split_once('?') {
            Some((m, q)) => (m, Some(q)),
            None => (rest, None),
        };
        let (auth_host, remote_port_str) = match main_part.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (main_part, None),
        };
        let (user, host_port) = match auth_host.split_once('@') {
            Some((u, h)) if !u.is_empty() => (u.to_string(), h),
            _ => ("root".to_string(), auth_host),
        };

        let (host, ssh_port) = parse_host_port_v4_v6(host_port, 22)?;
        let remote_target_port = match remote_port_str {
            Some(p) if !p.is_empty() => p
                .parse::<u16>()
                .with_context(|| format!("invalid remote port '{p}' in ssh:// URI"))?,
            _ => 443,
        };

        let mut identity_file = std::env::var("KHAYMALI_SSH_KEY").ok().filter(|s| !s.is_empty());
        let mut known_hosts = std::env::var("KHAYMALI_SSH_KNOWN_HOSTS").ok().filter(|s| !s.is_empty());
        let mut strict_host_key = false;
        let mut alive_interval_secs = 15u16;
        let mut alive_count_max = 3u16;

        if let Some(q) = query {
            for pair in q.split('&').filter(|s| !s.is_empty()) {
                if let Some((k, v)) = pair.split_once('=') {
                    match k {
                        "key" | "identity" => identity_file = Some(v.to_string()),
                        "known_hosts" => known_hosts = Some(v.to_string()),
                        "strict" => strict_host_key = v == "1" || v.eq_ignore_ascii_case("true"),
                        "alive" => {
                            if let Ok(n) = v.parse::<u16>() {
                                alive_interval_secs = n.clamp(5, 120);
                            }
                        }
                        "alive_max" => {
                            if let Ok(n) = v.parse::<u16>() {
                                alive_count_max = n.clamp(1, 10);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(Self {
            user,
            host,
            ssh_port,
            remote_target_port,
            identity_file,
            known_hosts,
            strict_host_key,
            alive_interval_secs,
            alive_count_max,
        })
    }

    pub fn known_hosts_entry(&self) -> String {
        let h = self.host.trim_matches(['[', ']']);
        if self.ssh_port == 22 && !h.contains(':') {
            h.to_string()
        } else {
            format!("[{h}]:{}", self.ssh_port)
        }
    }

    pub fn build_ssh_args(&self, local_port: u16) -> Vec<String> {
        let mut args = vec![
            "-o".into(), "BatchMode=yes".into(),
            "-o".into(), "ExitOnForwardFailure=yes".into(),
            "-o".into(), "TCPKeepAlive=yes".into(),
            "-o".into(), "Compression=no".into(),
            "-o".into(), format!("ServerAliveInterval={}", self.alive_interval_secs),
            "-o".into(), format!("ServerAliveCountMax={}", self.alive_count_max),
            "-o".into(), "ConnectTimeout=10".into(),
        ];
        if self.strict_host_key {
            args.extend(["-o".into(), "StrictHostKeyChecking=yes".into()]);
        } else {
            args.extend(["-o".into(), "StrictHostKeyChecking=accept-new".into()]);
        }
        if let Some(kh) = &self.known_hosts {
            args.extend(["-o".into(), format!("UserKnownHostsFile={kh}")]);
        }
        if let Some(id) = &self.identity_file {
            args.extend(["-i".into(), id.clone()]);
        }
        args.extend([
            "-p".into(),
            self.ssh_port.to_string(),
            "-L".into(),
            format!("127.0.0.1:{local_port}:127.0.0.1:{}", self.remote_target_port),
            format!("{}@{}", self.user, self.host.trim_matches(['[', ']'])),
            "while sleep 3600; do :; done".into(),
        ]);
        args
    }

    pub fn build_reverse_ssh_args(&self, remote_bind_port: u16, local_target_port: u16) -> Vec<String> {
        let mut args = vec![
            "-o".into(), "BatchMode=yes".into(),
            "-o".into(), "ExitOnForwardFailure=yes".into(),
            "-o".into(), "TCPKeepAlive=yes".into(),
            "-o".into(), "Compression=no".into(),
            "-o".into(), format!("ServerAliveInterval={}", self.alive_interval_secs),
            "-o".into(), format!("ServerAliveCountMax={}", self.alive_count_max),
        ];
        if let Some(id) = &self.identity_file {
            args.extend(["-i".into(), id.clone()]);
        }
        args.extend([
            "-p".into(),
            self.ssh_port.to_string(),
            "-R".into(),
            format!("127.0.0.1:{remote_bind_port}:127.0.0.1:{local_target_port}"),
            format!("{}@{}", self.user, self.host.trim_matches(['[', ']'])),
            "while sleep 3600; do :; done".into(),
        ]);
        args
    }
}

fn parse_host_port_v4_v6(s: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest.split_once(']').context("unclosed IPv6 bracket in ssh:// URI")?;
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>().context("invalid port after IPv6 literal")?
        } else {
            default_port
        };
        return Ok((h.to_string(), port));
    }
    if let Some((h, p)) = s.rsplit_once(':') {
        if !h.contains(':') {
            let port = p.parse::<u16>().with_context(|| format!("invalid ssh port '{p}'"))?;
            return Ok((h.to_string(), port));
        }
    }
    Ok((s.to_string(), default_port))
}

struct ManagedSshTunnel {
    local_port: u16,
    child: Child,
    started: Instant,
}

fn ssh_pool() -> &'static Mutex<HashMap<String, ManagedSshTunnel>> {
    static POOL: OnceLock<Mutex<HashMap<String, ManagedSshTunnel>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

fn pick_ephemeral_loopback_port() -> Result<u16> {
    let l = StdTcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

fn ensure_ssh_leg(uri: &str, spec: &SshCarrierSpec) -> Result<u16> {
    let mut map = ssh_pool().lock().unwrap();
    if let Some(existing) = map.get_mut(uri) {
        if let Ok(None) = existing.child.try_wait() {
            return Ok(existing.local_port);
        }
        stats::SSH_CARRIER_SESSIONS.fetch_sub(1, Relaxed);
        map.remove(uri);
    }
    let local_port = pick_ephemeral_loopback_port()?;
    let args = spec.build_ssh_args(local_port);
    let child = Command::new("ssh")
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn ssh carrier (ensure openssh-client is installed)")?;
    stats::SSH_CARRIER_SESSIONS.fetch_add(1, Relaxed);
    map.insert(
        uri.to_string(),
        ManagedSshTunnel { local_port, child, started: Instant::now() },
    );
    Ok(local_port)
}

pub async fn connect_ssh(uri: &str, connect_timeout: Duration) -> Result<BoxRw> {
    let spec = SshCarrierSpec::parse(uri)?;
    let local_port = ensure_ssh_leg(uri, &spec)?;
    let target = format!("127.0.0.1:{local_port}");
    let deadline = Instant::now() + connect_timeout;
    let mut last_err: Option<anyhow::Error> = None;

    while Instant::now() < deadline {
        match timeout(Duration::from_millis(800), TcpStream::connect(&target)).await {
            Ok(Ok(tcp)) => {
                link::tune(&tcp);
                return Ok(Box::new(tcp) as BoxRw);
            }
            Ok(Err(e)) => last_err = Some(e.into()),
            Err(e) => last_err = Some(e.into()),
        }
        sleep(Duration::from_millis(120)).await;
    }
    bail!(
        "ssh carrier {uri} local forward {target} not ready: {}",
        last_err.map(|e| e.to_string()).unwrap_or_else(|| "timeout".into())
    )
}

pub fn check_bagher_port_conflicts(links: &[(u32, Vec<u16>)]) -> Result<()> {
    let mut owner: HashMap<u16, u32> = HashMap::new();
    for (link_id, ports) in links {
        for &p in ports {
            if let Some(prev) = owner.insert(p, *link_id) {
                if prev != *link_id {
                    bail!("port {p} conflicts between Bagher link #{prev} and link #{link_id}");
                }
            }
        }
    }
    Ok(())
}

pub fn active_ssh_summary() -> Vec<(String, u16, u64)> {
    let mut map = ssh_pool().lock().unwrap();
    let mut out = Vec::new();
    map.retain(|k, v| {
        let alive = matches!(v.child.try_wait(), Ok(None));
        if alive {
            out.push((k.clone(), v.local_port, v.started.elapsed().as_secs()));
        }
        alive
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ssh_uri_ipv4_ipv6_and_query() {
        let s = SshCarrierSpec::parse("ssh://tunnel@203.0.113.5:2222/443?key=/root/.ssh/id_ed25519&strict=1").unwrap();
        assert_eq!(s.user, "tunnel");
        assert_eq!(s.host, "203.0.113.5");
        assert_eq!(s.ssh_port, 2222);
        assert_eq!(s.remote_target_port, 443);
        assert!(s.strict_host_key);
        assert_eq!(s.known_hosts_entry(), "[203.0.113.5]:2222");

        let v6 = SshCarrierSpec::parse("ssh://[2001:db8::9]:2200/8443").unwrap();
        assert_eq!(v6.host, "2001:db8::9");
        assert_eq!(v6.ssh_port, 2200);
        assert_eq!(v6.remote_target_port, 8443);
    }

    #[test]
    fn ssh_args_use_session_nudge_not_dash_n() {
        let s = SshCarrierSpec::parse("ssh://root@198.51.100.1:22/443").unwrap();
        let args = s.build_ssh_args(18443);
        assert!(!args.contains(&"-N".to_string()));
        assert!(args.iter().any(|a| a.contains("sleep")));
    }

    #[test]
    fn port_conflict_detector_catches_duplicates() {
        assert!(check_bagher_port_conflicts(&[(1, vec![443, 8443]), (2, vec![2053])]).is_ok());
        assert!(check_bagher_port_conflicts(&[(1, vec![443, 8443]), (2, vec![8443])]).is_err());
    }
}
