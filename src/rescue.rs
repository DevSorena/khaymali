//! Connectivity Rescue & Tunnel Egress Bridge (`src/rescue.rs`).
//!
//! Ported from Khaymali's `rescue.go` & `tunnel_egress.go`.

use anyhow::{bail, Result};
use std::process::Command;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

pub const DEFAULT_EGRESS_ALLOWED_HOSTS: &[&str] = &[
    "api.telegram.org",
    "api.cloudflare.com",
];

pub fn egress_host_allowed(host: &str, port: u16, extra_allowed: &[String]) -> bool {
    if port != 443 {
        return false;
    }
    let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if DEFAULT_EGRESS_ALLOWED_HOSTS.contains(&clean.as_str()) {
        return true;
    }
    extra_allowed
        .iter()
        .any(|h| h.trim().trim_end_matches('.').eq_ignore_ascii_case(&clean))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OneWayCheckResult {
    pub icmp_ok: bool,
    pub tcp_outbound_ok: bool,
    pub one_way_suspected: bool,
    pub rescue_advice: String,
}

pub async fn detect_one_way_block(
    peer_ip: &str,
    peer_port: u16,
    local_listen_port: u16,
) -> OneWayCheckResult {
    let icmp_ok = Command::new("ping")
        .args(["-c", "1", "-W", "2", peer_ip])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let addr = if peer_ip.contains(':') {
        format!("[{peer_ip}]:{peer_port}")
    } else {
        format!("{peer_ip}:{peer_port}")
    };
    let tcp_outbound_ok = timeout(Duration::from_secs(3), TcpStream::connect(&addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
    let one_way_suspected = icmp_ok && !tcp_outbound_ok;
    let rescue_advice = if one_way_suspected {
        format!(
            "One-way outbound TCP block suspected (ICMP ok, TCP to {addr} dropped). \
             Activate Rescue Reverse-Dial:\n  \
             Iran (Entry):   khaymali entry --listen-exit 0.0.0.0:{local_listen_port} ...\n  \
             Foreign (Exit): khaymali exit  --reverse-entry <IRAN_IP>:{local_listen_port} --reverse-pool 8 ..."
        )
    } else if tcp_outbound_ok {
        format!("Direct outbound TCP to {addr} succeeded; rescue not needed.")
    } else {
        format!("Both ICMP and TCP to {addr} failed; check firewall or try Bridge/Spoof mode.")
    };
    OneWayCheckResult { icmp_ok, tcp_outbound_ok, one_way_suspected, rescue_advice }
}

pub async fn serve_egress_bridge(
    bind_addr: String,
    upstream_socks: String,
    extra_allowed: Vec<String>,
) -> Result<()> {
    let listener = TcpListener::bind(&bind_addr).await?;
    eprintln!(
        "[egress-bridge] loopback SOCKS5 on {bind_addr} -> {upstream_socks} (Telegram + Cloudflare)"
    );
    loop {
        let Ok((cli, _)) = listener.accept().await else { continue };
        let up = upstream_socks.clone();
        let extra = extra_allowed.clone();
        tokio::spawn(async move {
            let _ = handle_egress_client(cli, &up, &extra).await;
        });
    }
}

async fn handle_egress_client(
    mut cli: TcpStream,
    upstream_socks: &str,
    extra_allowed: &[String],
) -> Result<()> {
    let mut hdr = [0u8; 2];
    timeout(Duration::from_secs(5), cli.read_exact(&mut hdr)).await??;
    if hdr[0] != 5 {
        bail!("not socks5");
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    cli.read_exact(&mut methods).await?;
    cli.write_all(&[5, 0]).await?;

    let mut req = [0u8; 4];
    timeout(Duration::from_secs(5), cli.read_exact(&mut req)).await??;
    if req[0] != 5 || req[1] != 1 {
        let _ = cli.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        bail!("only CONNECT supported");
    }

    let (host, raw_addr) = match req[3] {
        3 => {
            let mut l = [0u8; 1];
            cli.read_exact(&mut l).await?;
            let mut dom = vec![0u8; l[0] as usize];
            cli.read_exact(&mut dom).await?;
            let mut raw = Vec::with_capacity(2 + dom.len());
            raw.push(3);
            raw.push(l[0]);
            raw.extend_from_slice(&dom);
            (String::from_utf8_lossy(&dom).into_owned(), raw)
        }
        _ => {
            let _ = cli.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            bail!("egress bridge requires domain-name SOCKS5 (socks5h://)");
        }
    };
    let mut port_b = [0u8; 2];
    cli.read_exact(&mut port_b).await?;
    let port = u16::from_be_bytes(port_b);

    if !egress_host_allowed(&host, port, extra_allowed) {
        let _ = cli.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        bail!("egress bridge refused {host}:{port}");
    }

    let mut up = timeout(Duration::from_secs(10), TcpStream::connect(upstream_socks)).await??;
    up.write_all(&[5, 1, 0]).await?;
    let mut up_greet = [0u8; 2];
    timeout(Duration::from_secs(5), up.read_exact(&mut up_greet)).await??;
    if up_greet != [5, 0] {
        let _ = cli.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        bail!("upstream socks5 handshake failed");
    }
    let mut up_req = Vec::with_capacity(3 + raw_addr.len() + 2);
    up_req.extend_from_slice(&[5, 1, 0]);
    up_req.extend_from_slice(&raw_addr);
    up_req.extend_from_slice(&port_b);
    up.write_all(&up_req).await?;

    let mut up_rep = [0u8; 10];
    timeout(Duration::from_secs(10), up.read_exact(&mut up_rep)).await??;
    if up_rep[1] != 0 {
        let _ = cli.write_all(&[5, up_rep[1], 0, 1, 0, 0, 0, 0, 0, 0]).await;
        bail!("upstream socks5 connect error {}", up_rep[1]);
    }
    cli.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let _ = tokio::io::copy_bidirectional(&mut cli, &mut up).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_allowlist_restricts_to_telegram_cloudflare_443() {
        assert!(egress_host_allowed("api.telegram.org", 443, &[]));
        assert!(egress_host_allowed("API.CLOUDFLARE.COM.", 443, &[]));
        assert!(!egress_host_allowed("api.telegram.org", 80, &[]));
        assert!(!egress_host_allowed("evil.example.com", 443, &[]));
        assert!(egress_host_allowed("hooks.myorg.ir", 443, &["hooks.myorg.ir".into()]));
    }
}
