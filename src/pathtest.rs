//! End-to-End Multi-Carrier Path Test & Carrier Benchmark (`src/pathtest.rs`).
//!
//! Ported from Khaymali's `pathtest.go` & `benchmark.go`.

use crate::camo::{self, CamoCfg, Replay};
use crate::fallback::FallbackLimiter;
use crate::ktunnel::{self, KtunnelListener};
use crate::udp_transport::{self, UdpCarrierListener};
use crate::util::{hex, rand_bytes, unhex};
use crate::ws_transport::{self, b64_decode, b64url_encode, WsCarrierListener};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

pub const PT_CODE_PREFIX: &str = "pt1_";
const PT_ECHO_PAYLOAD: usize = 64 * 1024;

pub const OFF_TCP_UDP: u16 = 0;
pub const OFF_CAMO: u16 = 1;
pub const OFF_WS: u16 = 2;
pub const OFF_WSS: u16 = 3;
pub const OFF_UDP_FEC: u16 = 4;
pub const OFF_KTUNNEL: u16 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathTestCode {
    pub host: String,
    pub host6: Option<String>,
    pub base_port: u16,
    pub ssh_port: u16,
    pub secret_hex: String,
    pub sni: String,
    pub minutes: u16,
}

impl PathTestCode {
    pub fn encode(&self) -> String {
        let mut parts = vec![
            format!("h={}", self.host),
            format!("p={}", self.base_port),
            format!("ssh={}", self.ssh_port),
            format!("t={}", self.secret_hex),
            format!("sni={}", self.sni),
            format!("m={}", self.minutes),
        ];
        if let Some(h6) = &self.host6 {
            if !h6.is_empty() {
                parts.push(format!("h6={h6}"));
            }
        }
        format!("{PT_CODE_PREFIX}{}", b64url_encode(parts.join("&").as_bytes()))
    }

    pub fn decode(raw: &str) -> Result<Self> {
        let body = raw
            .trim()
            .strip_prefix(PT_CODE_PREFIX)
            .context("invalid path test code (expected pt1_...)")?;
        let bytes = b64_decode(body)?;
        let s = String::from_utf8(bytes).context("path test code is not UTF-8")?;
        let mut m = HashMap::new();
        for pair in s.split('&').filter(|x| !x.is_empty()) {
            if let Some((k, v)) = pair.split_once('=') {
                m.insert(k.to_string(), v.to_string());
            }
        }
        let host = m.remove("h").context("missing host 'h' in path test code")?;
        let base_port: u16 = m
            .remove("p")
            .context("missing base port 'p'")?
            .parse()
            .context("invalid base port")?;
        let ssh_port: u16 = m.remove("ssh").and_then(|v| v.parse().ok()).unwrap_or(22);
        let secret_hex = m.remove("t").context("missing secret 't'")?;
        let sni = m.remove("sni").unwrap_or_else(|| "www.cloudflare.com".to_string());
        let minutes: u16 = m.remove("m").and_then(|v| v.parse().ok()).unwrap_or(5);
        let host6 = m.remove("h6").filter(|v| !v.is_empty());
        Ok(Self { host, host6, base_port, ssh_port, secret_hex, sni, minutes })
    }
}

#[derive(Clone, Debug)]
pub struct CarrierProbeResult {
    pub id: &'static str,
    pub name: &'static str,
    pub proto: &'static str,
    pub status: &'static str,
    pub rtt_ms: f64,
    pub jitter_ms: f64,
    pub loss_pct: f64,
    pub mbps: f64,
    pub score: u8,
    pub note: String,
}

pub fn calculate_score(loss_pct: f64, rtt_ms: f64, jitter_ms: f64) -> u8 {
    if loss_pct >= 100.0 {
        return 0;
    }
    let mut score = 100.0;
    score -= loss_pct * 3.0;
    if rtt_ms > 50.0 {
        score -= (rtt_ms - 50.0) * 0.18;
    }
    score -= jitter_ms * 0.6;
    score.clamp(0.0, 100.0).round() as u8
}

pub fn determine_status(score: u8, loss_pct: f64) -> &'static str {
    if loss_pct >= 100.0 || score == 0 {
        "fail"
    } else if score >= 75 {
        "optimal"
    } else if score >= 45 {
        "degraded"
    } else {
        "poor"
    }
}

async fn echo_stream(mut s: crate::util::BoxRw) {
    let mut buf = vec![0u8; 16 * 1024];
    while let Ok(Ok(n)) = timeout(Duration::from_secs(10), s.read(&mut buf)).await {
        if n == 0 {
            break;
        }
        if s.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
}

pub async fn serve(
    host: String,
    host6: Option<String>,
    base_port: u16,
    ssh_port: u16,
    sni: String,
    minutes: u16,
) -> Result<()> {
    let minutes = minutes.clamp(1, 30);
    let secret = rand_bytes::<32>().to_vec();
    let code = PathTestCode {
        host: host.clone(),
        host6: host6.clone(),
        base_port,
        ssh_port,
        secret_hex: hex(&secret),
        sni: sni.clone(),
        minutes,
    };

    let camo_cfg = CamoCfg {
        secret: secret.clone(),
        sni: sni.clone(),
        fallback: None,
        pad_max: 32,
    };

    let tcp_l = TcpListener::bind(format!("0.0.0.0:{}", base_port + OFF_TCP_UDP)).await?;
    tokio::spawn(async move {
        while let Ok((s, _)) = tcp_l.accept().await {
            tokio::spawn(echo_stream(Box::new(s)));
        }
    });

    if host6.is_some() {
        if let Ok(l6) = TcpListener::bind(format!("[::]:{}", base_port + OFF_TCP_UDP)).await {
            tokio::spawn(async move {
                while let Ok((s, _)) = l6.accept().await {
                    tokio::spawn(echo_stream(Box::new(s)));
                }
            });
        }
    }

    let udp_s = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", base_port + OFF_TCP_UDP)).await?);
    {
        let u = udp_s.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, peer)) = u.recv_from(&mut buf).await {
                let _ = u.send_to(&buf[..n], peer).await;
            }
        });
    }

    let camo_l = TcpListener::bind(format!("0.0.0.0:{}", base_port + OFF_CAMO)).await?;
    let replay = Arc::new(Replay::new());
    let fb = FallbackLimiter::default_limiter();
    {
        let cc = camo_cfg.clone();
        tokio::spawn(async move {
            while let Ok((s, peer)) = camo_l.accept().await {
                let (cc, r, fb) = (cc.clone(), replay.clone(), fb.clone());
                tokio::spawn(async move {
                    if let Ok(Some(st)) = camo::server(s, peer.ip(), &cc, &r, &fb).await {
                        echo_stream(st).await;
                    }
                });
            }
        });
    }

    let ws_l = Arc::new(WsCarrierListener::bind(&format!("0.0.0.0:{}", base_port + OFF_WS), secret.clone(), None).await?);
    {
        let wl = ws_l.clone();
        tokio::spawn(async move {
            while let Ok((s, peer)) = wl.accept().await {
                let wl2 = wl.clone();
                tokio::spawn(async move {
                    if let Ok(Some(st)) = wl2.handshake(s, peer.ip()).await {
                        echo_stream(st).await;
                    }
                });
            }
        });
    }

    let wss_l = Arc::new(
        WsCarrierListener::bind(
            &format!("0.0.0.0:{}", base_port + OFF_WSS),
            secret.clone(),
            Some(camo_cfg.clone()),
        )
        .await?,
    );
    {
        let wl = wss_l.clone();
        tokio::spawn(async move {
            while let Ok((s, peer)) = wl.accept().await {
                let wl2 = wl.clone();
                tokio::spawn(async move {
                    if let Ok(Some(st)) = wl2.handshake(s, peer.ip()).await {
                        echo_stream(st).await;
                    }
                });
            }
        });
    }

    let mut u_l = UdpCarrierListener::bind(&format!("0.0.0.0:{}", base_port + OFF_UDP_FEC), secret.clone()).await?;
    tokio::spawn(async move {
        while let Some((st, _)) = u_l.accept().await {
            tokio::spawn(echo_stream(st));
        }
    });

    let mut k_l = KtunnelListener::bind(&format!("0.0.0.0:{}", base_port + OFF_KTUNNEL), secret.clone()).await?;
    tokio::spawn(async move {
        while let Some((st, _)) = k_l.accept().await {
            tokio::spawn(echo_stream(st));
        }
    });

    println!("pathtest-code: {}", code.encode());
    println!("ports:         {}..={} (TCP/UDP, Camo, WS, WSS, UDP+FEC, Ktunnel)", base_port, base_port + OFF_KTUNNEL);
    println!("expires-in:    {} minute(s)", minutes);
    println!("Run on the other server:\n  khaymali pathtest run {}", code.encode());

    tokio::time::sleep(Duration::from_secs((minutes as u64) * 60)).await;
    Ok(())
}

async fn measure_stream_echo(mut s: crate::util::BoxRw) -> Result<(f64, f64, f64)> {
    let mut rtts = Vec::with_capacity(3);
    let mut small_rx = [0u8; 32];
    for i in 0u8..3 {
        let tx = [0xA5 ^ i; 32];
        let t0 = Instant::now();
        timeout(Duration::from_secs(4), s.write_all(&tx)).await??;
        timeout(Duration::from_secs(4), s.read_exact(&mut small_rx)).await??;
        if small_rx != tx {
            bail!("echo payload corruption");
        }
        rtts.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    let avg_rtt = rtts.iter().sum::<f64>() / (rtts.len() as f64);
    let jitter = if rtts.len() >= 2 {
        let mut d = 0.0;
        for w in rtts.windows(2) {
            d += (w[1] - w[0]).abs();
        }
        d / ((rtts.len() - 1) as f64)
    } else {
        0.0
    };

    let payload = vec![0x5Au8; PT_ECHO_PAYLOAD];
    let mut rx = vec![0u8; PT_ECHO_PAYLOAD];
    let t_bw = Instant::now();
    let (mut rd, mut wr) = tokio::io::split(s);
    let write_task = tokio::spawn(async move { wr.write_all(&payload).await });
    timeout(Duration::from_secs(8), rd.read_exact(&mut rx)).await??;
    write_task.await??;
    let secs = t_bw.elapsed().as_secs_f64().max(0.0005);
    let mbps = ((PT_ECHO_PAYLOAD as f64) * 8.0 * 2.0) / (secs * 1_000_000.0);
    Ok((avg_rtt, jitter, mbps))
}

async fn probe_raw_udp(addr: &str) -> Result<(f64, f64, f64)> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(addr).await?;
    let mut rtts = Vec::new();
    let mut lost = 0usize;
    let mut buf = [0u8; 128];
    for seq in 0u8..5 {
        let pkt = [0x55, seq, 0xAA, 0x11, 0x22, 0x33, 0x44, 0x55];
        let t0 = Instant::now();
        let _ = sock.send(&pkt).await;
        match timeout(Duration::from_millis(1200), sock.recv(&mut buf)).await {
            Ok(Ok(n)) if n == pkt.len() && buf[..n] == pkt => {
                rtts.push(t0.elapsed().as_secs_f64() * 1000.0);
            }
            _ => lost += 1,
        }
    }
    let loss_pct = (lost as f64 / 5.0) * 100.0;
    if rtts.is_empty() {
        bail!("100% UDP packet loss");
    }
    let avg = rtts.iter().sum::<f64>() / (rtts.len() as f64);
    let jitter = if rtts.len() >= 2 {
        rtts.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / ((rtts.len() - 1) as f64)
    } else {
        0.0
    };
    Ok((avg, jitter, loss_pct))
}

async fn probe_ssh_banner(host: &str, port: u16) -> Result<f64> {
    let addr = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let t0 = Instant::now();
    let mut s = timeout(Duration::from_secs(4), TcpStream::connect(&addr)).await??;
    let mut buf = [0u8; 32];
    let n = timeout(Duration::from_secs(3), s.read(&mut buf)).await??;
    let banner = String::from_utf8_lossy(&buf[..n]);
    if !banner.starts_with("SSH-") {
        bail!("non-SSH banner");
    }
    Ok(t0.elapsed().as_secs_f64() * 1000.0)
}

pub async fn run_client(code_str: &str) -> Result<Vec<CarrierProbeResult>> {
    let code = PathTestCode::decode(code_str)?;
    let secret = unhex(&code.secret_hex).context("invalid secret hex in path test code")?;
    let camo_cfg = CamoCfg {
        secret: secret.clone(),
        sni: code.sni.clone(),
        fallback: None,
        pad_max: 32,
    };
    let host = code.host.clone();
    let base = code.base_port;
    let mut out = Vec::new();

    let tcp_addr = format!("{host}:{}", base + OFF_TCP_UDP);
    out.push(match timeout(Duration::from_secs(6), TcpStream::connect(&tcp_addr)).await {
        Ok(Ok(s)) => match measure_stream_echo(Box::new(s)).await {
            Ok((rtt, jit, mbps)) => CarrierProbeResult {
                id: "tcp", name: "TCP", proto: "tcp", status: "ok",
                rtt_ms: rtt, jitter_ms: jit, loss_pct: 0.0, mbps,
                score: calculate_score(0.0, rtt, jit), note: "clean".into(),
            },
            Err(e) => CarrierProbeResult {
                id: "tcp", name: "TCP", proto: "tcp", status: "fail",
                rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: e.to_string(),
            },
        },
        _ => CarrierProbeResult {
            id: "tcp", name: "TCP", proto: "tcp", status: "fail",
            rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: "connect failed".into(),
        },
    });

    out.push(match probe_raw_udp(&tcp_addr).await {
        Ok((rtt, jit, loss)) => CarrierProbeResult {
            id: "udp", name: "UDP (raw)", proto: "udp", status: "ok",
            rtt_ms: rtt, jitter_ms: jit, loss_pct: loss, mbps: 0.0,
            score: calculate_score(loss, rtt, jit), note: format!("loss {loss:.0}%"),
        },
        Err(e) => CarrierProbeResult {
            id: "udp", name: "UDP (raw)", proto: "udp", status: "fail",
            rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: e.to_string(),
        },
    });

    let camo_addr = format!("{host}:{}", base + OFF_CAMO);
    out.push(match timeout(Duration::from_secs(6), TcpStream::connect(&camo_addr)).await {
        Ok(Ok(s)) => match camo::client(s, &camo_cfg).await {
            Ok(st) => match measure_stream_echo(st).await {
                Ok((rtt, jit, mbps)) => CarrierProbeResult {
                    id: "camo", name: "TCP+Camo TLS", proto: "tcp", status: "ok",
                    rtt_ms: rtt, jitter_ms: jit, loss_pct: 0.0, mbps,
                    score: calculate_score(0.0, rtt, jit), note: format!("sni={}", code.sni),
                },
                Err(e) => CarrierProbeResult {
                    id: "camo", name: "TCP+Camo TLS", proto: "tcp", status: "fail",
                    rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: e.to_string(),
                },
            },
            Err(e) => CarrierProbeResult {
                id: "camo", name: "TCP+Camo TLS", proto: "tcp", status: "fail",
                rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: e.to_string(),
            },
        },
        _ => CarrierProbeResult {
            id: "camo", name: "TCP+Camo TLS", proto: "tcp", status: "fail",
            rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: "connect failed".into(),
        },
    });

    let ws_addr = format!("{host}:{}", base + OFF_WS);
    out.push(match ws_transport::connect_ws(&ws_addr, &secret, Duration::from_secs(6)).await {
        Ok(st) => match measure_stream_echo(st).await {
            Ok((rtt, jit, mbps)) => CarrierProbeResult {
                id: "ws", name: "WebSocket (ws://)", proto: "tcp", status: "ok",
                rtt_ms: rtt, jitter_ms: jit, loss_pct: 0.0, mbps,
                score: calculate_score(0.0, rtt, jit), note: "RFC 6455".into(),
            },
            Err(e) => CarrierProbeResult {
                id: "ws", name: "WebSocket (ws://)", proto: "tcp", status: "fail",
                rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: e.to_string(),
            },
        },
        Err(e) => CarrierProbeResult {
            id: "ws", name: "WebSocket (ws://)", proto: "tcp", status: "fail",
            rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: e.to_string(),
        },
    });

    let wss_addr = format!("{host}:{}", base + OFF_WSS);
    out.push(match ws_transport::connect_wss(&wss_addr, &camo_cfg, Duration::from_secs(6)).await {
        Ok(st) => match measure_stream_echo(st).await {
            Ok((rtt, jit, mbps)) => CarrierProbeResult {
                id: "wss", name: "WSS (wss://)", proto: "tcp", status: "ok",
                rtt_ms: rtt, jitter_ms: jit, loss_pct: 0.0, mbps,
                score: calculate_score(0.0, rtt, jit), note: "TLS+WS".into(),
            },
            Err(e) => CarrierProbeResult {
                id: "wss", name: "WSS (wss://)", proto: "tcp", status: "fail",
                rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: e.to_string(),
            },
        },
        Err(e) => CarrierProbeResult {
            id: "wss", name: "WSS (wss://)", proto: "tcp", status: "fail",
            rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: e.to_string(),
        },
    });

    let udp_fec_addr = format!("{host}:{}", base + OFF_UDP_FEC);
    out.push(match udp_transport::connect(&udp_fec_addr, &secret, Duration::from_secs(6)).await {
        Ok(st) => match measure_stream_echo(st).await {
            Ok((rtt, jit, mbps)) => CarrierProbeResult {
                id: "udp+fec", name: "UDP+ARQ+FEC (udp://)", proto: "udp", status: "ok",
                rtt_ms: rtt, jitter_ms: jit, loss_pct: 0.0, mbps,
                score: calculate_score(0.0, rtt, jit), note: "0-RTT FEC".into(),
            },
            Err(e) => CarrierProbeResult {
                id: "udp+fec", name: "UDP+ARQ+FEC (udp://)", proto: "udp", status: "fail",
                rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: e.to_string(),
            },
        },
        Err(e) => CarrierProbeResult {
            id: "udp+fec", name: "UDP+ARQ+FEC (udp://)", proto: "udp", status: "fail",
            rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: e.to_string(),
        },
    });

    let ktun_addr = format!("{host}:{}", base + OFF_KTUNNEL);
    out.push(match ktunnel::connect(&ktun_addr, &secret, ktunnel::DEFAULT_KTUN_FLOWS, Duration::from_secs(6)).await {
        Ok(st) => match measure_stream_echo(st).await {
            Ok((rtt, jit, mbps)) => CarrierProbeResult {
                id: "ktunnel", name: "Ktunnel Mux (ktunnel://)", proto: "tcp", status: "ok",
                rtt_ms: rtt, jitter_ms: jit, loss_pct: 0.0, mbps,
                score: calculate_score(0.0, rtt, jit), note: "8 flows".into(),
            },
            Err(e) => CarrierProbeResult {
                id: "ktunnel", name: "Ktunnel Mux (ktunnel://)", proto: "tcp", status: "fail",
                rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: e.to_string(),
            },
        },
        Err(e) => CarrierProbeResult {
            id: "ktunnel", name: "Ktunnel Mux (ktunnel://)", proto: "tcp", status: "fail",
            rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: e.to_string(),
        },
    });

    if let Some(h6) = &code.host6 {
        let v6_addr = format!("[{h6}]:{}", base + OFF_TCP_UDP);
        out.push(match timeout(Duration::from_secs(5), TcpStream::connect(&v6_addr)).await {
            Ok(Ok(s)) => match measure_stream_echo(Box::new(s)).await {
                Ok((rtt, jit, mbps)) => CarrierProbeResult {
                    id: "tcp6", name: "TCP over IPv6 (4in6 ready)", proto: "tcp6", status: "ok",
                    rtt_ms: rtt, jitter_ms: jit, loss_pct: 0.0, mbps,
                    score: calculate_score(0.0, rtt, jit), note: h6.clone(),
                },
                Err(e) => CarrierProbeResult {
                    id: "tcp6", name: "TCP over IPv6", proto: "tcp6", status: "fail",
                    rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: e.to_string(),
                },
            },
            _ => CarrierProbeResult {
                id: "tcp6", name: "TCP over IPv6", proto: "tcp6", status: "fail",
                rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: "IPv6 unreachable".into(),
            },
        });
    } else {
        out.push(CarrierProbeResult {
            id: "tcp6", name: "TCP over IPv6", proto: "tcp6", status: "skip",
            rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 0.0, mbps: 0.0, score: 0,
            note: "server has no public IPv6".into(),
        });
    }

    out.push(match probe_ssh_banner(&host, code.ssh_port).await {
        Ok(rtt) => CarrierProbeResult {
            id: "ssh", name: "Bagher SSH (ssh://)", proto: "tcp", status: "ok",
            rtt_ms: rtt, jitter_ms: 0.0, loss_pct: 0.0, mbps: 0.0,
            score: calculate_score(0.0, rtt, 0.0), note: format!("port {}", code.ssh_port),
        },
        Err(e) => CarrierProbeResult {
            id: "ssh", name: "Bagher SSH (ssh://)", proto: "tcp", status: "fail",
            rtt_ms: 0.0, jitter_ms: 0.0, loss_pct: 100.0, mbps: 0.0, score: 0, note: e.to_string(),
        },
    });

    Ok(out)
}

pub fn format_table(results: &[CarrierProbeResult]) -> String {
    let mut s = format!(
        "{:<10} {:<26} {:<6} {:<6} {:>8} {:>8} {:>8} {:>5}  {}\n",
        "ID", "CARRIER", "PROTO", "STATE", "RTT(ms)", "JIT(ms)", "MBPS", "SCORE", "NOTE"
    );
    s.push_str(&"-".repeat(96));
    s.push('\n');
    let mut best: Option<&CarrierProbeResult> = None;
    for r in results {
        s.push_str(&format!(
            "{:<10} {:<26} {:<6} {:<6} {:>8.1} {:>8.1} {:>8.1} {:>5}  {}\n",
            r.id, r.name, r.proto, r.status, r.rtt_ms, r.jitter_ms, r.mbps, r.score, r.note
        ));
        if r.status == "ok" && best.map_or(true, |b| r.score > b.score) {
            best = Some(r);
        }
    }
    if let Some(b) = best {
        s.push_str(&format!(
            "\nRecommended carrier: {} (score {}/100, status={}, rtt={:.1}ms, {:.1} Mbps)\n",
            b.name, b.score, determine_status(b.score, b.loss_pct), b.rtt_ms, b.mbps
        ));
    } else {
        s.push_str("\nRecommended carrier: NONE (try Bridge mode, Reverse-Dial, or Spoof)\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pathtest_code_roundtrip_and_scoring() {
        let c = PathTestCode {
            host: "203.0.113.5".into(),
            host6: Some("2001:db8::5".into()),
            base_port: 24000,
            ssh_port: 2222,
            secret_hex: "0123456789abcdef0123456789abcdef".into(),
            sni: "www.cloudflare.com".into(),
            minutes: 5,
        };
        let enc = c.encode();
        assert!(enc.starts_with("pt1_"));
        let dec = PathTestCode::decode(&enc).unwrap();
        assert_eq!(dec, c);
        assert_eq!(calculate_score(0.0, 20.0, 1.0), 99);
        assert_eq!(calculate_score(100.0, 0.0, 0.0), 0);
        assert_eq!(determine_status(90, 0.0), "optimal");
    }
}
