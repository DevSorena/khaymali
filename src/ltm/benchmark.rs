//! Automatic tunnel benchmark: iperf3 (+ TCP fallback) and ping.
//!
//! Flow (client side, after a tunnel is up with inner IPs):
//!   1. ping inner peer → RTT / loss
//!   2. iperf3 -c peer -J  → bits/s  (or pure-TCP flood if iperf3 missing)
//!
//! Server side: `khaymali tunnels-bench --server` listens with iperf3 -s (or TCP sink).

use crate::sysrun;
use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub const STREAM_PORT: u16 = 5201;
pub const DEFAULT_DURATION: u64 = 5;

#[derive(Debug, Clone)]
pub struct PingResult {
    pub success: bool,
    pub loss_pct: f64,
    pub avg_ms: f64,
}

#[derive(Debug, Clone)]
pub struct BenchResult {
    pub protocol: String,
    pub target: String,
    pub bind: Option<String>,
    pub ping: PingResult,
    /// Bits per second (0 if failed).
    pub bps: f64,
    pub method: &'static str, // "iperf3" | "tcp-fallback" | "none"
}

impl BenchResult {
    pub fn mbps(&self) -> f64 {
        self.bps / 1_000_000.0
    }

    pub fn summary_line(&self) -> String {
        format!(
            "{:<14}  {:>8.2} Mb/s  rtt {:>7.1} ms  loss {:>5.1}%  [{}]",
            self.protocol,
            self.mbps(),
            self.ping.avg_ms,
            self.ping.loss_pct,
            self.method
        )
    }
}

fn cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

fn have_iperf3() -> bool {
    sysrun::run(&cmd(&["which", "iperf3"])).ok
}

/// Parse `ping` output for loss% and avg RTT.
pub fn ping(target: &str, bind: Option<&str>, count: u32) -> PingResult {
    let count_s = count.to_string();
    let out = if let Some(b) = bind {
        sysrun::run(&cmd(&[
            "ping", "-I", b, "-c", &count_s, "-W", "1", "-i", "0.2", target,
        ]))
    } else {
        sysrun::run(&cmd(&["ping", "-c", &count_s, "-W", "1", "-i", "0.2", target]))
    };
    if !out.ok {
        let out2 = sysrun::run(&cmd(&["ping", "-c", &count_s, "-W", "1", "-i", "0.2", target]));
        if !out2.ok {
            return PingResult {
                success: false,
                loss_pct: 100.0,
                avg_ms: 999.0,
            };
        }
        return parse_ping(&out2.stdout);
    }
    parse_ping(&out.stdout)
}

fn parse_ping(stdout: &str) -> PingResult {
    let mut loss = 100.0;
    let mut avg = 999.0;
    for line in stdout.lines() {
        if line.contains("packet loss") {
            for part in line.split(',') {
                if part.contains("packet loss") {
                    if let Some(tok) = part.split_whitespace().find(|t| t.contains('%')) {
                        let num = tok.trim_end_matches('%');
                        if let Ok(v) = num.parse::<f64>() {
                            loss = v;
                        }
                    }
                }
            }
        }
        if line.starts_with("rtt ") || line.starts_with("round-trip ") {
            // rtt min/avg/max/mdev = 0.1/0.2/0.3/0.0 ms
            if let Some(rhs) = line.split('=').nth(1) {
                let fields: Vec<&str> = rhs.trim().split('/').collect();
                if fields.len() >= 2 {
                    if let Ok(v) = fields[1].split_whitespace().next().unwrap_or("").parse::<f64>() {
                        avg = v;
                    }
                }
            }
        }
    }
    PingResult {
        success: loss < 100.0,
        loss_pct: loss,
        avg_ms: avg,
    }
}

/// Start one-shot iperf3 server (`-1` exits after one test). Returns child handle.
pub fn start_iperf_server(port: u16) -> Result<Child> {
    let _ = sysrun::run(&cmd(&["pkill", "-9", "iperf3"]));
    thread::sleep(Duration::from_millis(150));
    let child = Command::new("iperf3")
        .args(["-s", "-p", &port.to_string(), "-1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn iperf3 -s (is iperf3 installed?)")?;
    // Give it a moment to bind.
    thread::sleep(Duration::from_millis(200));
    Ok(child)
}

/// Run iperf3 client; returns bits/s from JSON `sum_sent` / `sum_received`.
pub fn run_iperf_client(
    target: &str,
    port: u16,
    duration_sec: u64,
    bind: Option<&str>,
) -> Result<f64> {
    let mut args = vec![
        "iperf3".into(),
        "-c".into(),
        target.into(),
        "-p".into(),
        port.to_string(),
        "-t".into(),
        duration_sec.to_string(),
        "-P".into(),
        "2".into(),
        "-J".into(),
    ];
    if let Some(b) = bind {
        if b != "0.0.0.0" && b != "127.0.0.1" {
            args.push("-B".into());
            args.push(b.into());
        }
    }
    let out = Command::new(&args[0])
        .args(&args[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("run iperf3 client")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("iperf3 client failed: {}", err.trim());
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_iperf_json(&stdout).context("parse iperf3 JSON")
}

fn parse_iperf_json(stdout: &str) -> Option<f64> {
    // Minimal extraction without serde: "bits_per_second": 12345.6
    // Prefer sum_sent, then sum_received.
    let mut best = None;
    for key in ["sum_sent", "sum_received", "sum"] {
        if let Some(idx) = stdout.find(key) {
            let region = &stdout[idx..idx.saturating_add(400).min(stdout.len())];
            if let Some(bps_idx) = region.find("bits_per_second") {
                let tail = &region[bps_idx..];
                if let Some(colon) = tail.find(':') {
                    let num = tail[colon + 1..]
                        .trim()
                        .split(|c: char| c == ',' || c == '}' || c.is_whitespace())
                        .next()
                        .unwrap_or("");
                    if let Ok(v) = num.parse::<f64>() {
                        if v > 0.0 {
                            best = Some(v);
                            break;
                        }
                    }
                }
            }
        }
    }
    best
}

/// Pure-TCP sink (server): accept and discard for `duration_sec + 2`.
pub fn run_tcp_sink(port: u16, duration_sec: u64) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))?;
    listener.set_nonblocking(true)?;
    let stop = Instant::now() + Duration::from_secs(duration_sec + 3);
    let mut buf = [0u8; 65536];
    println!("[*] TCP sink on :{port} for ~{duration_sec}s (iperf3 fallback)");
    while Instant::now() < stop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_nodelay(true);
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                thread::spawn(move || {
                    let end = Instant::now() + Duration::from_secs(duration_sec + 2);
                    while Instant::now() < end {
                        match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
    Ok(())
}

/// Pure-TCP flood client; returns approximate bits/s.
pub fn run_tcp_flood(target: &str, port: u16, duration_sec: u64, streams: u32) -> f64 {
    let stop = Arc::new(AtomicBool::new(false));
    let total = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for _ in 0..streams {
        let stop = Arc::clone(&stop);
        let total = Arc::clone(&total);
        let addr = format!("{target}:{port}");
        handles.push(thread::spawn(move || {
            let Ok(mut s) = TcpStream::connect(&addr) else { return };
            let _ = s.set_nodelay(true);
            let _ = s.set_write_timeout(Some(Duration::from_millis(500)));
            let payload = vec![b'X'; 64 * 1024];
            while !stop.load(Ordering::Relaxed) {
                match s.write_all(&payload) {
                    Ok(()) => {
                        total.fetch_add(payload.len() as u64, Ordering::Relaxed);
                    }
                    Err(_) => break,
                }
            }
        }));
    }
    let t0 = Instant::now();
    thread::sleep(Duration::from_secs(duration_sec));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    let elapsed = t0.elapsed().as_secs_f64().max(0.001);
    let bytes = total.load(Ordering::Relaxed) as f64;
    (bytes * 8.0) / elapsed
}

/// Full client-side benchmark against an already-up tunnel peer.
pub fn run_client_bench(
    protocol: &str,
    target: &str,
    bind: Option<&str>,
    duration_sec: u64,
    port: u16,
) -> BenchResult {
    println!("[*] ping {target} ...");
    let pr = ping(target, bind, 5);
    if !pr.success {
        println!("[!] peer not reachable (100% loss)");
        return BenchResult {
            protocol: protocol.into(),
            target: target.into(),
            bind: bind.map(|s| s.into()),
            ping: pr,
            bps: 0.0,
            method: "none",
        };
    }
    println!(
        "[+] rtt avg {:.2} ms, loss {:.1}%",
        pr.avg_ms, pr.loss_pct
    );

    if have_iperf3() {
        println!("[*] iperf3 -c {target} -t {duration_sec} ...");
        match run_iperf_client(target, port, duration_sec, bind) {
            Ok(bps) => {
                let r = BenchResult {
                    protocol: protocol.into(),
                    target: target.into(),
                    bind: bind.map(|s| s.into()),
                    ping: pr,
                    bps,
                    method: "iperf3",
                };
                println!("[+] {}", r.summary_line());
                return r;
            }
            Err(e) => {
                println!("[!] iperf3 failed ({e}); falling back to TCP flood");
            }
        }
    } else {
        println!("[!] iperf3 not found; using TCP flood fallback");
    }

    let bps = run_tcp_flood(target, port, duration_sec, 2);
    let r = BenchResult {
        protocol: protocol.into(),
        target: target.into(),
        bind: bind.map(|s| s.into()),
        ping: pr,
        bps,
        method: "tcp-fallback",
    };
    println!("[+] {}", r.summary_line());
    r
}

/// Server-side listener for a single benchmark run.
pub fn run_server_bench(port: u16, duration_sec: u64) -> Result<()> {
    if have_iperf3() {
        println!("[*] iperf3 -s -p {port} -1  (one shot)");
        let mut child = start_iperf_server(port)?;
        // Wait up to duration+30s for a client.
        let limit = Duration::from_secs(duration_sec + 30);
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    println!("[+] iperf3 server finished ({status})");
                    break;
                }
                Ok(None) if start.elapsed() > limit => {
                    let _ = child.kill();
                    println!("[!] timed out waiting for client");
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(200)),
                Err(e) => bail!("wait iperf3: {e}"),
            }
        }
    } else {
        run_tcp_sink(port, duration_sec)?;
    }
    Ok(())
}

/// Rank a list of results by throughput then latency.
pub fn rank(results: &mut [BenchResult]) {
    results.sort_by(|a, b| {
        b.bps
            .partial_cmp(&a.bps)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                a.ping
                    .avg_ms
                    .partial_cmp(&b.ping.avg_ms)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
}

pub fn print_table(results: &[BenchResult]) {
    println!("\n=== Benchmark ranking ===");
    println!(
        "{:<4} {:<14} {:>10} {:>10} {:>8} {}",
        "#", "Protocol", "Mb/s", "RTT ms", "Loss%", "Method"
    );
    for (i, r) in results.iter().enumerate() {
        println!(
            "{:<4} {:<14} {:>10.2} {:>10.1} {:>7.1}% {}",
            i + 1,
            r.protocol,
            r.mbps(),
            r.ping.avg_ms,
            r.ping.loss_pct,
            r.method
        );
    }
}
