//! Interactive tunnel manager menu (integrated into `khaymali tunnels`).

use super::config::ensure_state_dir;
use super::drivers::{primary_ip, TunnelDriver};
use super::kmlight::{self, KmLightConfig};
use super::persistence::{self, SavedTunnel};
use super::registry::{by_id, PROTOCOLS};
use super::cleanup::auto_cleanup;
use crate::sysrun;
use anyhow::Result;
use std::io::{self, Write};

fn read_line(prompt: &str) -> String {
    print!("{prompt}");
    let _ = io::stdout().flush();
    let mut s = String::new();
    let _ = io::stdin().read_line(&mut s);
    s.trim().to_string()
}

fn need_root() -> Result<()> {
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        anyhow::bail!("Root privileges required. Run with sudo.");
    }
    Ok(())
}

fn banner() {
    println!("\n==================================");
    println!(" Khaymali Tunnels  (core-integrated)");
    println!(" Classic kernel tunnels + Light");
    println!("==================================");
    println!("1) List protocols");
    println!("2) Create tunnel");
    println!("3) Khaymali Light setup");
    println!("4) Light status / restart");
    println!("5) Restore persisted tunnels");
    println!("6) Install boot restore service");
    println!("7) Optimize network (sysctl + BBR/fq)");
    println!("8) QoS on tunnel iface (tc)");
    println!("9) Benchmark peer (iperf3 / TCP)");
    println!("c) Clean temporary interfaces");
    println!("0) Exit");
    println!("----------------------------------");
}

pub fn run_menu() -> Result<()> {
    need_root()?;
    ensure_state_dir().ok();
    loop {
        banner();
        match read_line("Select: ").as_str() {
            "1" => list_protocols(),
            "2" => create_tunnel()?,
            "3" => light_setup()?,
            "4" => light_manage(),
            "5" => persistence::restore_all()?,
            "6" => persistence::install_restore_service()?,
            "7" => optimize_sysctl(),
            "8" => run_qos_interactive()?,
            "9" => run_bench_interactive()?,
            "c" | "C" => auto_cleanup(true),
            "0" | "q" | "Q" => {
                println!("Bye.");
                break;
            }
            _ => println!("Unknown option."),
        }
    }
    Ok(())
}

fn list_protocols() {
    println!("\nSupported protocols:");
    for (i, p) in PROTOCOLS.iter().enumerate() {
        let port = p.port.map(|x| x.to_string()).unwrap_or_else(|| "-".into());
        println!("  {:>2}. {:<16} layer={} port={}", i + 1, p.name, p.layer, port);
    }
}

fn create_tunnel() -> Result<()> {
    list_protocols();
    let id = read_line("Protocol id (gre, vxlan, wireguard, ...): ");
    let proto = match by_id(&id) {
        Some(p) => p,
        None => {
            println!("Unknown protocol.");
            return Ok(());
        }
    };
    if proto.id == "kmlight" {
        return light_setup();
    }
    let remote = read_line("Remote IP: ");
    let local = {
        let s = read_line(&format!("Local bind IP [{}]: ", primary_ip().unwrap_or_default()));
        if s.is_empty() {
            primary_ip().unwrap_or_else(|| "0.0.0.0".into())
        } else {
            s
        }
    };
    let my_ip = {
        let s = read_line("Inner local IP [10.99.1.1]: ");
        if s.is_empty() { "10.99.1.1".into() } else { s }
    };
    let peer_ip = {
        let s = read_line("Inner peer IP [10.99.1.2]: ");
        if s.is_empty() { "10.99.1.2".into() } else { s }
    };
    let mtu: u32 = read_line("MTU [1400]: ").parse().unwrap_or(1400);
    let dev = format!("{}_0", proto.id);
    println!("[*] Creating {} on {} ...", proto.name, dev);
    TunnelDriver::setup(proto.id, &dev, &local, &remote, &my_ip, &peer_ip, mtu, proto.port)?;
    persistence::add_tunnel(SavedTunnel {
        proto: proto.id.into(),
        dev: dev.clone(),
        local,
        remote: remote.clone(),
        my_ip,
        peer_ip,
        mtu,
        port: proto.port,
    })?;
    println!("[+] Tunnel {dev} is up. Mirror settings on the remote (swap inner IPs).");
    Ok(())
}

fn light_setup() -> Result<()> {
    let role = read_line("Role [server/client]: ");
    let role = if role == "client" { "client" } else { "server" };
    let secret = {
        let s = read_line("Shared key (blank = auto): ");
        if s.is_empty() { kmlight::gen_secret() } else { s }
    };
    let tun_name = {
        let s = read_line("Interface [kmlight0]: ");
        if s.is_empty() { "kmlight0".into() } else { s }
    };
    let tun_ip = {
        let s = read_line("Inner IP [10.200.0.1]: ");
        if s.is_empty() { "10.200.0.1".into() } else { s }
    };
    let peer_ip = {
        let s = read_line("Peer inner IP [10.200.0.2]: ");
        if s.is_empty() { "10.200.0.2".into() } else { s }
    };
    let mtu: u32 = read_line("MTU [1400]: ").parse().unwrap_or(1400);
    let mut cfg = KmLightConfig {
        role: role.into(),
        listen: String::new(),
        remote: String::new(),
        local: String::new(),
        secret: secret.clone(),
        tun_name,
        tun_ip,
        peer_ip,
        prefix: 30,
        mtu,
        keepalive: 3,
    };
    if role == "server" {
        let port = {
            let s = read_line("Listen port [2096]: ");
            if s.is_empty() { "2096".into() } else { s }
        };
        let bind = {
            let s = read_line("Listen address [0.0.0.0]: ");
            if s.is_empty() { "0.0.0.0".into() } else { s }
        };
        cfg.listen = format!("{bind}:{port}");
    } else {
        cfg.remote = read_line("Remote host:port: ");
        cfg.local = read_line("Local bind IP (optional): ");
    }
    kmlight::save_config(&cfg)?;
    kmlight::install_service()?;
    println!("[+] Khaymali Light configured. Secret: {secret}");
    Ok(())
}

fn light_manage() {
    println!("a) status  b) restart  c) stop");
    match read_line("Light> ").as_str() {
        "a" => kmlight::service_status(),
        "b" => kmlight::service_restart(),
        "c" => kmlight::service_stop(),
        _ => {}
    }
}

fn optimize_sysctl() {
    match super::qos::apply_host_perf() {
        Ok(_) => {}
        Err(e) => eprintln!("[!] perf apply: {e}"),
    }
}

fn run_qos_interactive() -> Result<()> {
    use super::qos::{self, QosProfile};
    let dev = read_line("Tunnel interface [kmlight0]: ");
    let dev = if dev.is_empty() { "kmlight0".into() } else { dev };
    println!("Profiles:");
    println!("  1) host only (BBR + fq sysctl)");
    println!("  2) low-latency (fq_codel on iface)");
    println!("  3) cake (best default)");
    println!("  4) cake + bandwidth limit");
    println!("  5) HTB rate limit + fq_codel");
    println!("  s) status");
    println!("  c) clear qdisc");
    match read_line("QoS> ").as_str() {
        "1" => qos::apply_profile(&dev, QosProfile::Host, None)?,
        "2" => qos::apply_profile(&dev, QosProfile::LowLatency, None)?,
        "3" => qos::apply_profile(&dev, QosProfile::Cake, None)?,
        "4" => {
            let r = read_line("Bandwidth [100mbit]: ");
            let r = if r.is_empty() { "100mbit".into() } else { r };
            qos::apply_profile(&dev, QosProfile::CakeLimited, Some(&r))?;
        }
        "5" => {
            let r = read_line("Rate [50mbit]: ");
            let r = if r.is_empty() { "50mbit".into() } else { r };
            qos::apply_profile(&dev, QosProfile::RateLimit, Some(&r))?;
        }
        "s" | "S" => qos::status(&dev),
        "c" | "C" => qos::clear(&dev)?,
        _ => println!("Unknown."),
    }
    Ok(())
}



fn run_bench_interactive() -> Result<()> {
    use super::benchmark::{self, STREAM_PORT, DEFAULT_DURATION};
    let role = read_line("Role [client/server]: ");
    if role == "server" {
        let port: u16 = read_line(&format!("Port [{STREAM_PORT}]: ")).parse().unwrap_or(STREAM_PORT);
        let dur: u64 = read_line(&format!("Duration seconds [{DEFAULT_DURATION}]: ")).parse().unwrap_or(DEFAULT_DURATION);
        return benchmark::run_server_bench(port, dur);
    }
    let target = read_line("Peer inner IP (e.g. 10.99.1.2): ");
    if target.is_empty() {
        println!("No target.");
        return Ok(());
    }
    let bind = {
        let s = read_line("Bind inner IP (optional): ");
        if s.is_empty() { None } else { Some(s) }
    };
    let proto = {
        let s = read_line("Label/protocol name [manual]: ");
        if s.is_empty() { "manual".into() } else { s }
    };
    let dur: u64 = read_line(&format!("Duration seconds [{}]: ", super::benchmark::DEFAULT_DURATION))
        .parse()
        .unwrap_or(super::benchmark::DEFAULT_DURATION);
    let port: u16 = read_line(&format!("iperf port [{}]: ", super::benchmark::STREAM_PORT))
        .parse()
        .unwrap_or(super::benchmark::STREAM_PORT);
    let r = benchmark::run_client_bench(&proto, &target, bind.as_deref(), dur, port);
    let mut list = vec![r];
    benchmark::rank(&mut list);
    benchmark::print_table(&list);
    Ok(())
}
