use crate::config::VERSION;
use crate::managers::kmlight_svc;
use crate::managers::persistence;
use crate::netinfo;
use crate::protocols::cleanup::auto_cleanup;
use crate::protocols::registry::PROTOCOLS;
use crate::protocols::drivers::TunnelDriver;
use crate::system::{check_root, install_deps, optimize_sysctl, Result};
use crate::kmlight::config::KmLightConfig;
use std::io::{self, Write};

fn read_line(prompt: &str) -> String {
    print!("{prompt}");
    let _ = io::stdout().flush();
    let mut s = String::new();
    let _ = io::stdin().read_line(&mut s);
    s.trim().to_string()
}

fn banner() {
    println!("\n==================================");
    println!(" Khaymali Manager Companion  v{VERSION}");
    println!(" Companion for the Khaymali Tunnel suite");
    println!(" Pure Rust");
    println!("==================================");
    println!("1) List protocols");
    println!("2) Create tunnel (classic)");
    println!("3) Khaymali Light setup");
    println!("4) Khaymali Light status / restart");
    println!("5) Restore persisted tunnels");
    println!("6) Install boot restore service");
    println!("7) Optimize network (sysctl)");
    println!("8) Install dependencies");
    println!("c) Clean temporary interfaces");
    println!("0) Exit");
    println!("----------------------------------");
}

pub fn main_menu() -> Result<()> {
    check_root()?;
    crate::config::ensure_state_dir().ok();
    loop {
        banner();
        match read_line("Select: ").as_str() {
            "1" => list_protocols(),
            "2" => create_tunnel_interactive()?,
            "3" => kmlight_setup()?,
            "4" => kmlight_manage(),
            "5" => persistence::restore_all()?,
            "6" => persistence::install_restore_service()?,
            "7" => optimize_sysctl(),
            "8" => install_deps(),
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

fn create_tunnel_interactive() -> Result<()> {
    list_protocols();
    let id = read_line("Protocol id (e.g. gre, vxlan, wireguard): ");
    let proto = match crate::protocols::registry::by_id(&id) {
        Some(p) => p,
        None => {
            println!("Unknown protocol.");
            return Ok(());
        }
    };
    if proto.id == "kmlight" {
        return kmlight_setup();
    }
    let remote = read_line("Remote IP: ");
    let local = read_line(&format!(
        "Local bind IP [{}]: ",
        netinfo::primary_ip().unwrap_or_default()
    ));
    let local = if local.is_empty() {
        netinfo::primary_ip().unwrap_or_else(|| "0.0.0.0".into())
    } else {
        local
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
    let port = proto.port;

    println!("[*] Creating {} on {} ...", proto.name, dev);
    TunnelDriver::setup(proto.id, &dev, &local, &remote, &my_ip, &peer_ip, mtu, port)?;
    persistence::add_tunnel(persistence::SavedTunnel {
        proto: proto.id.into(),
        dev: dev.clone(),
        local,
        remote: remote.clone(),
        my_ip,
        peer_ip,
        mtu,
        port,
    })?;
    println!("[+] Tunnel {dev} is up.");
    println!("    Remote should use local={remote} (swap inner IPs).");
    Ok(())
}

fn kmlight_setup() -> Result<()> {
    if !kmlight_svc::build_core() {
        return Ok(());
    }
    let role = read_line("Role [server/client]: ");
    let role = if role == "client" { "client" } else { "server" };
    let secret = {
        let s = read_line("Shared key (blank = auto): ");
        if s.is_empty() { kmlight_svc::gen_secret() } else { s }
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

    kmlight_svc::save_config(&cfg)?;
    kmlight_svc::install_service()?;
    println!("[+] Khaymali Light configured. Secret: {secret}");
    Ok(())
}

fn kmlight_manage() {
    println!("a) status  b) restart  c) stop  d) back");
    match read_line("Light> ").as_str() {
        "a" => kmlight_svc::service_status(),
        "b" => kmlight_svc::service_restart(),
        "c" => kmlight_svc::service_stop(),
        _ => {}
    }
}
