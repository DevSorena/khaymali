//! Tunnel Engines (FRP & Backhaul), Setup Planner, and Auto Pool (`src/engines.rs`).
//!
//! Full Rust port of Khaymali's FRP/Backhaul engine management, `backhaulconf.go`,
//! `perf_frp.go`, `perf_backhaul.go`, `setup.go`, and `setup_autopool.go`:
//!   * **FRP Manager (`frps`/`frpc`)**: generates TOML for `tcp`, `kcp`, `quic`, and `websocket`
//!     transports, optional PROXY protocol (`v1`/`v2`), per-proxy bandwidth cap (MB/s), and TCP
//!     health checks, plus systemd units managed via `sysrun`.
//!   * **Backhaul Manager (`backhaul-server`/`backhaul-client`)**: generates TOML for
//!     `tcp`, `tcpmux`, `ws`, `wss`, `wsmux`, `wssmux`, and `udp` transports; includes a
//!     purpose-built TOML parser (`parse_backhaul_conf`) supporting both flat and sectioned
//!     dialects; live `connection_pool` (1..=64) tuning; and `backhaul-udp-*` companion units
//!     for forwarding UDP alongside TCP-only transports.
//!   * **Setup Planner (`SetupRequest` / `SetupPlan`)**: end-to-end Iran & Foreign setup
//!     supporting `frp`, `backhaul`, and `gre-backhaul` with bundle generation/import and
//!     atomic rollback via `UnitSwitchTx`.
//!   * **Auto Pool (`auto_pool_for_clash` / `undo_auto_pools`)**: detects port clashes when
//!     adding a second foreign server on an already-served port and synthesizes failover
//!     load-balancer pools automatically.

use crate::carrier_swap::{CarrierChoice, UnitSwitchTx, BACKHAUL_TRANSPORTS, FRP_PROTOCOLS};
use crate::hjson::{self, Json};
use crate::setup_bundle::{self, SetupBundle};
use crate::sysrun;
use anyhow::{bail, Result};
use std::collections::BTreeSet;

pub const BH_POOL_DEFAULT: u32 = 8;
pub const BH_POOL_MIN: u32 = 1;
pub const BH_POOL_MAX: u32 = 64;
pub const PERF_BANDWIDTH_MAX_MB: u32 = 10_000;

#[derive(Clone, Debug)]
pub struct EnginePaths {
    pub frp_dir: String,
    pub backhaul_dir: String,
    pub unit_dir: String,
    pub bin_dir: String,
    pub config_dir: String,
}

impl Default for EnginePaths {
    fn default() -> Self {
        Self {
            frp_dir: "/etc/frp".into(),
            backhaul_dir: "/etc/backhaul".into(),
            unit_dir: "/etc/systemd/system".into(),
            bin_dir: "/usr/local/bin".into(),
            config_dir: "/etc/khaymali".into(),
        }
    }
}

// ============================================================================
// FRP Engine Manager (`frps` / `frpc` + `perf_frp.go`)
// ============================================================================

#[derive(Clone, Debug)]
pub struct FrpPerfOpts {
    pub proxy_protocol: String, // "off" | "v1" | "v2"
    pub bandwidth_mb: u32,      // 0 = unlimited, max 10000
    pub health_check: bool,
}

impl Default for FrpPerfOpts {
    fn default() -> Self {
        Self {
            proxy_protocol: "off".into(),
            bandwidth_mb: 0,
            health_check: false,
        }
    }
}

impl FrpPerfOpts {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.proxy_protocol.as_str(), "off" | "v1" | "v2") {
            bail!("invalid proxy_protocol '{}' (expected off|v1|v2)", self.proxy_protocol);
        }
        if self.bandwidth_mb > PERF_BANDWIDTH_MAX_MB {
            bail!("bandwidth_mb exceeds maximum ({PERF_BANDWIDTH_MAX_MB} MB/s)");
        }
        Ok(())
    }

    pub fn render_proxy_extras(&self, is_tcp: bool) -> String {
        let mut s = String::new();
        if is_tcp && (self.proxy_protocol == "v1" || self.proxy_protocol == "v2") {
            s.push_str(&format!("transport.proxyProtocolVersion = \"{}\"\n", self.proxy_protocol));
        }
        if self.bandwidth_mb > 0 {
            s.push_str(&format!(
                "transport.bandwidthLimit = \"{}MB\"\ntransport.bandwidthLimitMode = \"client\"\n",
                self.bandwidth_mb
            ));
        }
        if is_tcp && self.health_check {
            s.push_str("healthCheck.type = \"tcp\"\nhealthCheck.timeoutSeconds = 3\nhealthCheck.maxFailed = 3\nhealthCheck.intervalSeconds = 10\n");
        }
        s
    }
}

#[derive(Clone, Debug)]
pub struct FrpConfig {
    pub unit_suffix: String, // "" for main ("frps"/"frpc"), "-2" for peer 2
    pub bind_addr: String,   // Iran side bind (e.g. "0.0.0.0" or "10.10.0.1")
    pub server_addr: String, // Foreign side dial address (Iran GRE or public IP)
    pub bind_port: u16,
    pub transport: String,   // tcp | kcp | quic | websocket
    pub token: String,
    pub ports: Vec<u16>,
    pub perf: FrpPerfOpts,
}

impl FrpConfig {
    pub fn validate(&self) -> Result<()> {
        if !FRP_PROTOCOLS.contains(&self.transport.as_str()) {
            bail!("unsupported FRP transport '{}' (expected {})", self.transport, FRP_PROTOCOLS.join(", "));
        }
        if self.bind_port == 0 {
            bail!("FRP bind_port must be > 0");
        }
        if self.token.is_empty() {
            bail!("FRP auth token cannot be empty");
        }
        self.perf.validate()
    }

    pub fn render_frps_toml(&self) -> Result<String> {
        self.validate()?;
        let bind = if self.bind_addr.is_empty() { "0.0.0.0" } else { &self.bind_addr };
        let mut s = format!(
            "bindAddr = \"{bind}\"\nbindPort = {}\nauth.method = \"token\"\nauth.token = \"{}\"\n",
            self.bind_port, self.token
        );
        match self.transport.as_str() {
            "kcp" => s.push_str(&format!("kcpBindPort = {}\n", self.bind_port)),
            "quic" => s.push_str(&format!("quicBindPort = {}\n", self.bind_port)),
            _ => {}
        }
        s.push_str("transport.tcpMux = true\ntransport.tcpMuxKeepaliveInterval = 20\n");
        Ok(s)
    }

    pub fn render_frpc_toml(&self) -> Result<String> {
        self.validate()?;
        if self.server_addr.trim().is_empty() {
            bail!("frpc server_addr is required");
        }
        let mut s = format!(
            "serverAddr = \"{}\"\nserverPort = {}\nauth.method = \"token\"\nauth.token = \"{}\"\ntransport.protocol = \"{}\"\ntransport.tcpMux = true\n",
            self.server_addr, self.bind_port, self.token, self.transport
        );
        for &p in &self.ports {
            let tcp_extra = self.perf.render_proxy_extras(true);
            let udp_extra = self.perf.render_proxy_extras(false);
            s.push_str(&format!(
                "\n[[proxies]]\nname = \"tcp_{p}\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = {p}\nremotePort = {p}\n{tcp_extra}\n[[proxies]]\nname = \"udp_{p}\"\ntype = \"udp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = {p}\nremotePort = {p}\n{udp_extra}"
            ));
        }
        Ok(s)
    }

    pub fn render_unit(&self, is_server: bool, paths: &EnginePaths) -> (String, String, String) {
        let role = if is_server { "frps" } else { "frpc" };
        let unit_name = format!("{role}{}.service", self.unit_suffix);
        let conf_path = format!("{}/{role}{}.toml", paths.frp_dir, self.unit_suffix);
        let bin = format!("{}/{role}", paths.bin_dir);
        let body = format!(
            "[Unit]\nDescription=Khaymali {role}{}\nAfter=network-online.target\nWants=network-online.target\n\n\
[Service]\nType=simple\nExecStart={bin} -c {conf_path}\nRestart=always\nRestartSec=2\nLimitNOFILE=65535\n\n\
[Install]\nWantedBy=multi-user.target\n",
            self.unit_suffix
        );
        (unit_name, conf_path, body)
    }
}

// ============================================================================
// Backhaul Engine Manager (`backhaul-server` / `backhaul-client` + `backhaulconf.go`)
// ============================================================================

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedBackhaulConf {
    pub transport: String,
    pub remote_addr: String,
    pub bind_addr: String,
    pub token: String,
    pub ports: Vec<String>,
    pub connection_pool: u32,
}

fn strip_toml_comment(s: &str) -> &str {
    let mut quote: Option<u8> = None;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match quote {
            Some(q) => {
                if c == b'\\' && q == b'"' {
                    i += 1;
                } else if c == q {
                    quote = None;
                }
            }
            None => {
                if c == b'"' || c == b'\'' {
                    quote = Some(c);
                } else if c == b'#' {
                    return &s[..i];
                }
            }
        }
        i += 1;
    }
    s
}

fn toml_unquote(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

fn split_toml_array(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut quote: Option<u8> = None;
    let mut start = 0;
    let bytes = inner.as_bytes();
    for i in 0..bytes.len() {
        let c = bytes[i];
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == b'"' || c == b'\'' {
                    quote = Some(c);
                } else if c == b',' {
                    let v = toml_unquote(&inner[start..i]);
                    if !v.is_empty() {
                        out.push(v);
                    }
                    start = i + 1;
                }
            }
        }
    }
    let tail = toml_unquote(&inner[start..]);
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

/// Parses both flat (`[server]`/`[client]`) and sectioned (`[transport] type=`) Backhaul TOML configs.
pub fn parse_backhaul_conf(data: &str) -> ParsedBackhaulConf {
    let mut c = ParsedBackhaulConf::default();
    let mut section = String::new();
    let lines: Vec<&str> = data.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = strip_toml_comment(lines[i]).trim();
        if line.is_empty() {
            i += 1;
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') && !line.contains('=') {
            section = line.trim_matches(|ch| ch == '[' || ch == ']' || ch == ' ' || ch == '\t').to_ascii_lowercase();
            i += 1;
            continue;
        }
        let Some((k_raw, v_raw)) = line.split_once('=') else {
            i += 1;
            continue;
        };
        let key = k_raw.trim().to_ascii_lowercase();
        let mut val = v_raw.trim().to_string();
        let is_arr = val.starts_with('[');
        let mut arr = Vec::new();
        if is_arr {
            while !val.contains(']') && i + 1 < lines.len() {
                i += 1;
                val.push(' ');
                val.push_str(strip_toml_comment(lines[i]).trim());
            }
            let end = val.rfind(']').unwrap_or(val.len());
            arr = split_toml_array(&val[1..end]);
        }
        match key.as_str() {
            "transport" if !is_arr && section != "transport" => c.transport = toml_unquote(&val),
            "type" if section == "transport" => c.transport = toml_unquote(&val),
            "remote_addr" => c.remote_addr = toml_unquote(&val),
            "bind_addr" => c.bind_addr = toml_unquote(&val),
            "token" => c.token = toml_unquote(&val),
            "connection_pool" => c.connection_pool = toml_unquote(&val).parse().unwrap_or(0),
            "ports" | "mapping" if is_arr => c.ports.extend(arr),
            _ => {}
        }
        i += 1;
    }
    c
}

#[derive(Clone, Debug)]
pub struct BackhaulConfig {
    pub unit_suffix: String, // "" for main, "-2" for peer 2
    pub bind_addr: String,   // e.g. "0.0.0.0:3080" or "10.10.0.1:3080"
    pub remote_addr: String, // e.g. "198.51.100.10:3080" or "[2001:db8::1]:3080"
    pub transport: String,   // tcp | tcpmux | ws | wss | wsmux | wssmux | udp
    pub token: String,
    pub raw_ports: Vec<String>,
    pub connection_pool: u32,
    pub nodelay: bool,
    pub keepalive_period: u32,
    pub accept_udp: bool,
    pub udp_companion_port: u16,
}

impl BackhaulConfig {
    pub fn validate(&self) -> Result<()> {
        if !BACKHAUL_TRANSPORTS.contains(&self.transport.as_str()) {
            bail!(
                "unsupported Backhaul transport '{}' (expected {})",
                self.transport,
                BACKHAUL_TRANSPORTS.join(", ")
            );
        }
        if self.token.is_empty() {
            bail!("Backhaul token cannot be empty");
        }
        Ok(())
    }

    pub fn effective_pool(&self) -> u32 {
        if (BH_POOL_MIN..=BH_POOL_MAX).contains(&self.connection_pool) {
            self.connection_pool
        } else {
            BH_POOL_DEFAULT
        }
    }

    pub fn render_server_toml(&self) -> Result<String> {
        self.validate()?;
        let ports_toml = self
            .raw_ports
            .iter()
            .map(|p| format!("  \"{}\"", p.replace('"', "")))
            .collect::<Vec<_>>()
            .join(",\n");
        let mut s = format!(
            "[server]\nbind_addr = \"{}\"\ntransport = \"{}\"\ntoken = \"{}\"\nkeepalive_period = {}\nnodelay = {}\n",
            self.bind_addr,
            self.transport,
            self.token,
            if self.keepalive_period == 0 { 75 } else { self.keepalive_period },
            self.nodelay
        );
        if self.transport == "tcpmux" || self.transport == "wsmux" || self.transport == "wssmux" {
            s.push_str("mux_con = 8\nmux_version = 2\n");
        }
        if self.transport == "tcp" || self.transport == "udp" {
            s.push_str("channel_size = 2048\n");
        }
        s.push_str("ports = [\n");
        if !ports_toml.is_empty() {
            s.push_str(&ports_toml);
            s.push('\n');
        }
        s.push_str("]\n");
        Ok(s)
    }

    pub fn render_client_toml(&self) -> Result<String> {
        self.validate()?;
        if self.remote_addr.trim().is_empty() {
            bail!("Backhaul client remote_addr is required");
        }
        let mut s = format!(
            "[client]\nremote_addr = \"{}\"\ntransport = \"{}\"\ntoken = \"{}\"\nconnection_pool = {}\nretry_interval = 3\nnodelay = {}\nkeepalive_period = {}\n",
            self.remote_addr,
            self.transport,
            self.token,
            self.effective_pool(),
            self.nodelay,
            if self.keepalive_period == 0 { 75 } else { self.keepalive_period }
        );
        if self.transport == "tcpmux" || self.transport == "wsmux" || self.transport == "wssmux" {
            s.push_str("mux_version = 2\n");
        }
        Ok(s)
    }

    /// Renders a companion UDP-transport Backhaul config for TCP-only transports (Khaymali `backhaul-udp-*`).
    pub fn render_udp_companion_toml(&self, is_server: bool) -> Result<Option<String>> {
        if !self.accept_udp || self.transport == "udp" || self.udp_companion_port == 0 {
            return Ok(None);
        }
        let mut c = self.clone();
        c.transport = "udp".into();
        c.accept_udp = false;
        if is_server {
            c.bind_addr = replace_host_port(&self.bind_addr, self.udp_companion_port);
            Ok(Some(c.render_server_toml()?))
        } else {
            c.remote_addr = replace_host_port(&self.remote_addr, self.udp_companion_port);
            Ok(Some(c.render_client_toml()?))
        }
    }

    pub fn render_unit(&self, is_server: bool, is_udp_companion: bool, paths: &EnginePaths) -> (String, String, String) {
        let base = match (is_server, is_udp_companion) {
            (true, false) => "backhaul-server",
            (false, false) => "backhaul-client",
            (true, true) => "backhaul-udp-server",
            (false, true) => "backhaul-udp-client",
        };
        let unit_name = format!("{base}{}.service", self.unit_suffix);
        let conf_path = format!("{}/{base}{}.toml", paths.backhaul_dir, self.unit_suffix);
        let bin = format!("{}/backhaul", paths.bin_dir);
        let body = format!(
            "[Unit]\nDescription=Khaymali {base}{}\nAfter=network-online.target\nWants=network-online.target\n\n\
[Service]\nType=simple\nExecStart={bin} -c {conf_path}\nRestart=always\nRestartSec=2\nLimitNOFILE=65535\n\n\
[Install]\nWantedBy=multi-user.target\n",
            self.unit_suffix
        );
        (unit_name, conf_path, body)
    }
}

/// Updates `connection_pool = N` inside a Backhaul client TOML file cleanly (Khaymali `applyBackhaulPool`).
pub fn rewrite_backhaul_pool_toml(src: &str, new_pool: u32) -> Result<String> {
    if !(BH_POOL_MIN..=BH_POOL_MAX).contains(&new_pool) {
        bail!("connection_pool must be within {BH_POOL_MIN}..={BH_POOL_MAX}");
    }
    let mut found = false;
    let mut out = Vec::new();
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("connection_pool") && trimmed.contains('=') {
            let indent_len = line.len() - trimmed.len();
            out.push(format!("{}connection_pool = {new_pool}", &line[..indent_len]));
            found = true;
        } else {
            out.push(line.to_string());
        }
    }
    if !found {
        bail!("Backhaul config has no connection_pool line");
    }
    let mut joined = out.join("\n");
    if src.ends_with('\n') {
        joined.push('\n');
    }
    Ok(joined)
}

fn replace_host_port(addr: &str, new_port: u16) -> String {
    if let Some(idx) = addr.rfind(':') {
        format!("{}:{new_port}", &addr[..idx])
    } else {
        format!("{addr}:{new_port}")
    }
}

fn format_host_port(ip: &str, port: u16) -> String {
    if ip.contains(':') && !ip.starts_with('[') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

// ============================================================================
// Setup Request & Transactional Setup Executor (Iran & Foreign)
// ============================================================================

#[derive(Clone, Debug)]
pub struct SetupRequest {
    pub role: String,       // "iran" | "foreign"
    pub engine: String,     // "frp" | "backhaul" | "gre-backhaul"
    pub transport: String,
    pub local_pub: String,
    pub remote_pub: String,
    pub ctrl_port: u16,
    pub local_gre: String,
    pub peer_gre: String,
    pub token: String,
    pub raw_ports: Vec<String>,
    pub accept_udp: bool,
    pub udp_companion_port: u16,
    pub connection_pool: u32,
    pub peer_id: u32,
    pub frp_perf: FrpPerfOpts,
    pub fou_port1: u16,
    pub fou_port2: u16,
}

impl SetupRequest {
    /// Creates a Foreign setup request directly from a parsed `hsh1_`/`bh1_`/`gh1_` bundle.
    pub fn from_bundle(b: &SetupBundle, extra_ports: Option<&str>) -> Self {
        let raw_ports = if !b.raw_ports.is_empty() {
            b.raw_ports.clone()
        } else if let Some(spec) = extra_ports {
            setup_bundle::parse_raw_ports(spec)
        } else {
            b.ports.iter().map(|p| p.to_string()).collect()
        };
        let (f1, f2) = if b.fou_ports.len() >= 2 {
            (b.fou_ports[0], b.fou_ports[1])
        } else {
            (443, 55555)
        };
        Self {
            role: "foreign".into(),
            engine: b.engine.clone(),
            transport: b.transport.clone(),
            local_pub: String::new(),
            remote_pub: b.iran_pub.clone(),
            ctrl_port: b.ctrl_port,
            local_gre: b.foreign_gre.clone(),
            peer_gre: b.iran_gre.clone(),
            token: b.token.clone(),
            raw_ports,
            accept_udp: b.udp,
            udp_companion_port: b.udp_port,
            connection_pool: BH_POOL_DEFAULT,
            peer_id: 0,
            frp_perf: FrpPerfOpts::default(),
            fou_port1: f1,
            fou_port2: f2,
        }
    }

    pub fn numeric_ports(&self) -> Vec<u16> {
        setup_bundle::extract_numeric_ports(&self.raw_ports)
    }

    pub fn unit_suffix(&self) -> String {
        if self.peer_id == 0 {
            String::new()
        } else {
            format!("-{}", self.peer_id)
        }
    }

    /// Generates the setup bundle string to paste onto the foreign server.
    pub fn make_foreign_bundle(&self) -> Result<String> {
        let choice = CarrierChoice::parse(&format!("{}:{}", self.engine, self.transport))?;
        let ports = self.numeric_ports();
        let bh_tr = setup_bundle::backhaul_bundle_transport(
            &choice.transport,
            if self.accept_udp { self.udp_companion_port } else { 0 },
        );
        Ok(match choice.engine.as_str() {
            "backhaul" => setup_bundle::make_backhaul_bundle(
                &self.local_pub,
                self.ctrl_port,
                &bh_tr,
                &self.token,
                &self.raw_ports,
            ),
            "gre-backhaul" => setup_bundle::make_gre_backhaul_bundle(
                &self.local_pub,
                self.ctrl_port,
                &self.local_gre,
                &self.peer_gre,
                &bh_tr,
                &self.token,
                &self.raw_ports,
            ),
            _ => setup_bundle::make_frp_bundle(
                &self.local_pub,
                self.ctrl_port,
                &self.local_gre,
                &self.peer_gre,
                &self.token,
                &ports,
                &choice.transport,
                self.fou_port1,
                self.fou_port2,
            ),
        })
    }
}

#[derive(Clone, Debug)]
pub struct SetupOutput {
    pub unit_names: Vec<String>,
    pub config_paths: Vec<String>,
    pub foreign_bundle: Option<String>,
}

/// Executes Iran or Foreign setup transactionally using `UnitSwitchTx` and `sysrun`.
pub fn apply_setup(req: &SetupRequest, paths: &EnginePaths) -> Result<SetupOutput> {
    let is_iran = match req.role.trim().to_ascii_lowercase().as_str() {
        "iran" | "local" | "server" => true,
        "foreign" | "remote" | "client" => false,
        other => bail!("invalid setup role '{other}' (expected iran|foreign)"),
    };
    let choice = CarrierChoice::parse(&format!("{}:{}", req.engine, req.transport))?;
    let suffix = req.unit_suffix();
    let ports = req.numeric_ports();
    let all_svcs = vec![
        format!("frps{suffix}"),
        format!("frpc{suffix}"),
        format!("backhaul-server{suffix}"),
        format!("backhaul-client{suffix}"),
        format!("backhaul-udp-server{suffix}"),
        format!("backhaul-udp-client{suffix}"),
    ];
    let mut tx = UnitSwitchTx::begin(all_svcs, Some("gre-tunnel".into()));
    let mut started_units = Vec::new();
    let mut config_paths = Vec::new();

    let result: Result<()> = (|| {
        match choice.engine.as_str() {
            "frp" => {
                let bind = if !req.local_gre.is_empty() {
                    req.local_gre.clone()
                } else {
                    "0.0.0.0".into()
                };
                let server_addr = if !req.peer_gre.is_empty() {
                    req.peer_gre.clone()
                } else {
                    req.remote_pub.clone()
                };
                let fc = FrpConfig {
                    unit_suffix: suffix.clone(),
                    bind_addr: bind,
                    server_addr,
                    bind_port: req.ctrl_port,
                    transport: choice.transport.clone(),
                    token: req.token.clone(),
                    ports: ports.clone(),
                    perf: req.frp_perf.clone(),
                };
                let toml = if is_iran {
                    fc.render_frps_toml()?
                } else {
                    fc.render_frpc_toml()?
                };
                let (unit_file, conf_path, unit_body) = fc.render_unit(is_iran, paths);
                tx.write_file(&conf_path, toml.as_bytes())?;
                tx.write_file(&format!("{}/{unit_file}", paths.unit_dir), unit_body.as_bytes())?;
                let svc = unit_file.trim_end_matches(".service").to_string();
                let _ = sysrun::run(&crate::v!["systemctl", "daemon-reload"]);
                tx.stop_unused(&[svc.as_str()]);
                tx.start_and_verify(&svc)?;
                started_units.push(svc);
                config_paths.push(conf_path);
            }
            "backhaul" | "gre-backhaul" => {
                let bind_ip = if choice.needs_gre() && !req.local_gre.is_empty() {
                    req.local_gre.as_str()
                } else {
                    "0.0.0.0"
                };
                let dial_ip = if choice.needs_gre() && !req.peer_gre.is_empty() {
                    req.peer_gre.as_str()
                } else {
                    req.remote_pub.as_str()
                };
                let bh = BackhaulConfig {
                    unit_suffix: suffix.clone(),
                    bind_addr: format_host_port(bind_ip, req.ctrl_port),
                    remote_addr: format_host_port(dial_ip, req.ctrl_port),
                    transport: choice.transport.clone(),
                    token: req.token.clone(),
                    raw_ports: req.raw_ports.clone(),
                    connection_pool: req.connection_pool,
                    nodelay: true,
                    keepalive_period: 75,
                    accept_udp: req.accept_udp,
                    udp_companion_port: req.udp_companion_port,
                };
                let toml = if is_iran {
                    bh.render_server_toml()?
                } else {
                    bh.render_client_toml()?
                };
                let (unit_file, conf_path, unit_body) = bh.render_unit(is_iran, false, paths);
                tx.write_file(&conf_path, toml.as_bytes())?;
                tx.write_file(&format!("{}/{unit_file}", paths.unit_dir), unit_body.as_bytes())?;
                let main_svc = unit_file.trim_end_matches(".service").to_string();
                config_paths.push(conf_path);

                let mut keep = vec![main_svc.clone()];
                if let Some(udp_toml) = bh.render_udp_companion_toml(is_iran)? {
                    let (u_unit, u_conf, u_body) = bh.render_unit(is_iran, true, paths);
                    tx.write_file(&u_conf, udp_toml.as_bytes())?;
                    tx.write_file(&format!("{}/{u_unit}", paths.unit_dir), u_body.as_bytes())?;
                    keep.push(u_unit.trim_end_matches(".service").to_string());
                    config_paths.push(u_conf);
                }

                let _ = sysrun::run(&crate::v!["systemctl", "daemon-reload"]);
                let keep_refs: Vec<&str> = keep.iter().map(|s| s.as_str()).collect();
                tx.stop_unused(&keep_refs);
                for svc in &keep {
                    tx.start_and_verify(svc)?;
                    started_units.push(svc.clone());
                }
            }
            other => bail!("setup does not manage engine '{other}'"),
        }

        if is_iran {
            let mut open = ports.clone();
            if req.ctrl_port > 0 && !open.contains(&req.ctrl_port) {
                open.push(req.ctrl_port);
            }
            if req.accept_udp && req.udp_companion_port > 0 && !open.contains(&req.udp_companion_port) {
                open.push(req.udp_companion_port);
            }
            let _ = setup_bundle::allow_ufw_tunnel_ports(
                &open,
                &format!("{}/ufw.opened", paths.config_dir),
            );
        }
        Ok(())
    })();

    if let Err(e) = result {
        tx.rollback();
        return Err(e);
    }

    let foreign_bundle = if is_iran && !req.local_pub.is_empty() {
        Some(req.make_foreign_bundle()?)
    } else {
        None
    };

    Ok(SetupOutput {
        unit_names: started_units,
        config_paths,
        foreign_bundle,
    })
}

// ============================================================================
// Auto Pool on Port Clash (Khaymali `setup_autopool.go`)
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutoPoolLink {
    pub id: u32,
    pub name: String,
    pub remote: String,
    pub engine: String,
    pub ports: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LbMember {
    pub link_id: u32,
    pub remote: String,
    pub weight: u32,
    pub priority: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LbPool {
    pub port: u16,
    pub proto: String, // "tcp" | "udp" | "both"
    pub mode: String,  // "failover" | "weighted"
    pub members: Vec<LbMember>,
}

impl LbPool {
    pub fn to_json(&self) -> Json {
        let members: Vec<Json> = self
            .members
            .iter()
            .map(|m| {
                Json::obj()
                    .set("link", m.link_id)
                    .set("remote", m.remote.clone())
                    .set("weight", m.weight)
                    .set("priority", m.priority)
            })
            .collect();
        Json::obj()
            .set("port", self.port)
            .set("proto", self.proto.clone())
            .set("mode", self.mode.clone())
            .set("members", members)
    }
}

/// Synthesizes failover LB pools for every requested port already served by an existing
/// tunnel and not yet covered by a pool (mirroring Khaymali's `autoPoolForClash`).
pub fn auto_pool_for_clash(
    requested_ports: &[u16],
    existing_links: &[AutoPoolLink],
    existing_pools: &mut Vec<LbPool>,
) -> Vec<LbPool> {
    let pooled: BTreeSet<u16> = existing_pools.iter().map(|p| p.port).collect();
    let mut made = Vec::new();

    for &port in requested_ports {
        if pooled.contains(&port) || made.iter().any(|p: &LbPool| p.port == port) {
            continue;
        }
        let owners: Vec<&AutoPoolLink> = existing_links
            .iter()
            .filter(|l| l.ports.contains(&port))
            .collect();
        if owners.is_empty() {
            continue;
        }
        // FRP forwards UDP with every port; Backhaul defaults to TCP unless companion enabled.
        let proto = if owners.iter().all(|l| l.engine == "frp") {
            "both"
        } else {
            "tcp"
        };
        let members = owners
            .iter()
            .enumerate()
            .map(|(i, l)| LbMember {
                link_id: l.id,
                remote: l.remote.clone(),
                weight: 1,
                priority: i as u32,
            })
            .collect();
        made.push(LbPool {
            port,
            proto: proto.into(),
            mode: "failover".into(),
            members,
        });
    }
    if !made.is_empty() {
        existing_pools.extend(made.clone());
        existing_pools.sort_by_key(|p| p.port);
    }
    made
}

/// Removes pools synthesized by [`auto_pool_for_clash`] if subsequent setup fails.
pub fn undo_auto_pools(existing_pools: &mut Vec<LbPool>, made: &[LbPool]) {
    existing_pools.retain(|p| !made.iter().any(|m| m.port == p.port && m.proto == p.proto));
}

/// Helper to persist/load `setup.json` metadata.
pub fn save_setup_meta(path: &str, req: &SetupRequest, bundle: Option<&str>) -> Result<()> {
    let mut j = Json::obj()
        .set("role", req.role.clone())
        .set("engine", req.engine.clone())
        .set("transport", req.transport.clone())
        .set("local_pub", req.local_pub.clone())
        .set("remote_pub", req.remote_pub.clone())
        .set("ctrl_port", req.ctrl_port)
        .set("local_gre", req.local_gre.clone())
        .set("peer_gre", req.peer_gre.clone())
        .set("raw_ports", req.raw_ports.clone());
    if let Some(b) = bundle {
        j.insert("foreign_bundle", b);
    }
    hjson::write_atomic(path, j.to_string_pretty().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frp_and_backhaul_toml_render_and_parse() {
        let fc = FrpConfig {
            unit_suffix: String::new(),
            bind_addr: "10.10.0.1".into(),
            server_addr: "10.10.0.1".into(),
            bind_port: 7000,
            transport: "quic".into(),
            token: "secret-tok".into(),
            ports: vec![443],
            perf: FrpPerfOpts {
                proxy_protocol: "v2".into(),
                bandwidth_mb: 50,
                health_check: true,
            },
        };
        let frps = fc.render_frps_toml().unwrap();
        assert!(frps.contains("quicBindPort = 7000"));
        let frpc = fc.render_frpc_toml().unwrap();
        assert!(frpc.contains("transport.proxyProtocolVersion = \"v2\""));
        assert!(frpc.contains("transport.bandwidthLimit = \"50MB\""));
        assert!(frpc.contains("healthCheck.type = \"tcp\""));

        let bh = BackhaulConfig {
            unit_suffix: String::new(),
            bind_addr: "0.0.0.0:3080".into(),
            remote_addr: "198.51.100.10:3080".into(),
            transport: "tcpmux".into(),
            token: "bh-tok".into(),
            raw_ports: vec!["443".into(), "2083=8443".into()],
            connection_pool: 16,
            nodelay: true,
            keepalive_period: 75,
            accept_udp: true,
            udp_companion_port: 3081,
        };
        let srv = bh.render_server_toml().unwrap();
        let parsed = parse_backhaul_conf(&srv);
        assert_eq!(parsed.transport, "tcpmux");
        assert_eq!(parsed.token, "bh-tok");
        assert_eq!(parsed.ports, vec!["443", "2083=8443"]);

        let cli = bh.render_client_toml().unwrap();
        let updated = rewrite_backhaul_pool_toml(&cli, 32).unwrap();
        assert_eq!(parse_backhaul_conf(&updated).connection_pool, 32);

        let udp_srv = bh.render_udp_companion_toml(true).unwrap().unwrap();
        assert!(udp_srv.contains("bind_addr = \"0.0.0.0:3081\""));
        assert!(udp_srv.contains("transport = \"udp\""));
    }

    #[test]
    fn setup_dry_run_and_auto_pool_on_clash() {
        sysrun::set_dry_run(true);
        let _ = sysrun::take_log();
        let req = SetupRequest {
            role: "iran".into(),
            engine: "backhaul".into(),
            transport: "tcpmux".into(),
            local_pub: "198.51.100.10".into(),
            remote_pub: "203.0.113.20".into(),
            ctrl_port: 3080,
            local_gre: String::new(),
            peer_gre: String::new(),
            token: "toksetup123456".into(),
            raw_ports: vec!["443".into(), "8443".into()],
            accept_udp: true,
            udp_companion_port: 3081,
            connection_pool: 12,
            peer_id: 0,
            frp_perf: FrpPerfOpts::default(),
            fou_port1: 443,
            fou_port2: 55555,
        };
        let out = apply_setup(&req, &EnginePaths::default()).unwrap();
        assert_eq!(out.unit_names, vec!["backhaul-server", "backhaul-udp-server"]);
        let bundle = out.foreign_bundle.unwrap();
        assert!(bundle.starts_with("bh1_198.51.100.10_3080_tcpmux+udp3081_"));
        let parsed = setup_bundle::parse_bundle(&bundle).unwrap();
        let foreign_req = SetupRequest::from_bundle(&parsed, None);
        let f_out = apply_setup(&foreign_req, &EnginePaths::default()).unwrap();
        assert_eq!(f_out.unit_names, vec!["backhaul-client", "backhaul-udp-client"]);
        sysrun::set_dry_run(false);

        let existing = vec![AutoPoolLink {
            id: 0,
            name: "main".into(),
            remote: "203.0.113.20".into(),
            engine: "frp".into(),
            ports: vec![443, 8443],
        }];
        let mut pools = Vec::new();
        let made = auto_pool_for_clash(&[443, 9000], &existing, &mut pools);
        assert_eq!(made.len(), 1);
        assert_eq!(made[0].port, 443);
        assert_eq!(made[0].proto, "both");
        assert_eq!(pools.len(), 1);
        undo_auto_pools(&mut pools, &made);
        assert!(pools.is_empty());
    }
}
