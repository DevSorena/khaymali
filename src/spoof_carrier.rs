//! Spoof Tunnel Carrier (`spoof://WG_PEER_IP:PORT`, `src/spoof_carrier.rs`).
//!
//! Full Rust port of Khaymali's `spoof.go` and `spoof_tester.go`, plus a native raw-socket
//! IPv4 spoof engine (`RawSpoofEngine`) built on `socket2` with RFC 1071 checksums:
//!   * Full `spoof.json` state persistence, reserved-port protection (SSH/excluded ports/recv_port),
//!     `config.json`, `spoof-ips.txt`, `wg-spoof.conf` (MTU 1280, Keepalive 25, PostUp/PostDown),
//!     idempotent `inet khaymali_spoof` nftables rules with bidirectional MSS clamping, UFW hooks,
//!     and WireGuard handshake freshness check (< 3 min).
//!   * Bidirectional Khaymali `spf1_<raw-url-b64(JSON)>` bundle format (with automatic send/recv
//!     transport mirroring and X25519 public-key derivation), while preserving backward
//!     compatibility with Khaymali's legacy `SPOOF1:` key-value bundle format.
//!   * Managed `SpoofTester` runner and output parser (`IP recv/sent loss%`).
//!   * Native `RawSpoofEngine` using `socket2` (`IP_HDRINCL`) for forging IPv4 UDP/TCP/ICMP
//!     packets and bridging them with the local WireGuard loopback port.

use crate::hjson::{self, Json};
use crate::link;
use crate::sysrun;
use crate::util::{now_unix, rand_bytes, BoxRw};
use anyhow::{bail, Context, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

pub const DEFAULT_SPOOF_PORT: u16 = 8090;
pub const DEFAULT_RECV_PORT: u16 = 5001;
pub const DEFAULT_CORE_PORT: u16 = 5000;
pub const DEFAULT_WG_LISTEN: u16 = 51820;
pub const DEFAULT_WG_MTU: u16 = 1280;
pub const SPOOF_LOCAL_WG_IP: &str = "10.20.0.1";
pub const SPOOF_REMOTE_WG_IP: &str = "10.20.0.2";
pub const SPOOF_IFACE: &str = "wg-spoof";
pub const SPOOF_NFT_TABLE: &str = "khaymali_spoof";
pub const SPOOF_CORE_SVC: &str = "spoof-core";
pub const SPOOF_HANDSHAKE_FRESH_SECS: u64 = 180;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpoofRole {
    Local,
    Remote,
}

impl SpoofRole {
    pub fn as_str(self) -> &'static str {
        match self {
            SpoofRole::Local => "local",
            SpoofRole::Remote => "remote",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "local" | "iran" | "entry" => Ok(SpoofRole::Local),
            "remote" | "foreign" | "exit" => Ok(SpoofRole::Remote),
            other => bail!("invalid spoof role '{other}' (expected local|remote)"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpoofTransport {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
}

impl SpoofTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            SpoofTransport::Tcp => "tcp",
            SpoofTransport::Udp => "udp",
            SpoofTransport::Icmp => "icmp",
            SpoofTransport::IcmpV6 => "icmpv6",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(SpoofTransport::Tcp),
            "udp" => Ok(SpoofTransport::Udp),
            "icmp" => Ok(SpoofTransport::Icmp),
            "icmpv6" => Ok(SpoofTransport::IcmpV6),
            other => bail!("unsupported spoof transport '{other}' (expected tcp|udp|icmp|icmpv6)"),
        }
    }
    pub fn ip_proto(self) -> u8 {
        match self {
            SpoofTransport::Tcp => 6,
            SpoofTransport::Udp => 17,
            SpoofTransport::Icmp => 1,
            SpoofTransport::IcmpV6 => 58,
        }
    }
}

/// Filesystem paths used by the Spoof lifecycle (overridable for tests or custom layouts).
#[derive(Clone, Debug)]
pub struct SpoofPaths {
    pub config_dir: String,
    pub spoof_dir: String,
    pub wg_conf_dir: String,
    pub unit_dir: String,
    pub spoof_bin: String,
}

impl Default for SpoofPaths {
    fn default() -> Self {
        Self {
            config_dir: "/etc/khaymali".into(),
            spoof_dir: "/etc/spoof".into(),
            wg_conf_dir: "/etc/wireguard".into(),
            unit_dir: "/etc/systemd/system".into(),
            spoof_bin: "/usr/local/bin/spoof".into(),
        }
    }
}

impl SpoofPaths {
    pub fn state_path(&self) -> String {
        format!("{}/spoof.json", self.config_dir)
    }
    pub fn core_config_path(&self) -> String {
        format!("{}/config.json", self.spoof_dir)
    }
    pub fn ip_file_path(&self) -> String {
        format!("{}/spoof-ips.txt", self.spoof_dir)
    }
    pub fn wg_conf_path(&self) -> String {
        format!("{}/{}.conf", self.wg_conf_dir, SPOOF_IFACE)
    }
    pub fn forward_nft_path(&self) -> String {
        format!("{}/forward.nft", self.spoof_dir)
    }
    pub fn core_unit_name(&self) -> String {
        format!("{}.service", SPOOF_CORE_SVC)
    }
}

#[derive(Clone, Debug)]
pub struct SpoofConfig {
    pub enabled: bool,
    pub role: SpoofRole,
    pub local_public_ip: String,
    pub peer_public_ip: String,
    pub listen_port: u16,
    pub recv_port: u16,
    pub spoof_port: u16,
    pub spoof_ips: Vec<String>,
    pub send_transport: SpoofTransport,
    pub recv_transport: SpoofTransport,
    pub wg_priv_key: String,
    pub wg_pub_key: String,
    pub wg_peer_priv: String,
    pub wg_peer_pub: String,
    pub wg_local_ip: String,
    pub wg_peer_ip: String,
    pub wg_listen_port: u16,
    pub core_port: u16,
    pub forward_ports: Vec<u16>,
}

impl SpoofConfig {
    pub fn new_default(role: SpoofRole, local_public_ip: String, peer_public_ip: String) -> Self {
        let (wg_local, wg_peer) = match role {
            SpoofRole::Local => (SPOOF_LOCAL_WG_IP.to_string(), SPOOF_REMOTE_WG_IP.to_string()),
            SpoofRole::Remote => (SPOOF_REMOTE_WG_IP.to_string(), SPOOF_LOCAL_WG_IP.to_string()),
        };
        Self {
            enabled: false,
            role,
            local_public_ip,
            peer_public_ip,
            listen_port: DEFAULT_SPOOF_PORT,
            recv_port: DEFAULT_RECV_PORT,
            spoof_port: 443,
            spoof_ips: Vec::new(),
            send_transport: SpoofTransport::Tcp,
            recv_transport: SpoofTransport::Udp,
            wg_priv_key: String::new(),
            wg_pub_key: String::new(),
            wg_peer_priv: String::new(),
            wg_peer_pub: String::new(),
            wg_local_ip: wg_local,
            wg_peer_ip: wg_peer,
            wg_listen_port: DEFAULT_WG_LISTEN,
            core_port: DEFAULT_CORE_PORT,
            forward_ports: Vec::new(),
        }
    }

    pub fn forwarding(&self) -> bool {
        self.role == SpoofRole::Local && !self.forward_ports.is_empty()
    }

    pub fn reserved_ports(&self, reserved_ports: &[u16]) -> BTreeMap<u16, String> {
        let mut r = BTreeMap::new();
        r.insert(22, "SSH".to_string());
        for &p in reserved_ports {
            if p > 0 {
                r.insert(p, "reserved local service".to_string());
            }
        }
        if self.recv_port > 0 {
            r.insert(self.recv_port, "the spoof recv port".to_string());
        }
        r
    }

    /// Parses `"443, 8080-8090"` into `forward_ports` after rejecting reserved ports.
    pub fn set_forward_ports(&mut self, spec: &str, reserved_ports: &[u16]) -> Result<()> {
        let spec = spec.trim();
        if spec.is_empty() {
            self.forward_ports.clear();
            return Ok(());
        }
        let ports = parse_port_spec(spec)?;
        let res = self.reserved_ports(reserved_ports);
        for &p in &ports {
            if let Some(why) = res.get(&p) {
                bail!("forwarded port {p} is used by {why} on this server");
            }
        }
        self.forward_ports = ports;
        Ok(())
    }

    pub fn clean_spoof_ips(raw: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        for entry in raw {
            for part in entry.split(|c: char| c == ',' || c.is_whitespace()) {
                let ip = part.trim();
                if ip.is_empty() {
                    continue;
                }
                if let Ok(IpAddr::V4(v4)) = ip.parse::<IpAddr>() {
                    let s = v4.to_string();
                    if !out.contains(&s) {
                        out.push(s);
                    }
                }
            }
        }
        out
    }

    pub fn validate(&self) -> Result<()> {
        let peer: IpAddr = self
            .peer_public_ip
            .trim()
            .parse()
            .with_context(|| format!("invalid peer_public_ip '{}'", self.peer_public_ip))?;
        if !peer.is_ipv4() {
            bail!("peer_public_ip '{}' must be IPv4 (spoof core works over IPv4 only)", self.peer_public_ip);
        }
        if self.spoof_ips.is_empty() {
            bail!("spoof_ips must contain at least one whitelisted IPv4 address");
        }
        for ip in &self.spoof_ips {
            let parsed: IpAddr = ip.parse().with_context(|| format!("invalid spoof IP '{ip}'"))?;
            if !parsed.is_ipv4() {
                bail!("spoof source IP '{ip}' must be IPv4");
            }
        }
        Ok(())
    }

    pub fn ready(&self) -> Result<()> {
        self.validate()?;
        if self.wg_peer_pub.trim().is_empty() {
            bail!("the peer WireGuard public key is missing: import the bundle from the Iran server first");
        }
        if self.wg_priv_key.trim().is_empty() {
            bail!("local WireGuard private key is missing");
        }
        Ok(())
    }

    pub fn generate_wg_keypair() -> Result<(String, String)> {
        let mut sk = rand_bytes::<32>();
        sk[0] &= 248;
        sk[31] = (sk[31] & 127) | 64;
        let pk = x25519_public_from_private(&sk);
        Ok((hjson::b64_encode(&sk), hjson::b64_encode(&pk)))
    }

    pub fn pubkey_from_priv(priv_b64: &str) -> Result<String> {
        let raw = hjson::b64_decode(priv_b64.trim())?;
        if raw.len() != 32 {
            bail!("WireGuard private key must decode to 32 bytes (got {})", raw.len());
        }
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&raw);
        let pk = x25519_public_from_private(&sk);
        Ok(hjson::b64_encode(&pk))
    }

    pub fn ensure_keys(&mut self) -> Result<()> {
        if let Ok(pub_k) = Self::pubkey_from_priv(&self.wg_priv_key) {
            if !self.wg_pub_key.is_empty() && pub_k == self.wg_pub_key {
                return Ok(());
            }
            self.wg_pub_key = pub_k;
            return Ok(());
        }
        let (sk, pk) = Self::generate_wg_keypair()?;
        self.wg_priv_key = sk;
        self.wg_pub_key = pk;
        Ok(())
    }

    pub fn ensure_peer_keypair(&mut self) -> Result<()> {
        if let Ok(pub_k) = Self::pubkey_from_priv(&self.wg_peer_priv) {
            if pub_k == self.wg_peer_pub && !pub_k.is_empty() {
                return Ok(());
            }
        }
        let (sk, pk) = Self::generate_wg_keypair()?;
        self.wg_peer_priv = sk;
        self.wg_peer_pub = pk;
        Ok(())
    }

    /// Renders Khaymali-compatible `spoof run -c` JSON (`config.json`).
    pub fn render_spoof_core_json(&self) -> String {
        self.render_spoof_core_json_with_ip_file("/etc/spoof/spoof-ips.txt")
    }

    pub fn render_spoof_core_json_with_ip_file(&self, ip_file: &str) -> String {
        let mut obj = Json::obj()
            .set("spoof_port", self.spoof_port)
            .set("send_transport", self.send_transport.as_str())
            .set("recv_transport", self.recv_transport.as_str());
        if self.spoof_ips.len() == 1 {
            obj.insert("spoof_ip", self.spoof_ips[0].clone());
        } else if self.spoof_ips.len() > 1 {
            obj.insert("spoof_ip_file", ip_file);
        }
        match self.role {
            SpoofRole::Local => {
                obj.insert("mode", "local");
                obj.insert("listen", format!("127.0.0.1:{}", self.core_port));
                obj.insert("remote", self.peer_public_ip.clone());
                obj.insert("remote_port", self.listen_port);
                obj.insert("recv_port", self.recv_port);
            }
            SpoofRole::Remote => {
                obj.insert("mode", "remote");
                obj.insert("listen_port", self.listen_port);
                obj.insert("forward", format!("127.0.0.1:{}", self.wg_listen_port));
                obj.insert("client_ip", self.peer_public_ip.clone());
                obj.insert("client_port", self.recv_port);
            }
        }
        obj.to_string_pretty()
    }

    pub fn render_wg_conf(&self) -> String {
        self.render_wg_conf_with_nft("/etc/spoof/forward.nft")
    }

    pub fn render_wg_conf_with_nft(&self, nft_path: &str) -> String {
        let mut b = String::new();
        b.push_str("[Interface]\n");
        b.push_str(&format!("Address = {}/24\n", self.wg_local_ip));
        b.push_str(&format!("PrivateKey = {}\n", self.wg_priv_key));
        b.push_str(&format!("MTU = {}\n", DEFAULT_WG_MTU));
        if self.role == SpoofRole::Remote {
            b.push_str(&format!("ListenPort = {}\n", self.wg_listen_port));
        }
        if self.forwarding() {
            b.push_str(&format!(
                "PostUp = sysctl -q -w net.ipv4.ip_forward=1; nft -f {nft_path}\n"
            ));
            b.push_str(&format!(
                "PostDown = nft delete table inet {SPOOF_NFT_TABLE} 2>/dev/null || true\n"
            ));
        }
        b.push_str("\n[Peer]\n");
        b.push_str(&format!("PublicKey = {}\n", self.wg_peer_pub));
        b.push_str(&format!("AllowedIPs = {}/32\n", self.wg_peer_ip));
        if self.role == SpoofRole::Local {
            b.push_str(&format!("Endpoint = 127.0.0.1:{}\n", self.core_port));
            b.push_str("PersistentKeepalive = 25\n");
        }
        b
    }

    /// Khaymali idempotent `forward.nft` with DNAT, masquerade, and bidirectional MSS clamping.
    pub fn render_forward_nft(&self) -> String {
        if !self.forwarding() {
            return String::new();
        }
        let pl = self
            .forward_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "table inet {t}\n\
delete table inet {t}\n\
table inet {t} {{\n\
  chain prerouting {{\n\
    type nat hook prerouting priority dstnat - 4; policy accept;\n\
    iifname != \"{iface}\" meta nfproto ipv4 fib daddr type local meta l4proto {{ tcp, udp }} th dport {{ {pl} }} dnat ip to {peer}\n\
  }}\n\
  chain postrouting {{\n\
    type nat hook postrouting priority srcnat + 4; policy accept;\n\
    oifname \"{iface}\" ip daddr {peer} masquerade\n\
  }}\n\
  chain forward {{\n\
    type filter hook forward priority mangle; policy accept;\n\
    oifname \"{iface}\" tcp flags syn tcp option maxseg size set rt mtu\n\
    iifname \"{iface}\" tcp flags syn tcp option maxseg size set rt mtu\n\
  }}\n\
}}\n",
            t = SPOOF_NFT_TABLE,
            iface = SPOOF_IFACE,
            pl = pl,
            peer = self.wg_peer_ip,
        )
    }

    /// Generates Khaymali's canonical `spf1_<raw-url-b64(JSON)>` bundle on the Iran (local) server.
    pub fn make_khaymali_bundle(&mut self) -> Result<String> {
        if self.role != SpoofRole::Local {
            bail!("the spf1_ bundle is generated on the Iran (local) server");
        }
        self.ensure_keys()?;
        self.ensure_peer_keypair()?;
        let local_ip: IpAddr = self
            .local_public_ip
            .trim()
            .parse()
            .context("local_public_ip must be a valid IPv4 address")?;
        if !local_ip.is_ipv4() {
            bail!("local_public_ip must be IPv4");
        }
        let j = Json::obj()
            .set("v", 1i64)
            .set("iran_ip", local_ip.to_string())
            .set("listen_port", self.listen_port)
            .set("recv_port", self.recv_port)
            .set("spoof_port", self.spoof_port)
            .set("send", self.send_transport.as_str())
            .set("recv", self.recv_transport.as_str())
            .set("iran_wg_pub", self.wg_pub_key.clone())
            .set("foreign_wg_priv", self.wg_peer_priv.clone())
            .set("wg_iran_ip", self.wg_local_ip.clone())
            .set("wg_foreign_ip", self.wg_peer_ip.clone())
            .set("wg_listen", self.wg_listen_port)
            .set("core_port", self.core_port);
        let raw = j.to_string_compact();
        Ok(format!("spf1_{}", hjson::b64url_encode(raw.as_bytes())))
    }

    /// Imports either Khaymali `spf1_...` or legacy Khaymali `SPOOF1:...` into a Remote config,
    /// mirroring send/recv transports and preserving this server's own `spoof_ips`.
    pub fn import_bundle(bundle: &str, prev: &SpoofConfig) -> Result<SpoofConfig> {
        let b = bundle.trim();
        if let Some(enc) = b.strip_prefix("spf1_") {
            let raw = hjson::b64_decode(enc).context("corrupted spf1_ base64 payload")?;
            let text = String::from_utf8(raw).context("spf1_ payload is not UTF-8")?;
            let j = Json::parse(&text).context("spf1_ payload is not valid JSON")?;
            if j.i64_of("v") != 1 {
                bail!("unsupported spf1_ bundle version");
            }
            let iran_ip = j.str_of("iran_ip");
            let listen_port = j.u64_of("listen_port") as u16;
            let recv_port = j.u64_of("recv_port") as u16;
            let wg_listen = j.u64_of("wg_listen") as u16;
            let core_port = j.u64_of("core_port") as u16;
            let iran_send = SpoofTransport::parse(&j.str_of("send"))?;
            let iran_recv = SpoofTransport::parse(&j.str_of("recv"))?;
            let iran_wg_pub = j.str_of("iran_wg_pub");
            let foreign_wg_priv = j.str_of("foreign_wg_priv");
            let wg_iran_ip = j.str_of("wg_iran_ip");
            let wg_foreign_ip = j.str_of("wg_foreign_ip");

            if iran_ip.parse::<Ipv4Addr>().is_err() {
                bail!("spf1_ bundle has invalid iran_ip");
            }
            if listen_port == 0 || recv_port == 0 || wg_listen == 0 || core_port == 0 {
                bail!("spf1_ bundle has invalid port");
            }
            if wg_iran_ip.parse::<Ipv4Addr>().is_err()
                || wg_foreign_ip.parse::<Ipv4Addr>().is_err()
                || wg_iran_ip == wg_foreign_ip
            {
                bail!("spf1_ bundle has invalid WireGuard addresses");
            }
            if hjson::b64_decode(&iran_wg_pub).map(|v| v.len()).unwrap_or(0) != 32 {
                bail!("spf1_ bundle has invalid iran_wg_pub");
            }
            let foreign_pub = Self::pubkey_from_priv(&foreign_wg_priv)?;

            let mut s = prev.clone();
            s.role = SpoofRole::Remote;
            s.peer_public_ip = iran_ip;
            s.listen_port = listen_port;
            s.recv_port = recv_port;
            s.spoof_port = listen_port;
            s.send_transport = iran_recv;
            s.recv_transport = iran_send;
            s.wg_priv_key = foreign_wg_priv;
            s.wg_pub_key = foreign_pub;
            s.wg_peer_priv.clear();
            s.wg_peer_pub = iran_wg_pub;
            s.wg_local_ip = wg_foreign_ip;
            s.wg_peer_ip = wg_iran_ip;
            s.wg_listen_port = wg_listen;
            s.core_port = core_port;
            return Ok(s);
        }
        if b.starts_with("SPOOF1:") {
            let m = Self::decode_remote_bundle(b)?;
            let mut s = prev.clone();
            s.role = SpoofRole::Remote;
            s.peer_public_ip = m.get("ip").cloned().context("missing ip")?;
            s.listen_port = m.get("lp").and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_SPOOF_PORT);
            s.recv_port = m.get("rp").and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_RECV_PORT);
            s.spoof_port = m.get("sp").and_then(|v| v.parse().ok()).unwrap_or(s.listen_port);
            if let Some(st) = m.get("st") {
                s.send_transport = SpoofTransport::parse(st)?;
            }
            if let Some(rt) = m.get("rt") {
                s.recv_transport = SpoofTransport::parse(rt)?;
            }
            if let Some(wgp) = m.get("wgp") {
                s.wg_priv_key = wgp.clone();
                s.wg_pub_key = Self::pubkey_from_priv(wgp)?;
            }
            if let Some(pubk) = m.get("wgrpub") {
                s.wg_peer_pub = pubk.clone();
            }
            if let Some(wgl) = m.get("wgl") {
                s.wg_local_ip = wgl.clone();
            }
            if let Some(wgr) = m.get("wgr") {
                s.wg_peer_ip = wgr.clone();
            }
            if let Some(wglp) = m.get("wglp").and_then(|v| v.parse().ok()) {
                s.wg_listen_port = wglp;
            }
            return Ok(s);
        }
        bail!("unrecognized spoof bundle (expected spf1_... or SPOOF1:...)");
    }

    /// Legacy Khaymali `SPOOF1:` bundle encoder (retained for v0.18 CLI & E2E compatibility).
    pub fn encode_remote_bundle(&self, remote_wg_priv: &str) -> String {
        let payload = format!(
            "ip={}&lp={}&rp={}&sp={}&st={}&rt={}&wgp={}&wgrpub={}&wgl={}&wgr={}&wglp={}&ips={}",
            self.local_public_ip,
            self.listen_port,
            self.recv_port,
            self.spoof_port,
            self.recv_transport.as_str(),
            self.send_transport.as_str(),
            remote_wg_priv,
            self.wg_pub_key,
            self.wg_peer_ip,
            self.wg_local_ip,
            self.wg_listen_port,
            self.spoof_ips.join(","),
        );
        format!("SPOOF1:{}", hjson::b64url_encode(payload.as_bytes()))
    }

    /// Decodes either `SPOOF1:` or `spf1_` into a flat key-value map for CLI inspection.
    pub fn decode_remote_bundle(bundle: &str) -> Result<HashMap<String, String>> {
        let trimmed = bundle.trim();
        if let Some(enc) = trimmed.strip_prefix("spf1_") {
            let raw = hjson::b64_decode(enc)?;
            let text = String::from_utf8(raw).context("spf1_ bundle is not UTF-8")?;
            let j = Json::parse(&text)?;
            let mut map = HashMap::new();
            for k in [
                "v",
                "iran_ip",
                "listen_port",
                "recv_port",
                "spoof_port",
                "send",
                "recv",
                "iran_wg_pub",
                "foreign_wg_priv",
                "wg_iran_ip",
                "wg_foreign_ip",
                "wg_listen",
                "core_port",
            ] {
                let v = j.str_of(k);
                if !v.is_empty() {
                    map.insert(k.to_string(), v);
                }
            }
            if let Some(ip) = map.get("iran_ip").cloned() {
                map.insert("ip".into(), ip);
            }
            return Ok(map);
        }
        let body = trimmed
            .strip_prefix("SPOOF1:")
            .context("invalid spoof bundle (expected spf1_... or SPOOF1:...)")?;
        let raw = hjson::b64_decode(body)?;
        let text = String::from_utf8(raw).context("spoof bundle is not valid UTF-8")?;
        let mut map = HashMap::new();
        for pair in text.split('&').filter(|s| !s.is_empty()) {
            if let Some((k, v)) = pair.split_once('=') {
                map.insert(k.to_string(), v.to_string());
            }
        }
        Ok(map)
    }

    pub fn to_json(&self) -> Json {
        Json::obj()
            .set("enabled", self.enabled)
            .set("role", self.role.as_str())
            .set("local_public", self.local_public_ip.clone())
            .set("peer_public_ip", self.peer_public_ip.clone())
            .set("listen_port", self.listen_port)
            .set("recv_port", self.recv_port)
            .set("spoof_port", self.spoof_port)
            .set("spoof_ips", self.spoof_ips.clone())
            .set("send_transport", self.send_transport.as_str())
            .set("recv_transport", self.recv_transport.as_str())
            .set("wg_priv_key", self.wg_priv_key.clone())
            .set("wg_pub_key", self.wg_pub_key.clone())
            .set("wg_peer_priv", self.wg_peer_priv.clone())
            .set("wg_peer_pub", self.wg_peer_pub.clone())
            .set("wg_local_ip", self.wg_local_ip.clone())
            .set("wg_peer_ip", self.wg_peer_ip.clone())
            .set("wg_listen", self.wg_listen_port)
            .set("core_port", self.core_port)
            .set("forward_ports", self.forward_ports.clone())
    }

    pub fn from_json(j: &Json) -> Result<Self> {
        let role = SpoofRole::parse(&j.str_of("role")).unwrap_or(SpoofRole::Local);
        let mut s = Self::new_default(role, j.str_of("local_public"), j.str_of("peer_public_ip"));
        s.enabled = j.bool_of("enabled");
        if j.u64_of("listen_port") > 0 {
            s.listen_port = j.u64_of("listen_port") as u16;
        }
        if j.u64_of("recv_port") > 0 {
            s.recv_port = j.u64_of("recv_port") as u16;
        }
        if j.u64_of("spoof_port") > 0 {
            s.spoof_port = j.u64_of("spoof_port") as u16;
        }
        s.spoof_ips = j
            .arr_of("spoof_ips")
            .into_iter()
            .filter_map(|v| v.as_str().map(|x| x.to_string()))
            .collect();
        if let Ok(st) = SpoofTransport::parse(&j.str_of("send_transport")) {
            s.send_transport = st;
        }
        if let Ok(rt) = SpoofTransport::parse(&j.str_of("recv_transport")) {
            s.recv_transport = rt;
        }
        s.wg_priv_key = j.str_of("wg_priv_key");
        s.wg_pub_key = j.str_of("wg_pub_key");
        s.wg_peer_priv = j.str_of("wg_peer_priv");
        s.wg_peer_pub = j.str_of("wg_peer_pub");
        let wgl = j.str_of("wg_local_ip");
        if !wgl.is_empty() {
            s.wg_local_ip = wgl;
        }
        let wgr = j.str_of("wg_peer_ip");
        if !wgr.is_empty() {
            s.wg_peer_ip = wgr;
        }
        if j.u64_of("wg_listen") > 0 {
            s.wg_listen_port = j.u64_of("wg_listen") as u16;
        }
        if j.u64_of("core_port") > 0 {
            s.core_port = j.u64_of("core_port") as u16;
        }
        s.forward_ports = j
            .arr_of("forward_ports")
            .into_iter()
            .filter_map(|v| v.as_f64().map(|n| n as u16))
            .filter(|&p| p > 0)
            .collect();
        Ok(s)
    }

    pub fn load_state(paths: &SpoofPaths) -> Result<Option<Self>> {
        match hjson::read_json_file(&paths.state_path())? {
            Some(j) => Ok(Some(Self::from_json(&j)?)),
            None => Ok(None),
        }
    }

    pub fn save_state(&self, paths: &SpoofPaths) -> Result<()> {
        hjson::write_atomic(&paths.state_path(), self.to_json().to_string_pretty().as_bytes())
    }
}

/// Runtime health status matching Khaymali's `spoofHealth`.
#[derive(Clone, Debug, Default)]
pub struct SpoofHealth {
    pub core_active: bool,
    pub wg_active: bool,
    pub peer_ping: bool,
    pub handshake_age_secs: Option<u64>,
}

/// Applies configs, systemd units, UFW rules, and starts `spoof-core` + `wg-quick@wg-spoof`.
/// Uses `sysrun` (respects `dry-run` mode cleanly for tests and `--plan`).
pub fn apply_spoof(cfg: &SpoofConfig, paths: &SpoofPaths, use_native_core: bool) -> Result<String> {
    cfg.ready()?;
    if !use_native_core && !sysrun::is_dry_run() && !std::path::Path::new(&paths.spoof_bin).is_file() {
        bail!(
            "spoof binary '{}' not installed (pass --native to run Khaymali's built-in raw-socket core)",
            paths.spoof_bin
        );
    }

    // 1. Write spoof-ips.txt + config.json
    if cfg.spoof_ips.len() > 1 {
        let mut body = cfg.spoof_ips.join("\n");
        body.push('\n');
        write_file_or_dry(&paths.ip_file_path(), body.as_bytes())?;
    }
    let core_json = cfg.render_spoof_core_json_with_ip_file(&paths.ip_file_path());
    write_file_or_dry(&paths.core_config_path(), core_json.as_bytes())?;

    // 2. Write forward.nft (if local forwarding) + wg-spoof.conf
    if cfg.forwarding() {
        let nft = cfg.render_forward_nft();
        write_file_or_dry(&paths.forward_nft_path(), nft.as_bytes())?;
    }
    let wg_conf = cfg.render_wg_conf_with_nft(&paths.forward_nft_path());
    write_file_or_dry(&paths.wg_conf_path(), wg_conf.as_bytes())?;

    // 3. Install spoof-core systemd unit
    let exec_cmd = if use_native_core {
        format!(
            "/usr/local/bin/khaymali spoof run-native --config {}",
            paths.core_config_path()
        )
    } else {
        format!("{} run -c {}", paths.spoof_bin, paths.core_config_path())
    };
    let unit = format!(
        "[Unit]\nDescription=Spoof Tunnel core ({})\nAfter=network-online.target\nWants=network-online.target\n\n\
[Service]\nType=simple\nExecStart={exec_cmd}\nRestart=always\nRestartSec=2\nLimitNOFILE=65535\n\n\
[Install]\nWantedBy=multi-user.target\n",
        cfg.role.as_str()
    );
    sysrun::install_unit(&paths.unit_dir, &paths.core_unit_name(), &unit, false)?;

    // 4. Open UFW ports + tunnel interface if UFW is active
    open_spoof_firewall(cfg);

    // 5. Start spoof-core first, then wg-quick@wg-spoof
    sysrun::must(&crate::v!["systemctl", "restart", SPOOF_CORE_SVC])?;
    let _ = sysrun::run(&crate::v!["systemctl", "enable", SPOOF_CORE_SVC]);
    let wg_unit = format!("wg-quick@{SPOOF_IFACE}");
    sysrun::must(&crate::v!["systemctl", "restart", &wg_unit])?;
    let _ = sysrun::run(&crate::v!["systemctl", "enable", &wg_unit]);

    let mut msg = format!(
        "Spoof tunnel is up on {} ({}/{}).",
        cfg.role.as_str(),
        cfg.send_transport.as_str(),
        cfg.recv_transport.as_str()
    );
    if cfg.forwarding() {
        msg.push_str(&format!(
            " Forwarding {} port(s) to {}.",
            cfg.forward_ports.len(),
            cfg.wg_peer_ip
        ));
    }
    Ok(msg)
}

pub fn stop_spoof() -> Result<()> {
    let wg_unit = format!("wg-quick@{SPOOF_IFACE}");
    let _ = sysrun::run(&crate::v!["systemctl", "disable", "--now", &wg_unit]);
    let _ = sysrun::run(&crate::v!["systemctl", "disable", "--now", SPOOF_CORE_SVC]);
    let _ = sysrun::run(&crate::v!["nft", "delete", "table", "inet", SPOOF_NFT_TABLE]);
    Ok(())
}

pub fn open_spoof_firewall(cfg: &SpoofConfig) {
    let ufw = sysrun::run(&crate::v!["ufw", "status"]);
    if !sysrun::is_dry_run() && (!ufw.ok || !ufw.stdout.contains("Status: active")) {
        return;
    }
    if cfg.role == SpoofRole::Remote && cfg.listen_port > 0 {
        let _ = sysrun::run(&crate::v!["ufw", "allow", format!("{}/tcp", cfg.listen_port)]);
        let _ = sysrun::run(&crate::v!["ufw", "allow", format!("{}/udp", cfg.listen_port)]);
        let _ = sysrun::run(&crate::v!["ufw", "allow", "in", "on", SPOOF_IFACE]);
    }
    if cfg.role == SpoofRole::Local {
        if cfg.recv_port > 0 {
            let _ = sysrun::run(&crate::v!["ufw", "allow", format!("{}/tcp", cfg.recv_port)]);
            let _ = sysrun::run(&crate::v!["ufw", "allow", format!("{}/udp", cfg.recv_port)]);
        }
        if cfg.forwarding() {
            let _ = sysrun::run(&crate::v!["ufw", "route", "allow", "out", "on", SPOOF_IFACE]);
            let _ = sysrun::run(&crate::v!["ufw", "route", "allow", "in", "on", SPOOF_IFACE]);
        }
    }
}

pub fn spoof_runtime_health(cfg: &SpoofConfig) -> SpoofHealth {
    let mut h = SpoofHealth {
        core_active: sysrun::unit_active(SPOOF_CORE_SVC),
        wg_active: sysrun::unit_active(&format!("wg-quick@{SPOOF_IFACE}")),
        peer_ping: false,
        handshake_age_secs: None,
    };
    let out = sysrun::run(&crate::v!["wg", "show", SPOOF_IFACE, "latest-handshakes"]);
    if out.ok {
        if let Some(age) = parse_wg_latest_handshake_age(&out.stdout, now_unix()) {
            h.handshake_age_secs = Some(age);
            h.peer_ping = cfg.enabled && age < SPOOF_HANDSHAKE_FRESH_SECS;
        }
    }
    h
}

pub fn parse_wg_latest_handshake_age(output: &str, now_ts: u64) -> Option<u64> {
    let fields: Vec<&str> = output.split_whitespace().collect();
    if fields.len() >= 2 {
        if let Ok(ts) = fields[fields.len() - 1].parse::<u64>() {
            if ts > 0 && now_ts >= ts {
                return Some(now_ts - ts);
            }
        }
    }
    None
}

fn write_file_or_dry(path: &str, data: &[u8]) -> Result<()> {
    if sysrun::is_dry_run() {
        let _ = sysrun::run(&crate::v!["write-file", path, format!("{}B", data.len())]);
        return Ok(());
    }
    hjson::write_atomic(path, data)
}

pub fn parse_port_spec(spec: &str) -> Result<Vec<u16>> {
    let mut out = Vec::new();
    for tok in spec.split(|c: char| c == ',' || c.is_whitespace()) {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        if let Some((a, b)) = t.split_once('-') {
            let lo: u16 = a.trim().parse().with_context(|| format!("bad port range '{t}'"))?;
            let hi: u16 = b.trim().parse().with_context(|| format!("bad port range '{t}'"))?;
            if lo == 0 || hi < lo || (hi - lo) > 2000 {
                bail!("invalid port range '{t}'");
            }
            for p in lo..=hi {
                if !out.contains(&p) {
                    out.push(p);
                }
            }
        } else {
            let p: u16 = t.parse().with_context(|| format!("bad port '{t}'"))?;
            if p == 0 {
                bail!("port 0 is invalid");
            }
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out.sort_unstable();
    Ok(out)
}

// ============================================================================
// SpoofTester (Khaymali `spoof_tester.go`)
// ============================================================================

#[derive(Clone, Debug, PartialEq)]
pub struct SpoofTesterResult {
    pub ip: String,
    pub received: u32,
    pub sent: u32,
    pub loss_pct: f64,
}

#[derive(Clone, Debug)]
pub struct SpoofTesterRequest {
    pub mode: String,     // "sender" | "receiver"
    pub protocol: String, // "tcp" | "icmp"
    pub sources: Vec<String>,
    pub dst_ip: String,
    pub dst_port: u16,
    pub timeout_secs: u32,
    pub packet_count: u32,
    pub max_loss_pct: f64,
}

impl SpoofTesterRequest {
    pub fn normalize(mut self) -> Self {
        if self.protocol != "tcp" && self.protocol != "icmp" {
            self.protocol = "icmp".into();
        }
        if self.dst_port == 0 {
            self.dst_port = 80;
        }
        if self.timeout_secs == 0 {
            self.timeout_secs = 30;
        }
        if self.packet_count == 0 {
            self.packet_count = 10;
        }
        if !(0.0..=100.0).contains(&self.max_loss_pct) {
            self.max_loss_pct = 20.0;
        }
        self
    }

    pub fn build_args(&self, src_list_path: &str) -> Result<Vec<String>> {
        if self.mode != "sender" && self.mode != "receiver" {
            bail!("tester mode must be sender or receiver");
        }
        if self.mode == "sender" && self.dst_ip.trim().is_empty() {
            bail!("dst_ip is required in sender mode");
        }
        if self.sources.is_empty() {
            bail!("add at least one source IP, range, or CIDR");
        }
        let mut args = vec![
            "tester".into(),
            "--mode".into(),
            self.mode.clone(),
            "--protocol".into(),
            self.protocol.clone(),
            "--src-list".into(),
            src_list_path.into(),
            "--timeout".into(),
            self.timeout_secs.to_string(),
            "--packet-count".into(),
            self.packet_count.to_string(),
            "--max-loss".into(),
            format!("{}", self.max_loss_pct),
        ];
        if self.mode == "sender" {
            args.push("--dst-ip".into());
            args.push(self.dst_ip.trim().into());
            args.push("--dst-port".into());
            args.push(self.dst_port.to_string());
        }
        Ok(args)
    }
}

/// Parses receiver output lines like `1.1.1.1 10/10 0.0%` or `8.8.8.8  8/10  20%`.
pub fn parse_spoof_tester_output(out: &str) -> Vec<SpoofTesterResult> {
    let mut res = Vec::new();
    for line in out.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        if parts[0].parse::<Ipv4Addr>().is_err() {
            continue;
        }
        let Some((r_s, s_s)) = parts[1].split_once('/') else {
            continue;
        };
        let (Ok(received), Ok(sent)) = (r_s.parse::<u32>(), s_s.parse::<u32>()) else {
            continue;
        };
        let Some(loss_s) = parts[2].strip_suffix('%') else {
            continue;
        };
        let Ok(loss_pct) = loss_s.parse::<f64>() else {
            continue;
        };
        res.push(SpoofTesterResult {
            ip: parts[0].to_string(),
            received,
            sent,
            loss_pct,
        });
    }
    res
}

pub fn run_spoof_tester(req: SpoofTesterRequest, paths: &SpoofPaths) -> Result<Vec<SpoofTesterResult>> {
    let req = req.normalize();
    let src_file = format!("{}/tester-sources.txt", paths.spoof_dir);
    let mut body = req.sources.join("\n");
    body.push('\n');
    write_file_or_dry(&src_file, body.as_bytes())?;
    let mut cmd = vec![paths.spoof_bin.clone()];
    cmd.extend(req.build_args(&src_file)?);
    let out = sysrun::run_timeout(&cmd, Duration::from_secs(req.timeout_secs as u64 + 15));
    if !out.ok {
        bail!("spoof tester failed ({}): {}", out.code, out.stderr.trim());
    }
    Ok(parse_spoof_tester_output(&out.stdout))
}

// ============================================================================
// Native Raw-Socket IPv4 Spoof Core (`RawSpoofEngine`) + Packet Builder
// ============================================================================

/// Standard RFC 1071 16-bit one's-complement Internet checksum.
pub fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn pseudo_header_sum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4_len: u16) -> u32 {
    let s = src.octets();
    let d = dst.octets();
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([s[0], s[1]]) as u32;
    sum += u16::from_be_bytes([s[2], s[3]]) as u32;
    sum += u16::from_be_bytes([d[0], d[1]]) as u32;
    sum += u16::from_be_bytes([d[2], d[3]]) as u32;
    sum += proto as u32;
    sum += l4_len as u32;
    sum
}

fn finish_checksum(mut sum: u32, data: &[u8]) -> u16 {
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds a complete IPv4 packet with forged source IP and UDP/TCP/ICMP encapsulation.
pub fn build_spoof_ipv4_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    transport: SpoofTransport,
    ip_id: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let l4 = match transport {
        SpoofTransport::Udp => {
            let l4_len = (8 + payload.len()) as u16;
            let mut u = Vec::with_capacity(l4_len as usize);
            u.extend_from_slice(&src_port.to_be_bytes());
            u.extend_from_slice(&dst_port.to_be_bytes());
            u.extend_from_slice(&l4_len.to_be_bytes());
            u.extend_from_slice(&[0, 0]);
            u.extend_from_slice(payload);
            let csum = finish_checksum(pseudo_header_sum(src_ip, dst_ip, 17, l4_len), &u);
            let csum = if csum == 0 { 0xffff } else { csum };
            u[6..8].copy_from_slice(&csum.to_be_bytes());
            u
        }
        SpoofTransport::Tcp => {
            let l4_len = (20 + payload.len()) as u16;
            let mut t = Vec::with_capacity(l4_len as usize);
            t.extend_from_slice(&src_port.to_be_bytes());
            t.extend_from_slice(&dst_port.to_be_bytes());
            let seq = ((ip_id as u32) << 16) | (src_port as u32);
            let ack = ((dst_port as u32) << 16) | 0x51a7;
            t.extend_from_slice(&seq.to_be_bytes());
            t.extend_from_slice(&ack.to_be_bytes());
            t.push(0x50); // data offset = 5 (20 bytes)
            t.push(0x18); // PSH | ACK
            t.extend_from_slice(&65535u16.to_be_bytes());
            t.extend_from_slice(&[0, 0]); // checksum
            t.extend_from_slice(&[0, 0]); // urgent ptr
            t.extend_from_slice(payload);
            let csum = finish_checksum(pseudo_header_sum(src_ip, dst_ip, 6, l4_len), &t);
            t[16..18].copy_from_slice(&csum.to_be_bytes());
            t
        }
        SpoofTransport::Icmp => {
            let mut ic = Vec::with_capacity(8 + payload.len());
            ic.push(8); // Echo Request
            ic.push(0); // Code 0
            ic.extend_from_slice(&[0, 0]); // checksum
            ic.extend_from_slice(&dst_port.to_be_bytes()); // identifier carries dst_port
            ic.extend_from_slice(&ip_id.to_be_bytes()); // sequence
            ic.extend_from_slice(payload);
            let csum = inet_checksum(&ic);
            ic[2..4].copy_from_slice(&csum.to_be_bytes());
            ic
        }
        SpoofTransport::IcmpV6 => bail!("RawSpoofEngine IPv4 builder does not support icmpv6"),
    };

    let total_len = 20 + l4.len();
    if total_len > 65535 {
        bail!("spoof packet too large ({total_len} bytes)");
    }
    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(0x45); // IPv4, IHL=5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&ip_id.to_be_bytes());
    pkt.extend_from_slice(&0x4000u16.to_be_bytes()); // DF flag
    pkt.push(64); // TTL
    pkt.push(transport.ip_proto());
    pkt.extend_from_slice(&[0, 0]); // header checksum placeholder
    pkt.extend_from_slice(&src_ip.octets());
    pkt.extend_from_slice(&dst_ip.octets());
    let ip_csum = inet_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    pkt.extend_from_slice(&l4);
    Ok(pkt)
}

/// Extracts payload from a received raw IPv4 packet matching expected transport & destination port.
pub fn parse_spoof_ipv4_packet(pkt: &[u8], expected_transport: SpoofTransport, expected_dst_port: u16) -> Option<&[u8]> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    if pkt[9] != expected_transport.ip_proto() {
        return None;
    }
    let l4 = &pkt[ihl..];
    match expected_transport {
        SpoofTransport::Udp => {
            if l4.len() < 8 {
                return None;
            }
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            let ulen = u16::from_be_bytes([l4[4], l4[5]]) as usize;
            if dport != expected_dst_port || ulen < 8 || ulen > l4.len() {
                return None;
            }
            Some(&l4[8..ulen])
        }
        SpoofTransport::Tcp => {
            if l4.len() < 20 {
                return None;
            }
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            let doff = ((l4[12] >> 4) as usize) * 4;
            if dport != expected_dst_port || doff < 20 || doff > l4.len() {
                return None;
            }
            Some(&l4[doff..])
        }
        SpoofTransport::Icmp => {
            if l4.len() < 8 {
                return None;
            }
            let ident = u16::from_be_bytes([l4[4], l4[5]]);
            if ident != expected_dst_port {
                return None;
            }
            Some(&l4[8..])
        }
        SpoofTransport::IcmpV6 => None,
    }
}

/// Native Rust raw-socket UDP<->Spoof bridge (requires root / `CAP_NET_RAW`).
pub struct RawSpoofEngine {
    pub cfg: SpoofConfig,
    pub spoof_v4s: Vec<Ipv4Addr>,
    pub peer_v4: Ipv4Addr,
    rr: AtomicUsize,
    id_ctr: AtomicUsize,
}

impl RawSpoofEngine {
    pub fn new(cfg: SpoofConfig) -> Result<Self> {
        cfg.validate()?;
        let peer_v4: Ipv4Addr = cfg.peer_public_ip.trim().parse()?;
        let mut spoof_v4s = Vec::new();
        for s in &cfg.spoof_ips {
            spoof_v4s.push(s.parse()?);
        }
        Ok(Self {
            cfg,
            spoof_v4s,
            peer_v4,
            rr: AtomicUsize::new(0),
            id_ctr: AtomicUsize::new(1),
        })
    }

    pub fn next_spoof_ip(&self) -> Ipv4Addr {
        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % self.spoof_v4s.len();
        self.spoof_v4s[idx]
    }

    pub fn build_outbound(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let dst_port = match self.cfg.role {
            SpoofRole::Local => self.cfg.listen_port,
            SpoofRole::Remote => self.cfg.recv_port,
        };
        let ip_id = (self.id_ctr.fetch_add(1, Ordering::Relaxed) & 0xffff) as u16;
        build_spoof_ipv4_packet(
            self.next_spoof_ip(),
            self.peer_v4,
            self.cfg.spoof_port,
            dst_port,
            self.cfg.send_transport,
            ip_id,
            payload,
        )
    }

    /// Runs the bidirectional raw-socket bridge until `stop` becomes true.
    pub async fn run(self: Arc<Self>, stop: Arc<AtomicBool>) -> Result<()> {
        let raw_tx = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(255)))
            .context("open IPPROTO_RAW socket (requires CAP_NET_RAW / root)")?;
        #[allow(deprecated)]
        raw_tx
            .set_header_included(true)
            .context("setsockopt IP_HDRINCL failed")?;
        let raw_tx = Arc::new(raw_tx);

        let rx_proto = Protocol::from(self.cfg.recv_transport.ip_proto() as i32);
        let raw_rx = Socket::new(Domain::IPV4, Type::RAW, Some(rx_proto))
            .context("open raw receive socket (requires CAP_NET_RAW / root)")?;
        let _ = raw_rx.set_read_timeout(Some(Duration::from_millis(250)));

        let (local_bind, wg_target, recv_port) = match self.cfg.role {
            SpoofRole::Local => (
                format!("127.0.0.1:{}", self.cfg.core_port),
                None,
                self.cfg.recv_port,
            ),
            SpoofRole::Remote => (
                "127.0.0.1:0".to_string(),
                Some(format!("127.0.0.1:{}", self.cfg.wg_listen_port)),
                self.cfg.listen_port,
            ),
        };
        let udp = Arc::new(UdpSocket::bind(&local_bind).await.context("bind local WG UDP pipe")?);
        let last_wg_client: Arc<std::sync::Mutex<Option<SocketAddr>>> = Arc::new(std::sync::Mutex::new(
            wg_target.and_then(|s| s.parse().ok()),
        ));

        let dst_port = match self.cfg.role {
            SpoofRole::Local => self.cfg.listen_port,
            SpoofRole::Remote => self.cfg.recv_port,
        };
        let dst_sa = SockAddr::from(SocketAddrV4::new(self.peer_v4, dst_port));

        // Blocking raw-socket RX thread -> local WG UDP socket
        let udp_rx = udp.clone();
        let stop_rx = stop.clone();
        let last_rx = last_wg_client.clone();
        let expected_tr = self.cfg.recv_transport;
        let rt = tokio::runtime::Handle::current();
        let rx_handle = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; 65535];
            while !stop_rx.load(Ordering::Relaxed) {
                match (&raw_rx).read(&mut buf) {
                    Ok(n) if n > 0 => {
                        if let Some(payload) = parse_spoof_ipv4_packet(&buf[..n], expected_tr, recv_port) {
                            let target = *last_rx.lock().unwrap();
                            if let Some(addr) = target {
                                let _ = rt.block_on(udp_rx.send_to(payload, addr));
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        // Async local WG UDP -> forged raw IPv4 TX
        let mut ubuf = vec![0u8; 65535];
        while !stop.load(Ordering::Relaxed) {
            match timeout(Duration::from_millis(250), udp.recv_from(&mut ubuf)).await {
                Ok(Ok((n, src))) => {
                    if self.cfg.role == SpoofRole::Local {
                        *last_wg_client.lock().unwrap() = Some(src);
                    }
                    if let Ok(pkt) = self.build_outbound(&ubuf[..n]) {
                        let _ = raw_tx.send_to(&pkt, &dst_sa);
                    }
                }
                Ok(Err(e)) => {
                    stop.store(true, Ordering::Relaxed);
                    let _ = rx_handle.await;
                    return Err(e.into());
                }
                Err(_) => {}
            }
        }
        let _ = rx_handle.await;
        Ok(())
    }
}

/// Connects to the tunnel exit over the active `wg-spoof` overlay (verifying active handshake if desired).
pub async fn connect_spoof(uri: &str, connect_timeout: Duration) -> Result<BoxRw> {
    let clean = uri.strip_prefix("spoof://").unwrap_or(uri);
    let tcp = timeout(connect_timeout, TcpStream::connect(clean)).await??;
    link::tune(&tcp);
    Ok(Box::new(tcp) as BoxRw)
}

// ============================================================================
// Pure-Rust Constant-Time X25519 (RFC 7748, TweetNaCl 16-limb field arithmetic)
// ============================================================================

type Gf = [i64; 16];

fn car25519(o: &mut Gf) {
    for i in 0..16 {
        o[i] += 1i64 << 16;
        let c = o[i] >> 16;
        if i < 15 {
            o[i + 1] += c - 1;
        } else {
            o[0] += (c - 1) * 38;
        }
        o[i] -= c << 16;
    }
}

fn sel25519(p: &mut Gf, q: &mut Gf, b: i64) {
    let c = -(b & 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn pack25519(n: &Gf) -> [u8; 32] {
    let mut t = *n;
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);
    let mut m = [0i64; 16];
    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(&mut t, &mut m, 1 - b);
    }
    let mut out = [0u8; 32];
    for i in 0..16 {
        out[2 * i] = (t[i] & 0xff) as u8;
        out[2 * i + 1] = ((t[i] >> 8) & 0xff) as u8;
    }
    out
}

fn unpack25519(n: &[u8; 32]) -> Gf {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = (n[2 * i] as i64) + ((n[2 * i + 1] as i64) << 8);
    }
    o[15] &= 0x7fff;
    o
}

fn gf_add(a: &Gf, b: &Gf) -> Gf {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
    o
}

fn gf_sub(a: &Gf, b: &Gf) -> Gf {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
    o
}

fn gf_mul(a: &Gf, b: &Gf) -> Gf {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut o = [0i64; 16];
    o.copy_from_slice(&t[..16]);
    car25519(&mut o);
    car25519(&mut o);
    o
}

fn gf_sq(a: &Gf) -> Gf {
    gf_mul(a, a)
}

fn gf_inv(i: &Gf) -> Gf {
    let mut c = *i;
    for a in (0..=253).rev() {
        c = gf_sq(&c);
        if a != 2 && a != 4 {
            c = gf_mul(&c, i);
        }
    }
    c
}

/// Computes `X25519(sk, basepoint=9)` matching WireGuard & RFC 7748.
pub fn x25519_public_from_private(sk: &[u8; 32]) -> [u8; 32] {
    let mut z = *sk;
    z[31] = (z[31] & 127) | 64;
    z[0] &= 248;
    let mut base = [0u8; 32];
    base[0] = 9;
    let x = unpack25519(&base);
    let mut a = [0i64; 16];
    let mut b = x;
    let mut c = [0i64; 16];
    let mut d = [0i64; 16];
    a[0] = 1;
    d[0] = 1;
    let mut c121665 = [0i64; 16];
    c121665[0] = 0xdb41;
    c121665[1] = 1;

    for i in (0..=254).rev() {
        let r = ((z[i >> 3] >> (i & 7)) & 1) as i64;
        sel25519(&mut a, &mut b, r);
        sel25519(&mut c, &mut d, r);
        let e = gf_add(&a, &c);
        a = gf_sub(&a, &c);
        c = gf_add(&b, &d);
        b = gf_sub(&b, &d);
        d = gf_sq(&e);
        let f = gf_sq(&a);
        a = gf_mul(&c, &a);
        c = gf_mul(&b, &e);
        let e2 = gf_add(&a, &c);
        a = gf_sub(&a, &c);
        b = gf_sq(&a);
        c = gf_sub(&d, &f);
        a = gf_mul(&c, &c121665);
        a = gf_add(&a, &d);
        c = gf_mul(&c, &a);
        a = gf_mul(&d, &f);
        d = gf_mul(&b, &x);
        b = gf_sq(&e2);
        sel25519(&mut a, &mut b, r);
        sel25519(&mut c, &mut d, r);
    }
    let inv_c = gf_inv(&c);
    pack25519(&gf_mul(&a, &inv_c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_matches_rfc7748_vector() {
        let sk = crate::util::unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk);
        let pk = x25519_public_from_private(&sk_arr);
        assert_eq!(
            crate::util::hex(&pk),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
    }

    #[test]
    fn rfc1071_checksum_and_raw_packet_roundtrip() {
        let hdr = crate::util::unhex("450000730000400040110000c0a80001c0a800c7").unwrap();
        assert_eq!(inet_checksum(&hdr), 0xb861);

        let payload = b"wg-encrypted-frame-payload";
        for tr in [SpoofTransport::Udp, SpoofTransport::Tcp, SpoofTransport::Icmp] {
            let pkt = build_spoof_ipv4_packet(
                Ipv4Addr::new(1, 1, 1, 1),
                Ipv4Addr::new(203, 0, 113, 20),
                443,
                8090,
                tr,
                42,
                payload,
            )
            .unwrap();
            assert_eq!(inet_checksum(&pkt[..20]), 0);
            let extracted = parse_spoof_ipv4_packet(&pkt, tr, 8090).unwrap();
            assert_eq!(extracted, payload);
            assert!(parse_spoof_ipv4_packet(&pkt, tr, 9999).is_none());
        }
    }

    #[test]
    fn spoof_khaymali_spf1_bundle_and_legacy_roundtrip() {
        let mut cfg = SpoofConfig::new_default(
            SpoofRole::Local,
            "198.51.100.10".into(),
            "203.0.113.20".into(),
        );
        cfg.spoof_ips = vec!["1.1.1.1".into(), "8.8.8.8".into()];
        cfg.send_transport = SpoofTransport::Tcp;
        cfg.recv_transport = SpoofTransport::Icmp;
        cfg.set_forward_ports("443, 8443-8444", &[8080]).unwrap();
        assert!(cfg.set_forward_ports("22", &[8080]).is_err());

        let spf1 = cfg.make_khaymali_bundle().unwrap();
        assert!(spf1.starts_with("spf1_"));
        assert!(cfg.render_wg_conf().contains("MTU = 1280"));
        assert!(cfg.render_wg_conf().contains("PersistentKeepalive = 25"));
        assert!(cfg.render_forward_nft().contains("maxseg size set rt mtu"));

        let mut foreign_prev = SpoofConfig::new_default(SpoofRole::Remote, "".into(), "".into());
        foreign_prev.spoof_ips = vec!["9.9.9.9".into()];
        let foreign = SpoofConfig::import_bundle(&spf1, &foreign_prev).unwrap();
        assert_eq!(foreign.role, SpoofRole::Remote);
        assert_eq!(foreign.peer_public_ip, "198.51.100.10");
        assert_eq!(foreign.send_transport, SpoofTransport::Icmp);
        assert_eq!(foreign.recv_transport, SpoofTransport::Tcp);
        assert_eq!(foreign.wg_peer_pub, cfg.wg_pub_key);
        assert_eq!(foreign.wg_pub_key, cfg.wg_peer_pub);
        assert_eq!(foreign.spoof_ips, vec!["9.9.9.9"]);

        // Legacy SPOOF1: compatibility
        let legacy = cfg.encode_remote_bundle(&cfg.wg_peer_priv);
        let parsed = SpoofConfig::decode_remote_bundle(&legacy).unwrap();
        assert_eq!(parsed.get("ip").map(|s| s.as_str()), Some("198.51.100.10"));
    }

    #[test]
    fn spoof_tester_parser_and_dry_run_lifecycle() {
        let sample = "starting receiver...\n1.1.1.1 10/10 0.0%\n8.8.8.8 8/10 20%\nbad line\n";
        let res = parse_spoof_tester_output(sample);
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].ip, "1.1.1.1");
        assert_eq!(res[1].received, 8);
        assert_eq!(res[1].loss_pct, 20.0);

        sysrun::set_dry_run(true);
        let _ = sysrun::take_log();
        let mut cfg = SpoofConfig::new_default(SpoofRole::Local, "198.51.100.1".into(), "203.0.113.2".into());
        cfg.spoof_ips = vec!["1.1.1.1".into()];
        cfg.forward_ports = vec![443];
        let _ = cfg.make_khaymali_bundle().unwrap();
        let paths = SpoofPaths::default();
        let msg = apply_spoof(&cfg, &paths, true).unwrap();
        assert!(msg.contains("Spoof tunnel is up"));
        stop_spoof().unwrap();
        let log = sysrun::take_log();
        assert!(log.iter().any(|l| l.contains("systemctl restart spoof-core")));
        assert!(log.iter().any(|l| l.contains("systemctl restart wg-quick@wg-spoof")));
        sysrun::set_dry_run(false);
    }
}
