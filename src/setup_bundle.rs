//! Khaymali Setup Bundles (`hsh1_`, `bh1_`, `gh1_`), Port Specs & UFW/TOML Helpers (`src/setup_bundle.rs`).
//!
//! Full Rust port of Khaymali's `setup_bundle.go` and `setup_ports.go`:
//!   * `hsh1_<IRAN_PUB>_<FRP_PORT>_<IRAN_GRE>_<FOREIGN_GRE>_<TOKEN>[_<PORTS>][_fou<P1>-<P2>][_tr-<TR>]`
//!   * `bh1_<IRAN_PUB>_<BH_PORT>_<TRANSPORT>[+udp<PORT>]_<TOKEN>[_<PORTS>]`
//!   * `gh1_<IRAN_PUB>_<BH_PORT>_<IRAN_GRE>_<FOREIGN_GRE>_<TRANSPORT>[+udp<PORT>]_<TOKEN>[_<PORTS>]`
//!   * Port list/range/mapping parser (`443`, `8080-8090`, `2083=8443`).
//!   * `rewrite_frpc_toml_ports` preserving per-proxy `localIP`, `proxyProtocolVersion`,
//!     `bandwidthLimit`, and `healthCheck.*` options.
//!   * `allow_ufw_tunnel_ports` & `ufw.opened` tracking via `sysrun`.

use crate::hjson;
use crate::sysrun;
use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

pub const BUNDLE_PREFIX: &str = "hsh1_";
pub const BUNDLE_PREFIX_BACKHAUL: &str = "bh1_";
pub const BUNDLE_PREFIX_GRE_BACKHAUL: &str = "gh1_";
pub const BUNDLE_UDP_MARK: &str = "+udp";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupBundle {
    pub engine: String,    // "frp" | "backhaul" | "gre-backhaul"
    pub transport: String, // frp: tcp|kcp|quic|websocket; backhaul: tcp|tcpmux|ws|wss|wsmux|wssmux|udp
    pub udp: bool,         // backhaul companion UDP forwarding enabled
    pub udp_port: u16,     // backhaul UDP companion control port (0 if none)
    pub iran_pub: String,
    pub ctrl_port: u16,
    pub iran_gre: String,
    pub foreign_gre: String,
    pub token: String,
    pub ports: Vec<u16>,
    pub raw_ports: Vec<String>,
    pub fou_ports: Vec<u16>,
}

pub fn is_bundle(s: &str) -> bool {
    let t = s.trim();
    t.starts_with(BUNDLE_PREFIX) || is_backhaul_bundle(t) || is_gre_backhaul_bundle(t)
}

pub fn is_backhaul_bundle(s: &str) -> bool {
    s.trim().starts_with(BUNDLE_PREFIX_BACKHAUL)
}

pub fn is_gre_backhaul_bundle(s: &str) -> bool {
    s.trim().starts_with(BUNDLE_PREFIX_GRE_BACKHAUL)
}

pub fn backhaul_bundle_transport(transport: &str, udp_port: u16) -> String {
    let t = if transport.trim().is_empty() {
        "tcpmux"
    } else {
        transport.trim()
    };
    if udp_port > 0 && t != "udp" && !t.contains(BUNDLE_UDP_MARK) {
        format!("{t}{BUNDLE_UDP_MARK}{udp_port}")
    } else {
        t.to_string()
    }
}

pub fn split_bundle_transport(t: &str) -> (String, bool, u16) {
    if let Some((base, rest)) = t.split_once(BUNDLE_UDP_MARK) {
        let port = rest.parse::<u16>().unwrap_or(0);
        (base.to_string(), true, port)
    } else {
        (t.to_string(), false, 0)
    }
}

/// Builds a Khaymali GRE+FRP setup bundle (`hsh1_...`).
#[allow(clippy::too_many_arguments)]
pub fn make_frp_bundle(
    iran_pub: &str,
    frp_port: u16,
    iran_gre: &str,
    foreign_gre: &str,
    token: &str,
    ports: &[u16],
    transport: &str,
    fou_port1: u16,
    fou_port2: u16,
) -> String {
    let p1 = if fou_port1 == 0 { 443 } else { fou_port1 };
    let p2 = if fou_port2 == 0 { 55555 } else { fou_port2 };
    let mut s = format!(
        "{BUNDLE_PREFIX}{iran_pub}_{frp_port}_{iran_gre}_{foreign_gre}_{token}"
    );
    let fou_part = format!("fou{p1}-{p2}");
    let tr_part = if !transport.is_empty() && transport != "tcp" {
        format!("_tr-{transport}")
    } else {
        String::new()
    };
    if ports.is_empty() {
        s.push_str(&format!("__{fou_part}{tr_part}"));
    } else {
        let ps = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("-");
        s.push_str(&format!("_{ps}_{fou_part}{tr_part}"));
    }
    s
}

/// Builds a Standalone Backhaul setup bundle (`bh1_...`, No-GRE, supports IPv4 or IPv6).
pub fn make_backhaul_bundle(
    iran_pub: &str,
    bh_port: u16,
    transport: &str,
    token: &str,
    raw_ports: &[String],
) -> String {
    let tr = if transport.is_empty() { "tcpmux" } else { transport };
    let mut s = format!("{BUNDLE_PREFIX_BACKHAUL}{iran_pub}_{bh_port}_{tr}_{token}");
    if !raw_ports.is_empty() {
        s.push('_');
        s.push_str(&raw_ports.join(","));
    }
    s
}

/// Builds a GRE + Backhaul setup bundle (`gh1_...`).
pub fn make_gre_backhaul_bundle(
    iran_pub: &str,
    bh_port: u16,
    iran_gre: &str,
    foreign_gre: &str,
    transport: &str,
    token: &str,
    raw_ports: &[String],
) -> String {
    let tr = if transport.is_empty() { "tcpmux" } else { transport };
    let mut s = format!(
        "{BUNDLE_PREFIX_GRE_BACKHAUL}{iran_pub}_{bh_port}_{iran_gre}_{foreign_gre}_{tr}_{token}"
    );
    if !raw_ports.is_empty() {
        s.push('_');
        s.push_str(&raw_ports.join(","));
    }
    s
}

/// Parses any Khaymali bundle (`hsh1_...`, `bh1_...`, or `gh1_...`).
pub fn parse_bundle(s: &str) -> Result<SetupBundle> {
    let t = s.trim();
    if t.starts_with(BUNDLE_PREFIX_BACKHAUL) {
        return parse_backhaul_bundle(t);
    }
    if t.starts_with(BUNDLE_PREFIX_GRE_BACKHAUL) {
        return parse_gre_backhaul_bundle(t);
    }
    let rest = t
        .strip_prefix(BUNDLE_PREFIX)
        .context("not a setup bundle (must start with hsh1_, bh1_, or gh1_)")?;
    let parts: Vec<&str> = rest.split('_').collect();
    if parts.len() < 5 || parts.len() > 8 {
        bail!("hsh1_ bundle must have 5..=8 underscore parts (got {})", parts.len());
    }
    let (iran_pub, port_s, iran_gre, foreign_gre, token) =
        (parts[0], parts[1], parts[2], parts[3], parts[4]);
    validate_ipv4(iran_pub, "Iran public IP")?;
    let ctrl_port = parse_nonzero_port(port_s, "control port")?;
    validate_ipv4(iran_gre, "Iran GRE IP")?;
    validate_ipv4(foreign_gre, "foreign GRE IP")?;
    validate_token(token)?;

    let mut b = SetupBundle {
        engine: "frp".into(),
        transport: "tcp".into(),
        udp: false,
        udp_port: 0,
        iran_pub: iran_pub.into(),
        ctrl_port,
        iran_gre: iran_gre.into(),
        foreign_gre: foreign_gre.into(),
        token: token.into(),
        ports: Vec::new(),
        raw_ports: Vec::new(),
        fou_ports: Vec::new(),
    };
    for &p in &parts[5..] {
        if p.is_empty() {
            continue;
        }
        if let Some(tr) = p.strip_prefix("tr-") {
            b.transport = tr.to_string();
        } else if let Some(fou_raw) = p.strip_prefix("fou") {
            for fp_s in fou_raw.split('-') {
                if let Ok(fp) = fp_s.parse::<u16>() {
                    if fp > 0 {
                        b.fou_ports.push(fp);
                    }
                }
            }
        } else {
            let nums = parse_numeric_ports(&p.replace('-', ","));
            if !nums.is_empty() {
                b.raw_ports = nums.iter().map(|n| n.to_string()).collect();
                b.ports = nums;
            }
        }
    }
    Ok(b)
}

pub fn parse_backhaul_bundle(s: &str) -> Result<SetupBundle> {
    let rest = s
        .trim()
        .strip_prefix(BUNDLE_PREFIX_BACKHAUL)
        .context("not a backhaul bundle (must start with bh1_)")?;
    let parts: Vec<&str> = rest.split('_').collect();
    if parts.len() < 4 || parts.len() > 5 {
        bail!("bh1_ bundle must have 4 or 5 underscore parts (got {})", parts.len());
    }
    let (iran_pub, port_s, tr_raw, token) = (parts[0], parts[1], parts[2], parts[3]);
    if iran_pub.parse::<IpAddr>().is_err() {
        bail!("bad Iran public IP in bh1_ bundle: '{iran_pub}'");
    }
    let ctrl_port = parse_nonzero_port(port_s, "control port")?;
    let (mut transport, udp, udp_port) = split_bundle_transport(tr_raw);
    if transport.is_empty() {
        transport = "tcpmux".into();
    }
    validate_token(token)?;
    let (raw_ports, ports) = if parts.len() == 5 && !parts[4].is_empty() {
        let raw = parse_raw_ports(parts[4]);
        let nums = extract_numeric_ports(&raw);
        (raw, nums)
    } else {
        (Vec::new(), Vec::new())
    };
    Ok(SetupBundle {
        engine: "backhaul".into(),
        transport,
        udp,
        udp_port,
        iran_pub: iran_pub.into(),
        ctrl_port,
        iran_gre: String::new(),
        foreign_gre: String::new(),
        token: token.into(),
        ports,
        raw_ports,
        fou_ports: Vec::new(),
    })
}

pub fn parse_gre_backhaul_bundle(s: &str) -> Result<SetupBundle> {
    let rest = s
        .trim()
        .strip_prefix(BUNDLE_PREFIX_GRE_BACKHAUL)
        .context("not a gre-backhaul bundle (must start with gh1_)")?;
    let parts: Vec<&str> = rest.split('_').collect();
    if parts.len() < 6 || parts.len() > 7 {
        bail!("gh1_ bundle must have 6 or 7 underscore parts (got {})", parts.len());
    }
    let (iran_pub, port_s, iran_gre, foreign_gre, tr_raw, token) =
        (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]);
    validate_ipv4(iran_pub, "Iran public IP")?;
    let ctrl_port = parse_nonzero_port(port_s, "control port")?;
    validate_ipv4(iran_gre, "Iran GRE IP")?;
    validate_ipv4(foreign_gre, "foreign GRE IP")?;
    let (mut transport, udp, udp_port) = split_bundle_transport(tr_raw);
    if transport.is_empty() {
        transport = "tcpmux".into();
    }
    validate_token(token)?;
    let (raw_ports, ports) = if parts.len() == 7 && !parts[6].is_empty() {
        let raw = parse_raw_ports(parts[6]);
        let nums = extract_numeric_ports(&raw);
        (raw, nums)
    } else {
        (Vec::new(), Vec::new())
    };
    Ok(SetupBundle {
        engine: "gre-backhaul".into(),
        transport,
        udp,
        udp_port,
        iran_pub: iran_pub.into(),
        ctrl_port,
        iran_gre: iran_gre.into(),
        foreign_gre: foreign_gre.into(),
        token: token.into(),
        ports,
        raw_ports,
        fou_ports: Vec::new(),
    })
}

fn validate_ipv4(s: &str, label: &str) -> Result<()> {
    if s.parse::<Ipv4Addr>().is_err() {
        bail!("bad {label} in bundle: '{s}'");
    }
    Ok(())
}

fn parse_nonzero_port(s: &str, label: &str) -> Result<u16> {
    let p: u16 = s.parse().with_context(|| format!("bad {label}: '{s}'"))?;
    if p == 0 {
        bail!("bad {label}: port 0 is invalid");
    }
    Ok(p)
}

fn validate_token(t: &str) -> Result<()> {
    if t.is_empty() || t.len() > 128 {
        bail!("bad token in bundle (length must be 1..=128)");
    }
    Ok(())
}

// ============================================================================
// Port Spec Parsers (Single, Range `a-b`, Mapping `listen=target`)
// ============================================================================

/// Splits raw Backhaul/FRP port strings like `"443, 8080-8085, 2083=8443"`.
pub fn parse_raw_ports(spec: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tok in spec.split(|c: char| c == ',' || c.is_whitespace()) {
        let t = tok.trim();
        if !t.is_empty() && is_valid_port_spec_entry(t) && !out.iter().any(|x| x == t) {
            out.push(t.to_string());
        }
    }
    out
}

pub fn is_valid_port_spec_entry(entry: &str) -> bool {
    let e = entry.trim();
    if let Some((lhs, rhs)) = e.split_once('=') {
        return is_port_or_range(lhs.trim()) && is_port_or_range(rhs.trim());
    }
    is_port_or_range(e)
}

fn is_port_or_range(s: &str) -> bool {
    if let Some((a, b)) = s.split_once('-') {
        if let (Ok(lo), Ok(hi)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
            return lo > 0 && hi >= lo && (hi - lo) <= 2000;
        }
        return false;
    }
    s.parse::<u16>().map(|p| p > 0).unwrap_or(false)
}

/// Expands raw Backhaul port entries into sorted unique listening port numbers.
pub fn extract_numeric_ports(raw: &[String]) -> Vec<u16> {
    let mut set = BTreeSet::new();
    for entry in raw {
        let lhs = entry.split_once('=').map(|(l, _)| l).unwrap_or(entry).trim();
        if let Some((a, b)) = lhs.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                if lo > 0 && hi >= lo && (hi - lo) <= 2000 {
                    for p in lo..=hi {
                        set.insert(p);
                    }
                }
            }
        } else if let Ok(p) = lhs.parse::<u16>() {
            if p > 0 {
                set.insert(p);
            }
        }
    }
    set.into_iter().collect()
}

pub fn parse_numeric_ports(spec: &str) -> Vec<u16> {
    extract_numeric_ports(&parse_raw_ports(spec))
}

// ============================================================================
// frpc.toml `[[proxies]]` Rewriter (Khaymali `rewriteTomlPorts`)
// ============================================================================

#[derive(Clone, Debug, Default)]
struct FrpProxyCarry {
    local_ip: String,
    extras: Vec<String>,
}

/// Rebuilds `[[proxies]]` sections in `frpc.toml` for `ports` while keeping the header
/// verbatim and carrying over per-proxy `localIP`, `proxyProtocolVersion`, `bandwidthLimit`,
/// and `healthCheck.*` options from prior blocks of the same type/port.
pub fn rewrite_frpc_toml_ports(src: &str, ports: &[u16]) -> String {
    let mut by_port: BTreeMap<String, FrpProxyCarry> = BTreeMap::new();
    let mut by_type: BTreeMap<String, FrpProxyCarry> = BTreeMap::new();
    let mut header = String::new();
    let mut in_proxy = false;
    let mut typ = String::new();
    let mut port: u16 = 0;
    let mut cur = FrpProxyCarry::default();

    let flush = |in_p: bool,
                 t: &str,
                 p: u16,
                 c: &FrpProxyCarry,
                 bp: &mut BTreeMap<String, FrpProxyCarry>,
                 bt: &mut BTreeMap<String, FrpProxyCarry>| {
        if !in_p || t.is_empty() {
            return;
        }
        if p > 0 {
            bp.insert(format!("{t}:{p}"), c.clone());
        }
        bt.entry(t.to_string()).or_insert_with(|| c.clone());
    };

    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("[[proxies]]") {
            flush(in_proxy, &typ, port, &cur, &mut by_port, &mut by_type);
            in_proxy = true;
            typ.clear();
            port = 0;
            cur = FrpProxyCarry::default();
            continue;
        }
        if trimmed.starts_with('[') {
            flush(in_proxy, &typ, port, &cur, &mut by_port, &mut by_type);
            in_proxy = false;
        }
        if !in_proxy {
            header.push_str(line);
            header.push('\n');
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            match k {
                "name" => {}
                "type" => typ = v.trim_matches(|c| c == '"' || c == '\'').to_string(),
                "localPort" => {
                    if port == 0 {
                        port = v.parse().unwrap_or(0);
                    }
                }
                "remotePort" => port = v.parse().unwrap_or(port),
                "localIP" => cur.local_ip = v.trim_matches(|c| c == '"' || c == '\'').to_string(),
                _ => cur.extras.push(trimmed.to_string()),
            }
        }
    }
    flush(in_proxy, &typ, port, &cur, &mut by_port, &mut by_type);

    let mut out = header.trim_end_matches('\n').to_string();
    out.push('\n');
    for &p in ports {
        for t in ["tcp", "udp"] {
            let carry = by_port
                .get(&format!("{t}:{p}"))
                .or_else(|| by_type.get(t))
                .cloned()
                .unwrap_or_default();
            let local_ip = if carry.local_ip.is_empty() {
                "127.0.0.1"
            } else {
                carry.local_ip.as_str()
            };
            out.push_str(&format!(
                "\n[[proxies]]\nname = \"{t}_{p}\"\ntype = \"{t}\"\nlocalIP = \"{local_ip}\"\nlocalPort = {p}\nremotePort = {p}\n"
            ));
            for e in carry.extras {
                out.push_str(&e);
                out.push('\n');
            }
        }
    }
    out
}

// ============================================================================
// UFW Tunnel Port Tracking (`ufw.opened`)
// ============================================================================

/// Opens TCP+UDP for `ports` when UFW is active, recording newly opened rules in `opened_path`.
pub fn allow_ufw_tunnel_ports(ports: &[u16], opened_path: &str) -> Result<Vec<String>> {
    let st = sysrun::run(&crate::v!["ufw", "status"]);
    if !sysrun::is_dry_run() && (!st.ok || !st.stdout.contains("Status: active")) {
        return Ok(Vec::new());
    }
    let mut added = Vec::new();
    for &p in ports {
        for proto in ["tcp", "udp"] {
            let rule = format!("{p}/{proto}");
            let res = sysrun::run(&crate::v!["ufw", "allow", &rule]);
            if res.ok && !res.stdout.contains("Skipping") {
                added.push(rule);
            }
        }
    }
    if !added.is_empty() && !sysrun::is_dry_run() {
        let existing = std::fs::read_to_string(opened_path).unwrap_or_default();
        let mut set: BTreeSet<String> = existing
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        for r in &added {
            set.insert(r.clone());
        }
        let body = set.into_iter().collect::<Vec<_>>().join("\n") + "\n";
        hjson::write_atomic(opened_path, body.as_bytes())?;
    }
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frp_backhaul_and_gre_backhaul_bundles_roundtrip() {
        let h = make_frp_bundle(
            "198.51.100.10",
            7000,
            "10.10.0.1",
            "10.10.0.2",
            "tok32charsabcdef0123456789",
            &[443, 8443],
            "quic",
            443,
            55555,
        );
        assert!(h.starts_with("hsh1_"));
        let pb = parse_bundle(&h).unwrap();
        assert_eq!(pb.engine, "frp");
        assert_eq!(pb.transport, "quic");
        assert_eq!(pb.ports, vec![443, 8443]);
        assert_eq!(pb.fou_ports, vec![443, 55555]);

        let tr = backhaul_bundle_transport("tcpmux", 3081);
        assert_eq!(tr, "tcpmux+udp3081");
        let bh = make_backhaul_bundle(
            "2001:db8::10",
            3080,
            &tr,
            "bh_tok_999",
            &["443".into(), "8080-8082".into(), "2083=8443".into()],
        );
        assert!(bh.starts_with("bh1_"));
        let pbh = parse_bundle(&bh).unwrap();
        assert_eq!(pbh.engine, "backhaul");
        assert_eq!(pbh.transport, "tcpmux");
        assert!(pbh.udp);
        assert_eq!(pbh.udp_port, 3081);
        assert_eq!(pbh.ports, vec![443, 2083, 8080, 8081, 8082]);

        let gh = make_gre_backhaul_bundle(
            "198.51.100.10",
            3080,
            "10.10.0.1",
            "10.10.0.2",
            "wsmux",
            "gh_tok_123",
            &["443".into()],
        );
        let pgh = parse_bundle(&gh).unwrap();
        assert_eq!(pgh.engine, "gre-backhaul");
        assert_eq!(pgh.iran_gre, "10.10.0.1");
        assert_eq!(pgh.foreign_gre, "10.10.0.2");
    }

    #[test]
    fn frpc_toml_rewrite_preserves_proxy_protocol_and_healthcheck() {
        let orig = r#"serverAddr = "10.10.0.1"
serverPort = 7000

[[proxies]]
name = "tcp_443"
type = "tcp"
localIP = "127.0.0.1"
localPort = 443
remotePort = 443
transport.proxyProtocolVersion = "v2"
healthCheck.type = "tcp"
"#;
        let rewritten = rewrite_frpc_toml_ports(orig, &[443, 8443]);
        assert!(rewritten.contains("serverAddr = \"10.10.0.1\""));
        assert!(rewritten.contains("name = \"tcp_8443\""));
        assert!(rewritten.contains("transport.proxyProtocolVersion = \"v2\""));
        assert!(rewritten.contains("healthCheck.type = \"tcp\""));
    }
}
