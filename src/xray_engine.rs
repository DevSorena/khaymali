//! Xray-Core Config Generator, REALITY Keygen, Presets & VLESS URIs (`src/xray_engine.rs`).
//!
//! Full Rust port of Khaymali's `xray_config.go` and `xray.go`:
//!   * RFC 4122 UUID v4 generator (`new_xray_uuid`) and REALITY X25519 keypair generator
//!     (`new_xray_reality_keys`) backed by our RFC 7748 verified `x25519_public_from_private`.
//!   * Built-in censorship-resistant presets (`reality-vision`, `reality-grpc`, `reality-xhttp`,
//!     `ws-tls`, `kcp-noise`) with `XrayFragment` and `XrayNoise` validation.
//!   * Complete Xray server (Foreign) and client/bridge (Iran `dokodemo-door` -> VLESS outbound)
//!     JSON config generation using dependency-free `hjson`.
//!   * Shareable `vless://` client URI renderer + systemd unit deployment via `sysrun`.

use crate::hjson::{self, Json};
use crate::spoof_carrier::x25519_public_from_private;
use crate::sysrun;
use crate::util::{hex, rand_bytes};
use anyhow::{bail, Result};

#[derive(Clone, Debug)]
pub struct XrayFragment {
    pub packets: String,  // "tlshello" | "1-3"
    pub length: String,   // "10-50"
    pub interval: String, // "10-30"
}

#[derive(Clone, Debug)]
pub struct XrayNoise {
    pub kind: String,  // "rand" | "str" | "base64"
    pub packet: String,
    pub delay: String, // e.g. "10-20"
}

impl XrayNoise {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.kind.as_str(), "rand" | "str" | "base64") {
            bail!("invalid XrayNoise type '{}' (expected rand|str|base64)", self.kind);
        }
        if self.packet.trim().is_empty() {
            bail!("XrayNoise packet cannot be empty");
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct XrayKeys {
    pub uuid: String,
    pub reality_priv: String,
    pub reality_pub: String,
    pub short_id: String,
}

impl XrayKeys {
    pub fn generate() -> Self {
        let (priv_k, pub_k) = new_xray_reality_keys();
        Self {
            uuid: new_xray_uuid(),
            reality_priv: priv_k,
            reality_pub: pub_k,
            short_id: hex(&rand_bytes::<8>()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct XrayProfile {
    pub name: String,
    pub transport: String,   // "tcp" | "grpc" | "xhttp" | "ws" | "kcp"
    pub security: String,    // "reality" | "tls" | "none"
    pub flow: String,        // "xtls-rprx-vision" | ""
    pub sni: String,
    pub dest: String,        // e.g. "www.cloudflare.com:443"
    pub fingerprint: String, // "chrome" | "firefox" | "safari" | "randomized"
    pub path: String,
    pub fragment: Option<XrayFragment>,
    pub noise: Option<XrayNoise>,
}

pub fn xray_preset(name: &str) -> Result<XrayProfile> {
    match name.trim().to_ascii_lowercase().as_str() {
        "reality-vision" | "reality" => Ok(XrayProfile {
            name: "reality-vision".into(),
            transport: "tcp".into(),
            security: "reality".into(),
            flow: "xtls-rprx-vision".into(),
            sni: "www.cloudflare.com".into(),
            dest: "www.cloudflare.com:443".into(),
            fingerprint: "chrome".into(),
            path: String::new(),
            fragment: None,
            noise: None,
        }),
        "reality-grpc" => Ok(XrayProfile {
            name: "reality-grpc".into(),
            transport: "grpc".into(),
            security: "reality".into(),
            flow: String::new(),
            sni: "www.microsoft.com".into(),
            dest: "www.microsoft.com:443".into(),
            fingerprint: "chrome".into(),
            path: "khaymali-grpc".into(),
            fragment: None,
            noise: None,
        }),
        "reality-xhttp" => Ok(XrayProfile {
            name: "reality-xhttp".into(),
            transport: "xhttp".into(),
            security: "reality".into(),
            flow: String::new(),
            sni: "www.apple.com".into(),
            dest: "www.apple.com:443".into(),
            fingerprint: "safari".into(),
            path: "/xh".into(),
            fragment: Some(XrayFragment {
                packets: "tlshello".into(),
                length: "20-60".into(),
                interval: "10-25".into(),
            }),
            noise: None,
        }),
        "ws-tls" => Ok(XrayProfile {
            name: "ws-tls".into(),
            transport: "ws".into(),
            security: "tls".into(),
            flow: String::new(),
            sni: "cdn.example.com".into(),
            dest: String::new(),
            fingerprint: "chrome".into(),
            path: "/ws".into(),
            fragment: Some(XrayFragment {
                packets: "tlshello".into(),
                length: "10-40".into(),
                interval: "10-20".into(),
            }),
            noise: None,
        }),
        "kcp-noise" => Ok(XrayProfile {
            name: "kcp-noise".into(),
            transport: "kcp".into(),
            security: "none".into(),
            flow: String::new(),
            sni: String::new(),
            dest: String::new(),
            fingerprint: String::new(),
            path: "seed-khaymali".into(),
            fragment: None,
            noise: Some(XrayNoise {
                kind: "rand".into(),
                packet: "10-40".into(),
                delay: "10-16".into(),
            }),
        }),
        other => bail!(
            "unknown Xray preset '{other}' (expected reality-vision|reality-grpc|reality-xhttp|ws-tls|kcp-noise)"
        ),
    }
}

#[derive(Clone, Debug)]
pub struct XrayLink {
    pub id: u32,
    pub side: String, // "iran" | "foreign"
    pub listen_port: u16,
    pub remote_host: String,
    pub forward_ports: Vec<u16>,
    pub keys: XrayKeys,
    pub profile: XrayProfile,
}

impl XrayLink {
    /// Renders Foreign (VLESS server inbound + freedom outbound) Xray JSON config.
    pub fn render_server_json(&self) -> Result<String> {
        if let Some(n) = &self.profile.noise {
            n.validate()?;
        }
        let client = Json::obj()
            .set("id", self.keys.uuid.clone())
            .set("flow", self.profile.flow.clone());
        let stream = build_stream_settings(&self.profile, &self.keys, true);
        let inbound = Json::obj()
            .set("tag", format!("vless-in-{}", self.id))
            .set("listen", "0.0.0.0")
            .set("port", self.listen_port)
            .set("protocol", "vless")
            .set(
                "settings",
                Json::obj()
                    .set("clients", vec![client])
                    .set("decryption", "none"),
            )
            .set("streamSettings", stream);
        let cfg = Json::obj()
            .set("log", Json::obj().set("loglevel", "warning"))
            .set("inbounds", vec![inbound])
            .set(
                "outbounds",
                vec![Json::obj().set("tag", "direct").set("protocol", "freedom")],
            );
        Ok(cfg.to_string_pretty())
    }

    /// Renders Iran (dokodemo-door port forwarders -> VLESS REALITY outbound) Xray JSON config.
    pub fn render_iran_bridge_json(&self) -> Result<String> {
        if self.remote_host.trim().is_empty() {
            bail!("Xray Iran bridge requires remote_host");
        }
        if let Some(n) = &self.profile.noise {
            n.validate()?;
        }
        let mut inbounds = Vec::new();
        for &p in &self.forward_ports {
            inbounds.push(
                Json::obj()
                    .set("tag", format!("doko-{p}"))
                    .set("listen", "0.0.0.0")
                    .set("port", p)
                    .set("protocol", "dokodemo-door")
                    .set(
                        "settings",
                        Json::obj()
                            .set("address", "127.0.0.1")
                            .set("port", p)
                            .set("network", "tcp,udp"),
                    ),
            );
        }
        let user = Json::obj()
            .set("id", self.keys.uuid.clone())
            .set("encryption", "none")
            .set("flow", self.profile.flow.clone());
        let vnext = Json::obj()
            .set("address", self.remote_host.clone())
            .set("port", self.listen_port)
            .set("users", vec![user]);
        let mut outbounds = vec![Json::obj()
            .set("tag", "vless-out")
            .set("protocol", "vless")
            .set("settings", Json::obj().set("vnext", vec![vnext]))
            .set("streamSettings", build_stream_settings(&self.profile, &self.keys, false))];

        if let Some(frag) = &self.profile.fragment {
            outbounds.push(
                Json::obj()
                    .set("tag", "fragment")
                    .set("protocol", "freedom")
                    .set(
                        "settings",
                        Json::obj().set(
                            "fragment",
                            Json::obj()
                                .set("packets", frag.packets.clone())
                                .set("length", frag.length.clone())
                                .set("interval", frag.interval.clone()),
                        ),
                    ),
            );
        }
        let cfg = Json::obj()
            .set("log", Json::obj().set("loglevel", "warning"))
            .set("inbounds", inbounds)
            .set("outbounds", outbounds);
        Ok(cfg.to_string_pretty())
    }

    /// Generates a standard shareable `vless://` client URI.
    pub fn vless_uri(&self, host: &str, label: &str) -> String {
        let mut params = vec![
            "encryption=none".to_string(),
            format!("type={}", self.profile.transport),
            format!("security={}", self.profile.security),
        ];
        if !self.profile.flow.is_empty() {
            params.push(format!("flow={}", self.profile.flow));
        }
        if !self.profile.sni.is_empty() {
            params.push(format!("sni={}", self.profile.sni));
        }
        if !self.profile.fingerprint.is_empty() {
            params.push(format!("fp={}", self.profile.fingerprint));
        }
        if self.profile.security == "reality" {
            params.push(format!("pbk={}", self.keys.reality_pub));
            params.push(format!("sid={}", self.keys.short_id));
        }
        if !self.profile.path.is_empty() {
            if self.profile.transport == "grpc" {
                params.push(format!("serviceName={}", self.profile.path));
            } else {
                params.push(format!("path={}", self.profile.path));
            }
        }
        format!(
            "vless://{}@{}:{}?{}#{label}",
            self.keys.uuid,
            host,
            self.listen_port,
            params.join("&")
        )
    }
}

fn build_stream_settings(p: &XrayProfile, k: &XrayKeys, is_server: bool) -> Json {
    let mut ss = Json::obj()
        .set("network", p.transport.clone())
        .set("security", p.security.clone());
    if p.security == "reality" {
        if is_server {
            ss.insert(
                "realitySettings",
                Json::obj()
                    .set("show", false)
                    .set("dest", p.dest.clone())
                    .set("serverNames", vec![p.sni.clone()])
                    .set("privateKey", k.reality_priv.clone())
                    .set("shortIds", vec![k.short_id.clone()]),
            );
        } else {
            ss.insert(
                "realitySettings",
                Json::obj()
                    .set("serverName", p.sni.clone())
                    .set("fingerprint", p.fingerprint.clone())
                    .set("publicKey", k.reality_pub.clone())
                    .set("shortId", k.short_id.clone()),
            );
        }
    }
    match p.transport.as_str() {
        "grpc" => ss.insert("grpcSettings", Json::obj().set("serviceName", p.path.clone())),
        "ws" => ss.insert("wsSettings", Json::obj().set("path", p.path.clone())),
        "xhttp" => ss.insert("xhttpSettings", Json::obj().set("path", p.path.clone())),
        "kcp" => ss.insert(
            "kcpSettings",
            Json::obj()
                .set("mtu", 1350i64)
                .set("tti", 20i64)
                .set("congestion", true)
                .set("seed", p.path.clone()),
        ),
        _ => {}
    }
    if !is_server && p.fragment.is_some() {
        ss.insert("sockopt", Json::obj().set("dialerProxy", "fragment"));
    }
    ss
}

/// Generates a random RFC 4122 UUID v4.
pub fn new_xray_uuid() -> String {
    let mut b = rand_bytes::<16>();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Generates an Xray REALITY X25519 `(privateKey, publicKey)` pair in unpadded URL-safe Base64.
pub fn new_xray_reality_keys() -> (String, String) {
    let mut sk = rand_bytes::<32>();
    sk[0] &= 248;
    sk[31] = (sk[31] & 127) | 64;
    let pk = x25519_public_from_private(&sk);
    (hjson::b64url_encode(&sk), hjson::b64url_encode(&pk))
}

pub fn apply_xray_link(link: &XrayLink, conf_dir: &str, unit_dir: &str) -> Result<String> {
    let json = if link.side == "iran" {
        link.render_iran_bridge_json()?
    } else {
        link.render_server_json()?
    };
    let conf_path = format!("{conf_dir}/xray-{}.json", link.id);
    if !sysrun::is_dry_run() {
        hjson::write_atomic(&conf_path, json.as_bytes())?;
    } else {
        let _ = sysrun::run(&crate::v!["write-file", &conf_path, format!("{}B", json.len())]);
    }
    let unit_name = format!("khaymali-xray-{}.service", link.id);
    let unit = format!(
        "[Unit]\nDescription=Khaymali Xray Link {}\nAfter=network-online.target\n\n\
[Service]\nType=simple\nExecStart=/usr/local/bin/xray run -c {conf_path}\nRestart=always\nRestartSec=2\nLimitNOFILE=65535\n\n\
[Install]\nWantedBy=multi-user.target\n",
        link.id
    );
    sysrun::install_unit(unit_dir, &unit_name, &unit, true)?;
    Ok(conf_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_uuid_reality_keys_and_json_generation() {
        let uuid = new_xray_uuid();
        assert_eq!(uuid.len(), 36);
        assert_eq!(&uuid[14..15], "4");

        let keys = XrayKeys::generate();
        assert_eq!(hjson::b64_decode(&keys.reality_priv).unwrap().len(), 32);
        assert_eq!(hjson::b64_decode(&keys.reality_pub).unwrap().len(), 32);

        let link = XrayLink {
            id: 1,
            side: "foreign".into(),
            listen_port: 8443,
            remote_host: "203.0.113.20".into(),
            forward_ports: vec![443, 2083],
            keys,
            profile: xray_preset("reality-vision").unwrap(),
        };
        let srv = link.render_server_json().unwrap();
        let parsed = Json::parse(&srv).unwrap();
        assert_eq!(parsed.arr_of("inbounds").len(), 1);
        let bridge = link.render_iran_bridge_json().unwrap();
        let bp = Json::parse(&bridge).unwrap();
        assert_eq!(bp.arr_of("inbounds").len(), 2);

        let uri = link.vless_uri("203.0.113.20", "NetBaz-DE");
        assert!(uri.starts_with("vless://"));
        assert!(uri.contains("security=reality"));
        assert!(uri.contains("flow=xtls-rprx-vision"));
    }
}
