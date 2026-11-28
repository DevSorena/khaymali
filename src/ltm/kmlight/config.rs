use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct KmLightConfig {
    pub role: String,
    pub listen: String,
    pub remote: String,
    pub local: String,
    pub secret: String,
    pub tun_name: String,
    pub tun_ip: String,
    pub peer_ip: String,
    pub prefix: u8,
    pub mtu: u32,
    pub keepalive: u64,
}

fn get_str(obj: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let i = obj.find(&pat)?;
    let rest = obj[i + pat.len()..].trim_start();
    if !rest.starts_with(':') {
        return None;
    }
    let rest = rest[1..].trim_start();
    if rest.starts_with('"') {
        let rest = &rest[1..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    } else {
        let end = rest
            .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
            .unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

impl KmLightConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let g = |k: &str, def: &str| get_str(&data, k).unwrap_or_else(|| def.to_string());
        Ok(KmLightConfig {
            role: g("role", "server"),
            listen: g("listen", ""),
            remote: g("remote", ""),
            local: g("local", ""),
            secret: g("secret", ""),
            tun_name: {
                let t = g("tun_name", "kmlight0");
                if t.is_empty() { "kmlight0".into() } else { t }
            },
            tun_ip: g("tun_ip", "10.200.0.1"),
            peer_ip: g("peer_ip", "10.200.0.2"),
            prefix: get_str(&data, "prefix").and_then(|s| s.parse().ok()).unwrap_or(30),
            mtu: get_str(&data, "mtu").and_then(|s| s.parse().ok()).unwrap_or(1400),
            keepalive: get_str(&data, "keepalive").and_then(|s| s.parse().ok()).unwrap_or(3),
        })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut map: HashMap<&str, String> = HashMap::new();
        map.insert("role", self.role.clone());
        map.insert("listen", self.listen.clone());
        map.insert("remote", self.remote.clone());
        map.insert("local", self.local.clone());
        map.insert("secret", self.secret.clone());
        map.insert("tun_name", self.tun_name.clone());
        map.insert("tun_ip", self.tun_ip.clone());
        map.insert("peer_ip", self.peer_ip.clone());
        map.insert("prefix", self.prefix.to_string());
        map.insert("mtu", self.mtu.to_string());
        map.insert("keepalive", self.keepalive.to_string());
        let mut parts = Vec::new();
        for (k, v) in &map {
            if v.parse::<i64>().is_ok() {
                parts.push(format!("  \"{k}\": {v}"));
            } else {
                parts.push(format!("  \"{k}\": \"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"")));
            }
        }
        fs::write(path, format!("{{\n{}\n}}\n", parts.join(",\n")))?;
        Ok(())
    }
}
