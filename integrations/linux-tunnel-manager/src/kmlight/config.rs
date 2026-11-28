use crate::json_min;
use crate::system::Result;
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

impl KmLightConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)?;
        let g = |k: &str, def: &str| {
            json_min::get_str(&data, k).unwrap_or(def).to_string()
        };
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
            prefix: json_min::get_u64(&data, "prefix").unwrap_or(30) as u8,
            mtu: json_min::get_u64(&data, "mtu").unwrap_or(1400) as u32,
            keepalive: json_min::get_u64(&data, "keepalive").unwrap_or(3),
        })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut map = HashMap::new();
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
        fs::write(path, json_min::obj_from_map(&map))?;
        Ok(())
    }
}
