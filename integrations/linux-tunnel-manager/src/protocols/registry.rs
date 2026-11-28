//! Catalogue of classic tunnel protocols.

#[derive(Debug, Clone, Copy)]
pub struct Protocol {
    pub id: &'static str,
    pub name: &'static str,
    pub layer: &'static str,
    pub port: Option<u16>,
}

pub const PROTOCOLS: &[Protocol] = &[
    Protocol { id: "kmlight", name: "Khaymali Light", layer: "L3", port: Some(2096) },
    Protocol { id: "ipip", name: "IPIP", layer: "L3", port: None },
    Protocol { id: "gre", name: "GRE", layer: "L3", port: None },
    Protocol { id: "gretap", name: "GRETAP", layer: "L2", port: None },
    Protocol { id: "eoip", name: "EoIP", layer: "L2", port: None },
    Protocol { id: "vxlan", name: "VXLAN", layer: "L2", port: Some(4789) },
    Protocol { id: "geneve", name: "GENEVE", layer: "L2", port: Some(6081) },
    Protocol { id: "sit", name: "SIT-6in4", layer: "L3", port: None },
    Protocol { id: "l2tp", name: "L2TPv3", layer: "L2", port: Some(5000) },
    Protocol { id: "wireguard", name: "WireGuard", layer: "L3", port: Some(51820) },
];

pub fn by_id(id: &str) -> Option<&'static Protocol> {
    PROTOCOLS.iter().find(|p| p.id == id)
}
