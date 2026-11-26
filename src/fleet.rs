//! Fleet & Service Governance (`src/fleet.rs`).
//!
//! Provides:
//!   * `NodeRegistry`: multi-Entry / multi-Bridge / multi-Exit inventory with health heartbeats
//!     and capacity tracking.
//!   * `ServiceIdentity` & `ServiceRegistry`: isolated per-service credentials and routing tags
//!     for reverse-tunneled Bridge services.
//!   * `SignedConfig`: monotonic revision-numbered, expiry-bounded configuration bundles signed
//!     with HMAC-SHA256 to prevent unauthorized tampering or rollback attacks.

use crate::util::{ct_eq, hex, now_unix};
use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeRole {
    Entry,
    Bridge,
    Exit,
}

impl NodeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeRole::Entry => "entry",
            NodeRole::Bridge => "bridge",
            NodeRole::Exit => "exit",
        }
    }
}

#[derive(Clone, Debug)]
pub struct NodeRecord {
    pub node_id: String,
    pub role: NodeRole,
    pub endpoint: String,
    pub pubkey_hex: String,
    pub region: String,
    pub active_streams: u32,
    pub max_streams: u32,
    pub last_heartbeat_unix: u64,
    pub healthy: bool,
}

pub struct NodeRegistry {
    nodes: Mutex<HashMap<String, NodeRecord>>,
}

impl Default for NodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeRegistry {
    pub fn new() -> Self {
        Self {
            nodes: Mutex::new(HashMap::new()),
        }
    }

    pub fn upsert(&self, rec: NodeRecord) {
        self.nodes.lock().unwrap().insert(rec.node_id.clone(), rec);
    }

    pub fn heartbeat(&self, node_id: &str, active_streams: u32, healthy: bool, now_secs: u64) -> bool {
        let mut map = self.nodes.lock().unwrap();
        if let Some(n) = map.get_mut(node_id) {
            n.active_streams = active_streams;
            n.healthy = healthy;
            n.last_heartbeat_unix = now_secs;
            true
        } else {
            false
        }
    }

    pub fn healthy_nodes_for_role(&self, role: NodeRole, max_stale_secs: u64, now_secs: u64) -> Vec<NodeRecord> {
        self.nodes
            .lock()
            .unwrap()
            .values()
            .filter(|n| {
                n.role == role
                    && n.healthy
                    && now_secs.saturating_sub(n.last_heartbeat_unix) <= max_stale_secs
            })
            .cloned()
            .collect()
    }

    pub fn snapshot(&self) -> Vec<NodeRecord> {
        let mut v: Vec<_> = self.nodes.lock().unwrap().values().cloned().collect();
        v.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        v
    }
}

#[derive(Clone, Debug)]
pub struct ServiceIdentity {
    pub service_id: String,
    pub service_token_hex: String,
    pub allowed_bridge_pub_hex: String,
    pub target_exit_region: String,
    pub max_bandwidth_bps: u64,
}

pub struct ServiceRegistry {
    services: Mutex<HashMap<String, ServiceIdentity>>,
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            services: Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&self, svc: ServiceIdentity) -> Result<()> {
        if svc.service_id.is_empty() || svc.service_token_hex.len() < 32 {
            bail!("invalid service identity parameters");
        }
        self.services
            .lock()
            .unwrap()
            .insert(svc.service_id.clone(), svc);
        Ok(())
    }

    pub fn authenticate(&self, service_id: &str, token_hex: &str) -> Option<ServiceIdentity> {
        let map = self.services.lock().unwrap();
        let svc = map.get(service_id)?;
        if ct_eq(svc.service_token_hex.as_bytes(), token_hex.as_bytes()) {
            Some(svc.clone())
        } else {
            None
        }
    }

    pub fn count(&self) -> usize {
        self.services.lock().unwrap().len()
    }
}

/// Signed configuration envelope preventing tampering and rollback attacks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedConfig {
    pub revision: u64,
    pub expires_unix: u64,
    pub payload: String,
    pub signature_hex: String,
}

impl SignedConfig {
    fn compute_sig(signing_key: &[u8], revision: u64, expires_unix: u64, payload: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(signing_key).expect("hmac accepts any key");
        mac.update(b"khaymali/signed-config/v1");
        mac.update(&revision.to_be_bytes());
        mac.update(&expires_unix.to_be_bytes());
        mac.update(payload.as_bytes());
        hex(&mac.finalize().into_bytes())
    }

    pub fn sign(signing_key: &[u8], revision: u64, expires_unix: u64, payload: String) -> Self {
        let signature_hex = Self::compute_sig(signing_key, revision, expires_unix, &payload);
        Self {
            revision,
            expires_unix,
            payload,
            signature_hex,
        }
    }

    pub fn verify(&self, signing_key: &[u8], min_revision: u64, now_secs: u64) -> Result<()> {
        if self.revision <= min_revision {
            bail!(
                "config rollback rejected: revision {} <= current {}",
                self.revision,
                min_revision
            );
        }
        if self.expires_unix <= now_secs {
            bail!("signed config expired at {}", self.expires_unix);
        }
        let expected = Self::compute_sig(signing_key, self.revision, self.expires_unix, &self.payload);
        if !ct_eq(expected.as_bytes(), self.signature_hex.as_bytes()) {
            bail!("signed config HMAC verification failed");
        }
        Ok(())
    }

    pub fn render_file(&self) -> String {
        format!(
            "revision={}
expires_unix={}
signature={}
---
{}
",
            self.revision, self.expires_unix, self.signature_hex, self.payload
        )
    }

    pub fn parse_file(text: &str) -> Result<Self> {
        let (hdr, body) = text
            .split_once("
---
")
            .ok_or_else(|| anyhow::anyhow!("missing '---' separator in signed config"))?;
        let mut revision = None;
        let mut expires_unix = None;
        let mut signature_hex = None;
        for line in hdr.lines() {
            if let Some((k, v)) = line.split_once('=') {
                match k.trim() {
                    "revision" => revision = Some(v.trim().parse::<u64>()?),
                    "expires_unix" => expires_unix = Some(v.trim().parse::<u64>()?),
                    "signature" => signature_hex = Some(v.trim().to_string()),
                    _ => {}
                }
            }
        }
        Ok(Self {
            revision: revision.ok_or_else(|| anyhow::anyhow!("missing revision"))?,
            expires_unix: expires_unix.ok_or_else(|| anyhow::anyhow!("missing expires_unix"))?,
            payload: body.trim_end_matches('\n').to_string(),
            signature_hex: signature_hex.ok_or_else(|| anyhow::anyhow!("missing signature"))?,
        })
    }
}

pub fn verify_signed_config_now(cfg: &SignedConfig, signing_key: &[u8], min_revision: u64) -> Result<()> {
    cfg.verify(signing_key, min_revision, now_unix())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_config_verifies_and_blocks_rollback_and_tamper() {
        let key = b"fleet-governance-signing-key-32b";
        let sc = SignedConfig::sign(key, 5, 2_000_000_000, "exit=1.2.3.4:443
pool=12".into());
        let wire = sc.render_file();
        let parsed = SignedConfig::parse_file(&wire).unwrap();
        assert_eq!(parsed, sc);

        // Valid verification
        parsed.verify(key, 4, 1_900_000_000).unwrap();
        // Rollback rejected
        assert!(parsed.verify(key, 5, 1_900_000_000).is_err());
        // Expired rejected
        assert!(parsed.verify(key, 4, 2_000_000_001).is_err());
        // Tampered payload rejected
        let mut tampered = parsed.clone();
        tampered.payload.push_str("
allow-private=true");
        assert!(tampered.verify(key, 4, 1_900_000_000).is_err());
    }

    #[test]
    fn node_and_service_registries_track_health_and_auth() {
        let nr = NodeRegistry::new();
        nr.upsert(NodeRecord {
            node_id: "exit-fra-1".into(),
            role: NodeRole::Exit,
            endpoint: "198.51.100.10:443".into(),
            pubkey_hex: "aa".repeat(32),
            region: "eu-central".into(),
            active_streams: 12,
            max_streams: 2048,
            last_heartbeat_unix: 1000,
            healthy: true,
        });
        assert_eq!(nr.healthy_nodes_for_role(NodeRole::Exit, 30, 1020).len(), 1);
        assert_eq!(nr.healthy_nodes_for_role(NodeRole::Exit, 30, 1050).len(), 0);

        let sr = ServiceRegistry::new();
        sr.register(ServiceIdentity {
            service_id: "vless-main".into(),
            service_token_hex: "11".repeat(32),
            allowed_bridge_pub_hex: "22".repeat(32),
            target_exit_region: "eu-central".into(),
            max_bandwidth_bps: 100_000_000,
        })
        .unwrap();
        assert!(sr.authenticate("vless-main", &"11".repeat(32)).is_some());
        assert!(sr.authenticate("vless-main", &"ff".repeat(32)).is_none());
    }
}
