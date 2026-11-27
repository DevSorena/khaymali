//! Tunnel Node Link Framing, Migration & Fleet Probing (`src/node_cluster.rs`).
//!
//! Pure tunneling multi-node coordination layer (no web panel / HTTP admin relay):
//!   * Bounded length-prefixed JSON `NodeFrame` transport (`MAX_NODE_FRAME = 1 MiB`) over
//!     async Tokio streams with HMAC-SHA256 challenge-response authentication.
//!   * `NodeMigrateOffer` + HMAC-SHA256 verification for zero-downtime tunnel link migration.
//!   * `FleetNode` inventory (`nodes.json`) + async TCP latency `probe_node` / `probe_fleet`.

use crate::hjson::{self, Json};
use crate::util::{ct_eq, hex, now_unix, rand_bytes};
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

type HmacSha256 = Hmac<Sha256>;

pub const MAX_NODE_FRAME: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub struct NodeFrame {
    pub kind: String, // "auth" | "auth_ok" | "ping" | "pong" | "swap" | "migrate"
    pub id: String,
    pub payload: Json,
}

impl NodeFrame {
    pub fn to_bytes(&self) -> Vec<u8> {
        let j = Json::obj()
            .set("type", self.kind.clone())
            .set("id", self.id.clone())
            .set("payload", self.payload.clone());
        j.to_string_compact().into_bytes()
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(raw).context("node frame not UTF-8")?;
        let j = Json::parse(text)?;
        let kind = j.str_of("type");
        if kind.is_empty() {
            bail!("node frame missing type");
        }
        Ok(Self {
            kind,
            id: j.str_of("id"),
            payload: j.get("payload").cloned().unwrap_or(Json::Null),
        })
    }
}

pub async fn send_node_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &NodeFrame) -> Result<()> {
    let data = frame.to_bytes();
    if data.len() > MAX_NODE_FRAME {
        bail!("node frame exceeds {MAX_NODE_FRAME} bytes");
    }
    w.write_all(&(data.len() as u32).to_be_bytes()).await?;
    w.write_all(&data).await?;
    w.flush().await?;
    Ok(())
}

pub async fn recv_node_frame<R: AsyncRead + Unpin>(r: &mut R, io_timeout: Duration) -> Result<NodeFrame> {
    let mut hdr = [0u8; 4];
    timeout(io_timeout, r.read_exact(&mut hdr)).await??;
    let len = u32::from_be_bytes(hdr) as usize;
    if len == 0 || len > MAX_NODE_FRAME {
        bail!("invalid node frame length {len}");
    }
    let mut buf = vec![0u8; len];
    timeout(io_timeout, r.read_exact(&mut buf)).await??;
    NodeFrame::from_bytes(&buf)
}

pub fn sign_node_auth(token: &str, node_id: &str, nonce: &str, ts_unix: u64) -> String {
    let mut mac = HmacSha256::new_from_slice(token.as_bytes()).expect("HMAC key");
    mac.update(b"khaymali-node-auth-v1\n");
    mac.update(node_id.as_bytes());
    mac.update(b"\n");
    mac.update(nonce.as_bytes());
    mac.update(b"\n");
    mac.update(ts_unix.to_string().as_bytes());
    hex(&mac.finalize().into_bytes())
}

pub fn verify_node_auth(token: &str, node_id: &str, nonce: &str, ts_unix: u64, sig: &str, now_ts: u64) -> Result<()> {
    if now_ts.abs_diff(ts_unix) > 120 {
        bail!("node auth timestamp skew > 120s");
    }
    let want = sign_node_auth(token, node_id, nonce, ts_unix);
    if !ct_eq(want.as_bytes(), sig.trim().as_bytes()) {
        bail!("node auth signature mismatch");
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeMigrateOffer {
    pub node_id: String,
    pub hub_url: String,
    pub issued_at: u64,
    pub nonce: String,
    pub mac: String,
}

impl NodeMigrateOffer {
    pub fn create(token: &str, node_id: &str, hub_url: &str, issued_at: u64) -> Self {
        let nonce = hex(&rand_bytes::<12>());
        let mac = node_migrate_mac(token, "offer", &[node_id, hub_url, &issued_at.to_string(), &nonce]);
        Self {
            node_id: node_id.into(),
            hub_url: hub_url.into(),
            issued_at,
            nonce,
            mac,
        }
    }

    pub fn verify(&self, token: &str, now_ts: u64) -> Result<()> {
        if now_ts.abs_diff(self.issued_at) > 600 {
            bail!("node migrate offer expired");
        }
        let want = node_migrate_mac(
            token,
            "offer",
            &[&self.node_id, &self.hub_url, &self.issued_at.to_string(), &self.nonce],
        );
        if !ct_eq(want.as_bytes(), self.mac.as_bytes()) {
            bail!("node migrate offer MAC mismatch");
        }
        Ok(())
    }
}

pub fn node_migrate_mac(token: &str, label: &str, parts: &[&str]) -> String {
    let mut mac = HmacSha256::new_from_slice(token.as_bytes()).expect("HMAC key");
    mac.update(b"khaymali-node-migrate-v1\n");
    mac.update(label.as_bytes());
    for p in parts {
        mac.update(b"\n");
        mac.update(p.as_bytes());
    }
    hex(&mac.finalize().into_bytes())
}

#[derive(Clone, Debug)]
pub struct FleetNode {
    pub id: String,
    pub name: String,
    pub role: String, // "iran" | "foreign"
    pub addr: String, // "IP:PORT"
    pub token: String,
    pub online: bool,
    pub rtt_ms: f64,
    pub last_probe_unix: u64,
    pub tags: Vec<String>,
}

impl FleetNode {
    pub fn to_json(&self) -> Json {
        Json::obj()
            .set("id", self.id.clone())
            .set("name", self.name.clone())
            .set("role", self.role.clone())
            .set("addr", self.addr.clone())
            .set("token", self.token.clone())
            .set("online", self.online)
            .set("rtt_ms", self.rtt_ms)
            .set("last_probe_unix", self.last_probe_unix)
            .set("tags", self.tags.clone())
    }

    pub fn from_json(j: &Json) -> Result<Self> {
        let id = j.str_of("id");
        if id.is_empty() {
            bail!("fleet node missing id");
        }
        Ok(Self {
            id,
            name: j.str_of("name"),
            role: j.str_of("role"),
            addr: j.str_of("addr"),
            token: j.str_of("token"),
            online: j.bool_of("online"),
            rtt_ms: j.num_of("rtt_ms"),
            last_probe_unix: j.u64_of("last_probe_unix"),
            tags: j
                .arr_of("tags")
                .into_iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
        })
    }
}

pub fn load_fleet(path: &str) -> Result<Vec<FleetNode>> {
    let Some(j) = hjson::read_json_file(path)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for item in j.arr_of("nodes") {
        if let Ok(n) = FleetNode::from_json(&item) {
            out.push(n);
        }
    }
    Ok(out)
}

pub fn save_fleet(path: &str, nodes: &[FleetNode]) -> Result<()> {
    let arr: Vec<Json> = nodes.iter().map(|n| n.to_json()).collect();
    let j = Json::obj().set("nodes", arr);
    hjson::write_atomic(path, j.to_string_pretty().as_bytes())
}

/// Probes a tunnel node's TCP endpoint and returns `(reachable, rtt_ms)`.
pub async fn probe_node(addr: &str, probe_timeout: Duration) -> (bool, f64) {
    let t0 = Instant::now();
    match timeout(probe_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => (true, (t0.elapsed().as_secs_f64() * 10000.0).round() / 10.0),
        _ => (false, 0.0),
    }
}

pub async fn probe_fleet(nodes: &mut [FleetNode], probe_timeout: Duration) {
    let now = now_unix();
    for n in nodes.iter_mut() {
        let (ok, rtt) = probe_node(&n.addr, probe_timeout).await;
        n.online = ok;
        n.rtt_ms = rtt;
        n.last_probe_unix = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn node_auth_and_migrate_offer() {
        let tok = "node-secret-token-abcdef0123456789";
        let sig = sign_node_auth(tok, "de-node-1", "nonce1234567890", 1_700_000_000);
        assert!(verify_node_auth(tok, "de-node-1", "nonce1234567890", 1_700_000_000, &sig, 1_700_000_010).is_ok());
        assert!(verify_node_auth(tok, "de-node-1", "nonce1234567890", 1_700_000_000, &sig, 1_700_000_500).is_err());

        let offer = NodeMigrateOffer::create(tok, "de-node-1", "http://198.51.100.1:18081", 1_700_000_000);
        assert!(offer.verify(tok, 1_700_000_050).is_ok());
        assert!(offer.verify("wrong-token", 1_700_000_050).is_err());
    }

    #[tokio::test]
    async fn node_frame_wire_roundtrip_and_probe() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let f = recv_node_frame(&mut s, Duration::from_secs(2)).await.unwrap();
            assert_eq!(f.kind, "ping");
            send_node_frame(
                &mut s,
                &NodeFrame { kind: "pong".into(), id: f.id, payload: Json::obj().set("ok", true) },
            )
            .await
            .unwrap();
        });

        let mut c = TcpStream::connect(addr).await.unwrap();
        send_node_frame(
            &mut c,
            &NodeFrame { kind: "ping".into(), id: "1".into(), payload: Json::Null },
        )
        .await
        .unwrap();
        let reply = recv_node_frame(&mut c, Duration::from_secs(2)).await.unwrap();
        assert_eq!(reply.kind, "pong");
        assert!(reply.payload.bool_of("ok"));
        srv.await.unwrap();

        let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a2 = l2.local_addr().unwrap();
        let (ok, rtt) = probe_node(&a2.to_string(), Duration::from_secs(1)).await;
        assert!(ok && rtt >= 0.0);
        drop(l2);
    }
}
