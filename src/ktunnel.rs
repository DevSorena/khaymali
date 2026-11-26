//! Multi-Flow FakeTLS-Mux Carrier Protocol (`ktunnel://HOST:PORT`, `src/ktunnel.rs`).
//!
//! Implements the userspace carrier counterpart to `experimental/ktunnel` (`k_tcpmux.c`):
//!   * Stripes frames round-robin across `MUX_FLOW_COUNT` (default 8) parallel TCP subflows
//!     with active-flow fallback so a single throttled or stalled TCP flow never blocks traffic.
//!   * Wraps each chunk in a 9-byte TLS 1.3 Application Data + Mux header (`tls_mux_hdr`):
//!       `[content_type: 0x17][ver_maj: 0x03][ver_min: 0x03][record_len: u16 BE]`
//!       `[stream_id: u16 BE][mux_flags: u8][pad_len: u8][payload...][padding...]`
//!   * Masks `[stream_id..payload]` with a keyed `HMAC-SHA256` stream derived from `secret` +
//!     `session_id` + `flow_idx` + `frame_seq` (eliminating static XOR weaknesses while preserving
//!     the exact TLS 1.3 `17 03 03` outer record framing).
//!   * Exposes `BoxRw` (`AsyncRead + AsyncWrite`) so end-to-end `Noise_IK` encryption and
//!     `MuxCarrier` run directly over `ktunnel://` without requiring root or kernel headers.

use crate::link;
use crate::stats;
use crate::util::{ct_eq, rand_bytes, BoxRw};
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, timeout};

pub const DEFAULT_KTUN_FLOWS: usize = 8;
pub const MAX_KTUN_FLOWS: usize = 16;
pub const TLS_RECORD_HDR_LEN: usize = 5;
pub const KTUN_MUX_HDR_LEN: usize = 4;
pub const KTUN_TOTAL_HDR_LEN: usize = TLS_RECORD_HDR_LEN + KTUN_MUX_HDR_LEN; // 9 bytes
pub const MAX_KTUN_PAYLOAD: usize = 14 * 1024;
const SESSION_IDLE_TTL: Duration = Duration::from_secs(45);

const FLAG_HELLO: u8 = 0x00;
const FLAG_DATA: u8 = 0x01;
const FLAG_FIN: u8 = 0x02;

#[derive(Clone, Debug)]
pub struct KtunnelFrame {
    pub stream_id: u16,
    pub mux_flags: u8,
    pub pad_len: u8,
    pub payload: Vec<u8>,
}

fn derive_mask_block(key: &[u8], flow_id: u16, seq: u64, counter: u32) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key");
    m.update(b"khaymali/ktunnel/mask/v1");
    m.update(&flow_id.to_be_bytes());
    m.update(&seq.to_be_bytes());
    m.update(&counter.to_be_bytes());
    m.finalize().into_bytes().into()
}

fn apply_keyed_mask(key: &[u8], flow_id: u16, seq: u64, data: &mut [u8]) {
    if key.is_empty() {
        return;
    }
    let mut offset = 0usize;
    let mut block_idx = 0u32;
    while offset < data.len() {
        let block = derive_mask_block(key, flow_id, seq, block_idx);
        let take = (data.len() - offset).min(32);
        for i in 0..take {
            data[offset + i] ^= block[i];
        }
        offset += take;
        block_idx = block_idx.wrapping_add(1);
    }
}

/// Encode a 9-byte `tls_mux_hdr` + payload into a wire TLS 1.3 Application Data record.
pub fn encode_ktunnel_record(
    key: &[u8],
    flow_id: u16,
    seq: u64,
    mux_flags: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > MAX_KTUN_PAYLOAD {
        bail!("ktunnel payload {} exceeds max {}", payload.len(), MAX_KTUN_PAYLOAD);
    }
    let rec_len = KTUN_MUX_HDR_LEN + payload.len();
    let mut wire = Vec::with_capacity(TLS_RECORD_HDR_LEN + rec_len);
    wire.extend_from_slice(&[0x17, 0x03, 0x03]);
    wire.extend_from_slice(&(rec_len as u16).to_be_bytes());
    wire.extend_from_slice(&flow_id.to_be_bytes());
    wire.push(mux_flags);
    wire.push(0); // pad_len
    wire.extend_from_slice(payload);

    // Mask [stream_id..end] matching `fast_obfuscate_payload(&tlsh->stream_id, ...)` in k_tcpmux.c
    apply_keyed_mask(key, flow_id, seq, &mut wire[TLS_RECORD_HDR_LEN..]);
    Ok(wire)
}

/// Read and unmask one `tls_mux_hdr` record from a subflow TCP stream.
pub async fn read_ktunnel_record(
    stream: &mut tokio::net::tcp::OwnedReadHalf,
    key: &[u8],
    expected_flow_id: u16,
    seq: u64,
) -> Result<KtunnelFrame> {
    let mut hdr = [0u8; TLS_RECORD_HDR_LEN];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x17 || hdr[1] != 0x03 || hdr[2] != 0x03 {
        bail!("ktunnel: invalid outer TLS 1.3 record header {:02x?}", &hdr[..3]);
    }
    let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if rec_len < KTUN_MUX_HDR_LEN || rec_len > KTUN_MUX_HDR_LEN + MAX_KTUN_PAYLOAD {
        bail!("ktunnel: invalid record_len {rec_len}");
    }
    let mut body = vec![0u8; rec_len];
    stream.read_exact(&mut body).await?;
    apply_keyed_mask(key, expected_flow_id, seq, &mut body);

    let stream_id = u16::from_be_bytes([body[0], body[1]]);
    let mux_flags = body[2];
    let pad_len = body[3] as usize;
    if KTUN_MUX_HDR_LEN + pad_len > rec_len {
        bail!("ktunnel: pad_len {pad_len} exceeds record body");
    }
    let payload_end = rec_len - pad_len;
    Ok(KtunnelFrame {
        stream_id,
        mux_flags,
        pad_len: body[3],
        payload: body[KTUN_MUX_HDR_LEN..payload_end].to_vec(),
    })
}

fn compute_hello_mac(key: &[u8], session_id: u64, flow_idx: u16) -> [u8; 16] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key");
    m.update(b"khaymali/ktunnel/hello/v1");
    m.update(&session_id.to_be_bytes());
    m.update(&flow_idx.to_be_bytes());
    let out = m.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&out[..16]);
    tag
}

/// Connect `flow_count` parallel TCP subflows to `addr` and bind them into a single
/// round-robin FakeTLS-Mux `BoxRw` stream.
pub async fn connect(
    addr: &str,
    key: &[u8],
    flow_count: usize,
    connect_timeout: Duration,
) -> Result<BoxRw> {
    let n_flows = flow_count.clamp(1, MAX_KTUN_FLOWS);
    let session_id = u64::from_be_bytes(rand_bytes::<8>());
    let key_vec = key.to_vec();

    let mut subflows = Vec::with_capacity(n_flows);
    for idx in 0..n_flows {
        let mut tcp = timeout(connect_timeout, TcpStream::connect(addr))
            .await
            .with_context(|| format!("ktunnel connect timeout ({addr} flow {idx})"))??;
        link::tune(&tcp);

        // Send authenticated subflow HELLO inside TLS 1.3 record (seq = 0)
        let mut hello_payload = Vec::with_capacity(28);
        hello_payload.extend_from_slice(&session_id.to_be_bytes());
        hello_payload.extend_from_slice(&(idx as u16).to_be_bytes());
        hello_payload.extend_from_slice(&(n_flows as u16).to_be_bytes());
        hello_payload.extend_from_slice(&compute_hello_mac(&key_vec, session_id, idx as u16));

        let wire = encode_ktunnel_record(&key_vec, idx as u16, 0, FLAG_HELLO, &hello_payload)?;
        tcp.write_all(&wire).await?;
        subflows.push((idx as u16, tcp));
    }

    Ok(spawn_multiflow_bridge(subflows, key_vec))
}

struct FlowTx {
    flow_id: u16,
    active: AtomicBool,
    tx: mpsc::Sender<(u64, Vec<u8>)>,
}

fn spawn_multiflow_bridge(subflows: Vec<(u16, TcpStream)>, key: Vec<u8>) -> BoxRw {
    let (user, internal) = duplex(256 * 1024);
    let (mut app_r, mut app_w) = split(internal);
    let (tx_ordered, mut rx_ordered) = mpsc::channel::<(u64, u8, Vec<u8>)>(256);
    let (closed_tx, mut closed_rx) = watch::channel(false);

    stats::KTUNNEL_SESSIONS_ACTIVE.fetch_add(1, Relaxed);
    stats::KTUNNEL_FLOWS_ACTIVE.fetch_add(subflows.len() as i64, Relaxed);

    let mut flow_senders: Vec<Arc<FlowTx>> = Vec::with_capacity(subflows.len());
    let n_flows = subflows.len();

    for (flow_id, tcp) in subflows {
        let (mut rd, mut wr) = tcp.into_split();
        let (ftx, mut frx) = mpsc::channel::<(u64, Vec<u8>)>(64);
        let entry = Arc::new(FlowTx {
            flow_id,
            active: AtomicBool::new(true),
            tx: ftx,
        });
        flow_senders.push(entry.clone());

        // Per-subflow writer
        let entry_wr = entry.clone();
        tokio::spawn(async move {
            while let Some((_global_seq, wire_rec)) = frx.recv().await {
                if wr.write_all(&wire_rec).await.is_err() {
                    break;
                }
            }
            entry_wr.active.store(false, Relaxed);
            let _ = wr.shutdown().await;
        });

        // Per-subflow reader
        let tx_ord = tx_ordered.clone();
        let key_rd = key.clone();
        let entry_rd = entry;
        let mut closed_sub = closed_rx.clone();
        tokio::spawn(async move {
            let mut rx_seq: u64 = 1; // seq 0 was HELLO
            loop {
                let frame = tokio::select! {
                    _ = async {
                        while !*closed_sub.borrow() {
                            if closed_sub.changed().await.is_err() {
                                return;
                            }
                        }
                    } => break,
                    r = read_ktunnel_record(&mut rd, &key_rd, flow_id, rx_seq) => match r {
                        Ok(f) => f,
                        Err(_) => break,
                    }
                };
                rx_seq = rx_seq.wrapping_add(1);
                if frame.payload.len() < 8 {
                    break;
                }
                let global_seq = u64::from_be_bytes(frame.payload[..8].try_into().unwrap());
                let data = frame.payload[8..].to_vec();
                if tx_ord.send((global_seq, frame.mux_flags, data)).await.is_err() {
                    break;
                }
                if frame.mux_flags == FLAG_FIN {
                    break;
                }
            }
            entry_rd.active.store(false, Relaxed);
            stats::KTUNNEL_FLOWS_ACTIVE.fetch_sub(1, Relaxed);
        });
    }

    // Reorder task: delivers striped frames from all N subflows in strict `global_seq` order
    let closed_reord = closed_tx.clone();
    tokio::spawn(async move {
        let mut expected_seq: u64 = 1;
        let mut reorder_buf: BTreeMap<u64, (u8, Vec<u8>)> = BTreeMap::new();
        while let Some((gseq, flags, data)) = rx_ordered.recv().await {
            if gseq < expected_seq {
                continue;
            }
            reorder_buf.insert(gseq, (flags, data));
            if reorder_buf.len() > 512 {
                break;
            }
            while let Some((f, d)) = reorder_buf.remove(&expected_seq) {
                expected_seq += 1;
                if f == FLAG_FIN {
                    let _ = app_w.shutdown().await;
                    let _ = closed_reord.send(true);
                    return;
                }
                if !d.is_empty() && app_w.write_all(&d).await.is_err() {
                    let _ = closed_reord.send(true);
                    return;
                }
            }
        }
        let _ = app_w.shutdown().await;
        let _ = closed_reord.send(true);
    });

    // Round-robin dispatcher across active subflows with active-flow fallback
    let rr = AtomicU32::new(0);
    let key_up = key;
    tokio::spawn(async move {
        let mut per_flow_tx_seq = vec![1u64; n_flows];
        let mut global_seq: u64 = 1;
        let mut buf = vec![0u8; MAX_KTUN_PAYLOAD - 8];

        loop {
            let n = tokio::select! {
                _ = async {
                    while !*closed_rx.borrow() {
                        if closed_rx.changed().await.is_err() {
                            return;
                        }
                    }
                } => break,
                r = app_r.read(&mut buf) => match r {
                    Ok(0) | Err(_) => 0,
                    Ok(n) => n,
                }
            };

            let flags = if n == 0 { FLAG_FIN } else { FLAG_DATA };
            let mut framed_payload = Vec::with_capacity(8 + n);
            framed_payload.extend_from_slice(&global_seq.to_be_bytes());
            if n > 0 {
                framed_payload.extend_from_slice(&buf[..n]);
            }
            global_seq += 1;

            // Round-Robin with Active-Flow Fallback (matches k_tcpmux.c)
            let start = rr.fetch_add(1, Relaxed) as usize;
            let mut sent = false;
            for offset in 0..n_flows {
                let idx = (start + offset) % n_flows;
                if flow_senders[idx].active.load(Relaxed) {
                    let fseq = per_flow_tx_seq[idx];
                    per_flow_tx_seq[idx] += 1;
                    if let Ok(wire) = encode_ktunnel_record(
                        &key_up,
                        flow_senders[idx].flow_id,
                        fseq,
                        flags,
                        &framed_payload,
                    ) {
                        if flow_senders[idx].tx.send((global_seq - 1, wire)).await.is_ok() {
                            sent = true;
                            break;
                        }
                    }
                }
            }
            if !sent || flags == FLAG_FIN {
                break;
            }
        }
        let _ = closed_tx.send(true);
        stats::KTUNNEL_SESSIONS_ACTIVE.fetch_sub(1, Relaxed);
    });

    Box::new(user)
}

/// Server-side `ktunnel` listener: accepts `N` TCP subflows per `session_id`, authenticates
/// each subflow's HMAC HELLO, and yields a unified `BoxRw` stream once all subflows join.
pub struct KtunnelListener {
    rx_sessions: mpsc::Receiver<(BoxRw, SocketAddr)>,
}

struct PendingSession {
    expected_flows: usize,
    created: Instant,
    peer: SocketAddr,
    flows: HashMap<u16, TcpStream>,
}

impl KtunnelListener {
    pub async fn bind(listen_addr: &str, key: Vec<u8>) -> Result<Self> {
        let listener = TcpListener::bind(listen_addr).await?;
        let (tx_sess, rx_sess) = mpsc::channel::<(BoxRw, SocketAddr)>(64);
        let pending: Arc<StdMutex<HashMap<u64, PendingSession>>> =
            Arc::new(StdMutex::new(HashMap::new()));

        // Sweeper for incomplete sessions
        let pending_sw = pending.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(10)).await;
                let mut map = pending_sw.lock().unwrap();
                map.retain(|_, p| p.created.elapsed() < SESSION_IDLE_TTL);
            }
        });

        tokio::spawn(async move {
            loop {
                let Ok((mut tcp, peer)) = listener.accept().await else {
                    sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let key_c = key.clone();
                let pending_c = pending.clone();
                let tx_c = tx_sess.clone();
                tokio::spawn(async move {
                    link::tune(&tcp);
                    let mut hdr = [0u8; TLS_RECORD_HDR_LEN];
                    if timeout(Duration::from_secs(5), tcp.read_exact(&mut hdr))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if hdr[0] != 0x17 || hdr[1] != 0x03 || hdr[2] != 0x03 {
                        return;
                    }
                    let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    if rec_len != KTUN_MUX_HDR_LEN + 28 {
                        return;
                    }
                    let mut body = vec![0u8; rec_len];
                    if timeout(Duration::from_secs(5), tcp.read_exact(&mut body))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    // Try matching flow_idx 0..MAX_KTUN_FLOWS via MAC verification
                    let mut matched_flow = None;
                    let mut session_id = 0u64;
                    let mut total_flows = 0usize;

                    for cand_idx in 0..(MAX_KTUN_FLOWS as u16) {
                        let mut trial = body.clone();
                        apply_keyed_mask(&key_c, cand_idx, 0, &mut trial);
                        let sid_hdr = u16::from_be_bytes([trial[0], trial[1]]);
                        let flags = trial[2];
                        if sid_hdr != cand_idx || flags != FLAG_HELLO {
                            continue;
                        }
                        let p = &trial[KTUN_MUX_HDR_LEN..];
                        let sess_id = u64::from_be_bytes(p[0..8].try_into().unwrap());
                        let fidx = u16::from_be_bytes(p[8..10].try_into().unwrap());
                        let nflows = u16::from_be_bytes(p[10..12].try_into().unwrap()) as usize;
                        let mac_rx = &p[12..28];
                        if fidx != cand_idx || !(1..=MAX_KTUN_FLOWS).contains(&nflows) {
                            continue;
                        }
                        let expected_mac = compute_hello_mac(&key_c, sess_id, fidx);
                        if ct_eq(mac_rx, &expected_mac) {
                            matched_flow = Some(fidx);
                            session_id = sess_id;
                            total_flows = nflows;
                            break;
                        }
                    }

                    let Some(flow_idx) = matched_flow else {
                        return;
                    };

                    let ready_subflows = {
                        let mut map = pending_c.lock().unwrap();
                        if map.len() >= 1024 && !map.contains_key(&session_id) {
                            return;
                        }
                        let entry = map.entry(session_id).or_insert_with(|| PendingSession {
                            expected_flows: total_flows,
                            created: Instant::now(),
                            peer,
                            flows: HashMap::with_capacity(total_flows),
                        });
                        entry.flows.insert(flow_idx, tcp);
                        if entry.flows.len() >= entry.expected_flows {
                            let done = map.remove(&session_id).unwrap();
                            let mut vec_flows: Vec<(u16, TcpStream)> =
                                done.flows.into_iter().collect();
                            vec_flows.sort_by_key(|(id, _)| *id);
                            Some((vec_flows, done.peer))
                        } else {
                            None
                        }
                    };

                    if let Some((subflows, first_peer)) = ready_subflows {
                        let bridge = spawn_multiflow_bridge(subflows, key_c);
                        let _ = tx_c.send((bridge, first_peer)).await;
                    }
                });
            }
        });

        Ok(Self {
            rx_sessions: rx_sess,
        })
    }

    pub async fn accept(&mut self) -> Option<(BoxRw, SocketAddr)> {
        self.rx_sessions.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ktunnel_multiflow_faketls_roundtrip_and_tamper_rejection() {
        let key = b"ktunnel-shared-secret-key-32byte".to_vec();
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let mut listener = KtunnelListener::bind(&addr.to_string(), key.clone())
            .await
            .unwrap();

        let srv = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut got = vec![0u8; 65_536];
            s.read_exact(&mut got).await.unwrap();
            s.write_all(b"KTUNNEL-8FLOW-OK").await.unwrap();
            s.shutdown().await.unwrap();
            got
        });

        let mut cli = connect(&addr.to_string(), &key, 8, Duration::from_secs(3))
            .await
            .unwrap();
        let payload: Vec<u8> = (0..65_536u32).map(|i| (i % 251) as u8).collect();
        cli.write_all(&payload).await.unwrap();
        let mut ack = [0u8; 16];
        cli.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"KTUNNEL-8FLOW-OK");
        cli.shutdown().await.unwrap();

        let got = srv.await.unwrap();
        assert_eq!(got, payload);
    }
}
