//! Mandatory Negative & Security Integration Test Suite (SPEC §8).
//!
//! Runs directly against the real `khaymali` library modules (NO standalone simulators).
//! Covers all 10 SPEC negative gates + multi-threaded CAS log limiter, safe manifest dir guard,
//! and strict time-tick Hysteresis / HalfOpen state parity.

use khaymali::camo::{self, CamoCfg, Replay};
use khaymali::control::{self, ControlState};
use khaymali::entry::{self, BridgeHandshakeLimiter};
use khaymali::fallback::FallbackLimiter;
use khaymali::health::{AdvisoryHint, CircuitState, Exits, FailureKind};
use khaymali::link::{
    self, BridgeReplayCache, BRIDGE_READY_V1, MAX_HANDSHAKE_FRAME, MAX_LINK_FRAME, PATTERN,
    PROLOGUE_BRIDGE,
};
use khaymali::stats;
use khaymali::transport;
use khaymali::udp;
use khaymali::util::{self, ip_prefix_key, now_unix};
use snow::Builder;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

/// #1: Post-auth Bridge Replay Cache resists garbage flooding & silently drops replayed/stale m1.
#[tokio::test]
async fn neg_01_bridge_replay_and_cache_poisoning() {
    let (esk, epk) = link::keygen().unwrap();
    let (bsk, bpk) = link::keygen().unwrap();
    let (evil_sk, _) = link::keygen().unwrap();
    let allowed = vec![bpk];
    let replay = Arc::new(BridgeReplayCache::with_limits(8, Duration::from_secs(240)));

    // Capture a valid m1 from authorized bridge
    let mut hs = Builder::new(PATTERN.parse().unwrap())
        .prologue(PROLOGUE_BRIDGE)
        .local_private_key(&bsk)
        .remote_public_key(&epk)
        .build_initiator()
        .unwrap();
    let mut m1_buf = vec![0u8; MAX_HANDSHAKE_FRAME];
    let m1_len = hs.write_message(&now_unix().to_be_bytes(), &mut m1_buf).unwrap();
    let captured_m1 = m1_buf[..m1_len].to_vec();

    // First submission records m1 after decrypt + allowlist + timestamp
    let (mut c1, mut s1) = duplex(4096);
    let (esk1, al1, r1) = (esk.clone(), allowed.clone(), replay.clone());
    let srv1 = tokio::spawn(async move { link::auth_respond(&mut s1, &esk1, &al1, &r1, false).await });
    link::write_frame(&mut c1, &captured_m1).await.unwrap();
    drop(c1);
    assert!(srv1.await.unwrap().is_err());
    assert_eq!(replay.len(), 1);

    // Flood 32 unauthorized m1 messages (> cache cap 8): MUST NOT pollute or evict replay cache
    for _ in 0..32 {
        let mut ehs = Builder::new(PATTERN.parse().unwrap())
            .prologue(PROLOGUE_BRIDGE)
            .local_private_key(&evil_sk)
            .remote_public_key(&epk)
            .build_initiator()
            .unwrap();
        let mut eb = vec![0u8; MAX_HANDSHAKE_FRAME];
        let elen = ehs.write_message(&now_unix().to_be_bytes(), &mut eb).unwrap();
        let (mut ce, mut se) = duplex(4096);
        let (eske, ale, re) = (esk.clone(), allowed.clone(), replay.clone());
        let srve = tokio::spawn(async move { link::auth_respond(&mut se, &eske, &ale, &re, false).await });
        link::write_frame(&mut ce, &eb[..elen]).await.unwrap();
        drop(ce);
        assert!(srve.await.unwrap().is_err());
    }
    assert_eq!(replay.len(), 1, "unallowed flood must not enter or evict replay cache");

    // Replaying captured_m1 MUST receive silent close (0 bytes written, no m2)
    let (mut c2, mut s2) = duplex(4096);
    let (esk2, al2, r2) = (esk.clone(), allowed.clone(), replay.clone());
    let srv2 = tokio::spawn(async move { link::auth_respond(&mut s2, &esk2, &al2, &r2, false).await });
    link::write_frame(&mut c2, &captured_m1).await.unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(c2.read(&mut byte).await.unwrap(), 0, "replay must get silent close");
    assert!(srv2.await.unwrap().is_err());

    // Stale timestamp (now - 500s) rejected silently
    let (mut c3, mut s3) = duplex(4096);
    let (esk3, al3, r3) = (esk.clone(), allowed.clone(), replay.clone());
    let srv3 = tokio::spawn(async move { link::auth_respond(&mut s3, &esk3, &al3, &r3, false).await });
    let _ = link::auth_initiate_at(&mut c3, &bsk, &epk, now_unix().saturating_sub(500)).await;
    assert!(srv3.await.unwrap().is_err());
}

/// #2: Legacy READY v1 rejected when `--require-channel-binding` is enabled.
#[tokio::test]
async fn neg_02_bridge_downgrade_rejected_when_cb_required() {
    let (esk, epk) = link::keygen().unwrap();
    let (bsk, bpk) = link::keygen().unwrap();
    let allowed = vec![bpk];
    let replay = Arc::new(BridgeReplayCache::new());

    let (mut cli, mut srv_stream) = duplex(4096);
    let r2 = replay.clone();
    let srv = tokio::spawn(async move {
        link::auth_respond(&mut srv_stream, &esk, &allowed, &r2, true).await
    });

    let mut hs = Builder::new(PATTERN.parse().unwrap())
        .prologue(PROLOGUE_BRIDGE)
        .local_private_key(&bsk)
        .remote_public_key(&epk)
        .build_initiator()
        .unwrap();
    let mut buf = vec![0u8; MAX_HANDSHAKE_FRAME];
    let n = hs.write_message(&now_unix().to_be_bytes(), &mut buf).unwrap();
    link::write_frame(&mut cli, &buf[..n]).await.unwrap();
    let m2 = link::read_frame_bounded(&mut cli, MAX_HANDSHAKE_FRAME).await.unwrap();
    hs.read_message(&m2, &mut buf).unwrap();
    let ts = hs.into_stateless_transport_mode().unwrap();
    let n = ts.write_message(0, BRIDGE_READY_V1, &mut buf).unwrap();
    link::write_frame(&mut cli, &buf[..n]).await.unwrap();

    assert!(srv.await.unwrap().is_err(), "READY v1 downgrade must be refused");
}

/// #3: Single IPv6 /64 prefix cannot starve clean Bridge handshake slots.
#[tokio::test]
async fn neg_03_bridge_handshake_prefix_flood_bounded() {
    let lim = BridgeHandshakeLimiter::new(8, 2);
    let g1 = lim.try_acquire("2001:4860:4860:1::1".parse().unwrap()).unwrap();
    let g2 = lim.try_acquire("2001:4860:4860:1::2".parse().unwrap()).unwrap();
    assert!(lim.try_acquire("2001:4860:4860:1::3".parse().unwrap()).is_none());
    let g_clean = lim.try_acquire("198.51.100.5".parse().unwrap());
    assert!(g_clean.is_some());
    drop(g1);
    assert!(lim.try_acquire("2001:4860:4860:1::4".parse().unwrap()).is_some());
    drop(g2);
}

/// #4: Slowloris SOCKS5 times out; missing method 0 gets `[5, 0xff]`; garbage fails cleanly.
#[tokio::test]
async fn neg_04_socks5_slowloris_and_malformed() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();

    let srv = tokio::spawn(async move {
        let (mut s1, _) = l.accept().await.unwrap();
        assert!(timeout(Duration::from_millis(120), entry::socks_handshake(&mut s1)).await.is_err());

        let (mut s2, _) = l.accept().await.unwrap();
        assert!(entry::socks_handshake(&mut s2).await.is_err());

        let (mut s3, _) = l.accept().await.unwrap();
        assert!(entry::socks_handshake(&mut s3).await.is_err());
    });

    let mut c1 = TcpStream::connect(addr).await.unwrap();
    c1.write_all(&[5]).await.unwrap();
    sleep(Duration::from_millis(160)).await;
    drop(c1);

    let mut c2 = TcpStream::connect(addr).await.unwrap();
    c2.write_all(&[5, 1, 2]).await.unwrap();
    let mut rep = [0u8; 2];
    c2.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep, [5, 0xff]);

    let mut c3 = TcpStream::connect(addr).await.unwrap();
    c3.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
    drop(c3);

    srv.await.unwrap();
}

/// #5: Comprehensive TCP & UDP anti-SSRF + atomic mixed-resolution DNS-rebinding defense.
#[tokio::test]
async fn neg_05_prohibited_destinations_tcp_and_udp() {
    let blocked = [
        "0.0.0.0", "0.0.0.1", "0.1.2.3",
        "127.0.0.1", "10.0.0.5", "172.16.1.1", "192.168.1.1",
        "100.64.0.1", "169.254.169.254", "198.18.0.1", "192.0.2.1", "224.0.0.1", "240.0.0.1",
        "::1", "::", "::2", "::ffff:0.0.0.2", "::ffff:127.0.0.1", "::ffff:10.0.0.5",
        "64:ff9b::10.0.0.1", "64:ff9b:1::1",
        "2002:c0a8:0101::1", "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
        "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "100::1",
    ];
    for s in blocked {
        let ip: IpAddr = s.parse().unwrap();
        assert!(util::is_prohibited_destination(ip, &[]), "TCP check must block {s}");
        assert!(udp::resolve_udp_target(s, 53, false).await.is_none(), "UDP check must block {s}");
    }

    // Mixed public + private resolution MUST fail atomically
    let mixed = vec!["1.1.1.1:443".parse().unwrap(), "10.0.0.1:443".parse().unwrap()];
    assert!(util::validate_resolved_addrs(mixed.clone(), false).is_err());
    assert!(util::validate_resolved_addrs(mixed, true).is_ok());

    // Public targets allowed
    assert!(!util::is_prohibited_destination("1.1.1.1".parse().unwrap(), &[]));
    assert!(udp::resolve_udp_target("1.1.1.1", 53, false).await.is_some());
}

/// #6: Oversized handshake/link frame headers fail before allocation.
#[tokio::test]
async fn neg_06_frame_length_overflow_rejected() {
    let (mut w, mut r) = duplex(64);
    w.write_all(&((MAX_HANDSHAKE_FRAME as u16 + 100).to_be_bytes())).await.unwrap();
    assert!(link::read_frame_bounded(&mut r, MAX_HANDSHAKE_FRAME).await.is_err());

    let (mut w2, mut r2) = duplex(64);
    w2.write_all(&u16::MAX.to_be_bytes()).await.unwrap();
    assert!(link::read_frame_bounded(&mut r2, MAX_LINK_FRAME).await.is_err());
}

/// #7: IPv6 /64 rotation stays bounded by FallbackLimiter prefix quota & evicts oldest idle.
#[tokio::test]
async fn neg_07_fallback_ipv6_prefix_quota_and_lru() {
    let lim = FallbackLimiter::new(10, 2, 3);
    let p_a = ip_prefix_key("2001:4860:4860:1::1".parse().unwrap());
    let p_b = ip_prefix_key("2001:4860:4860:2::1".parse().unwrap());

    let l1 = lim.acquire("2001:4860:4860:1::1".parse().unwrap());
    sleep(Duration::from_millis(5)).await;
    let l2 = lim.acquire("2001:4860:4860:1::2".parse().unwrap());
    sleep(Duration::from_millis(5)).await;
    let l3 = lim.acquire("2001:4860:4860:1::3".parse().unwrap());
    assert_eq!(lim.count_for_prefix(p_a), 3);

    let _l4 = lim.acquire("2001:4860:4860:1::4".parse().unwrap());
    assert_eq!(lim.count_for_prefix(p_a), 3);
    timeout(Duration::from_millis(100), l1.evicted())
        .await
        .expect("oldest lease l1 in /64 prefix must be evicted");

    let _lb = lim.acquire("2001:4860:4860:2::1".parse().unwrap());
    assert_eq!(lim.count_for_prefix(p_b), 1);
    drop(l2);
    drop(l3);
}

/// #8: Normal fallback mirrors Decoy half-close without artificial early timeout or RST.
#[tokio::test]
async fn neg_08_fallback_normal_mirrors_decoy_half_close() {
    let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_addr = decoy.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut c, _) = decoy.accept().await.unwrap();
        let mut req = Vec::new();
        let _ = c.read_to_end(&mut req).await;
        sleep(Duration::from_millis(80)).await;
        let _ = c.write_all(b"HALF-CLOSE-MIRROR-OK").await;
        let _ = c.shutdown().await;
    });

    let sc = CamoCfg {
        secret: b"0123456789abcdef0123456789abcdef".to_vec(),
        sni: "decoy.example".into(),
        fallback: Some(decoy_addr),
        pad_max: 32,
    };
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let replay = Arc::new(Replay::new());
    let fb = FallbackLimiter::default_limiter();
    tokio::spawn(async move {
        let (s, peer) = l.accept().await.unwrap();
        let _ = camo::server(s, peer.ip(), &sc, &replay, &fb).await;
    });

    let mut p = TcpStream::connect(addr).await.unwrap();
    p.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    p.shutdown().await.unwrap();
    let mut resp = Vec::new();
    timeout(Duration::from_secs(3), p.read_to_end(&mut resp)).await.unwrap().unwrap();
    assert_eq!(resp, b"HALF-CLOSE-MIRROR-OK");
}

/// #9: Real `wrap_bound_stream` over `tokio::io::duplex`: 64 KiB roundtrip, wire injection, wire replay.
#[tokio::test]
async fn neg_09_channel_binding_duplex_roundtrip_injection_replay() {
    let keys = transport::derive_channel_binding_keys(&[0x11u8; 32], &[0x22u8; 32]);

    // Round-trip
    let (wire_a, wire_b) = duplex(1 << 16);
    let mut bridge_end = transport::wrap_bound_stream(Box::new(wire_a), keys.b2e, keys.e2b);
    let mut entry_end = transport::wrap_bound_stream(Box::new(wire_b), keys.e2b, keys.b2e);
    let msg: Vec<u8> = (0..65_536u32).map(|i| (i % 251) as u8).collect();
    let m2 = msg.clone();
    let t = tokio::spawn(async move {
        let mut got = vec![0u8; m2.len()];
        entry_end.read_exact(&mut got).await.unwrap();
        assert_eq!(got, m2);
        entry_end.write_all(b"OK-BOUND").await.unwrap();
        entry_end.shutdown().await.unwrap();
    });
    bridge_end.write_all(&msg).await.unwrap();
    let mut ack = [0u8; 8];
    bridge_end.read_exact(&mut ack).await.unwrap();
    assert_eq!(&ack, b"OK-BOUND");
    t.await.unwrap();

    // Wire injection (1-bit flip) -> 0 bytes delivered
    let (mut raw_tx, wire_rx) = duplex(4096);
    let mut bound_rx = transport::wrap_bound_stream(Box::new(wire_rx), keys.e2b, keys.b2e);
    let mut f0 = transport::seal_bound_frame(&keys.b2e, 0, b"legit-payload").unwrap();
    let last = f0.len() - 1;
    f0[last] ^= 1;
    raw_tx.write_all(&f0).await.unwrap();
    raw_tx.shutdown().await.unwrap();
    let mut out = Vec::new();
    assert_eq!(bound_rx.read_to_end(&mut out).await.unwrap(), 0);

    // Wire replay (duplicate frame seq=0) -> 2nd frame rejected
    let (mut raw_tx2, wire_rx2) = duplex(4096);
    let mut bound_rx2 = transport::wrap_bound_stream(Box::new(wire_rx2), keys.e2b, keys.b2e);
    let vf0 = transport::seal_bound_frame(&keys.b2e, 0, b"once-only").unwrap();
    raw_tx2.write_all(&vf0).await.unwrap();
    raw_tx2.write_all(&vf0).await.unwrap();
    raw_tx2.shutdown().await.unwrap();
    let mut out2 = Vec::new();
    bound_rx2.read_to_end(&mut out2).await.unwrap();
    assert_eq!(out2, b"once-only");
}

/// #10: Control API enforces read-only + drain boundary (refuses mutating RPCs).
#[cfg(unix)]
#[tokio::test]
async fn neg_10_control_api_readonly_and_drain() {
    use tokio::net::UnixStream;
    let sock = format!("/tmp/khaymali-neg10-{}.sock", std::process::id());
    let st = ControlState::new("exit", None, vec![vec![7u8; 32]]);
    let (st2, sock2) = (st.clone(), sock.clone());
    let srv = tokio::spawn(async move { control::serve(sock2, st2).await });
    sleep(Duration::from_millis(60)).await;

    for bad in ["{\"method\":\"peers.add\"}\n", "{\"method\":\"peers.revoke\"}\n", "{\"method\":\"policy.set\"}\n"] {
        let mut c = UnixStream::connect(&sock).await.unwrap();
        c.write_all(bad.as_bytes()).await.unwrap();
        let mut resp = String::new();
        c.read_to_string(&mut resp).await.unwrap();
        assert!(resp.contains("\"ok\":false"), "mutating RPC {bad} must fail");
    }

    let mut c_drain = UnixStream::connect(&sock).await.unwrap();
    c_drain.write_all(b"{\"method\":\"drain\"}\n").await.unwrap();
    let mut r_drain = String::new();
    c_drain.read_to_string(&mut r_drain).await.unwrap();
    assert!(r_drain.contains("\"draining\":true"));
    assert!(st.is_draining());

    srv.abort();
    let _ = std::fs::remove_file(&sock);
}

/// #11: Single-AtomicU64 CAS log rate limiter is strictly race-free under 16 concurrent threads.
#[test]
fn neg_11_log_rate_limiter_race_free() {
    let state = Arc::new(AtomicU64::new(0));
    let granted = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..16 {
        let (st, gr) = (state.clone(), granted.clone());
        handles.push(thread::spawn(move || {
            for _ in 0..20 {
                if stats::try_acquire_log_slot(&st, 12345, 10) {
                    gr.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(granted.load(Ordering::Relaxed), 10, "exact cap of 10 slots/sec must hold under 16-thread contention");
    // Next second resets cleanly
    assert!(stats::try_acquire_log_slot(&state, 12346, 10));
}

/// #12: `ensure_manifest_state_dir` refuses arbitrary/system parent dirs like `/tmp` or `/var/lib`.
#[test]
fn neg_12_manifest_dir_refuses_system_paths() {
    assert!(util::ensure_manifest_state_dir("/tmp/manifest.state").is_err());
    assert!(util::ensure_manifest_state_dir("/var/lib/manifest.state").is_err());
    let safe_dir = format!("/tmp/khaymali-neg12-{}", std::process::id());
    let safe_path = format!("{safe_dir}/khaymali/manifest.state");
    assert!(util::ensure_manifest_state_dir(&safe_path).is_ok());
    let _ = std::fs::remove_dir_all(&safe_dir);
}

/// #13: Time-tick Hysteresis ignores rapid calls & HalfOpen probe-in-flight matches `snapshot().selectable`.
#[test]
fn neg_13_health_hysteresis_and_half_open_consistency() {
    let t0 = Instant::now();
    let e = Exits::with_hysteresis_interval(vec!["a:1".into(), "b:1".into()], Duration::from_secs(10));
    for _ in 0..5 {
        e.ok("a:1", Duration::from_millis(200));
        e.ok("b:1", Duration::from_millis(20));
    }

    // First pick at t0 only records baseline timestamp (does NOT advance counter)
    let _ = e.pick_at(t0);
    // 10 rapid evaluate_tick_at calls within <10s MUST NOT flip preferred exit
    for ms in 1..=10 {
        e.evaluate_tick_at(t0 + Duration::from_millis(ms * 100));
    }
    assert_eq!(e.preferred().as_deref(), Some("a:1"));

    // 2 valid ticks (t0+10s, t0+20s) still hold a:1 (needs 3)
    e.evaluate_tick_at(t0 + Duration::from_secs(10));
    e.evaluate_tick_at(t0 + Duration::from_secs(20));
    assert_eq!(e.preferred().as_deref(), Some("a:1"));

    // 3rd valid tick (t0+30s) promotes b:1
    e.evaluate_tick_at(t0 + Duration::from_secs(30));
    assert_eq!(e.preferred().as_deref(), Some("b:1"));

    // HalfOpen probe-in-flight parity: snapshot().selectable MUST become false once probe is sent
    let e2 = Exits::new(vec!["only:1".into()]);
    e2.fail_kind_at("only:1", FailureKind::Reset, t0);
    e2.fail_kind_at("only:1", FailureKind::Reset, t0); // trips Open (cooldown = 4s)
    let snap_open = e2.snapshot_at(t0 + Duration::from_secs(1));
    assert_eq!(snap_open[0].circuit, CircuitState::Open);
    assert!(!snap_open[0].up);
    assert!(!snap_open[0].selectable);

    // After cooldown expires (t0+10s): pick transitions to HalfOpen and sends single probe
    let _ = e2.pick_at(t0 + Duration::from_secs(10));
    let snap_ho = e2.snapshot_at(t0 + Duration::from_secs(10));
    assert_eq!(snap_ho[0].circuit, CircuitState::HalfOpen);
    assert!(!snap_ho[0].up, "HalfOpen is not Closed");
    assert!(!snap_ho[0].selectable, "HalfOpen with probe in flight MUST report selectable=false");
    assert!(snap_ho[0].half_open_probe_in_flight);

    // Advisory diagnose() works read-only
    let hints = e2.diagnose(8);
    assert!(hints.iter().any(|h| matches!(h, AdvisoryHint::InvestigateResetOrDrift(_))));

    // Typed error classification
    let rst = anyhow::Error::new(std::io::Error::from(ErrorKind::ConnectionReset)).context("outer");
    assert_eq!(Exits::classify_error(&rst), FailureKind::Reset);
}

/// #14: L4 ForwardSpec enforces port-range FD cap, byte quota state, and read-only `forwards.list` RPC.
#[cfg(unix)]
#[tokio::test]
async fn neg_14_forward_bounds_quota_and_readonly_rpc() {
    use khaymali::forward::{ForwardRegistry, ForwardSpec};
    use tokio::net::UnixStream;

    // Excessive port range MUST be refused (prevents FD exhaustion)
    assert!(ForwardSpec::parse("1-65535").is_err());
    assert!(ForwardSpec::parse("2000-2100").is_err());

    let reg = ForwardRegistry::new();
    let st = reg.register(ForwardSpec::parse("8080=80@name=Mirror,quota=10K,failover=helsinki").unwrap());
    assert_eq!(st.state_label(), "on");
    st.add_usage(6000, 5000);
    assert!(st.quota_reached());
    assert_eq!(st.state_label(), "quota reached");

    let sock = format!("/tmp/khaymali-neg14-{}.sock", std::process::id());
    let ctl = ControlState::with_forwards("entry", None, Some(reg), vec![]);
    let (ctl2, sock2) = (ctl.clone(), sock.clone());
    let srv = tokio::spawn(async move { control::serve(sock2, ctl2).await });
    sleep(Duration::from_millis(60)).await;

    let mut c = UnixStream::connect(&sock).await.unwrap();
    c.write_all(b"{\"method\":\"forwards.list\"}\n").await.unwrap();
    let mut resp = String::new();
    c.read_to_string(&mut resp).await.unwrap();
    assert!(resp.contains("\"name\":\"Mirror\""));
    assert!(resp.contains("\"state\":\"quota reached\""));
    assert!(resp.contains("\"failover\":\"helsinki\""));

    srv.abort();
    let _ = std::fs::remove_file(&sock);
}


/// #15: Turbo-Tunnel SessionOwner survives carrier death and replays unacked data without RST.
#[tokio::test]
async fn neg_15_live_session_resume_and_replay_protection() {
    use khaymali::session_resume::{
        compute_resume_proof, verify_resume_proof, ReplayLedger, ResumeFrame, SessionOwner,
        SessionRegistry,
    };
    use tokio::sync::mpsc;

    let (to_sock_tx, mut to_sock_rx) = mpsc::channel::<Vec<u8>>(16);
    let peer_pub = vec![0x44u8; 32];
    let owner = SessionOwner::new(peer_pub.clone(), vec![1, 1, 1, 1, 1, 0, 80], to_sock_tx);
    let reg = SessionRegistry::new();
    reg.insert(owner.clone()).unwrap();

    // Attach Carrier A (epoch 1)
    let (tx_a, mut rx_a) = mpsc::channel::<ResumeFrame>(16);
    owner.reattach_carrier(1, 0, tx_a).await.unwrap();
    owner.send_from_socket(b"part-1-".to_vec(), Duration::from_secs(2)).await.unwrap();
    let f1 = rx_a.recv().await.unwrap();
    assert!(matches!(f1, ResumeFrame::SeqData { seq: 1, .. }));

    // Kill Carrier A; stage part-2 while detached
    owner.detach_carrier();
    drop(rx_a);
    let ow_bg = owner.clone();
    let send_task = tokio::spawn(async move {
        ow_bg.send_from_socket(b"part-2".to_vec(), Duration::from_secs(5)).await
    });
    sleep(Duration::from_millis(40)).await;

    // Reattach Carrier B (epoch 2, peer ACKed seq 1 -> replays seq 2)
    let (tx_b, mut rx_b) = mpsc::channel::<ResumeFrame>(16);
    let replayed = owner.reattach_carrier(2, 1, tx_b).await.unwrap();
    assert_eq!(replayed, 1);
    send_task.await.unwrap().unwrap();
    let f2 = rx_b.recv().await.unwrap();
    match f2 {
        ResumeFrame::SeqData { seq, epoch, payload, .. } => {
            assert_eq!(seq, 2);
            assert_eq!(epoch, 2);
            assert_eq!(payload, b"part-2");
        }
        other => panic!("unexpected frame: {other:?}"),
    }

    // Inbound delivery & ACK
    let ack = owner.deliver_from_carrier(2, 1, 2, b"downstream-ok".to_vec()).await.unwrap();
    assert_eq!(ack, 1);
    assert_eq!(to_sock_rx.recv().await.unwrap(), b"downstream-ok");

    // Forged & replayed resume proofs must be rejected
    let proof2 = compute_resume_proof(&owner.resume_token, &peer_pub, &owner.session_id, 2);
    assert!(verify_resume_proof(&owner.resume_token, &peer_pub, &owner.session_id, 2, &proof2));
    assert!(!verify_resume_proof(&owner.resume_token, &[0x99u8; 32], &owner.session_id, 2, &proof2));

    let ledger = ReplayLedger::new();
    ledger.validate_and_record(&owner.session_id, 2, &proof2).unwrap();
    assert!(ledger.validate_and_record(&owner.session_id, 2, &proof2).is_err());
}

/// #16: L3 GRE/IPIP encapsulation, PMTU clamping, and anti-SSRF route filtering.
#[test]
fn neg_16_l3_encap_pmtu_and_ssrf_routes() {
    use khaymali::l3::{CidrRoute, GreEncap, IpipEncap, PmtuTracker, RoutePolicy, MIN_IPV6_MTU};
    use std::net::Ipv4Addr;

    let mut pkt = vec![0u8; 28];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&[198, 51, 100, 1]);
    pkt[16..20].copy_from_slice(&[1, 1, 1, 1]);

    let gre = GreEncap::encapsulate(&pkt, Some(0x12345678)).unwrap();
    let (_, dec) = GreEncap::decapsulate(&gre, Some(0x12345678)).unwrap();
    assert_eq!(dec, pkt.as_slice());
    assert!(GreEncap::decapsulate(&gre, Some(0xdeadbeef)).is_err());

    let ipip = IpipEncap::encapsulate_v4(Ipv4Addr::new(198, 51, 100, 1), Ipv4Addr::new(203, 0, 113, 2), &pkt).unwrap();
    assert_eq!(IpipEncap::decapsulate_v4(&ipip).unwrap().1, pkt.as_slice());

    let pmtu = PmtuTracker::new(1380);
    assert_eq!(pmtu.record_frag_needed(500), MIN_IPV6_MTU);

    let rp = RoutePolicy::new(false);
    rp.add_route(CidrRoute::parse("0.0.0.0/0", "exit-1:443").unwrap());
    assert_eq!(rp.resolve_packet_exit(&pkt).unwrap().as_deref(), Some("exit-1:443"));

    // Private destination must be blocked by L3 anti-SSRF policy
    pkt[16..20].copy_from_slice(&[127, 0, 0, 1]);
    assert!(rp.resolve_packet_exit(&pkt).is_err());
}

/// #17: Transport benchmark, FEC recovery, and SignedConfig anti-rollback enforcement.
#[test]
fn neg_17_transport_fec_and_signed_config_anti_rollback() {
    use khaymali::fleet::SignedConfig;
    use khaymali::transport_engine::{CarrierKind, KcpFecCarrier, TransportBenchmark, TransportRegistry};

    let s1 = b"block-alpha-0001";
    let s2 = b"block-bravo-0002";
    let parity = KcpFecCarrier::build_parity_shard(&[s1, s2]);
    assert_eq!(KcpFecCarrier::recover_missing_shard(&[s1], &parity, s2.len()).unwrap(), s2);

    let reg = TransportRegistry::new();
    let sample = TransportBenchmark::evaluate_rtts_and_bytes(
        &[Duration::from_millis(25)],
        1,
        10_000_000,
        Duration::from_secs(1),
        100,
    );
    reg.record_benchmark(CarrierKind::UdpArq, sample);
    assert_eq!(reg.select_best(Instant::now()), CarrierKind::UdpArq);

    let key = b"test-signing-key-32-bytes-long!!";
    let cfg = SignedConfig::sign(key, 10, 4_000_000_000, "pool=16".into());
    cfg.verify(key, 9, 1_700_000_000).unwrap();
    assert!(cfg.verify(key, 10, 1_700_000_000).is_err(), "rollback must fail");
    assert!(cfg.verify(b"wrong-key", 9, 1_700_000_000).is_err(), "forged sig must fail");
}


/// #18: PROXY Protocol v2 binary header injection in `--forward ...@proxy=v2`.
#[test]
fn neg_18_proxy_protocol_v2_wire_verification() {
    use khaymali::forward::{encode_proxy_v2_header, ForwardProto, ForwardSpec, PROXY_V2_SIG};
    use std::net::SocketAddr;

    let spec = ForwardSpec::parse("443@name=Xray,target=127.0.0.1:8443,proxy=v2").unwrap();
    assert!(spec.proxy_v2);

    let client: SocketAddr = "185.143.220.15:49152".parse().unwrap();
    let entry_dst: SocketAddr = "198.51.100.1:443".parse().unwrap();
    let hdr = encode_proxy_v2_header(client, entry_dst, ForwardProto::Tcp);
    assert_eq!(hdr.len(), 28);
    assert_eq!(&hdr[..12], &PROXY_V2_SIG);
    assert_eq!(hdr[12], 0x21);
    assert_eq!(hdr[13], 0x11);
    assert_eq!(&hdr[16..20], &[185, 143, 220, 15]);
    assert_eq!(&hdr[24..26], &49152u16.to_be_bytes());
}

/// #19: End-to-End Entry MuxCarrier <-> Exit `serve_exit_with_registry` live stream survival across carrier death!
#[tokio::test]
async fn neg_19_end_to_end_mux_carrier_session_resume_across_carrier_kill() {
    use khaymali::mux::{serve_exit_with_registry, MuxCarrier, ResumableOpenResult};
    use khaymali::session_resume::SessionRegistry;
    use khaymali::util::encode_sockaddr;

    // Destination echo server
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = echo.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let (esk, epk) = link::keygen().unwrap();
    let (xsk, xpk) = link::keygen().unwrap();
    let exit_reg = Arc::new(SessionRegistry::new());
    let entry_reg = Arc::new(SessionRegistry::new());
    let allowed = vec![epk];

    // Carrier 1 (will be killed mid-session)
    let (a1, b1) = duplex(1 << 16);
    let (xsk1, al1, er1) = (xsk.clone(), allowed.clone(), exit_reg.clone());
    let xpk1 = xpk.clone();
    let exit_c1 = tokio::spawn(async move {
        let lk = link::respond(Box::new(b1), &xsk1, &al1).await.unwrap();
        let _ = serve_exit_with_registry(lk, true, er1, xpk1).await;
    });
    let entry_lk1 = link::initiate(Box::new(a1), &esk, &xpk).await.unwrap();
    let carrier1 = MuxCarrier::spawn(entry_lk1, Duration::from_secs(60));

    let ResumableOpenResult::Opened(mut rstream) = carrier1
        .open_resumable_stream(&encode_sockaddr(echo_addr), &entry_reg)
        .await
    else {
        panic!("expected resumable stream to open");
    };

    rstream.send_data(b"hello-on-carrier-1-").await.unwrap();
    let first_reply = timeout(Duration::from_secs(3), rstream.recv_chunk())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_reply, b"hello-on-carrier-1-");

    // Kill Carrier 1 abruptly! Destination socket on Exit stays alive in `exit_reg`.
    exit_c1.abort();
    drop(carrier1);
    sleep(Duration::from_millis(50)).await;

    // Spin up Carrier 2 and reattach the detached SessionOwner with epoch = 2
    let (a2, b2) = duplex(1 << 16);
    let (xsk2, al2, er2) = (xsk, allowed, exit_reg);
    let xpk2 = xpk.clone();
    let exit_c2 = tokio::spawn(async move {
        let lk = link::respond(Box::new(b2), &xsk2, &al2).await.unwrap();
        let _ = serve_exit_with_registry(lk, true, er2, xpk2).await;
    });
    let entry_lk2 = link::initiate(Box::new(a2), &esk, &xpk).await.unwrap();
    let carrier2 = MuxCarrier::spawn(entry_lk2, Duration::from_secs(60));

    let next_ep = rstream.owner.bump_epoch();
    assert!(carrier2.attach_session(&rstream.owner, next_ep, false).await.unwrap());

    rstream.send_data(b"survived-on-carrier-2").await.unwrap();
    let second_reply = timeout(Duration::from_secs(3), rstream.recv_chunk())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second_reply, b"survived-on-carrier-2");

    drop(rstream);
    drop(carrier2);
    exit_c2.abort();
}


/// #20: Multi-Flow FakeTLS-Mux (`ktunnel://`) 8-flow roundtrip + wrong-key rejection.
#[tokio::test]
async fn neg_20_ktunnel_multiflow_faketls_roundtrip_and_tamper_rejection() {
    use khaymali::ktunnel::{self, KtunnelListener};

    let key = b"ktunnel-neg20-secret-key-32bytes".to_vec();
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let mut listener = KtunnelListener::bind(&addr.to_string(), key.clone())
        .await
        .unwrap();

    let srv = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut got = vec![0u8; 32_768];
        s.read_exact(&mut got).await.unwrap();
        s.write_all(b"KTUN-NEG20-PASS").await.unwrap();
        s.shutdown().await.unwrap();
        got
    });

    // Wrong key handshake must never trigger session acceptance
    let bad_key = b"wrong-ktunnel-secret-key-32bytes".to_vec();
    let mut bad_cli = ktunnel::connect(&addr.to_string(), &bad_key, 2, Duration::from_secs(2))
        .await
        .unwrap();
    bad_cli.write_all(b"unauthenticated").await.unwrap();
    drop(bad_cli);

    // Valid 8-flow FakeTLS-Mux client succeeds cleanly
    let mut cli = ktunnel::connect(&addr.to_string(), &key, 8, Duration::from_secs(3))
        .await
        .unwrap();
    let payload: Vec<u8> = (0..32_768u32).map(|i| (i % 251) as u8).collect();
    cli.write_all(&payload).await.unwrap();
    let mut ack = [0u8; 15];
    cli.read_exact(&mut ack).await.unwrap();
    assert_eq!(&ack, b"KTUN-NEG20-PASS");
    cli.shutdown().await.unwrap();

    let got = srv.await.unwrap();
    assert_eq!(got, payload);
}


/// #21: UDP XOR-Parity FEC 0-RTT packet recovery & comma-separated forward parser.
#[test]
fn neg_21_udp_fec_zero_rtt_recovery_and_comma_forwards() {
    use khaymali::forward::{ForwardMode, ForwardSpec};
    use khaymali::udp_transport::{encode_fec_parity, recover_fec_shard};

    let s0 = b"fec-shard-0-payload";
    let s1 = b"fec-shard-1-payload-longer";
    let s2 = b"fec-shard-2";
    let s3 = b"fec-shard-3-payload-end";
    let parity = encode_fec_parity(&[s0, s1, s2, s3]);

    // Simulate packet #2 dropped on wire -> reconstructed immediately in 0-RTT
    let (missing_idx, recovered) =
        recover_fec_shard(&[Some(s0), Some(s1), None, Some(s3)], &parity).unwrap();
    assert_eq!(missing_idx, 2);
    assert_eq!(recovered, s2);

    // Comma-separated port shorthand + kernel transparent mode parsing
    let specs = ForwardSpec::parse_many("443,2052,8443@name=Edge,proxy=v2,mode=kernel").unwrap();
    assert_eq!(specs.len(), 3);
    assert_eq!(specs[0].listen_start, 443);
    assert_eq!(specs[1].listen_start, 2052);
    assert_eq!(specs[2].listen_start, 8443);
    assert!(specs[0].proxy_v2);
    assert_eq!(specs[0].mode, ForwardMode::KernelTransparent);
}

/// #22: KernelTransparentForwarder command generation & Reverse-Dial Noise_IK handshake.
#[tokio::test]
async fn neg_22_reverse_dial_handshake_and_kernel_forward_rules() {
    use khaymali::l3::{KernelForwardRule, KernelTransparentForwarder};
    use std::net::Ipv4Addr;

    let kfwd = KernelTransparentForwarder::new(
        "khaymali0",
        vec![KernelForwardRule {
            proto: "tcp",
            listen_port: 443,
            target_ip: Ipv4Addr::new(10, 200, 0, 2),
            target_port: 443,
        }],
    )
    .unwrap();
    let apply_cmds = kfwd.render_apply_commands();
    assert!(apply_cmds.iter().any(|c| c.contains(&"DNAT".to_string()) && c.contains(&"10.200.0.2:443".to_string())));
    let clean_cmds = kfwd.render_cleanup_commands();
    assert!(clean_cmds.iter().any(|c| c.contains(&"KHAYMALI_PREROUTING".to_string())));

    // Reverse-dial transport simulation: Exit dials Entry over TCP, then Entry initiates Noise_IK
    let (esk, epk) = link::keygen().unwrap();
    let (xsk, xpk) = link::keygen().unwrap();
    let entry_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let entry_addr = entry_listener.local_addr().unwrap();

    let entry_task = tokio::spawn(async move {
        let (sock, _) = entry_listener.accept().await.unwrap();
        let mut lk = link::initiate(Box::new(sock), &esk, &xpk).await.unwrap();
        lk.send(b"REVERSE-PING").await.unwrap();
        lk.recv().await.unwrap()
    });

    let exit_sock = TcpStream::connect(entry_addr).await.unwrap();
    let allowed = vec![epk];
    let mut exit_lk = link::respond(Box::new(exit_sock), &xsk, &allowed).await.unwrap();
    let msg = exit_lk.recv().await.unwrap();
    assert_eq!(msg, b"REVERSE-PING");
    exit_lk.send(b"REVERSE-PONG").await.unwrap();

    assert_eq!(entry_task.await.unwrap(), b"REVERSE-PONG");
}
