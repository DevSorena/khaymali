# Khaymali Tunnel — Master Engineering Specification (`docs/SPEC.md`)

**Status:** Locked Engineering Contract (v0.4.2)
**Scope:** Architecture, Threat Model, Cryptographic Layer, Channel Binding, Transport & Fallback Registry, Control Plane Boundaries, Health/KANI Engine, Probabilistic Diagnostics (`khaymali-doctor`), Phased Roadmap, and Negative/Regression Test Gates.

Every code change across `Cargo.toml`, `src/*.rs`, `tests/*`, `scripts/*`, and `.github/workflows/*` MUST trace to a section in this contract and pass its verification gate before release.

---

## 1. Product-Level Invariants & Threat Model

### 1.1 Topology & Trust Boundaries
```text
[User App] --SOCKS5--> [ENTRY] <--(dial out)-- [BRIDGE] --(dial out)--> [EXIT] --> [Internet]
                          |                                               ^
                          +------ End-to-End Noise_IK Encryption ---------+
                                 (Bridge only observes ciphertext)
```
* **Single Primary Data Path First:** TCP remains the primary data path until numeric baselines and negative tests are green. No secondary transport enters production before measured evidence justifies it.
* **Key & Trust Separation:** Offline Ed25519 root key (Phase 3), independent per-Exit Noise key, strictly monotonic manifest versions persisted with `fsync`, and initial trust bootstrap strictly out-of-band.
* **Every Resource Is Bounded:** Separate caps for handshakes (global + per-prefix `/64` or `/24`), active Bridge links, SOCKS5 clients, Exit connections (global + per-peer), and isolated Fallback sockets. Zero `unbounded_channel` queues anywhere in the codebase.
* **Atomic Destination Policy (Zero DNS Rebinding):** Resolve ALL A/AAAA records once; if ANY returned address is prohibited (`is_prohibited_destination`), reject the entire request and connect directly to the validated `SocketAddr` — never re-resolve by hostname.
* **Observable Failures, Never Guesses:** Separate counters for `Timeout` vs `Reset` (`std::io::ErrorKind` downcast, not string matching), bounded history ring, and time-tick Hysteresis (never per-`pick()`).
* **Control Plane Isolated from Data Plane:** Unix socket (`0600` + `SO_PEERCRED`), read-only inspection + `drain` ONLY. **No RPC command may alter cryptographic keys, allowlists, or destination policy.**
* **Security & Performance Regressions Are Equal Gates:** Every change must pass all negative tests AND must not regress `RSS`, `p99` latency, or `goodput` against saved baselines.
* **Claims Never Exceed Measurements:** Diagnostic output is explicitly labeled `"probabilistic"`. Unmeasured claims do not enter documentation.

### 1.2 Threat Model Summary
| Threat Vector | Mitigation in Khaymali | Explicit Scope / Caveat |
|---|---|---|
| **Active Probing (TLS / HTTP / Slowloris)** | Authenticated ClientHello tag + isolated Fallback Registry mirroring same-ASN Decoy with IP + prefix (`/64`, `/24`) quotas & zero artificial timeout in normal state | Mimicked server flight for authorized peers is NOT full Reality/ShadowTLS (Phase 4 decision gated on `doctor` data) |
| **Bridge Handshake Flood & Replay** | Dual limiter (`32` total / `4` per prefix `/64` or `/24` for handshakes; `256` active), post-auth Replay Cache (`4096`), `±120s` timestamp, encrypted `READY` | `m1` replay cannot bypass `Noise_IK` auth; defense bounds CPU/socket DoS and prevents cache poisoning |
| **On-Path Byte Injection (`Entry↔Bridge`)** | Secret-bound directional Channel Binding (`HKDF-SHA256(salt=h, ikm=cb_secret)`) + `--require-channel-binding` downgrade prevention | Length XOR-masking is **cosmetic parser hardening**, NOT traffic-length hiding (TCP segment/frame sizes remain visible) |
| **SSRF & DNS Rebinding (TCP & UDP)** | `is_prohibited_destination()` blocking `0.0.0.0/8`, RFC1918, loopback, link-local, CGNAT `100.64/10`, IETF `192.0.0/24`, benchmarking `198.18/15`, doc, multicast, reserved `240/4`, IPv4-mapped `::ffff:0:0/96`, IPv4-compatible `::/96`, NAT64 `64:ff9b::/96` & `64:ff9b:1::/48` (+ custom prefixes), 6to4 `2002::/16`, Teredo `2001::/32`, ULA `fc00::/7`, `fe80::/10`, `fec0::/10`, `100::/64` | Opt-out only via explicit `--allow-private` (lab/loopback tests) |
| **Log-Flood / Disk DoS** | Race-free single-`AtomicU64` CAS error log rate limiter (`(sec_u32 << 32) | count`, `10/s` exact cap) on accept/auth error paths | Prevents scan floods from saturating disk I/O or CPU |
| **Single-VPS Key Compromise** | Phase 3 Signed Exit Manifest (offline Ed25519 root + per-Exit independent Noise key) | Does not protect sessions already terminating on the seized Exit |

---

## 2. Cryptographic Layer

### 2.1 `Noise_IK` Links & Bridge Anti-Replay Contract
* **Cipher Suite:** `Noise_IK_25519_ChaChaPoly_BLAKE2s` (`snow = "0.9"`).
* **Domain Separation Prologues:** `b"khaymali/link/1"` (Entry↔Exit), `b"khaymali/bridge/1"` (Bridge→Entry).
* **Pre-Allocation Frame Ceilings:**
  * Handshake frames: `MAX_HANDSHAKE_FRAME = 2048` bytes.
  * Data transport frames: `MAX_LINK_FRAME = 32768` bytes.
  * Headers exceeding these bounds MUST abort **before** allocating payload memory.

#### Normative Bridge Anti-Replay Order (Anti-Cache-Poisoning)
Entry MUST execute checks in this exact sequence so unauthenticated garbage cannot evict legitimate entries from the replay cache:
1. Bounded read of `m1` (`<= 2048` bytes).
2. Noise decryption of `m1` (`hs.read_message`). Failure → silent close.
3. Constant-time allowlist check (`allowed_bridges`). Failure → silent close (do NOT touch replay cache).
4. Timestamp check (`8`-byte BE `u64`, `|ts - now_unix()| <= 120s`). Failure → silent close (do NOT touch replay cache).
5. **Only after steps 1–4 succeed**, check & insert `SHA-256(m1)` into `BridgeReplayCache` (`cap = 4096`, `ttl = 240s`, oldest-entry eviction if full). Duplicate → **silent close** (no `m2`, no fake `READY`).
6. Send `m2`, derive transport state, and verify encrypted nonce-`0` `READY`:
   * `BRIDGE_READY_V2 || cb_secret (32 bytes)` → enables Channel Binding.
   * Legacy `BRIDGE_READY_V1` (`khaymali-bridge-ok`) → accepted ONLY when `--require-channel-binding` is NOT set; rejected immediately when `--require-channel-binding` is enabled (prevents silent downgrade).

### 2.2 Channel Binding (`Entry ↔ Bridge` Boundary)
* **Boundary:** Protects ONLY the `Entry ↔ Bridge` hop after `Bridge` completes its independent `Noise_IK` authentication. Bridge never sees Entry↔Exit plaintext or keys.
* **Secret-Bound Key Derivation (Fixes Public `h` Pitfall):**
  * Bridge generates 32 random bytes `cb_secret` via OS CSPRNG and sends it inside encrypted `READY v2`.
  * Both sides compute RFC 5869 `HKDF-SHA256`:
    * `PRK = HKDF-Extract(salt = h, ikm = cb_secret)`
    * `K_b2e_mac = HKDF-Expand(PRK, b"khaymali/cb/v2/b2e/mac", 32)`
    * `K_b2e_len = HKDF-Expand(PRK, b"khaymali/cb/v2/b2e/len", 32)`
    * `K_e2b_mac = HKDF-Expand(PRK, b"khaymali/cb/v2/e2b/mac", 32)`
    * `K_e2b_len = HKDF-Expand(PRK, b"khaymali/cb/v2/e2b/len", 32)`
* **Wire Format & Honest Security Scope:**
  * `masked_len (2 bytes) | tag (16 bytes) | payload (len bytes, max 16384)`.
  * `tag = HMAC-SHA256(K_dir_mac, seq_u64_be || len_be || payload)[0..16]`.
  * **Honest Note on Length Masking:** XOR-masking the 2-byte length header is **cosmetic parser hardening** only; an on-path observer can still infer frame/segment sizes from TCP wire lengths. Cryptographic integrity/anti-injection is provided by the 128-bit directional HMAC bound to `cb_secret` and strict monotonic `seq` (`checked_add(1)`, closing cleanly on `u64::MAX`).

### 2.3 Signed Exit Manifest & Root Verification (Phase 3 Contract)
* Path `/var/lib/khaymali/manifest.state` is reserved via `MANIFEST_STATE_PATH` and `ensure_manifest_state_dir()`, which refuses any path whose parent leaf directory is not literally named `khaymali` (preventing accidental `chmod 0700` on `/var/lib` or `/tmp`).
* Atomic persistence requires advisory lock + temp write + `fsync(file)` + `rename()` + `fsync(parent_dir)`.
* **Out-of-Band Root Verification:**
  * `ui-tag` (`XXX-XXX`, 6 chars / ~30 bits): visual UI label ONLY — NEVER for security proof.
  * `check-code` (`XXXX-XXXX-XXXX`, 12 chars / ~60 bits): compact out-of-band check code displayed outside Join Code.
  * `sha256` (full 64-hex SHA-256): mandatory out-of-band verification for high-assurance initial setup.

---

## 3. Transport Layer & Isolated Fallback Registry

### 3.1 `Transport` Trait & Encrypted Capability Negotiation
* `Transport` decouples `Link` from `Tcp`, `Camo`, and future transports.
* Encrypted 4-byte capability header (`proto_version: u8`, `feature_bits: u16`, `reserved: u8`): rejects unsupported `proto_version != 1`; masks unknown/reserved feature bits safely.

### 3.2 Fallback Registry & Prefix Quotas
* **Separate Listener & Registry:** Decoy fallback NEVER shares capacity with authenticated Exit connections (`4096`) or Bridge listeners.
* **Quotas:** `FALLBACK_MAX_TOTAL = 256`, `FALLBACK_MAX_PER_IP = 24`, `FALLBACK_MAX_PER_PREFIX = 38` (`~15%`, bucketed by IPv6 `/64` and IPv4 `/24`).
* **Normal State:** Zero artificial timeout; full bidirectional half-close (`FIN`) mirroring matching the real Decoy.
* **Saturation Only:** Conditional Idle LRU Eviction removes the oldest `last_active_ms` lease from the offending IP/prefix (or largest-share prefix on global cap) cleanly via `FIN`.

---

## 4. Control Plane, Egress Policy & Graceful Drain
* **Unix Socket Control API (`--control /run/khaymali/control.sock`):**
  * Forced `chmod 0600`, `SO_PEERCRED` restricted to `uid == 0` or process `euid`, max request `8192` bytes, max `16` concurrent clients.
  * **Allowed Methods (Strict Read-Only + Drain):** `status`, `peers.list`, `health.history`, `kani.diagnose`, `drain`.
  * **Explicit Prohibition:** No RPC method may add/remove keys, alter allowlists, or modify destination/SSRF policies.
* **Graceful Drain (`drain`):** Stops accepting new connections immediately and allows active streams up to `15s` (`DRAIN_WINDOW`) to finish cleanly.

---

## 5. `health.rs` & KANI (Advisory Intelligence)
* **Explicit State Parity (`up` vs `selectable`):** `Snap.up` is strictly `circuit == Closed`. `Snap.selectable` uses `is_selectable_now(s, now)` — matching `pick()` 1:1 (false during `Open` cooldown AND false when `HalfOpen` already has a probe in flight). `Exits::diagnose()` is strictly advisory/read-only.
* **Strict Time-Tick Hysteresis:** First observation only sets `last_hysteresis_tick = Some(now)` (does NOT count as tick #1). Subsequent advances strictly enforce `>= 10s` elapsed (no `force` bypass on `evaluate_tick()`). Requires `>= 15%` score improvement across `3` consecutive ticks AND `samples >= 2`.
* **Typed Failure Classification:** `Exits::classify_error` walks `anyhow::Error::chain()` downcasting `std::io::Error` (`ErrorKind`) and `tokio::time::error::Elapsed` — zero fragile string matching.
* **Control-Plane `TinyNetNlp` (`src/kani_nlp.rs`):** Strictly advisory/diagnostic off the Data Plane hot path (uses small temporary `Vec`/`String` allocations per diagnostic call — NOT zero-allocation and NEVER placed on the packet hot path). Filters tokens by Unicode character count (`tok.chars().count() >= 2`) and never executes autonomous changes.

---

## 6. `khaymali-doctor` & Regression Gates
* Always run initial tests on an isolated test port (e.g. `8443`) firewalled to the domestic test IP.
* All outputs carry `"verdict_confidence": "probabilistic"` and separate `timeout` vs `reset`, run a second-connection freeze disambiguator, and step-probe PMTU.
* `scripts/check_baseline_regression.py` compares candidate stress/doctor JSON runs against a saved baseline and exits non-zero on `p99`, `RSS`, or `goodput` regressions.

---

## 7. Phased Roadmap & Verification Gates
* **Phase 1 — Security Stabilization:** Dual Bridge limiter (`32` total / `4` per prefix / `256` active), post-auth Bridge Anti-Replay (`±120s`, `4096` cache, `READY`), `--require-channel-binding`, SOCKS5 `10s` timeout + method check, anti-SSRF/anti-rebinding `is_prohibited_destination()` (incl. `0.0.0.0/8`, 6to4, Teredo, CGNAT, NAT64, IPv4-mapped) on TCP & UDP, pre-allocation frame limits, rate-limited error logging, `--locked` CI & provenance attestation.
* **Phase 2A — Core Architecture:** `Transport` Trait, Encrypted Capability Negotiation, secret-bound `HKDF(h, cb_secret)` Channel Binding verified end-to-end on `tokio::io::duplex`, reusable hot-path buffers, zero unbounded queues, Graceful Drain.
* **Phase 2B — Control & Fallback:** Read-only+drain Unix Socket Control API (`0600` + `SO_PEERCRED`), Fallback Registry (`256`/`24`/`38` per prefix, zero normal timeout, conditional Idle LRU, half-close mirroring), alert-only Decoy Watchdog.
* **Phase 3 — Scale & KANI:** Time-tick Hysteresis + typed Timeout/Reset Circuit Breaker in `health.rs`, Signed Exit Manifest (offline Ed25519 + `fsync` `manifest.state` + 12-char & SHA-256 out-of-band check), Signed Policy Push with `30s` Commit-Confirm Rollback.
* **Phase 4 — Data-Driven Selection (strictly gated on Phase 1 `doctor` baseline):** (A) Mux + independent Session Resume + OpenWrt `khaymali-bridge-lite` (post real RAM measurement) + 3-stage Split-Path, OR (B) XHTTP/CDN, OR (C) BoringSSL / Aparecium-hardened ShadowTLS v3; QUIC optional last.

---

## 8. Mandatory Negative & Integration Test Matrix
1. `neg_bridge_replay_and_cache_poisoning` — Unallowed flood cannot poison cache; replayed/stale `m1` gets silent close (`0` bytes).
2. `neg_bridge_downgrade_rejected_when_cb_required` — Legacy `READY v1` rejected when `--require-channel-binding` is set.
3. `neg_bridge_handshake_prefix_flood_bounded` — Single `/64` or `/24` capped at `4`; clean prefix not starved.
4. `neg_socks5_slowloris_and_malformed` — Slowloris times out; missing `0x00` gets `[5, 0xff]`; garbage fails cleanly.
5. `neg_prohibited_destinations_and_mixed_resolution` + `neg_udp_ssrf_targets_blocked` — `0.0.0.0/8`, `::2`, 6to4, Teredo, CGNAT, NAT64, mapped, ULA, multicast, mixed public+private all rejected on TCP & UDP.
6. `neg_frame_length_overflow_rejected` — Oversized handshake/link headers fail before allocation.
7. `neg_fallback_prefix_ipv6_quota_and_lru` — IPv6 `/64` rotation capped via oldest-idle LRU; unrelated `/64` unstarved.
8. `neg_fallback_normal_mirrors_decoy_half_close` — Exact Decoy response & `FIN` after client half-close.
9. `wrap_bound_stream_duplex_roundtrip_injection_and_replay` — Real async `wrap_bound_stream` over `tokio::io::duplex` verifying 64 KiB round-trip, live wire byte-injection rejection, and wire frame-replay rejection.
10. `neg_control_api_cannot_mutate_keys_or_policy` — Rejects any mutating RPC method (`peers.add`, `peers.revoke`, `policy.set`).
11. Live binary verification: `tests/integration.sh`, `tests/netem.sh`, `scripts/stress_live_300.sh --json`, and `scripts/check_baseline_regression.py`.

### TinyNetNlp v2 (harsh-network hardening)
512 hashed buckets x 6 classes (~6 KiB i16). Adds Persian normalisation, log-noise stripping, magic-size features (12–20 KB freeze, 64 KB, MTU values), Unicode trigrams, `LinkMetrics` (numeric telemetry -> tokens), abstention below `MIN_CONFIDENCE` (0.5 -> `keep_normal`), and `NlpAdvisor` hysteresis (same non-healthy verdict twice before an action is released). Still advisory only; never on the data-plane hot path.
Harsh stress: `bash tests/stress_harsh.sh` (no root) runs 200 and 300 concurrent SOCKS5 clients through `tests/harsh_proxy.py` profiles (latency/jitter, TCP-like loss, throttle, early RST, 16 KB freeze, blackhole bursts, mixed).
