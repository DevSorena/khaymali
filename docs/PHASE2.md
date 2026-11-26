# Phase 2 plan / نقشه‌ی فاز بعدی

Status: **design only**. None of this is implemented in v0.3.0; the Rust sources are unchanged from v0.2.0.
Order is chosen so each step is measurable before the next one is built.

## 0. Measure first (before any new transport)
1. On the real Iran server run `khaymali-manager doctor <exit-ip> 443` (nc, path, UDP, dig). It decides Direct vs Bridge.
2. Run `sudo bash tests/netem.sh target/release/khaymali` to get a baseline under loss 5/15 %, jitter, reordering.
   Record throughput and connect time per profile. Every later item must beat this baseline.
3. Measure on the *real* link too (loopback + netem is only an approximation).

## 1. Foundation refactor (small, unlocks everything)
* Split crypto from transport: `Link` takes any `AsyncRead + AsyncWrite` (already `BoxRw`); add a
  `trait Transport { async fn dial(&self, target) -> Result<BoxRw>; async fn accept(&self) -> Result<BoxRw>; }`
  with implementations: `Tcp`, `TcpCamo` (current), later `Quic`, `XHttp`.
* Channel binding on Entry↔Bridge: derive a key from the Noise handshake hash after bridge auth and wrap the spliced
  stream in a lightweight AEAD framing so injected bytes are rejected on that hop (closes the README limitation).
* Fallback FIN/RST fidelity: mirror the decoy's close behaviour (half-close, RST) to probes.

## 2. Transport candidates (each behind the trait, each benchmarked against section 0)
| Candidate | Why | Crates | Risk |
|---|---|---|---|
| QUIC with datagrams | real UDP, no head-of-line blocking | `quinn` (needs newer rustc than 1.75) | QUIC is blocked/throttled in some networks: keep TCP as fallback |
| Custom congestion control (Brutal-style) | fixed-rate sending under artificial loss | quinn `congestion::Controller` | unfair to other flows; make opt-in |
| Multiplexing over pooled links | fewer sockets, more natural NetFlow | `yamux` or own framing | head-of-line blocking if too many streams per link |
| XHTTP / SplitHTTP | CDN-fronted fallback | `hyper`, `h2` | complexity; only worthwhile if IP blocking is the real problem |

Do **not** start with all of them. Pick by the numbers from section 0.

## 3. Camouflage upgrade
* Replace mimicry with a real TLS 1.3 handshake against the decoy (ShadowTLS v3 style: relay the genuine handshake,
  switch to the tunnel after an HMAC-marked record). Largest single improvement against active probing; also the
  riskiest to get right, so it needs its own review.
* Verify JA3/JA4 against real Chrome captures; add X25519MLKEM768 key share to match current Chrome.
* Padding on the first N records (Vision/AnyTLS-style) to hide TLS-in-TLS size patterns.

## 4. Operations
* `khaymali scan-decoy <exit-ip>`: suggest TLS 1.3 sites hosted in the Exit's ASN.
* Hot-reload `--allow` (SIGHUP) so key changes don't drop users (manager currently restarts the service).
* Optional SOCKS5 username/password; TUN mode; mobile client via UniFFI.

## Honest caveats
* Techniques copied from Xray/Hysteria/Zapret/AmneziaWG are proven *there*, not automatically here; each needs
  testing on the real network you target.
* Raw-socket tricks (fake TTL packets, TCP overlap) need root/CAP_NET_RAW and conflict with the sandboxed systemd units.
* Post-quantum hybrid handshakes protect recorded traffic later; they do nothing against blocking. Prioritise accordingly.

---

## Review of the "v0.4 patch set" proposal (corrections)

An external proposal (Network Weather script, `policy.rs`, `finalmask.rs`, `intelligence.rs`) was reviewed. Keep the ideas, fix these:

**Doctor script**
* Its "16 KB freeze" test fetched `GET /` from a normal site and treated "no more data" as a freeze, so any page
  smaller than 16 KB (with keep-alive) is reported as frozen. Replaced by `scripts/khaymali-doctor`
  (serve/probe) which talks to a server *we* control with exact byte counts, per direction.
* The SNI scan connected to each site itself. A DPI whitelist is decided on *(SNI, destination IP)*, so the
  scan must connect to **your Exit IP** with each candidate SNI. Fixed. The chosen SNI must also be a name
  the decoy IP actually serves (otherwise probes forwarded to the decoy see a mismatch).
* "QUIC open" was inferred from a version-negotiation probe to 1.1.1.1. Censors block on the *Initial packet's SNI*,
  so that probe proves nothing. The new doctor only claims what it measured (UDP echo to your own Exit).
* The DNS check hard-coded one sinkhole range. Now: system resolver vs. raw UDP to 1.1.1.1, flag bogon/private answers.
* Country presets with hard-coded SNIs (cloudflare/microsoft) are guesses. SNIs must come from measurement per network.

**Rust modules**
* `serde` and `blake2` are not in Cargo.toml (and generate and commit Cargo.lock with the pinned rustc 1.75 toolchain before using --locked). Use the existing `hmac`+`sha2`
  and a tiny hand-written encoding, or budget a dependency/toolchain upgrade explicitly.
* Policy push: the Bridge only relays ciphertext, so it cannot read a policy the Exit sends to the Entry.
  Chain of trust must be Exit → Entry → Bridge (the Bridge already pins the Entry key). Policies must be
  bounds-checked, monotonic (`revision`) and limited to a pre-approved set of options; they must never carry secrets.
* `junk_prefix_bytes` of *random* bytes is high-entropy: the opposite of what first-packet exemptions look for
  (printable-ASCII / TLS- or HTTP-like prefixes). Use a low-entropy, HTTP-like prefix.
* Splitting at a fixed offset 3 does not split the SNI. The offset must be computed from the ClientHello we generate.
  Research on Iran found fake-packet/overlap tricks stopped working once a stateful middlebox validated sequence
  numbers and checksums, so treat fragmentation as optional and measure it.
* `rotate_after_bytes = 14 KiB` is meaningless today: each user connection has its own link, so rotation needs
  stream continuity across links (multiplexing + resume). It is a protocol feature, not a config flag, and
  whether the Russian freeze is per-connection or per-destination is unproven until the doctor says so.
* The channel-binding frame needs direction-separated keys, sequence checking on receive, and the handshake hash taken
  from the auth handshake before it leaves handshake mode. A cleartext length prefix is itself a pattern.
* `intelligence.rs` duplicates `health.rs` (EWMA + back-off + exploration already exist). Extend it with
  loss/freeze counters, hysteresis (no flapping) and a *per-network* key, rather than replacing it.

**Roadmap changes**
* QUIC stays optional and last; never default on Iran/China paths.
* ShadowTLS-style relaying needs the published fixes; real-Chrome ClientHello fidelity needs BoringSSL-based code
  (rustls cannot reproduce Chrome's extension order/GREASE) and complicates static musl release builds.
* L4 port forwarding (BackPack-style) is a separate product feature; do not let it delay the anti-detection work.
