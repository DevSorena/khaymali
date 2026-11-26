# Khaymali Threat Model (`docs/THREAT_MODEL.md`)

## Trust Boundaries
1. **Entry ↔ Exit (`Noise_IK`):** End-to-end encrypted & mutually authenticated with pinned static keys.
2. **Entry ↔ Bridge (`Noise_IK` + Secret-Bound Channel Binding):** Bridge is an untrusted relay. It proves static key possession via `Noise_IK` + `±120s` timestamp + post-auth replay cache + encrypted `READY v2` carrying 32-byte `cb_secret`. All frames between Entry and Bridge are authenticated with directional `HMAC-SHA256` derived via `HKDF-SHA256(salt=h, ikm=cb_secret)`.
3. **Exit Egress Boundary (Anti-SSRF & Anti-DNS-Rebinding):** Every TCP and UDP destination is resolved once, checked atomically against `is_prohibited_destination()` (`0.0.0.0/8`, RFC1918, loopback, link-local, CGNAT `100.64/10`, IPv4-mapped `::ffff:0:0/96`, IPv4-compatible `::/96`, NAT64 `64:ff9b::/96` & `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/32`, ULA, multicast, reserved), and dialed directly by validated `SocketAddr`.
4. **Fallback Isolation:** Unauthenticated traffic to Exit is isolated inside `FallbackLimiter` (`256` total, `24` per IP, `38` per IPv6 `/64` or IPv4 `/24`) so active probers cannot exhaust authenticated tunnel capacity (`4096`).
5. **Control Plane Boundary:** Unix socket (`0600` + `SO_PEERCRED`) exposes strictly read-only status/history/diagnose plus graceful `drain`. No RPC call can alter keys, allowlists, or destination policy.

## Explicit Non-Goals / Honest Boundaries
* Current `camo` mimics a TLS 1.3 handshake for authenticated peers; it is NOT full Reality/ShadowTLS (Phase 4 decision gated on real `khaymali-doctor` baselines).
* Length XOR-masking in Channel Binding is cosmetic parser hardening, not traffic-size hiding.
* Not formally security-audited; do not rely on Khaymali for life-critical anonymity.
