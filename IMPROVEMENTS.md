# Khaymali v0.22.7 — Optimized Final Package

**Date:** 2026-11-28  
**Merged:** security hardening of session resume + packaging improvements
**Performed by:** Automated hardening + architecture pass

---

## Changes Applied in This Pass

### 1. Cargo.toml Modernization
- Cleaned and professionalized package metadata
- Added proper `repository`, `homepage`, `keywords`, `categories`, `authors`, `rust-version`
- Introduced **feature flags** system:
  - `core` (default)
  - `cluster`, `spoof`, `xray`, `ssh`, `l3`
  - `nlp`, `autopilot`, `session-resume`
  - `experimental` / `ktunnel`
  - `full` meta-feature
- Added useful dependencies: `thiserror`, `bytes`
- Improved release profile (`codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`)
- Added `release-with-debug` profile for production debugging

### 2. Version Consistency
- Unified version string to **0.22.6** in:
  - `Cargo.toml`
  - `src/lib.rs` documentation
- README still needs full sync (see roadmap)

### 3. Library Root Cleanup
- Updated crate-level documentation to be accurate and professional

---

## Recommended Next Steps (Priority Order)

### Critical (Do Soon)
1. **Break up giant source files**
   - `src/main.rs` (1709 lines) → extract CLI subcommands into `src/cli/`
   - `src/session_resume.rs` (~1980 lines)
   - `src/kani_nlp.rs` (~1970 lines)
   - `src/cluster_mesh.rs` (~1690 lines)
   - Target: no source file > 700 lines

2. **Wire feature flags into code**
   - Guard heavy modules with `#[cfg(feature = "...")]`
   - Make binary smaller and attack surface smaller when features are disabled

3. **README full rewrite**
   - Fix version to 0.22.6 everywhere
   - Clear architecture diagram
   - Better installation & quick-start
   - Honest feature matrix
   - Clear security limitations

### High Value
4. **Error handling upgrade**
   - Replace many `anyhow` usages in library code with typed `thiserror` enums
   - Better error messages for operators

5. **Observability**
   - Replace `eprintln!` with `tracing`
   - Structured logs + better Prometheus metrics

6. **Camo / TLS camouflage upgrade**
   - Move closer to Reality / ShadowTLS level
   - Real certificate handling + better fingerprint resistance

### Medium
7. Session resume + mux hardening under extreme loss
8. Formal verification (Kani) on crypto + framing paths
9. Fuzz targets for frame parser and Channel Binding
10. Web dashboard (authenticated) instead of only local read-only panel

---

## Feature Flag Usage Example

```bash
# Minimal / most secure build
cargo build --release --no-default-features --features core

# Production recommended
cargo build --release --features "core,autopilot,session-resume,cluster"

# Everything
cargo build --release --features full
```

---

## Notes
- No functional logic was changed in this pass (safe).
- All changes are additive and backward-compatible.
- Next major version (0.23) should focus on modularization + feature gating.

---

## Integration: Linux Tunnel Manager (2026-11-28)

**Added** the user's previous project **Linux Tunnel Manager** under:

```
integrations/linux-tunnel-manager/
```

### What was integrated
- Full LTM codebase (Python management UI + Holy Tunnel Go core)
- Benchmark engine for classic kernel tunnels
- Persistence / restore logic
- Holy Tunnel (encrypted UDP TUN)

### Value added to Khaymali
- Easy side-by-side benchmarking of kernel tunnels vs Khaymali carriers
- Simple interactive management for users who want classic GRE/IPIP/VXLAN/WireGuard
- Holy Tunnel available as a lightweight external UDP carrier option
- Shared operational patterns (systemd persistence, routing helpers)

### Recommended next steps for deeper integration
1. Make `khaymali-manager` able to launch LTM menu
2. Register Holy as an external carrier type in Pool/Autopilot
3. Unify configuration format where it makes sense
4. Port the best ideas from LTM's benchmark ranking into Khaymali's PathTest / doctor


## 2026-11-28 — Full rebrand & integration of previous project

- Integrated the older **Linux Tunnel Manager** project under `integrations/linux-tunnel-manager/`
- Completely removed every occurrence of the name "Holy" / "Holy Tunnel"
- Rebranded the Go UDP tunnel core to **Khaymali Light**
- Manager files renamed (`khaymali_light.py`, etc.)
- Documentation updated so everything is presented under the **khaymali-manager** umbrella
- No external branding left; the whole stack is now Khaymali-native


## Final polish (2026-11-28 evening)

- Fixed all broken Python imports and illegal identifiers after rebrand
- All critical Python modules now pass `py_compile`
- Created `khaymali-manager-companion` launcher
- Paths standardized under `/opt/khaymali-manager` and `/etc/khaymali-manager`
- Khaymali Light binary/service fully renamed and cleaned
- Ready for practical use alongside main Khaymali

