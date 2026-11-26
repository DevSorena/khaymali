# Public Open-Source Release Guide (`docs/RELEASE_GUIDE.md`)

Khaymali is packaged as a **single public open-source MIT repository** containing full Rust source, automated GitHub Actions CI & static musl release workflows, hardened `systemd` units, Grafana dashboard, and loopback stress/security test suites.

## Pre-Release Checklist
1. Replace `OWNER/khaymali` in `install.sh`, `README.md`, and `.github/ISSUE_TEMPLATE/config.yml` with `<YOUR_USER>/<YOUR_REPO>`.
2. Generate and commit `Cargo.lock` with Rust 1.75+ (`cargo generate-lockfile`), then verify locally:
   ```bash
   RUN_HARSH=1 bash scripts/verify_build_and_tests.sh
   ```
3. Run the 200/250/300-client harsh loopback A/B comparison (`shadow` vs `active`) and record real host numbers in `README.md`:
   ```bash
   KHAYMALI_NLP_MODE=shadow OUT=/tmp/khaymali-shadow POOL=48 bash tests/stress_harsh.sh target/release/khaymali
   KHAYMALI_NLP_MODE=active OUT=/tmp/khaymali-active POOL=48 bash tests/stress_harsh.sh target/release/khaymali
   python3 scripts/ab_compare.py /tmp/khaymali-shadow /tmp/khaymali-active
   ```
4. Enable **Private Vulnerability Reporting** in GitHub Settings → Security (as referenced in `SECURITY.md`).
5. Push to `main`, confirm `.github/workflows/ci.yml` is green, and tag your first public pre-release:
   ```bash
   git tag v0.15.0-rc.1 && git push --tags
   ```
   `.github/workflows/release.yml` automatically builds static `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` tarballs with `.sha256` checksums and GitHub Build Provenance Attestation.

## Security Hygiene
* **NEVER** commit private keys (`KHAYMALI_KEY`), camouflage secrets (`KHAYMALI_CAMO_SECRET`), `.env` files, or deployment `.model`/`.state` artifacts (blocked by `.gitignore`).
* Verify release downloads with:
  ```bash
  sha256sum -c khaymali-linux-amd64.tar.gz.sha256
  gh attestation verify khaymali-linux-amd64.tar.gz -R <YOUR_USER>/<YOUR_REPO>
  ```
