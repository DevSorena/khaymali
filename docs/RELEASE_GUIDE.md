# Release Guide (`docs/RELEASE_GUIDE.md`)

Khaymali is one public MIT repository: Rust source, CI and static-musl release workflows, hardened
`systemd` units, a Grafana dashboard and loopback/netns stress and security suites.

## Before you push or tag

1. **Run the server verification once, on a real Linux server** (root, systemd, iproute2, nftables):
   ```bash
   sudo bash scripts/server_verify.sh
   # optional: real Telegram delivery (sends ONE test message)
   sudo TG_TOKEN=<bot token> TG_CHAT=<chat id> bash scripts/server_verify.sh
   ```
   It builds with the pinned toolchain (Rust 1.85.0), runs every test, the root-only checks
   (netns/tc, GRE, FOU, nft, WireGuard, raw-socket spoof, systemd unit verification), `chaos.sh`,
   `netem.sh`, `stress.sh` (clean + netem), `stress_harsh.sh` in shadow and active mode, the A/B gate,
   the NLP replay audit and `stress_harsh_300_ab.sh`. Result: `<out>/server_verify_report.txt`.
   Every step is `PASS`, `FAIL` or `SKIP` (with the reason). Do not release with a `FAIL`.
   Use `--quick` for a ~10 minute smoke run. Check `nproc`: on a multi-core host the stress run is a
   real multi-core test; on one core it is not.
2. **Real Iran <-> abroad path** (needs two servers; cannot be simulated):
   ```bash
   bash scripts/real_path_check.sh origin          # on the Exit (abroad)
   bash scripts/real_path_check.sh run EXIT_IP     # on the Entry (Iran), Entry already running
   ```
3. Record the real numbers (A/B table, real-path JSON) in `README.md`/`RELEASE_STATUS.txt`.
4. Enable **Private Vulnerability Reporting** in GitHub Settings -> Security (referenced by `SECURITY.md`).
5. Push to `main`, wait for `.github/workflows/ci.yml` to be green, then tag:
   ```bash
   git tag v0.22.1 && git push --tags
   ```
   `release.yml` builds static `x86_64` and `aarch64` musl tarballs (binary, `khaymali-manager`,
   `khaymali-tui`, deploy files, test scripts), smoke-tests the amd64 binary, writes `.sha256` files and
   a GitHub build-provenance attestation.

## Installer trust model

`install.sh` verifies the archive SHA-256 (or builds from source with `--locked`). The menu and
dashboard helpers come from the same verified archive; if one is missing they are fetched from the
SAME ref as the binary (the pinned tag, `main` for `latest`), not blindly from `main`
(`KHAYMALI_HELPERS_REF` overrides). Unknown installer options are rejected instead of ignored.

## Security hygiene

* **Never** commit private keys (`KHAYMALI_KEY`), camouflage secrets (`KHAYMALI_CAMO_SECRET`), `.env`
  files or `.model`/`.state` artifacts (blocked by `.gitignore`).
* Verify downloads:
  ```bash
  sha256sum -c khaymali-linux-amd64.tar.gz.sha256
  gh attestation verify khaymali-linux-amd64.tar.gz -R DevSorena/khaymali
  ```
* Run the server verification with a throwaway Telegram bot/chat, not the production alert bot.
