#!/usr/bin/env bash
# One-command loopback verification suite for Khaymali v0.15.1.
# Runs on Ubuntu with Rust 1.75+ (no public network listeners).
# Usage:
#   bash scripts/verify_build_and_tests.sh
#   sudo NETEM=1 bash scripts/verify_build_and_tests.sh   # also runs tc netem profiles
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== 1. Rust toolchain check ==="
rustc --version
cargo --version
if [ ! -f Cargo.lock ]; then
  echo "Cargo.lock missing; generating it with the installed toolchain"
  cargo generate-lockfile
fi

echo "=== 2. Unit tests (including v0.14 intelligence and NLP artifact persistence) ==="
cargo test --locked --lib
echo "--- v0.15.1 regression tests ---"
cargo test --locked --lib v0151_ -- --nocapture
cargo test --locked --lib intelligence:: -- --nocapture
cargo test --locked --lib kani_nlp:: -- --nocapture
cargo test --locked --lib recovery:: -- --nocapture
cargo test --locked --lib health:: -- --nocapture
echo "--- v0.22.0 Khaymali pure tunneling suite & Micro-NLP unit tests ---"
cargo test --locked --lib hjson:: sysrun:: spoof_carrier:: cluster_mesh:: carrier_swap:: setup_bundle:: engines:: cluster_lb:: node_cluster:: sshfwd:: xray_engine:: ops_suite:: harsh_nlp:: -- --nocapture

echo "=== 3. Negative security tests (cargo test --locked --test neg_security) ==="
cargo test --locked --test neg_security

echo "=== 4. Generate ClientHello sample for OpenSSL TLS 1.3 check ==="
cargo test --locked --lib camo::tests::dump_hello -- --ignored

echo "=== 5. Release build (cargo build --locked --release) ==="
cargo build --locked --release

echo "=== 5b. Offline digital-twin smoke test ==="
target/release/khaymali doctor
target/release/khaymali intelligence-lab --scenario all --steps 500 --capacity-kbps 2500 --offered-kbps 2000 --queue 64
bash tests/intelligence_cli.sh target/release/khaymali

echo "=== 6. Loopback integration suite (Direct + UDP + Bridge + Camo + Failover) ==="
# The plain-HTTP probe check is the documented "known gap" (README section 11); it is the only
# failure tolerated here. Anything else fails the run.
set +e
bash tests/integration.sh target/release/khaymali 2>&1 | tee /tmp/khaymali-integration.log
INTEGRATION_STATUS=${PIPESTATUS[0]}
set -e
BAD=$(grep -E "^  FAIL:" /tmp/khaymali-integration.log | grep -vc "plain-HTTP probe" || true)
[ "$BAD" = "0" ] || { echo "integration: $BAD unexpected failure(s)"; exit 1; }
if [ "$INTEGRATION_STATUS" != "0" ]; then
  echo "NOTE: integration exited non-zero only for the documented plain-HTTP probe known gap"
fi

echo "=== 6b. Installer syntax check ==="
bash -n install.sh
if [ -f scripts/khaymali-manager ]; then
  bash -n scripts/khaymali-manager
  [ ! -f tests/manager.sh ] || bash tests/manager.sh
else
  echo "SKIP: optional manager script/tests are not present in this source archive"
fi

echo "=== 7. Chaos test of the adaptive engine (Exit killed and restarted, real binary) ==="
bash tests/chaos.sh target/release/khaymali

echo "=== 8. Loopback stress suite (concurrency up to 300) ==="
POOL=8 bash tests/stress.sh target/release/khaymali 300

if [ "${RUN_HARSH:-0}" = "1" ]; then
  echo "=== 8b. Harsh loopback profiles at 200/250/300 clients (NLP shadow) ==="
  LABEL_FROM_PROFILE=1 OUT=/tmp/khaymali-harsh-shadow POOL=8 KHAYMALI_NLP_MODE=shadow bash tests/stress_harsh.sh target/release/khaymali
  python3 scripts/eval_nlp_replay.py target/release/khaymali /tmp/khaymali-harsh-shadow/replay_dataset.jsonl
  python3 scripts/make_annotation_set.py /tmp/khaymali-harsh-shadow/replay_dataset.jsonl /tmp/khaymali-annotate.tsv
fi

if [ "${RUN_AB:-0}" = "1" ]; then
  echo "=== 8c. A/B shadow vs active, ${REPEATS:-3} repetitions per profile/step ==="
  OUT=/tmp/khaymali-ab-shadow POOL=8 REPEATS="${REPEATS:-3}" KHAYMALI_NLP_MODE=shadow bash tests/stress_harsh.sh target/release/khaymali || true
  OUT=/tmp/khaymali-ab-active POOL=8 REPEATS="${REPEATS:-3}" KHAYMALI_NLP_MODE=active bash tests/stress_harsh.sh target/release/khaymali || true
  python3 scripts/ab_compare.py /tmp/khaymali-ab-shadow /tmp/khaymali-ab-active --json /tmp/khaymali-ab.json
fi

if [ "${NETEM:-0}" = "1" ]; then
  echo "=== 9. Loopback netem degraded-network suite ==="
  bash tests/netem.sh target/release/khaymali
fi

echo "=== ALL CHECKS PASSED ==="
