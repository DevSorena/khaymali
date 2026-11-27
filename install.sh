#!/usr/bin/env bash
# Khaymali Tunnel - hardened one-line installer (SPEC -7)
#   bash <(curl -fsSL https://raw.githubusercontent.com/DevSorena/khaymali/main/install.sh)
# Flags:
#   --tune                 apply optional BBR/socket sysctl tuning (with backup)
#   --revert-tune          restore previous sysctl state and remove 99-khaymali.conf
#   --verify-attestation   require GitHub build provenance check (`gh attestation verify`)
#   --allow-unverified     continue when no checksum is published (default: fall back to a source build)
# Env overrides:
#   KHAYMALI_REPO=owner/repo   KHAYMALI_VERSION=v0.4.0 (default: latest)
#   --join CODE            install, then configure this server as Entry from the Exit join code
#   --join-bridge CODE     install, then configure this server as Bridge
#   KHAYMALI_BIN=/path/to/khaymali   KHAYMALI_BUILD=1   KHAYMALI_NO_MENU=1
set -euo pipefail
umask 077   # state/config created here may hold keys: private by default

REPO="${KHAYMALI_REPO:-DevSorena/khaymali}"
VERSION="${KHAYMALI_VERSION:-latest}"
PREFIX="${PREFIX:-/usr/local/bin}"
STATE_DIR="/var/lib/khaymali"
SYSCTL_FILE="/etc/sysctl.d/99-khaymali.conf"
SYSCTL_BACKUP="/etc/khaymali/sysctl.backup"
DO_TUNE=0
REVERT_TUNE=0
VERIFY_ATTEST=0
ALLOW_UNVERIFIED=0
LOG="/var/log/khaymali-install.log"

MIRROR=""
JOIN=""
JOIN_BRIDGE=""
JOIN_MODE=""
while (( $# )); do
  case "$1" in
    --tune) DO_TUNE=1; shift ;;
    --revert-tune) REVERT_TUNE=1; shift ;;
    --verify-attestation) VERIFY_ATTEST=1; shift ;;
    --allow-unverified) ALLOW_UNVERIFIED=1; shift ;;
    --from-source) KHAYMALI_BUILD=1; shift ;;
    --local) KHAYMALI_BIN="$2"; shift 2 ;;
    --local=*) KHAYMALI_BIN="${1#*=}"; shift ;;
    --mirror) MIRROR="$2"; shift 2 ;;
    --mirror=*) MIRROR="${1#*=}"; shift ;;
    --join) JOIN="$2"; shift 2 ;;
    --join=*) JOIN="${1#*=}"; shift ;;
    --join-bridge) JOIN_BRIDGE="$2"; shift 2 ;;
    --mode) JOIN_MODE="$2"; shift 2 ;;
    *) shift ;;
  esac
done

c_ok=$'\e[32m'; c_err=$'\e[31m'; c_inf=$'\e[36m'; c_off=$'\e[0m'
say()  { printf '%s[*]%s %s\n' "$c_inf" "$c_off" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$c_ok" "$c_off" "$*"; }
die()  { printf '%s[x]%s %s\n' "$c_err" "$c_off" "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root (sudo -i, then re-run)."
[ "$(uname -s)" = Linux ] || die "Linux only."

if [ "$REVERT_TUNE" -eq 1 ]; then
  n=0
  if [ -f "$SYSCTL_BACKUP" ]; then
    while IFS= read -r line; do
      k="${line%% = *}"; v="${line#* = }"
      [ -n "$k" ] && sysctl -w "$k=$v" >/dev/null 2>&1 && n=$((n+1))
    done < "$SYSCTL_BACKUP"
    ok "Restored $n original kernel values from $SYSCTL_BACKUP"
  fi
  rm -f "$SYSCTL_FILE" "$SYSCTL_BACKUP" /etc/sysctl.d/99-khaymali-bbr.conf
  sysctl --system >/dev/null 2>&1 || true
  ok "Removed Khaymali sysctl files and reloaded system defaults."
  exit 0
fi

command -v systemctl >/dev/null || die "systemd is required."
[ "$REPO" != "OWNER/khaymali" ] || die "Set KHAYMALI_REPO=owner/repo before running."

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "Unsupported CPU: $(uname -m)" ;;
esac

need() { command -v "$1" >/dev/null 2>&1; }
need curl || need wget || {
  # try to install curl automatically (Debian/Ubuntu, RHEL family, Alpine)
  say "curl/wget missing - installing curl..."
  if need apt-get; then apt-get update -qq >>"$LOG" 2>&1 || true; DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates >>"$LOG" 2>&1
  elif need dnf; then dnf install -y curl ca-certificates >>"$LOG" 2>&1
  elif need yum; then yum install -y curl ca-certificates >>"$LOG" 2>&1
  elif need apk; then apk add --no-cache curl ca-certificates >>"$LOG" 2>&1
  fi
  need curl || die "Install curl first (apt install curl)."
}
need tar || die "tar is required."
need sha256sum || die "sha256sum (coreutils) is required."
fetch() {
  if need curl; then curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$1"
  else wget -q -O "$2" "$1"; fi
}


# Print the sha256 for file $1 found in checksum text on stdin (checksums.txt style or a bare hash).
pick_sha256() {
  local name="$1" text h; text="$(cat)"
  h="$(printf '%s\n' "$text" | grep -F -- "$name" | grep -oiE '\b[0-9a-f]{64}\b' | head -1)"
  if [ -z "$h" ] && [ "$(printf '%s\n' "$text" | grep -ciE '^[0-9a-f]{64}')" = 1 ]; then
    h="$(printf '%s\n' "$text" | grep -oiE '^[0-9a-f]{64}' | head -1)"
  fi
  echo "${h,,}"
}
# Look for the expected hash in: GitHub release asset digest, <asset>.sha256, checksums.txt,
# sha256sums.txt, SHA256SUMS. Returns 0 verified, 1 MISMATCH (fatal), 2 nothing published.
verify_archive() {
  local file="$1" name="$2" url="$3" expected="" src="" c="" actual json base="${3%/*}"
  if [ "$VERSION" != latest ]; then
    json="$(curl -fsS --max-time 10 "https://api.github.com/repos/$REPO/releases/tags/$VERSION" 2>/dev/null || true)"
  else
    json="$(curl -fsS --max-time 10 "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null || true)"
  fi
  if [ -n "$json" ]; then
    expected="$(printf '%s\n' "$json" | tr ',' '\n' | awk -v n="\"$name\"" '
      /"name":/ { cur = ($0 ~ n) }
      cur && /"digest": *"sha256:/ { sub(/.*sha256:/, ""); sub(/".*/, ""); print; exit }')"
    [ -n "$expected" ] && src="GitHub release digest"
  fi
  if [ -z "$expected" ]; then
    for c in "$url.sha256" "$base/checksums.txt" "$base/sha256sums.txt" "$base/SHA256SUMS"; do
      expected="$(curl -fsSL --max-time 10 "$c" 2>/dev/null | pick_sha256 "$name" || true)"
      [ -n "$expected" ] && { src="${c##*/}"; break; }
    done
  fi
  [ -n "$expected" ] || return 2
  actual="$(sha256sum "$file" | awk '{print $1}')"
  if [ "$actual" != "$expected" ]; then
    printf '%s[x]%s expected %s (%s)\n    got      %s\n' "$c_err" "$c_off" "$expected" "$src" "$actual" >&2
    return 1
  fi
  ok "SHA-256 verified ($src)"
}

TMP="$(mktemp -d)"
BACKUP="$(mktemp -d)"
trap 'rm -rf "$TMP" "$BACKUP"' EXIT

# Reserve state dir for Phase 3 Manifest anti-rollback (SPEC -2.3)
mkdir -p "$STATE_DIR" /etc/khaymali
chmod 0700 "$STATE_DIR" /etc/khaymali

backup_existing() {
  for f in khaymali khaymali-tui khaymali-manager khaymali-doctor khaymali-web; do
    if [ -f "$PREFIX/$f" ]; then cp -a "$PREFIX/$f" "$BACKUP/$f"; fi
  done
  return 0
}

rollback_existing() {
  say "Rolling back previous installation..."
  for f in khaymali khaymali-tui khaymali-manager khaymali-doctor khaymali-web; do
    if [ -f "$BACKUP/$f" ]; then install -m 0755 "$BACKUP/$f" "$PREFIX/$f"; fi
  done
  return 0
}

install_from_dir() {
  backup_existing
  if ! install -m 0755 "$1/khaymali" "$PREFIX/khaymali"; then
    rollback_existing
    die "Failed to install khaymali binary."
  fi
  for f in khaymali-tui khaymali-manager khaymali-doctor khaymali-web; do
    if [ -f "$1/$f" ]; then install -m 0755 "$1/$f" "$PREFIX/$f"; fi
  done
  return 0
}

build_from_source() {
  say "Building from source (tag: $VERSION)..."
  need git || die "git is required to build from source."
  if ! need cargo; then
    say "Installing Rust toolchain (rustup, minimal profile)..."
    fetch https://sh.rustup.rs "$TMP/rustup.sh"
    sh "$TMP/rustup.sh" -y --profile minimal >/dev/null
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
  fi
  if [ "$VERSION" != latest ]; then
    git clone --depth 1 --branch "$VERSION" "https://github.com/$REPO.git" "$TMP/src"
  else
    git clone --depth 1 "https://github.com/$REPO.git" "$TMP/src"
  fi
  ( cd "$TMP/src" && { [ -f Cargo.lock ] || cargo generate-lockfile; } && cargo build --release --locked )
  mkdir -p "$TMP/out"
  cp "$TMP/src/target/release/khaymali" "$TMP/out/"
  for f in khaymali-tui khaymali-manager khaymali-doctor khaymali-web; do
    [ ! -f "$TMP/src/scripts/$f" ] || cp "$TMP/src/scripts/$f" "$TMP/out/"
  done
  install_from_dir "$TMP/out"
}

if [ -n "${KHAYMALI_BIN:-}" ]; then
  say "Installing local binary $KHAYMALI_BIN"
  mkdir -p "$TMP/out"
  cp "$KHAYMALI_BIN" "$TMP/out/khaymali"
  for f in khaymali-tui khaymali-manager khaymali-doctor khaymali-web; do
    if [ -f "$(dirname "$0")/scripts/$f" ]; then cp "$(dirname "$0")/scripts/$f" "$TMP/out/"; fi
  done
  install_from_dir "$TMP/out"
elif [ "${KHAYMALI_BUILD:-0}" = 1 ]; then
  build_from_source
else
  if [ -n "$MIRROR" ]; then base="$MIRROR"
  elif [ "$VERSION" = latest ]; then base="https://github.com/$REPO/releases/latest/download"
  else base="https://github.com/$REPO/releases/download/$VERSION"; fi
  asset="khaymali-linux-$ARCH.tar.gz"
  say "Downloading $asset ($VERSION)..."
  if fetch "$base/$asset" "$TMP/$asset"; then
    rc=0; verify_archive "$TMP/$asset" "$asset" "$base/$asset" || rc=$?
    case "$rc" in
      0) ;;
      1) die "Checksum mismatch - aborting." ;;
      *) if [ "$ALLOW_UNVERIFIED" -eq 1 ]; then
           say "No checksum published for $asset; continuing (--allow-unverified). sha256: $(sha256sum "$TMP/$asset" | awk '{print $1}')"
         else
           say "No checksum published for $asset; falling back to a --locked source build (or pass --allow-unverified)."
           build_from_source; asset=""
         fi ;;
    esac
  else
    asset=""; say "No prebuilt release found; falling back to --locked source build."; build_from_source
  fi
  if [ -n "$asset" ]; then
    if [ "$VERIFY_ATTEST" -eq 1 ]; then
      need gh || die "--verify-attestation requires GitHub CLI (gh)."
      gh attestation verify "$TMP/$asset" --repo "$REPO" || die "Attestation verification failed!"
      ok "Build provenance attestation verified"
    fi
    tar -xzf "$TMP/$asset" -C "$TMP"
    # release tarballs contain a top-level khaymali-linux-<arch>/ directory
    if [ -x "$TMP/khaymali-linux-$ARCH/khaymali" ]; then
      install_from_dir "$TMP/khaymali-linux-$ARCH"
    else
      install_from_dir "$TMP"
    fi
  fi
fi

if [ "$DO_TUNE" -eq 1 ]; then
  # Back up the ORIGINAL values once; re-running --tune must not overwrite them with tuned values.
  [ -f "$SYSCTL_FILE" ] && [ -f "$SYSCTL_BACKUP" ] || sysctl -a 2>/dev/null | grep -E '^(net\.core\.default_qdisc|net\.ipv4\.tcp_congestion_control|net\.core\.[rw]mem_max|net\.ipv4\.tcp_[rw]mem|net\.ipv4\.tcp_sack|net\.ipv4\.tcp_keepalive_|net\.ipv4\.tcp_mtu_probing|net\.ipv4\.tcp_slow_start_after_idle)' > "$SYSCTL_BACKUP" || true
  chmod 600 "$SYSCTL_BACKUP" 2>/dev/null || true
  cat > "$SYSCTL_FILE" <<'SYSCTL'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_sack = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_slow_start_after_idle = 0
SYSCTL
  modprobe tcp_bbr 2>/dev/null || true
  grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || {
    say "BBR is not available in kernel $(uname -r); keeping the current congestion control."
    sed -i '/tcp_congestion_control/d' "$SYSCTL_FILE"
  }
  sysctl --system >/dev/null 2>&1 || say "Some sysctl keys skipped (restricted kernel)."
  ok "Applied optional sysctl tuning (revert via: install.sh --revert-tune)"
fi

# always install the latest manager + TUI from main (release tarballs may carry an old/buggy menu)
for f in khaymali-manager khaymali-tui; do
  if fetch "https://raw.githubusercontent.com/$REPO/main/scripts/$f" "$TMP/$f" 2>/dev/null; then
    sed -i 's/\r$//' "$TMP/$f"
    if [ "$f" = khaymali-manager ] && ! bash -n "$TMP/$f"; then say "downloaded $f failed syntax check; keeping existing"; continue; fi
    install -m 0755 "$TMP/$f" "$PREFIX/$f" && ok "Installed: $f"
  fi
done
command -v python3 >/dev/null 2>&1 || say "python3 not found: live dashboard (khaymali-tui) needs it; the text menu works without it."
# v0.15.1: the optional helper tools (khaymali-manager / -tui / -web / -doctor) are not part of
# this release; only the core binary is required. Never fail the install because they are absent.
[ -x "$PREFIX/khaymali" ] || die "khaymali binary was not installed."
ok "Installed: $("$PREFIX/khaymali" version 2>/dev/null || echo khaymali)"
echo "  Host readiness check : khaymali doctor"
echo "  Generate keys        : khaymali keygen"
echo "  Menu                 : khaymali-manager"
echo "  Live dashboard       : khaymali-tui"
echo "  Help / all commands  : khaymali --help"
echo "  systemd unit samples : https://github.com/$REPO/tree/main/deploy/systemd"
# one-command setup: install.sh --join 'khaymali://v1?...'  (code printed by the Exit)
if [ -n "$JOIN" ]; then exec "$PREFIX/khaymali-manager" join "$JOIN" "$JOIN_MODE"; fi
if [ -n "$JOIN_BRIDGE" ]; then exec "$PREFIX/khaymali-manager" join-bridge "$JOIN_BRIDGE"; fi
if [ -t 0 ] && [ -t 1 ] && [ "${KHAYMALI_NO_MENU:-0}" != 1 ]; then
  for f in khaymali-manager; do
    if [ -x "$PREFIX/$f" ]; then exec "$PREFIX/$f"; fi
  done
fi
