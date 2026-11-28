#!/usr/bin/env bash
#
# Khaymali Manager Companion — pure Rust installer
#
set -euo pipefail

INSTALL_DIR="/opt/khaymali-manager"
BIN_MGR="/usr/local/bin/khaymali-manager"
BIN_LIGHT="/usr/local/bin/khaymali-light"
BIN_TUNNEL="/usr/local/bin/tunnel"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: run as root (sudo)."
    exit 1
fi

have() { command -v "$1" >/dev/null 2>&1; }

pkg_install() {
    if have apt-get; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
    elif have dnf; then
        dnf install -y -q "$@"
    elif have yum; then
        yum install -y -q "$@"
    fi
}

echo "==> Prerequisites"
have cargo || pkg_install cargo rustc build-essential pkg-config || {
    echo "Install Rust via https://rustup.rs and re-run."
    exit 1
}
have ip || pkg_install iproute2 || true

echo "==> Building release binaries"
cd "${SCRIPT_DIR}"
cargo build --release --bins

echo "==> Installing into ${INSTALL_DIR}"
rm -rf "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
cp -a "${SCRIPT_DIR}/." "${INSTALL_DIR}/"
rm -rf "${INSTALL_DIR}/target" 2>/dev/null || true

install -m 0755 "${SCRIPT_DIR}/target/release/khaymali-manager" "${BIN_MGR}"
install -m 0755 "${SCRIPT_DIR}/target/release/khaymali-light" "${BIN_LIGHT}"

cat > "${BIN_TUNNEL}" <<WRAPPER
#!/usr/bin/env bash
exec "${BIN_MGR}" "\$@"
WRAPPER
chmod +x "${BIN_TUNNEL}"

echo
echo "Done (pure Rust)."
echo "  Manager:  sudo tunnel   or   sudo khaymali-manager"
echo "  Light:    khaymali-light --config /etc/khaymali-light/config.json"
