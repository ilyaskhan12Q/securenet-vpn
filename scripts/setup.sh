#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# scripts/setup.sh
# SecureNet VPN — automated server provisioning
#
# Tested on: Ubuntu 22.04 LTS / Debian 12 (x86_64, aarch64)
# Run as root (or with sudo).
#
# Usage:
#   chmod +x scripts/setup.sh
#   sudo ./scripts/setup.sh
# ---------------------------------------------------------------------------

set -euo pipefail

# ---- Colours ---------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()   { error "$*"; exit 1; }

# ---- Privilege check -------------------------------------------------------
[[ $EUID -eq 0 ]] || die "This script must be run as root."

# ---- Variables (override via environment) ----------------------------------
INSTALL_DIR="${INSTALL_DIR:-/opt/securenet}"
CONFIG_DIR="${CONFIG_DIR:-/etc/securenet}"
DATA_DIR="${DATA_DIR:-/var/lib/securenet}"
LOG_DIR="${LOG_DIR:-/var/log/securenet}"
RUST_VERSION="${RUST_VERSION:-1.80.0}"
WG_PORT="${WG_PORT:-51820}"
API_PORT="${API_PORT:-8080}"

# ---- Detect OS -------------------------------------------------------------
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID}"
    OS_VERSION_ID="${VERSION_ID}"
else
    die "Cannot determine OS.  /etc/os-release not found."
fi

info "Detected OS: ${OS_ID} ${OS_VERSION_ID}"

# ---- System packages -------------------------------------------------------
info "Installing system dependencies…"
case "${OS_ID}" in
    ubuntu | debian)
        apt-get update -qq
        apt-get install -y --no-install-recommends \
            build-essential        \
            pkg-config             \
            libssl-dev             \
            curl                   \
            wget                   \
            git                    \
            iptables               \
            iptables-persistent    \
            iproute2               \
            wireguard-tools        \
            postgresql-client      \
            ca-certificates        \
            jq
        ;;
    centos | rhel | fedora | almalinux | rocky)
        dnf install -y \
            gcc make pkg-config openssl-devel \
            curl wget git iptables iproute    \
            wireguard-tools postgresql        \
            ca-certificates jq
        ;;
    *)
        warn "Unsupported distro '${OS_ID}'.  Installing packages manually may be required."
        ;;
esac

# ---- Enable IP forwarding --------------------------------------------------
info "Enabling IP forwarding…"
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1"         >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
fi

# ---- Rust toolchain --------------------------------------------------------
if ! command -v cargo &>/dev/null; then
    info "Installing Rust ${RUST_VERSION} via rustup…"
    curl --proto '=https' --tlsv1.3 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain "${RUST_VERSION}" --profile minimal
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
else
    INSTALLED=$(rustc --version | awk '{print $2}')
    info "Rust already installed: ${INSTALLED}"
fi

# ---- Build binaries --------------------------------------------------------
info "Building SecureNet binaries (this may take several minutes)…"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
cd "${REPO_ROOT}"

cargo build --release \
    -p securenet-server \
    -p securenet-api    \
    -p securenet-client

# ---- Install binaries ------------------------------------------------------
info "Installing binaries to /usr/local/bin…"
install -m 755 target/release/securenet-server /usr/local/bin/securenet-server
install -m 755 target/release/securenet-api    /usr/local/bin/securenet-api
install -m 755 target/release/sn               /usr/local/bin/sn

# ---- Directory structure ---------------------------------------------------
info "Creating directories…"
mkdir -p "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}"
chmod 700 "${CONFIG_DIR}"
chmod 755 "${DATA_DIR}" "${LOG_DIR}"

# ---- Generate key pair if not present --------------------------------------
KEY_FILE="${CONFIG_DIR}/server.key"
PUB_FILE="${CONFIG_DIR}/server.pub"

if [[ ! -f "${KEY_FILE}" ]]; then
    info "Generating WireGuard key pair…"
    wg genkey | tee "${KEY_FILE}" | wg pubkey > "${PUB_FILE}"
    chmod 600 "${KEY_FILE}"
    chmod 644 "${PUB_FILE}"
    info "Private key: ${KEY_FILE}"
    info "Public key:  $(cat "${PUB_FILE}")"
else
    info "Existing key pair found — skipping generation."
fi

PRIVATE_KEY=$(cat "${KEY_FILE}")
PUBLIC_KEY=$(cat "${PUB_FILE}")

# ---- Install config template -----------------------------------------------
if [[ ! -f "${CONFIG_DIR}/server.toml" ]]; then
    info "Installing configuration template…"
    sed \
        -e "s|REPLACE_WITH_BASE64_PRIVATE_KEY|${PRIVATE_KEY}|g" \
        "${REPO_ROOT}/config/server.toml.example" \
        > "${CONFIG_DIR}/server.toml"
    chmod 600 "${CONFIG_DIR}/server.toml"
    warn "Configuration written to ${CONFIG_DIR}/server.toml."
    warn "Edit this file before starting the service (set jwt_secret, database URL, etc.)."
fi

# ---- systemd service — securenet-server ------------------------------------
info "Installing systemd service: securenet-server…"
cat > /etc/systemd/system/securenet-server.service <<EOF
[Unit]
Description=SecureNet VPN Server Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/securenet-server --config ${CONFIG_DIR}/server.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s

# Capabilities required for TUN device and iptables.
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

# Hardening
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# ---- systemd service — securenet-api ---------------------------------------
info "Installing systemd service: securenet-api…"
cat > /etc/systemd/system/securenet-api.service <<EOF
[Unit]
Description=SecureNet VPN Control-Plane API
After=network-online.target securenet-server.service postgresql.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/securenet-api --config ${CONFIG_DIR}/server.toml
Restart=on-failure
RestartSec=5s
EnvironmentFile=-${CONFIG_DIR}/.env

# Hardening
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable securenet-server securenet-api

# ---- Firewall rules --------------------------------------------------------
info "Configuring firewall rules…"
# Allow WireGuard UDP
iptables -I INPUT  -p udp --dport "${WG_PORT}" -j ACCEPT
iptables -I OUTPUT -p udp --sport "${WG_PORT}" -j ACCEPT
# Allow API TCP (adjust if API is behind a reverse proxy)
iptables -I INPUT  -p tcp --dport "${API_PORT}" -j ACCEPT

# Persist iptables rules
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
elif command -v iptables-save &>/dev/null; then
    iptables-save > /etc/iptables/rules.v4
fi

# ---- Summary ---------------------------------------------------------------
echo ""
info "======================================================================"
info "  SecureNet VPN installation complete!"
info "======================================================================"
echo ""
echo "  Server public key : ${PUBLIC_KEY}"
echo "  WireGuard port    : UDP ${WG_PORT}"
echo "  API port          : TCP ${API_PORT}"
echo "  Config            : ${CONFIG_DIR}/server.toml"
echo ""
echo "  Next steps:"
echo "  1. Edit ${CONFIG_DIR}/server.toml"
echo "     - Set [database].url to your PostgreSQL connection string"
echo "     - Set [api].jwt_secret to a long random value"
echo "  2. Start services:"
echo "     systemctl start securenet-server"
echo "     systemctl start securenet-api"
echo "  3. Check status:"
echo "     systemctl status securenet-server"
echo "     journalctl -u securenet-server -f"
echo ""
