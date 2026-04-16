#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# cloud-deploy/cloud-deploy.sh
# SecureNet VPN — Automated Cloud Deployment (Ubuntu 22.04+)
#
# Usage:
#   chmod +x cloud-deploy/cloud-deploy.sh
#   ./cloud-deploy/cloud-deploy.sh user@<public-ip> [path/to/ssh-key]
# ---------------------------------------------------------------------------

set -euo pipefail

# ---- Colours ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()   { error "$*"; exit 1; }

# ---- Args ----
REMOTE_USER_HOST="${1:-}"
[[ -n "${REMOTE_USER_HOST}" ]] || die "Usage: $0 user@host [ssh-key]"
SSH_KEY="${2:-}"
SSH_OPTS="-o StrictHostKeyChecking=no"
if [[ -n "${SSH_KEY}" ]]; then
    SSH_OPTS="${SSH_OPTS} -i ${SSH_KEY}"
fi

# ---- Local Checks ----
info "Checking local build artifacts..."
[[ -f "target/release/securenet-api" ]] || die "API binary missing. Run 'cargo build --release' first."
[[ -f "target/release/securenet-server" ]] || die "Server binary missing. Run 'cargo build --release' first."

# ---- Remote Provisioning ----
info "Connecting to ${REMOTE_USER_HOST}..."
REMOTE_CMD="ssh ${SSH_OPTS} ${REMOTE_USER_HOST}"

${REMOTE_CMD} "uname -a" || die "Failed to connect to remote host."

info "Installing Docker and dependencies on remote host..."
${REMOTE_CMD} <<'EOF'
    set -e
    sudo apt-get update -qq
    sudo apt-get install -y ca-certificates curl gnupg lsb-release iptables iproute2 jq wireguard-tools
    
    # Install Docker if not present
    if ! command -v docker &>/dev/null; then
        sudo mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
            | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt-get update -qq
        sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    fi
EOF

# ---- Upload Files ----
info "Uploading project files..."
${REMOTE_CMD} "sudo mkdir -p /opt/securenet && sudo chown \$USER:\$USER /opt/securenet"
scp ${SSH_OPTS} -r Cargo.toml docker-compose.yml Dockerfile.api Dockerfile.server config crates cloud-deploy migrations "${REMOTE_USER_HOST}:/opt/securenet/"

# ---- Setup Config ----
info "Configuring production environment..."
PUBLIC_IP=$(echo "${REMOTE_USER_HOST}" | cut -d'@' -f2)
JWT_SECRET=$(openssl rand -hex 32)
DB_PASS=$(openssl rand -hex 16)

${REMOTE_CMD} <<EOF
    cd /opt/securenet
    # Create production .env
    cat > .env <<INNER_EOF
POSTGRES_PASSWORD=${DB_PASS}
JWT_SECRET=${JWT_SECRET}
SECURENET_LISTEN_ADDR=0.0.0.0:51820
SECURENET_API_BIND=0.0.0.0:8080
SECURENET_CONFIG=/etc/securenet/server.toml
RUST_LOG=info
INNER_EOF

    # Fix server.toml
    sudo mkdir -p /etc/securenet
    sed -e "s|REPLACE_WITH_LONG_RANDOM_SECRET|${JWT_SECRET}|g" \
        -e "s|changeme_use_a_strong_random_password|${DB_PASS}|g" \
        config/server.toml > config/server.toml.prod
    sudo cp config/server.toml.prod /etc/securenet/server.toml
EOF

# ---- Start Stack ----
info "Deploying Docker stack..."
${REMOTE_CMD} "cd /opt/securenet && docker compose build && docker compose up -d"

# ---- Summary ----
info "======================================================================"
info "  SecureNet VPN successfully deployed to ${PUBLIC_IP}"
info "======================================================================"
info "  API URL      : http://${PUBLIC_IP}:8080"
info "  WireGuard    : UDP 51820"
info ""
info "  To connect, run on your local machine:"
info "  sn init --api-url http://${PUBLIC_IP}:8080"
info "  sn up"
info "======================================================================"
