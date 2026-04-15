#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# scripts/generate-keys.sh
# Generate a Curve25519 key pair for WireGuard and print TOML-ready output.
#
# Usage:
#   ./scripts/generate-keys.sh [--psk]
#
#   --psk    Also generate a pre-shared key (PSK).
#
# Dependencies: wg (wireguard-tools), OR openssl >= 3.0, OR the sn CLI.
# ---------------------------------------------------------------------------

set -euo pipefail

GENERATE_PSK=false
for arg in "$@"; do
    [[ "$arg" == "--psk" ]] && GENERATE_PSK=true
done

# ---- Choose backend --------------------------------------------------------
if command -v wg &>/dev/null; then
    PRIVATE=$(wg genkey)
    PUBLIC=$(echo "${PRIVATE}" | wg pubkey)
    [[ "${GENERATE_PSK}" == "true" ]] && PSK=$(wg genpsk) || PSK=""
elif command -v openssl &>/dev/null; then
    PRIVATE=$(openssl genpkey -algorithm x25519 2>/dev/null \
        | openssl pkey -outform DER 2>/dev/null \
        | tail -c 32 \
        | base64)
    # Derive public key via DH (requires openssl 3.0+)
    PUBLIC=$(echo "${PRIVATE}" | base64 -d \
        | openssl pkey -in - -inform DER -pubout -outform DER 2>/dev/null \
        | tail -c 32 \
        | base64)
    [[ "${GENERATE_PSK}" == "true" ]] && PSK=$(openssl rand -base64 32) || PSK=""
elif command -v sn &>/dev/null; then
    PAIR=$(sn keygen)
    PRIVATE=$(echo "${PAIR}" | grep private | awk -F'"' '{print $2}')
    PUBLIC=$(echo "${PAIR}"  | grep public  | awk -F'"' '{print $2}')
    [[ "${GENERATE_PSK}" == "true" ]] && PSK=$(openssl rand -base64 32) || PSK=""
else
    echo "ERROR: Install wireguard-tools, openssl >= 3.0, or the sn CLI." >&2
    exit 1
fi

# ---- Output ----------------------------------------------------------------
echo "# ---- WireGuard Key Pair ----"
echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "#"
echo "# [interface] section (this machine):"
echo "private_key = \"${PRIVATE}\""
echo ""
echo "# [[peers]] section (the other machine):"
echo "public_key  = \"${PUBLIC}\""

if [[ "${GENERATE_PSK}" == "true" ]]; then
    echo ""
    echo "# Pre-Shared Key (add to BOTH sides of the [[peers]] block):"
    echo "pre_shared_key = \"${PSK}\""
fi

echo ""
echo "# IMPORTANT: The private_key is secret.  Never share it or commit it."
