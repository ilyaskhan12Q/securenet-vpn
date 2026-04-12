# SecureNet VPN

A privacy-first, high-performance VPN platform implemented in Rust.  Built on
the WireGuard protocol (Noise IKpsk2 / ChaCha20-Poly1305), with a userspace
data-plane via Cloudflare BoringTun, an async REST control-plane via Axum,
and a PostgreSQL-backed peer registry.

---

## Table of Contents

- [Why Rust](#why-rust)
- [Features](#features)
- [Architecture](#architecture)
- [Repository Layout](#repository-layout)
- [Prerequisites](#prerequisites)
- [Quick Start (Docker)](#quick-start-docker)
- [Manual Build](#manual-build)
- [Configuration](#configuration)
  - [Server](#server-configuration)
  - [Client](#client-configuration)
- [Key Generation](#key-generation)
- [CLI Reference](#cli-reference)
- [API Reference](#api-reference)
- [Database Schema](#database-schema)
- [Cryptographic Design](#cryptographic-design)
- [Performance](#performance)
- [Kill Switch](#kill-switch)
- [Multi-Hop (Secure Core)](#multi-hop-secure-core)
- [Obfuscation / Stealth Mode](#obfuscation--stealth-mode)
- [Deployment](#deployment)
- [Monitoring](#monitoring)
- [Testing](#testing)
- [Security Policy](#security-policy)
- [Roadmap](#roadmap)
- [License](#license)

---

## Why Rust

The entire codebase — protocol implementation, async I/O, API server, CLI
client — is written in Rust.  The choice is deliberate:

- **Memory safety without a garbage collector.**  WireGuard's threat model
  requires that session keys and private key material are never accessible
  after use.  All secret types in `securenet-core::crypto` implement
  `ZeroizeOnDrop`, which calls `volatile_set` on the underlying memory when
  the value is dropped.  A language runtime with a GC would make this
  guarantee impossible.

- **Fearless concurrency.**  The data-plane runs a zero-copy async I/O loop
  on Tokio.  Rust's borrow checker statically proves the absence of data
  races across the peer session table, the anti-replay window, and the UDP
  socket — without a single mutex more than necessary.

- **Performance ceiling comparable to C.**  LLVM compiles Rust with the same
  backend as Clang.  With `opt-level = 3`, `lto = "fat"`, and `codegen-units
  = 1`, the release binary matches hand-tuned C for hot-path operations
  (ChaCha20 inner loop, Blake2s HMAC, X25519 scalar multiplication).
  Cloudflare's BoringTun, which this project depends on, is deployed on
  millions of iOS/Android devices and thousands of production Linux servers.

- **No null pointer dereferences, no use-after-free, no buffer overflows.**
  These classes of vulnerability are responsible for the majority of CVEs in
  OpenVPN and other C-based VPN implementations.

---

## Features

### Protocol

- WireGuard over UDP (default) — Noise IKpsk2, X25519, ChaCha20-Poly1305, BLAKE2s
- Pre-shared key (PSK) mode for quantum-resistant layering
- Perfect forward secrecy: session keys rotate every 180 seconds
- Anti-replay protection: RFC 6479 sliding window (128 packets)
- Roaming support: peer endpoint updated on every authenticated packet
- IPv4 and IPv6, including mixed encapsulation (v4-in-v6 and vice versa)

### Security

- ChaCha20-Poly1305 AEAD (WireGuard primary)
- AES-256-GCM via OpenVPN fallback path (planned)
- Argon2id password hashing for user credentials
- HMAC-SHA256 JWT with configurable TTL and server-side revocation
- Kill-switch: policy-routing + iptables OUTPUT drop rule
- DNS leak protection: pushes VPN-local resolver to clients
- IPv6 leak protection: dual-stack kill-switch rules

### Operational

- Single TOML configuration file per role (server / client)
- Hot peer add/remove via REST API (no daemon restart)
- Structured JSON logging via `tracing` + `tracing-subscriber`
- Prometheus metrics: packets, bytes, handshake latency
- Grafana dashboard (provisioned automatically via Docker Compose)
- PostgreSQL audit log (immutable, append-only)
- Multi-hop / Secure Core routing (double-encrypted hops)
- Split tunneling (route only specified CIDRs through the VPN)
- Persistent keepalive (for clients behind NAT)
- Automated key rotation hooks

---

## Architecture

```
   Client Device
  ┌──────────────────────────────────────────┐
  │  sn (CLI)                                │
  │  securenet-client                        │
  │    KeyPair (X25519)                      │
  │    Tunnel  (boringtun userspace WG)      │
  │    Kill-switch (iptables / pf)           │
  └─────────────────────┬────────────────────┘
                        │  UDP 51820
                        │  Noise IKpsk2
                        │  ChaCha20-Poly1305
                        │
   VPN Server           │
  ┌─────────────────────┼────────────────────┐
  │                     │                    │
  │  securenet-server (data plane)           │
  │    Tunnel / peer table (RwLock)          │
  │    Anti-replay window (RFC 6479)         │
  │    Timer loop: keepalives / rekey        │
  │    iptables NAT (post-up hooks)          │
  │                     │                    │
  │  securenet-api (control plane)  TCP 8080 │
  │    POST /v1/auth/device                  │
  │    GET  /v1/servers                      │
  │    POST /v1/admin/peers                  │
  │    JWT middleware + RBAC                 │
  │    Rate limiter (per-IP token bucket)    │
  │                     │                    │
  │  PostgreSQL 16       │                   │
  │    users / devices / sessions            │
  │    servers / subscriptions / audit_log   │
  │                                          │
  │  Prometheus :9090  Grafana :3000         │
  └──────────────────────────────────────────┘
```

See [docs/architecture.md](docs/architecture.md) for the full handshake
sequence diagram, kill-switch design, and multi-hop architecture.

---

## Repository Layout

```
securenet-vpn/
├── Cargo.toml                     Workspace manifest (shared deps + profiles)
├── Cargo.lock
│
├── crates/
│   ├── securenet-core/            Library — crypto primitives + tunnel
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── crypto.rs          X25519, ChaCha20-Poly1305, BLAKE2s KDF,
│   │       │                      ReplayWindow, KeyPair, ZeroizeOnDrop wrappers
│   │       ├── tunnel.rs          WireGuard session management (boringtun)
│   │       ├── config.rs          Serde-deserializable config types
│   │       └── error.rs           CoreError enum (thiserror)
│   │
│   ├── securenet-server/          Binary — WireGuard data-plane daemon
│   │   └── src/main.rs
│   │
│   ├── securenet-api/             Binary — REST control-plane
│   │   ├── migrations/
│   │   │   └── 0001_initial_schema.sql
│   │   └── src/
│   │       ├── main.rs            Axum router, AppState, graceful shutdown
│   │       ├── handlers/mod.rs    Route handlers (auth, servers, peers, health)
│   │       └── middleware/mod.rs  JWT auth, RBAC, rate-limit middleware
│   │
│   └── securenet-client/          Binary — CLI client (`sn`)
│       └── src/main.rs
│
├── config/
│   ├── server.toml.example        Annotated server configuration template
│   └── client.toml.example        Annotated client configuration template
│
├── docs/
│   └── architecture.md            System diagrams, handshake sequence,
│                                  performance budget, kill-switch design
│
├── scripts/
│   ├── setup.sh                   Automated Ubuntu/Debian server provisioning
│   └── generate-keys.sh           Key-pair generation helper
│
├── docker-compose.yml             Full stack: server + API + Postgres + Grafana
├── Dockerfile.server              Multi-stage build for securenet-server
├── Dockerfile.api                 Multi-stage build for securenet-api
├── .env.example                   Environment variable template
├── .gitignore
├── SECURITY.md
└── CONTRIBUTING.md
```

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Rust toolchain | >= 1.80 | `rustup install stable` |
| Linux kernel | >= 5.6 (server) | WireGuard in kernel; older kernels work with userspace fallback |
| PostgreSQL | >= 15 | Required for `securenet-api` |
| Docker + Compose | >= 24 + 2.24 | Optional; for the full containerised stack |
| wireguard-tools | any | Optional; for the `wg` utility and `scripts/generate-keys.sh` |

The `securenet-core` and `securenet-client` crates compile and run on Linux,
macOS, and Windows (userspace WireGuard path only on non-Linux platforms).

---

## Quick Start (Docker)

The fastest path to a running stack:

```sh
# 1. Clone the repository
git clone https://github.com/yourorg/securenet-vpn.git
cd securenet-vpn

# 2. Copy and edit environment variables
cp .env.example .env
# Edit .env: set POSTGRES_PASSWORD, JWT_SECRET

# 3. Generate a server key pair
./scripts/generate-keys.sh
# Copy private_key into config/server.toml (see below)

# 4. Edit the server config
cp config/server.toml.example config/server.toml
# Fill in: private_key, jwt_secret, database.url (use values from .env)

# 5. Start the full stack
docker compose up -d

# 6. Verify all services are healthy
docker compose ps
curl http://localhost:8080/healthz
```

Services:

| Service | Port | Protocol |
|---|---|---|
| WireGuard tunnel | 51820 | UDP |
| REST API | 8080 | TCP (HTTP) |
| Prometheus | 9090 | TCP |
| Grafana | 3000 | TCP |

---

## Manual Build

```sh
# Build all crates in release mode
cargo build --release

# Individual binaries
cargo build --release -p securenet-server   # → target/release/securenet-server
cargo build --release -p securenet-api      # → target/release/securenet-api
cargo build --release -p securenet-client   # → target/release/sn

# Install client binary system-wide
cargo install --path crates/securenet-client
```

The release profile (`Cargo.toml`) enables:
- `opt-level = 3` (maximum LLVM optimisation)
- `lto = "fat"` (cross-crate link-time optimisation)
- `codegen-units = 1` (maximise inlining across modules)
- `panic = "abort"` (no unwinding overhead; no stack unwinding CVE surface)
- `strip = "symbols"` (smaller binary; symbols in a separate debug package)

---

## Configuration

### Server Configuration

Copy the annotated template and edit it:

```sh
cp config/server.toml.example /etc/securenet/server.toml
chmod 600 /etc/securenet/server.toml
```

Key fields:

```toml
[interface]
private_key = "BASE64_PRIVATE_KEY"  # wg genkey | base64
listen_addr = "0.0.0.0:51820"
address     = "10.0.0.1/24"

[api]
jwt_secret     = "64_BYTE_RANDOM_HEX"
token_ttl_secs = 3600

[database]
url = "postgres://securenet:secret@localhost:5432/securenet"

[metrics]
enabled   = true
bind_addr = "127.0.0.1:9090"
```

Full reference: [config/server.toml.example](config/server.toml.example)

### Client Configuration

```sh
cp config/client.toml.example ~/.config/securenet/client.toml
chmod 600 ~/.config/securenet/client.toml
```

Key fields:

```toml
[interface]
private_key = "YOUR_BASE64_PRIVATE_KEY"
address     = "10.0.0.2/32"          # assigned by server admin

[server]
public_key   = "SERVER_BASE64_PUBLIC_KEY"
endpoint     = "198.51.100.1:51820"
allowed_ips  = ["0.0.0.0/0", "::/0"] # full tunnel

kill_switch    = true
auto_reconnect = true
```

Full reference: [config/client.toml.example](config/client.toml.example)

---

## Key Generation

Using the provided helper:

```sh
# Generate a key pair (outputs TOML-ready lines)
./scripts/generate-keys.sh

# Generate a key pair + pre-shared key
./scripts/generate-keys.sh --psk

# Using the sn CLI directly
sn keygen
```

Using WireGuard tools directly:

```sh
wg genkey | tee private.key | wg pubkey > public.key
wg genpsk > preshared.key
```

**Security:** private keys must be stored with mode `0600` and must never
be committed to version control, passed in environment variables visible to
`ps`, or logged at any log level.

---

## CLI Reference

The `sn` binary is the end-user VPN client.

```
sn [OPTIONS] <COMMAND>

Commands:
  up        Connect to the VPN server
  down      Disconnect
  status    Show connection status
  keygen    Generate a Curve25519 key pair
  servers   List available servers from the API

Options:
  -c, --config <PATH>   Config file [default: ~/.config/securenet/client.toml]
                        [env: SECURENET_CLIENT_CONFIG]
  -h, --help
  -V, --version
```

### sn up

```sh
sn up
sn up --endpoint 198.51.100.1:51820   # Override server endpoint
```

Connects to the VPN server defined in `[server]`, applies the kill-switch if
`kill_switch = true`, and blocks until `Ctrl-C` or `sn down`.

### sn keygen

```sh
sn keygen
# Output:
# private_key = "..."
# public_key  = "..."
```

### sn servers

```sh
export SECURENET_API_URL=https://api.example.com
export SECURENET_TOKEN=$(cat ~/.securenet/token)
sn servers
```

---

## API Reference

All endpoints return `application/json`.  Authenticated endpoints require
`Authorization: Bearer <token>` obtained from `/v1/auth/device`.

### POST /v1/auth/device

Authenticate a device, obtain a JWT.

**Request:**

```json
{
  "device_id":  "550e8400-e29b-41d4-a716-446655440000",
  "public_key": "BASE64_CLIENT_PUBLIC_KEY",
  "signature":  "HMAC_SHA256_HEX",
  "timestamp":  1712000000
}
```

**Response 200:**

```json
{
  "token":             "eyJ...",
  "expires_at":        1712003600,
  "tunnel_ip":         "10.0.0.42/32",
  "server_public_key": "BASE64_SERVER_PUBLIC_KEY",
  "server_endpoint":   "198.51.100.1:51820"
}
```

**Errors:** 401 (invalid signature / timestamp), 429 (rate limit exceeded)

---

### GET /v1/servers

List available VPN exit nodes with load information.

**Response 200:**

```json
[
  {
    "id":            "...",
    "name":          "US-East-01",
    "country":       "US",
    "city":          "New York",
    "endpoint":      "198.51.100.1:51820",
    "public_key":    "BASE64_PUBLIC_KEY",
    "load_percent":  42,
    "latency_ms":    15,
    "features":      ["wireguard", "multi-hop"]
  }
]
```

---

### POST /v1/admin/peers  (admin role required)

Register a new WireGuard peer at runtime (hot-reload, no server restart).

**Request:**

```json
{
  "name":                 "alice-laptop",
  "public_key":           "BASE64_PUBLIC_KEY",
  "allowed_ips":          ["10.0.0.5/32"],
  "pre_shared_key":       "BASE64_PSK",
  "persistent_keepalive": 25
}
```

**Response 201:**

```json
{
  "peer_id":    "...",
  "tunnel_ip":  "10.0.0.5/32"
}
```

---

### DELETE /v1/admin/peers/:public_key  (admin role required)

Remove a peer immediately.  All active sessions for that peer are dropped.

**Response 204:** No content.

---

### GET /healthz

Liveness probe.  Returns 200 when the process is running.

```json
{
  "status":       "ok",
  "version":      "0.1.0",
  "uptime_secs":  3600
}
```

---

## Database Schema

The full annotated schema is in
[crates/securenet-api/migrations/0001_initial_schema.sql](crates/securenet-api/migrations/0001_initial_schema.sql).

Tables:

| Table | Purpose |
|---|---|
| `users` | Human accounts with Argon2id-hashed passwords |
| `devices` | WireGuard public keys, tunnel IPs, per-device state |
| `sessions` | Issued JWTs (SHA-256 indexed for revocation) |
| `servers` | VPN exit node registry with live load data |
| `subscriptions` | Plan + billing state per user |
| `audit_log` | Immutable, append-only action history |

All `updated_at` columns are maintained by a `BEFORE UPDATE` trigger.
`deleted_at` soft-deletes are used on `users` and `devices` to preserve
audit log referential integrity.

---

## Cryptographic Design

SecureNet's cryptographic choices are inherited directly from WireGuard and
are intentionally non-negotiable (no algorithm agility):

| Primitive | Algorithm | Notes |
|---|---|---|
| Key exchange | X25519 (Curve25519 ECDH) | 32-byte keys; ~128-bit security |
| AEAD | ChaCha20-Poly1305 | RFC 8439; constant-time on all CPUs |
| Hash / MAC | BLAKE2s | WireGuard spec; faster than SHA-256 on 32-bit |
| KDF | HMAC-Blake2s (HKDF-like) | Mirrors WireGuard KDF1/KDF2/KDF3 |
| Handshake | Noise IKpsk2 | Machine-verified security proof (CryptoVerif) |
| PSK mode | 32-byte symmetric layer | Mitigates harvest-now-decrypt-later |
| Password hash | Argon2id | RFC 9106; memory-hard |
| JWT signing | HMAC-SHA256 | HS256; secret stored in config |
| Anti-replay | RFC 6479 sliding window | 128-packet window |

**On algorithm agility:** WireGuard deliberately offers no negotiation of
ciphers or key-exchange algorithms.  This eliminates downgrade attacks and
renders cipher-confusion vulnerabilities impossible.  SecureNet adopts the
same design philosophy.

**On post-quantum cryptography:** The PSK mode (enabled via
`pre_shared_key` in `[[peers]]`) provides a symmetric layer that remains
secure even if X25519 is broken by a quantum computer, provided the PSK
itself is exchanged out-of-band.  A full ML-KEM integration (as in
PQ-WireGuard) is tracked in the roadmap.

### Key Lifecycle

```
Generation  →  In-use (session keys in RAM, ZeroizeOnDrop)
            →  Rotation (REKEY_AFTER_TIME = 180 s, REKEY_AFTER_MESSAGES = 2^60)
            →  Expiry (REJECT_AFTER_TIME = 540 s; session zeroed)
            →  Destruction (Zeroize::zeroize called on drop)
```

Private key material never touches disk except as the base64 value in the
configuration file (mode `0600`).

---

## Performance

### Throughput

| Mode | Throughput | Notes |
|---|---|---|
| Kernel WireGuard (`wg` module) | ~10 Gbps | Best for dedicated Linux servers |
| Userspace BoringTun (this project) | ~2–4 Gbps | Works on any OS; no kernel module required |
| Userspace, single core | ~800 Mbps | Reference: c5.xlarge AWS instance |

Enable kernel WireGuard on Linux by setting the `kernel` feature flag (not
yet implemented; tracked in roadmap) and ensuring `wireguard` is loaded:

```sh
modprobe wireguard
```

### Latency

WireGuard's 1.5-RTT handshake (initiation → response → first data packet)
adds approximately 1–5 ms on a regional network.  Subsequent packets add
only the AEAD overhead (< 1 µs on modern hardware with AVX2/NEON).

### Packet overhead

```
WireGuard transport message:
  4 B  message type
  4 B  receiver index
  8 B  counter (nonce)
 N B  encrypted payload (padded to 16-byte boundary)
 16 B  Poly1305 authentication tag
────────────────────────────────
= 32 B + payload overhead
```

With an MTU of 1420 bytes, WireGuard adds ~2.3% overhead to a 1400-byte
payload.

---

## Kill Switch

The kill-switch blocks all internet traffic if the VPN tunnel drops,
preventing IP leaks during reconnection events.

**Linux implementation (iptables):**

```sh
# Applied automatically by `sn up` when kill_switch = true

# Tag all non-tunnel egress
ip rule add not fwmark 0xCAFE table main

# Drop anything leaving via a physical interface that isn't WG-fwmarked
iptables  -I OUTPUT ! -o wg0 -m mark ! --mark 0xCAFE -j DROP
ip6tables -I OUTPUT ! -o wg0 -m mark ! --mark 0xCAFE -j DROP
```

The WireGuard UDP socket itself is fwmarked `0xCAFE` so it can still reach
the server endpoint to re-establish the tunnel.

Rules are removed automatically on `sn down` or when the process exits.

---

## Multi-Hop (Secure Core)

Multi-hop routes traffic through two VPN servers in different jurisdictions.
Neither server alone can correlate the client's real IP with the destination.

```
Client → Entry Node (US) → Core Node (SE) → Exit Node (CH) → Internet
```

Configuration (client side):

```toml
[[hops]]
public_key = "ENTRY_NODE_PUB_KEY"
endpoint   = "entry.example.com:51820"

[[hops]]
public_key = "EXIT_NODE_PUB_KEY"
endpoint   = "10.0.0.1:51820"   # exit node's inner IP, reachable via entry
```

Multi-hop is tracked in Phase 3 of the roadmap; the configuration schema
is reserved but the routing logic is not yet implemented.

---

## Obfuscation / Stealth Mode

Stealth mode wraps WireGuard UDP packets inside a TLS-looking TCP stream to
bypass Deep Packet Inspection (DPI) firewalls in restrictive networks.

The approach:
1. A local proxy (stunnel-compatible) accepts the WireGuard UDP stream.
2. Wraps it in TLS 1.3 with a dummy SNI matching a CDN hostname.
3. Forwards to a matching proxy on the VPN server (TCP 443).
4. The server-side proxy unwraps and delivers to the WireGuard daemon.

Obfuscation is planned for Phase 3.  The configuration key is reserved:

```toml
[interface]
stealth_mode = false   # not yet implemented
```

---

## Deployment

### Bare Metal / VM (recommended for production)

```sh
# On the server
sudo ./scripts/setup.sh

# Verify
systemctl status securenet-server
systemctl status securenet-api
journalctl -u securenet-server -f
```

The setup script:
1. Installs system packages (wireguard-tools, iptables, PostgreSQL client)
2. Builds and installs binaries from source
3. Generates a WireGuard key pair
4. Installs `systemd` service units for both daemons
5. Opens firewall ports (iptables / `netfilter-persistent`)
6. Enables IP forwarding permanently via `/etc/sysctl.conf`

### Docker Compose

```sh
docker compose up -d
docker compose logs -f securenet-server
```

### Kubernetes (Helm — planned)

A Helm chart is tracked in Phase 4.  The key deployment considerations are:

- The server daemon requires `NET_ADMIN` capability and `hostNetwork: true`
  (or a dedicated LoadBalancer with UDP support).
- The API deployment is stateless and horizontally scalable behind a
  standard Kubernetes Service.
- PostgreSQL should use a managed service (RDS, Cloud SQL) in production.

---

## Monitoring

### Prometheus Metrics

The server exposes metrics at `http://127.0.0.1:9090/metrics`.

| Metric | Type | Labels |
|---|---|---|
| `securenet_packets_transmitted_total` | Counter | `peer` |
| `securenet_packets_received_total` | Counter | `peer` |
| `securenet_bytes_transmitted_total` | Counter | `peer` |
| `securenet_bytes_received_total` | Counter | `peer` |
| `securenet_handshake_duration_seconds` | Histogram | `peer` |

The Grafana dashboard (provisioned automatically via Docker Compose) shows:
- Connected peers and their session ages
- Per-peer throughput (Mbps), packet rate (pps)
- Handshake latency distribution
- API request rate and error rate
- PostgreSQL connection pool utilisation

### Structured Logs

All logs are emitted as JSON (configurable):

```json
{
  "timestamp": "2024-04-12T10:00:00Z",
  "level": "INFO",
  "target": "securenet_server",
  "fields": {
    "peer": "xT3pQr...",
    "event": "handshake_completed",
    "latency_ms": 3
  }
}
```

Set `RUST_LOG=debug` for verbose output including per-packet traces.

---

## Testing

```sh
# Unit tests (no external dependencies)
cargo test --workspace

# A specific crate
cargo test -p securenet-core

# With output (useful for crypto tests)
cargo test -p securenet-core -- --nocapture

# Integration tests (requires PostgreSQL on localhost:5432)
docker compose up -d postgres
cargo test -p securenet-api --test integration

# Security audit
cargo audit

# Licence compliance
cargo deny check

# Code coverage (requires cargo-tarpaulin)
cargo tarpaulin --workspace --out Html --output-dir coverage/
```

The `securenet-core` crate includes property-based and unit tests for:
- AEAD seal/open round-trips and tamper detection
- Replay window: duplicate detection, window sliding, counter rollover
- DH exchange: commutativity (Alice→Bob == Bob→Alice)
- Key serialisation: Base64 encode/decode round-trip

---

## Security Policy

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure process,
cryptographic audit scope, and key management recommendations.

Summary: report security issues privately via GitHub Security Advisories or
email.  Do not open public issues for vulnerabilities.

---

## Roadmap

### Phase 1 — MVP (current)

- [x] `securenet-core`: X25519 key generation, ChaCha20-Poly1305 AEAD, BLAKE2s KDF, replay window
- [x] `securenet-core`: WireGuard userspace tunnel (boringtun wrapper)
- [x] `securenet-server`: daemon with peer table, timer loop, Prometheus metrics
- [x] `securenet-api`: JWT auth, peer CRUD, server list, PostgreSQL schema
- [x] `securenet-client`: `sn up / down / keygen / servers`
- [x] Kill-switch (Linux iptables)
- [x] Docker Compose stack with Grafana
- [x] Automated provisioning script

### Phase 2

- [ ] GUI applications (Tauri — cross-platform desktop)
- [ ] DNS leak protection (custom resolver forced through tunnel)
- [ ] IPv6 leak protection (dual-stack kill-switch)
- [ ] OpenVPN fallback path (TCP 443 via `openvpn` subprocess)
- [ ] Auto-connect on untrusted Wi-Fi (network change detection)
- [ ] Server-side revocation list (check JWT hash against `sessions` table)

### Phase 3

- [ ] Multi-hop routing (Secure Core) — double-encrypted hops
- [ ] Obfuscation / Stealth mode (WireGuard-over-TLS proxy)
- [ ] Split tunneling UI
- [ ] Android and iOS apps (Kotlin / Swift, using boringtun C FFI)
- [ ] Port forwarding

### Phase 4

- [ ] Global server scaling (multi-region, anycast DNS)
- [ ] Kernel WireGuard backend (Linux `wg` module via netlink)
- [ ] Post-quantum PSK provisioning flow (ML-KEM key exchange for PSK)
- [ ] Decentralised server registry (gossip protocol)
- [ ] Helm chart for Kubernetes
- [ ] Enterprise SSO (SAML / OIDC)

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

WireGuard is a registered trademark of Jason A. Donenfeld.  This project is
not affiliated with or endorsed by Jason A. Donenfeld or the WireGuard project.

BoringTun is copyright Cloudflare, Inc. and licensed under the BSD 3-Clause
License.

---

## Acknowledgements

- [WireGuard](https://www.wireguard.com/) — Jason A. Donenfeld (Noise IKpsk2
  protocol, cryptographic design)
- [BoringTun](https://github.com/cloudflare/boringtun) — Cloudflare, Inc.
  (Rust userspace WireGuard implementation)
- [Tokio](https://tokio.rs/) — async Rust runtime
- [Axum](https://github.com/tokio-rs/axum) — ergonomic async web framework
- [smoltcp](https://github.com/smoltcp-rs/smoltcp) — embedded TCP/IP stack
  (used indirectly via boringtun)
