# Contributing to SecureNet VPN

Thank you for your interest in contributing.  This document describes the
development workflow, coding conventions, and review criteria.

## Table of Contents

1. [Development Environment](#development-environment)
2. [Project Structure](#project-structure)
3. [Building](#building)
4. [Testing](#testing)
5. [Code Style](#code-style)
6. [Pull Request Process](#pull-request-process)
7. [Security Contributions](#security-contributions)

---

## Development Environment

**Requirements:**

| Tool          | Minimum version | Install                                   |
|---------------|-----------------|-------------------------------------------|
| Rust          | 1.80.0          | `rustup install stable`                   |
| Docker        | 24.0            | https://docs.docker.com/get-docker/       |
| Docker Compose| 2.24            | bundled with Docker Desktop               |
| PostgreSQL    | 15 (or Docker)  |                                           |
| wireguard-tools | any           | `apt install wireguard-tools`             |

**Recommended:**

    cargo install cargo-audit cargo-deny cargo-tarpaulin cargo-watch

---

## Project Structure

```
securenet-vpn/
├── crates/
│   ├── securenet-core/     Core crypto + tunnel (library)
│   ├── securenet-server/   WireGuard data-plane daemon (binary)
│   ├── securenet-api/      REST control-plane (binary)
│   └── securenet-client/   CLI client (binary)
├── config/                 Configuration templates
├── docs/                   Architecture and deployment docs
├── scripts/                Provisioning and key-generation helpers
├── deploy/                 Prometheus / Grafana configs
└── docker-compose.yml
```

---

## Building

Build all crates in release mode:

    cargo build --release

Build a single crate:

    cargo build -p securenet-core

Run the server in development mode (debug logging):

    RUST_LOG=debug cargo run -p securenet-server -- --config config/server.toml.example

---

## Testing

Run the full test suite:

    cargo test --workspace

Run tests for a single crate with output:

    cargo test -p securenet-core -- --nocapture

Run integration tests (requires PostgreSQL via Docker):

    docker compose up -d postgres
    cargo test -p securenet-api --test integration

Check for security vulnerabilities in dependencies:

    cargo audit

Check for disallowed licences:

    cargo deny check

Generate code coverage (HTML report in `coverage/`):

    cargo tarpaulin --workspace --out Html

---

## Code Style

- Formatting: `cargo fmt --all` (enforced in CI).
- Lints: `cargo clippy --workspace -- -D warnings` (no warnings allowed).
- All public items must have doc comments (`///`).
- Error types use `thiserror`.  No `unwrap()` or `expect()` in library code.
- Secrets must be wrapped in `Zeroize`-on-drop types from `securenet-core::crypto`.
- Do not print or log secrets, private keys, or session tokens at any level.
- Use `tracing` macros for structured logging; never use `println!` in library code.

---

## Pull Request Process

1. Fork the repository and create a branch from `main`.
2. Make your changes following the code style above.
3. Add or update tests for any changed behaviour.
4. Run `cargo fmt`, `cargo clippy`, `cargo test`, and `cargo audit`.
5. Update `CHANGELOG.md` in the `Unreleased` section.
6. Open a pull request against `main`.  The PR description must explain:
   - What problem this solves and why.
   - Any cryptographic or security implications.
   - How to test the change.
7. At least one maintainer review is required before merging.
8. Squash commits before merge (CI enforces linear history).

---

## Security Contributions

Vulnerabilities must be reported privately.  See [SECURITY.md](SECURITY.md).

If your PR touches cryptographic code, AEAD, handshake logic, or key
management, it requires review by a maintainer with cryptography expertise
before merging, regardless of test coverage.
