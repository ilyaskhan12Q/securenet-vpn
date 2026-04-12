# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | Yes       |

Only the latest release on the `main` branch receives security patches.
Older branches are unsupported.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Security issues must be reported privately so a fix can be prepared before
public disclosure.  Use one of the following channels:

1. **GitHub Security Advisories** (preferred):
   Navigate to the repository's Security tab and click
   "Report a vulnerability."

2. **Email**: security@securenet.example.com
   Encrypt your message using our PGP key (fingerprint below) if possible.

We aim to acknowledge reports within **48 hours** and to release a patch
within **14 days** for critical vulnerabilities.

## Scope

The following are in scope:

- Cryptographic protocol implementation in `securenet-core`
- Authentication bypass in `securenet-api`
- Information leakage (IP addresses, traffic metadata)
- Privilege escalation in the server daemon
- DNS or IPv6 leak in the client kill-switch

The following are **out of scope**:

- Vulnerabilities in dependencies that have already been disclosed upstream
- Denial-of-service attacks that require physical network access
- Social engineering or phishing

## Cryptographic Design

SecureNet's cryptographic choices are intentionally minimal and conservative:

| Primitive       | Algorithm              | Standard            |
|-----------------|------------------------|---------------------|
| Key exchange    | X25519 (ECDH)          | RFC 7748            |
| AEAD encryption | ChaCha20-Poly1305      | RFC 8439            |
| MAC / KDF       | HMAC-BLAKE2s           | WireGuard spec      |
| Handshake       | Noise IKpsk2           | Noise Protocol v34  |
| Password hash   | Argon2id               | RFC 9106            |
| Token signing   | HMAC-SHA256 (JWT)      | RFC 7519            |

Algorithm agility (negotiation) is deliberately avoided to eliminate
downgrade attacks.

## Key Management Recommendations

- Rotate interface private keys every 90 days.
- Enable pre-shared keys (PSK) for post-quantum resistance against
  harvest-now-decrypt-later attacks (per WireGuard PSK specification).
- Store private keys on the filesystem with mode 0600 and root ownership.
- Consider HSM or secrets-manager integration for production deployments.

## Dependency Auditing

Run `cargo audit` regularly and pin it in CI:

    cargo install cargo-audit
    cargo audit

A GitHub Actions workflow at `.github/workflows/audit.yml` runs this
automatically on every push and weekly on a schedule.
