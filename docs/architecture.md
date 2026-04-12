# Architecture Overview

## System Diagram

```
   Client Device
  ┌─────────────────────────────────────────┐
  │  sn CLI                                 │
  │  ┌──────────────────────────────────┐   │
  │  │ securenet-client                 │   │
  │  │  - KeyPair (X25519)              │   │
  │  │  - Tunnel (boringtun userspace)  │   │
  │  │  - Kill-switch (iptables)        │   │
  │  └──────────────┬───────────────────┘   │
  └─────────────────┼───────────────────────┘
                    │ UDP / Noise IKpsk2
                    │ (ChaCha20-Poly1305)
                    │
   VPN Server
  ┌─────────────────┼───────────────────────┐
  │                 │                       │
  │  securenet-server (data plane)          │
  │  ┌──────────────▼───────────────────┐   │
  │  │ Tunnel (boringtun)               │   │
  │  │  - Peer table (RwLock<HashMap>)  │   │
  │  │  - Anti-replay window (RFC 6479) │   │
  │  │  - Timer loop (keepalives/rekey) │   │
  │  │  - NAT via iptables post-up      │   │
  │  └──────────────────────────────────┘   │
  │                                         │
  │  securenet-api (control plane)          │
  │  ┌──────────────────────────────────┐   │
  │  │ Axum HTTP                        │   │
  │  │  POST /v1/auth/device            │   │
  │  │  GET  /v1/servers                │   │
  │  │  POST /v1/admin/peers            │   │
  │  │  GET  /healthz                   │   │
  │  │  GET  /metrics (Prometheus)      │   │
  │  ├──────────────────────────────────┤   │
  │  │ Middleware                       │   │
  │  │  - JWT bearer verification       │   │
  │  │  - Role-based access control     │   │
  │  │  - Request tracing (OpenTelemetry│   │
  │  └───────────────┬──────────────────┘   │
  │                  │                      │
  │  ┌───────────────▼──────────────────┐   │
  │  │ PostgreSQL 16                    │   │
  │  │  users / devices / sessions      │   │
  │  │  servers / subscriptions         │   │
  │  │  audit_log                       │   │
  │  └──────────────────────────────────┘   │
  └─────────────────────────────────────────┘
                    │
                  Internet
```

---

## Crate Dependency Graph

```
securenet-core   (library — no binary)
      ▲
      │  (depends on)
      ├── securenet-server   (binary: wireguard data-plane)
      ├── securenet-api      (binary: REST control-plane)
      └── securenet-client   (binary: CLI)
```

`securenet-core` has zero inter-crate dependencies (only external crates).
This ensures the cryptographic core can be audited in isolation.

---

## WireGuard Handshake (Noise IKpsk2)

```
Initiator (client)                          Responder (server)
──────────────────                          ──────────────────

Know:  server static public key (S_r)       Know:  own static key-pair (S_r)

1. Generate ephemeral key-pair (E_i)
2. Compute:
     C  = HASH("Noise_IKpsk2_..." || S_r)
     H  = HASH(C || identifier || S_r)
     (C, H) <- MixHash(E_i.pub)
     (C)    <- MixDH(E_i.priv, S_r.pub)    ──── HandshakeInitiation ───►
     (C)    <- MixDH(S_i.priv, S_r.pub)         [unencrypted E_i.pub]
     Encrypt S_i.pub under C                     [encrypted S_i.pub  ]
     Encrypt timestamp under C                   [encrypted timestamp ]
                                                 [mac1, mac2          ]

                                            3. Verify mac1 (anti-DoS)
                                            4. Decrypt S_i.pub
                                            5. Lookup peer by S_i.pub
                                            6. Generate E_r ephemeral
                                            7. Compute session keys (T_send, T_recv)
                                            8. Mix in PSK (if configured)
                                            ◄─── HandshakeResponse ────
                                                 [unencrypted E_r.pub]
                                                 [empty AEAD payload ]
                                                 [mac1, mac2         ]

9. Derive T_send, T_recv from C
10. Send first transport packet             ──── TransportData ────────►
    (confirms handshake to responder)
```

Both peers then hold matching symmetric session keys and can exchange
encrypted IP packets.  Keys rotate every 180 seconds (REKEY_AFTER_TIME)
or after 2^60 packets (REKEY_AFTER_MESSAGES).

---

## Multi-Hop Architecture (Secure Core)

```
Client → Entry Node → Core Node → Exit Node → Internet
         (encrypts    (re-encrypts  (decrypts
          for core)    for exit)     for net)
```

The entry node sees the client's real IP but not the destination.
The exit node sees the destination but not the client's real IP.
The core node (in a different jurisdiction) ties the two together
but sees neither plaintext.

Implementation: the client constructs a double-encrypted packet addressed
to the exit node's inner IP, routed through the entry node's tunnel.

---

## Kill-Switch Design (Linux)

The client uses an `iptables` policy-routing approach:

1. Before the tunnel comes up, save the existing default route.
2. Add a routing rule: all traffic except the WireGuard UDP socket
   is marked with fwmark `0xCAFE`.
3. An iptables OUTPUT rule drops all marked packets that do NOT egress
   through the `wg0` interface.
4. On tunnel teardown (or unexpected drop), all non-VPN traffic is blocked
   until the tunnel is re-established or the user explicitly runs `sn down`.

This prevents IP leaks during reconnection, DHCP renewal, and interface
flaps.

---

## Data-Plane Performance Budget

| Component            | Target             |
|----------------------|--------------------|
| Handshake latency    | < 5 ms (LAN)       |
| Per-packet overhead  | 32 bytes (WG header) + 16 bytes (Poly1305 tag) |
| Interface MTU        | 1420 bytes (IPv6-safe) |
| Throughput (single core, userspace boringtun) | ~2 Gbps (AES-NI off) |
| Throughput (kernel WireGuard, `wg` module)    | ~10 Gbps            |
| Session re-key interval | 180 s / 2^60 pkts  |

For maximum throughput on Linux servers, prefer the kernel WireGuard module
(`ip link add wg0 type wireguard`) over the userspace BoringTun path.
The userspace path is used for macOS, Windows, iOS, and Android portability.
