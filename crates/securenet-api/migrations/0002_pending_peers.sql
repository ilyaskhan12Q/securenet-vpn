-- Migration: 0002_pending_peers.sql
-- Queue for dynamically adding peers to WireGuard tunnel

CREATE TABLE IF NOT EXISTS pending_peers (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- Base64-encoded Curve25519 public key of the client.
    public_key      TEXT        NOT NULL UNIQUE,
    -- Optional pre-shared key (base64-encoded).
    pre_shared_key  TEXT,
    -- Allowed IPs (comma-separated, e.g. "10.0.0.5/32").
    allowed_ips     TEXT        NOT NULL,
    -- Persistent keepalive interval in seconds.
    persistent_keepalive INT,
    -- Status: 'pending', 'applied', 'failed'
    status          TEXT        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'failed')),
    -- Error message if status = 'failed'
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_at      TIMESTAMPTZ
);

CREATE INDEX idx_pending_peers_status ON pending_peers (status) WHERE status = 'pending';