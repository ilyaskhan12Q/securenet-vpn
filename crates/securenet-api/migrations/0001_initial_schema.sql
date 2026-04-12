-- Migration: 0001_initial_schema.sql
-- Executed by sqlx::migrate! at API startup.
-- All timestamps are stored as UTC.

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    username      TEXT        NOT NULL UNIQUE,
    -- Argon2id hash of the password.
    password_hash TEXT        NOT NULL,
    role          TEXT        NOT NULL DEFAULT 'client' CHECK (role IN ('client', 'admin')),
    email         TEXT        UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at    TIMESTAMPTZ
);

CREATE INDEX idx_users_username ON users (username) WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- Devices (one user can have multiple WireGuard devices)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS devices (
    id                  UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name                TEXT        NOT NULL,
    -- Base64-encoded Curve25519 public key.
    public_key          TEXT        NOT NULL UNIQUE,
    -- Assigned inner tunnel IPv4 address (e.g. "10.0.0.42").
    tunnel_ip           INET        UNIQUE,
    -- Optional pre-shared key (stored encrypted with pgcrypto).
    pre_shared_key_enc  BYTEA,
    last_handshake_at   TIMESTAMPTZ,
    last_seen_endpoint  TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ
);

CREATE INDEX idx_devices_user    ON devices (user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_devices_pub_key ON devices (public_key);

-- ---------------------------------------------------------------------------
-- Sessions (issued JWT records — enables server-side revocation)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id         UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id  UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    -- SHA-256 of the raw JWT for fast lookup.
    token_hash TEXT        NOT NULL UNIQUE,
    issued_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    ip_address INET
);

CREATE INDEX idx_sessions_device  ON sessions (device_id);
CREATE INDEX idx_sessions_expires ON sessions (expires_at);

-- ---------------------------------------------------------------------------
-- Servers (VPN exit nodes)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS servers (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    name         TEXT        NOT NULL,
    country_code CHAR(2)     NOT NULL,
    city         TEXT        NOT NULL,
    -- Public endpoint exposed to clients (e.g. "198.51.100.1:51820").
    endpoint     TEXT        NOT NULL,
    -- WireGuard public key of this exit node.
    public_key   TEXT        NOT NULL UNIQUE,
    -- Current load 0-100 (updated by monitoring agent).
    load_percent SMALLINT    NOT NULL DEFAULT 0 CHECK (load_percent BETWEEN 0 AND 100),
    -- Feature tags: "wireguard", "multi-hop", "obfuscated", "p2p", etc.
    features     TEXT[]      NOT NULL DEFAULT '{}',
    online       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_servers_country ON servers (country_code) WHERE online = TRUE;

-- ---------------------------------------------------------------------------
-- Subscriptions
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS subscriptions (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    plan            TEXT        NOT NULL CHECK (plan IN ('free', 'plus', 'pro', 'enterprise')),
    status          TEXT        NOT NULL CHECK (status IN ('active', 'cancelled', 'expired', 'trial')),
    -- Max simultaneous device connections allowed under this plan.
    device_limit    INT         NOT NULL DEFAULT 5,
    -- External billing reference (Stripe, etc.).
    external_ref    TEXT,
    current_period_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    current_period_end   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_subscriptions_user ON subscriptions (user_id);

-- ---------------------------------------------------------------------------
-- Audit log (immutable append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGSERIAL   PRIMARY KEY,
    actor_id   UUID        REFERENCES users (id),
    action     TEXT        NOT NULL,   -- e.g. "device.created", "session.revoked"
    target_id  UUID,
    metadata   JSONB,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_actor  ON audit_log (actor_id);
CREATE INDEX idx_audit_action ON audit_log (action);
CREATE INDEX idx_audit_ts     ON audit_log (created_at DESC);

-- ---------------------------------------------------------------------------
-- Trigger: auto-update updated_at on every mutable row
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DO $$ BEGIN
    CREATE TRIGGER trg_users_updated_at
        BEFORE UPDATE ON users
        FOR EACH ROW EXECUTE FUNCTION set_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TRIGGER trg_devices_updated_at
        BEFORE UPDATE ON devices
        FOR EACH ROW EXECUTE FUNCTION set_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TRIGGER trg_servers_updated_at
        BEFORE UPDATE ON servers
        FOR EACH ROW EXECUTE FUNCTION set_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TRIGGER trg_subscriptions_updated_at
        BEFORE UPDATE ON subscriptions
        FOR EACH ROW EXECUTE FUNCTION set_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
