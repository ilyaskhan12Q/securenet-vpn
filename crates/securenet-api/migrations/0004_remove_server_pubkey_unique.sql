-- Migration: 0004_remove_server_pubkey_unique.sql
-- Drop the UNIQUE constraint on servers(public_key) to support anycast services like Cloudflare WARP 
-- where multiple endpoints share the same public key.

ALTER TABLE servers DROP CONSTRAINT IF EXISTS servers_public_key_key;
