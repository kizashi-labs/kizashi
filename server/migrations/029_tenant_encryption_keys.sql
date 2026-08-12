-- Per-tenant encryption key storage for AES-256-GCM envelope encryption
CREATE TABLE IF NOT EXISTS tenant_encryption_keys (
    tenant_id   TEXT PRIMARY KEY,
    encrypted_key BYTEA NOT NULL,
    key_version INT NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    rotated_at  TIMESTAMPTZ
);
