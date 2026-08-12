-- Migration 206: Installer Tokens
-- Stores pre-shared tokens used to authenticate agent installation.

CREATE TABLE IF NOT EXISTS installer_tokens (
    id          VARCHAR(32) PRIMARY KEY,
    label       VARCHAR(255),
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at     TIMESTAMPTZ,
    agent_id    UUID REFERENCES agents(id) ON DELETE SET NULL,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_installer_tokens_created_at ON installer_tokens(created_at DESC);
