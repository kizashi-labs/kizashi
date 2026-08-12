-- Migration 362: endpoint disk-encryption status.
--
-- The compliance scorer (internal/scorecard) checks `COUNT(*) FROM
-- endpoint_encryption` for control PR.DS-1 ("Data-at-rest is protected"), but
-- the table never existed so the control was stuck at the "no data" partial
-- score. This table is populated by the agent's encryption reporter, which
-- probes disk-encryption state (LUKS on Linux, BitLocker on Windows, FileVault
-- on macOS) and POSTs it to /api/v1/agents/:id/encryption/report. One row per
-- agent (upsert), so the scorer counts endpoints with encryption enabled.
CREATE TABLE IF NOT EXISTS endpoint_encryption (
  agent_id    UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
  encrypted   BOOLEAN NOT NULL DEFAULT FALSE,
  method      TEXT,          -- LUKS / BitLocker / FileVault
  details     TEXT,          -- device list or human-readable status
  reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_endpoint_encryption_encrypted ON endpoint_encryption(encrypted);
