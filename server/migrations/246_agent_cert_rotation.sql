-- Migration 246: Agent certificate auto-rotation support
--
-- Adds three columns to the agents table:
--   cert_not_after      — when the current mTLS cert expires (populated on Enroll/renew)
--   cert_renewal_token  — one-time token sent to the agent to authenticate the renewal CSR
--   cert_renewal_expires — when the one-time token expires (7 days from issue)
--
-- An index on cert_not_after lets the daily scheduler cheaply find agents whose
-- certs are expiring within the next N days without scanning the full table.

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS cert_not_after       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS cert_renewal_token   TEXT,
    ADD COLUMN IF NOT EXISTS cert_renewal_expires TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS agents_cert_not_after_idx
    ON agents (cert_not_after)
    WHERE cert_not_after IS NOT NULL;
