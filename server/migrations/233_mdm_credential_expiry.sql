-- Migration 233: persist per-integration credential expiry so the scheduler
-- can raise alerts independently of whether an operator is clicking Sync.
--
-- Before this migration CredentialExpiry was returned only in the /sync JSON
-- response, so the platform had no durable record to scan against. After
-- this migration every Sync call writes the expiry on success, and the
-- MDMCredentialExpiryChecker scheduler reads it once a day.

ALTER TABLE mdm_integrations
  ADD COLUMN IF NOT EXISTS credential_expiry TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_mdm_integrations_credential_expiry
  ON mdm_integrations (credential_expiry)
  WHERE credential_expiry IS NOT NULL;
