-- Add enrichment columns to ioc_entries that are expected by ioc_enrichment_handler
-- and ioc_matcher scheduler.

ALTER TABLE ioc_entries
    ADD COLUMN IF NOT EXISTS tags        TEXT[]      NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS first_seen  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_seen   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS source_feed TEXT        NOT NULL DEFAULT '';

-- Back-fill first_seen / last_seen from existing created_at / updated_at.
UPDATE ioc_entries
   SET first_seen = created_at,
       last_seen  = updated_at
 WHERE first_seen IS NULL;

-- Index for time-range queries.
CREATE INDEX IF NOT EXISTS idx_ioc_last_seen ON ioc_entries(last_seen DESC);
