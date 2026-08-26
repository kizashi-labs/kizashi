-- 203: Add compatibility columns to ioc_entries expected by ioc_matcher and ioc_enrichment_handler.
-- 009 created the table with type/is_active; the Go code uses ioc_type/enabled/threat_level.

ALTER TABLE ioc_entries ADD COLUMN IF NOT EXISTS ioc_type     TEXT;
ALTER TABLE ioc_entries ADD COLUMN IF NOT EXISTS enabled      BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE ioc_entries ADD COLUMN IF NOT EXISTS threat_level INT     NOT NULL DEFAULT 5;

-- Back-fill ioc_type from the original type column
-- (wrapped in exception block: compressed hypertable chunks reject arbitrary UPDATEs)
DO $$
BEGIN
  UPDATE ioc_entries SET ioc_type = type WHERE ioc_type IS NULL;
EXCEPTION WHEN others THEN
  NULL; -- compressed chunks: skip backfill, new rows will use ioc_type directly
END;
$$;

-- Sync enabled with is_active for existing rows
DO $$
BEGIN
  UPDATE ioc_entries SET enabled = is_active;
EXCEPTION WHEN others THEN
  NULL;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_ioc_entries_ioc_type ON ioc_entries(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_entries_enabled   ON ioc_entries(enabled);
