-- alerts.tags — the column the bulk-tag endpoint has always written to.
--
-- POST /api/v1/alerts/bulk-tag issues
--   UPDATE alerts SET tags = COALESCE(tags,'[]'::jsonb) || jsonb_build_array($1::text)
-- and no migration has ever created the column. Measured against the migrated
-- schema: the statement fails with 42703 `column "tags" does not exist`, the
-- handler catches it and answers 200 {"updated": 0, "note": ...}, and the
-- console reports 「N件にタグを追加しました」 because it only checks the HTTP
-- status. Tagging alerts has therefore never worked, and never looked broken.
--
-- JSONB rather than TEXT[] because that is the shape the producer already
-- writes and the one the API serialises. The GIN index is what makes
-- `tags ? 'triage'` usable for filtering a large alerts table.

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tags JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_alerts_tags ON alerts USING GIN (tags);
