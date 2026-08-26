ALTER TABLE alerts ADD COLUMN IF NOT EXISTS enrichment JSONB;
CREATE INDEX IF NOT EXISTS idx_alerts_enrichment ON alerts USING GIN(enrichment) WHERE enrichment IS NOT NULL;
