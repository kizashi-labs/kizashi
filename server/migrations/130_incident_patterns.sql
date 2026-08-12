CREATE TABLE IF NOT EXISTS incident_patterns (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  description    TEXT,
  pattern_type   VARCHAR(100) NOT NULL,  -- sequence, cluster, anomaly, recurring
  conditions     JSONB NOT NULL DEFAULT '[]',
  severity       VARCHAR(50) NOT NULL DEFAULT 'medium',
  confidence_threshold NUMERIC(4,2) NOT NULL DEFAULT 0.7,
  match_count    INT NOT NULL DEFAULT 0,
  is_active      BOOLEAN NOT NULL DEFAULT true,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS pattern_matches (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pattern_id     UUID NOT NULL REFERENCES incident_patterns(id) ON DELETE CASCADE,
  incident_ids   JSONB NOT NULL DEFAULT '[]',
  confidence     NUMERIC(4,2) NOT NULL,
  summary        TEXT,
  details        JSONB NOT NULL DEFAULT '{}',
  status         VARCHAR(50) NOT NULL DEFAULT 'new',  -- new, reviewed, actioned, false_positive
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pattern_matches_pattern ON pattern_matches(pattern_id, created_at DESC);
