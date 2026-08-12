-- Migration 325: asset criticality scores.
--
-- The compliance scorer (internal/scorecard) checks `COUNT(*) FROM
-- asset_criticality_scores` as an "asset inventory / criticality classification
-- exists" evidence signal, but the table never existed so the control always
-- scored 0. This table is populated server-side by the AssetCriticalityScorer
-- scheduler worker, which derives a 0-100 criticality score per agent from its
-- tags plus open critical alerts / critical & high vulnerabilities (no agent
-- changes required).
CREATE TABLE IF NOT EXISTS asset_criticality_scores (
  agent_id       UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
  score          INT NOT NULL DEFAULT 0,   -- 0-100
  factors        JSONB NOT NULL DEFAULT '{}',
  calculated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asset_criticality_score ON asset_criticality_scores(score DESC);
