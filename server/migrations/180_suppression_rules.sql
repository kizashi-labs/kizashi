-- Migration 180: Alert suppression rules engine tables
CREATE TABLE IF NOT EXISTS suppression_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    conditions JSONB NOT NULL DEFAULT '[]',
    duration_seconds INTEGER DEFAULT 0,
    expires_at TIMESTAMPTZ,
    hit_count BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
-- 010 created suppression_rules with is_active (not enabled); add before indexing
ALTER TABLE suppression_rules ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true;

CREATE INDEX IF NOT EXISTS idx_suppression_rules_enabled ON suppression_rules(enabled);
