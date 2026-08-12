-- Migration 213: Feed Analytics
-- B-07: Threat feed quality metrics and analytics

CREATE TABLE IF NOT EXISTS feed_analytics (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  feed_name             TEXT NOT NULL,
  feed_type             TEXT NOT NULL DEFAULT 'osint' CHECK (feed_type IN ('commercial','osint','isac','internal')),
  provider              TEXT NOT NULL DEFAULT '',
  ioc_count             INT NOT NULL DEFAULT 0,
  freshness_score       FLOAT NOT NULL DEFAULT 0,
  accuracy_score        FLOAT NOT NULL DEFAULT 0,
  false_positive_rate   FLOAT NOT NULL DEFAULT 0,
  hit_rate              FLOAT NOT NULL DEFAULT 0,
  last_updated          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  cost_per_month        FLOAT NOT NULL DEFAULT 0,
  overall_quality_score FLOAT NOT NULL DEFAULT 0,
  status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','degraded','disabled')),
  ioc_type_breakdown    JSONB NOT NULL DEFAULT '{"ip":0,"domain":0,"hash":0,"url":0}',
  monthly_hit_rate      JSONB NOT NULL DEFAULT '[]',
  monthly_fp_rate       JSONB NOT NULL DEFAULT '[]',
  monthly_ioc_volume    JSONB NOT NULL DEFAULT '[]',
  incidents_prevented_est INT NOT NULL DEFAULT 0,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
