-- Migration 218: Unified integration configuration store
CREATE TABLE IF NOT EXISTS integration_configs (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  integ_type   TEXT NOT NULL,       -- 'elastic', 'splunk', 'sentinel', 'qradar', 'jira', 'servicenow', 'slack', 'virustotal', etc.
  config       JSONB NOT NULL DEFAULT '{}',
  enabled      BOOLEAN NOT NULL DEFAULT FALSE,
  last_tested  TIMESTAMPTZ,
  test_status  TEXT,                -- 'ok', 'error', NULL
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(integ_type)
);
