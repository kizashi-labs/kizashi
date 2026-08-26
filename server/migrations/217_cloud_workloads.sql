-- Migration 217: Cloud workload security tables
CREATE TABLE IF NOT EXISTS cloud_workloads (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workload_name     TEXT NOT NULL,
  type              TEXT NOT NULL DEFAULT 'vm',
  provider          TEXT NOT NULL DEFAULT 'aws',
  region            TEXT NOT NULL DEFAULT '',
  protection_status TEXT NOT NULL DEFAULT 'unprotected' CHECK (protection_status IN ('protected','unprotected','partial')),
  agent_version     TEXT,
  last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  threats_count     INT NOT NULL DEFAULT 0,
  tags              JSONB NOT NULL DEFAULT '[]',
  runtime_events    JSONB NOT NULL DEFAULT '[]',
  vulnerabilities   JSONB NOT NULL DEFAULT '[]',
  config_issues     JSONB NOT NULL DEFAULT '[]',
  account_id        TEXT NOT NULL DEFAULT '',
  instance_id       TEXT NOT NULL DEFAULT '',
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cloud_workloads_provider ON cloud_workloads(provider);
CREATE INDEX IF NOT EXISTS idx_cloud_workloads_threats ON cloud_workloads(threats_count DESC);

CREATE TABLE IF NOT EXISTS cloud_runtime_threats (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workload_id           TEXT NOT NULL DEFAULT '',
  workload_name         TEXT NOT NULL DEFAULT '',
  provider              TEXT NOT NULL DEFAULT 'aws',
  threat_type           TEXT NOT NULL DEFAULT 'suspicious_process',
  severity              TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical','high','medium','low')),
  process               TEXT NOT NULL DEFAULT '',
  cmdline               TEXT NOT NULL DEFAULT '',
  auto_blocked          BOOLEAN NOT NULL DEFAULT FALSE,
  process_tree          JSONB NOT NULL DEFAULT '[]',
  network_connections   JSONB NOT NULL DEFAULT '[]',
  recommended_response  JSONB NOT NULL DEFAULT '[]',
  timestamp             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cloud_threats_ts ON cloud_runtime_threats(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_cloud_threats_severity ON cloud_runtime_threats(severity);

CREATE TABLE IF NOT EXISTS cloud_misconfigurations (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workload_id    TEXT NOT NULL DEFAULT '',
  workload_name  TEXT NOT NULL DEFAULT '',
  provider       TEXT NOT NULL DEFAULT 'aws',
  issue_type     TEXT NOT NULL DEFAULT '',
  severity       TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical','high','medium','low')),
  description    TEXT NOT NULL DEFAULT '',
  remediation    TEXT NOT NULL DEFAULT '',
  status         TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','fixed','suppressed')),
  quick_fixable  BOOLEAN NOT NULL DEFAULT FALSE,
  region         TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cloud_misconfigs_status ON cloud_misconfigurations(status);
CREATE INDEX IF NOT EXISTS idx_cloud_misconfigs_provider ON cloud_misconfigurations(provider);
