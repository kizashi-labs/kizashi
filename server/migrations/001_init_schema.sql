-- EDR Platform Database Schema
-- Requires: PostgreSQL 16 + TimescaleDB extension

-- ─── Extensions ───────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pg_trgm; -- for fast text search

-- ─── Users ────────────────────────────────────────────────────

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT,                          -- bcrypt, nullable for SSO-only users
    full_name     TEXT,
    role          TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst', 'viewer')),
    mfa_secret    TEXT,                          -- TOTP secret (encrypted at rest)
    mfa_enabled   BOOLEAN DEFAULT FALSE,
    last_login    TIMESTAMPTZ,
    is_active     BOOLEAN DEFAULT TRUE,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Agent Groups ─────────────────────────────────────────────

CREATE TABLE agent_groups (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Policies ─────────────────────────────────────────────────

CREATE TABLE policies (
    id                          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                        TEXT NOT NULL,
    description                 TEXT,
    -- Collection toggles
    process_monitoring          BOOLEAN DEFAULT TRUE,
    file_monitoring             BOOLEAN DEFAULT TRUE,
    network_monitoring          BOOLEAN DEFAULT TRUE,
    dns_monitoring              BOOLEAN DEFAULT TRUE,
    registry_monitoring         BOOLEAN DEFAULT TRUE,
    auth_monitoring             BOOLEAN DEFAULT TRUE,
    yara_scan_on_exec           BOOLEAN DEFAULT TRUE,
    memory_scanning             BOOLEAN DEFAULT FALSE,
    -- Collection config
    event_batch_interval_ms     INTEGER DEFAULT 500,
    monitored_paths             TEXT[],
    excluded_paths              TEXT[],
    excluded_processes          TEXT[],
    -- Auto-response
    auto_response_enabled       BOOLEAN DEFAULT TRUE,
    auto_isolate_severity       INTEGER DEFAULT 9,
    auto_kill_severity          INTEGER DEFAULT 8,
    auto_quarantine_severity    INTEGER DEFAULT 7,
    -- AI analysis
    ai_analysis_enabled         BOOLEAN DEFAULT TRUE,
    ai_analysis_min_severity    INTEGER DEFAULT 5,
    created_at                  TIMESTAMPTZ DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ DEFAULT NOW()
);

-- Default policy
INSERT INTO policies (name, description)
VALUES ('Default', 'デフォルトポリシー - 全機能有効');

-- ─── Agents ───────────────────────────────────────────────────

CREATE TABLE agents (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname         TEXT NOT NULL,
    os_type          TEXT NOT NULL CHECK (os_type IN ('windows', 'linux', 'darwin')),
    os_version       TEXT,
    agent_version    TEXT,
    ip_addresses     INET[],
    status           TEXT NOT NULL DEFAULT 'online'
                         CHECK (status IN ('online', 'offline', 'isolated', 'error')),
    last_seen        TIMESTAMPTZ,
    enrolled_at      TIMESTAMPTZ DEFAULT NOW(),
    group_id         UUID REFERENCES agent_groups(id) ON DELETE SET NULL,
    policy_id        UUID REFERENCES policies(id) ON DELETE SET NULL,
    config_version   INTEGER DEFAULT 0,
    tls_thumbprint   TEXT,                       -- client cert fingerprint for mTLS
    tags             TEXT[],
    -- Isolation state
    isolated_at      TIMESTAMPTZ,
    isolated_reason  TEXT,
    isolated_by      TEXT,                       -- 'ai_agent' | 'auto_rule' | user_id
    -- Hardware info
    cpu_model        TEXT,
    total_memory_mb  INTEGER,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX ON agents (status);
CREATE INDEX ON agents (os_type);
CREATE INDEX ON agents (last_seen DESC);
CREATE INDEX ON agents USING GIN (tags);

-- ─── Detection Rules ──────────────────────────────────────────

CREATE TABLE rules (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name          TEXT NOT NULL,
    type          TEXT NOT NULL CHECK (type IN ('yara', 'sigma', 'behavioral')),
    platform      TEXT[] NOT NULL DEFAULT ARRAY['windows', 'linux', 'darwin'],
    severity      SMALLINT NOT NULL CHECK (severity BETWEEN 1 AND 10),
    content       TEXT NOT NULL,                -- raw rule content
    compiled      BYTEA,                        -- pre-compiled binary (YARA)
    enabled       BOOLEAN DEFAULT TRUE,
    source        TEXT DEFAULT 'custom'
                      CHECK (source IN ('community', 'custom', 'threat-intel', 'ai-generated', 'builtin')),
    mitre_tags    TEXT[],                       -- ATT&CK technique IDs
    -- Auto-response config per rule
    auto_isolate  BOOLEAN DEFAULT FALSE,
    auto_kill     BOOLEAN DEFAULT FALSE,
    auto_quarantine BOOLEAN DEFAULT FALSE,
    -- Metadata
    description   TEXT,
    ref_links     TEXT[],
    tags          TEXT[],
    false_positive_rate FLOAT DEFAULT 0.0,
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX ON rules (type, enabled);
CREATE INDEX ON rules USING GIN (platform);
CREATE INDEX ON rules USING GIN (mitre_tags);

-- ─── Alerts ───────────────────────────────────────────────────

CREATE TABLE alerts (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id          UUID REFERENCES rules(id) ON DELETE SET NULL,
    agent_id         UUID REFERENCES agents(id) ON DELETE CASCADE,
    severity         SMALLINT NOT NULL CHECK (severity BETWEEN 1 AND 10),
    status           TEXT NOT NULL DEFAULT 'open'
                         CHECK (status IN ('open', 'investigating', 'resolved',
                                           'false_positive', 'auto_resolved')),
    title            TEXT NOT NULL,
    description      TEXT,
    event_ids        UUID[],                    -- linked raw event IDs
    mitre_technique  TEXT,
    anomaly_score    FLOAT,                     -- from local ML model
    -- AI Analysis
    ai_analyzed      BOOLEAN DEFAULT FALSE,
    ai_is_threat     BOOLEAN,
    ai_severity      SMALLINT,
    ai_confidence    FLOAT,
    ai_threat_name   TEXT,
    ai_summary       TEXT,                      -- Japanese summary
    ai_report        TEXT,                      -- Full Japanese report
    ai_attack_chain  TEXT[],
    ai_mitre_tags    TEXT[],
    -- Assignment / workflow
    assigned_to      UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at      TIMESTAMPTZ,
    resolved_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    -- Timestamps
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX ON alerts (agent_id, created_at DESC);
CREATE INDEX ON alerts (status, severity DESC);
CREATE INDEX ON alerts (created_at DESC);
CREATE INDEX ON alerts (assigned_to);

-- Alert comments for investigation workflow
CREATE TABLE alert_comments (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id    UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    content     TEXT NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX ON alert_comments (alert_id, created_at);

-- ─── Response Action Log ──────────────────────────────────────

CREATE TABLE response_actions (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id     UUID REFERENCES alerts(id) ON DELETE SET NULL,
    agent_id     UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    action_type  TEXT NOT NULL
                     CHECK (action_type IN ('isolate', 'unisolate', 'kill_process',
                                            'quarantine_file', 'restore_file',
                                            'collect_artifact', 'scan')),
    target       TEXT,                          -- PID, file path, etc.
    reason       TEXT,
    executed_by  TEXT NOT NULL,                 -- 'ai_agent' | 'auto_rule' | user UUID
    success      BOOLEAN NOT NULL,
    error_msg    TEXT,
    executed_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX ON response_actions (agent_id, executed_at DESC);
CREATE INDEX ON response_actions (alert_id);

-- ─── Quarantined Files ────────────────────────────────────────

CREATE TABLE quarantined_files (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    alert_id        UUID REFERENCES alerts(id) ON DELETE SET NULL,
    original_path   TEXT NOT NULL,
    file_size       BIGINT,
    hash_md5        TEXT,
    hash_sha256     TEXT,
    quarantined_at  TIMESTAMPTZ DEFAULT NOW(),
    restored_at     TIMESTAMPTZ,
    restored_by     TEXT
);

-- ─── Notification Channels ────────────────────────────────────

CREATE TABLE notification_channels (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name          TEXT NOT NULL,
    type          TEXT NOT NULL CHECK (type IN ('email', 'slack', 'webhook', 'teams')),
    config        JSONB NOT NULL,               -- encrypted channel-specific config
    enabled       BOOLEAN DEFAULT TRUE,
    min_severity  SMALLINT DEFAULT 7,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Server Settings ──────────────────────────────────────────

CREATE TABLE settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    description TEXT,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO settings (key, value, description) VALUES
    ('claude_api_key',           '',    'Anthropic Claude API Key (encrypted)'),
    ('claude_model',             'claude-opus-4-6', 'Claude model to use for AI analysis'),
    ('ai_analysis_enabled',      'true', 'Enable AI-powered threat analysis'),
    ('auto_response_enabled',    'true', 'Enable automatic response actions'),
    ('enrollment_token',         '',    'Current enrollment token for new agents'),
    ('data_retention_days',      '90',  'Raw event retention period in days'),
    ('report_schedule',          '0 9 * * 1', 'Weekly report cron schedule');
