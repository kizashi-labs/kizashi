-- Migration 016: Add missing tables referenced by store layer
-- Tables: vulnerabilities, threat_feeds, endpoint_software, notification_history

-- ─── Vulnerabilities ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    cve_id          TEXT,
    title           TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT 'medium'
                        CHECK (severity IN ('critical','high','medium','low')),
    cvss_score      NUMERIC(4,1),
    affected_package TEXT NOT NULL DEFAULT '',
    affected_version TEXT NOT NULL DEFAULT '',
    fixed_version   TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open','mitigated','patched','accepted')),
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes           TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_agent_id  ON vulnerabilities(agent_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity  ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status    ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id    ON vulnerabilities(cve_id) WHERE cve_id IS NOT NULL;

-- ─── Threat Feeds ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS threat_feeds (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                 TEXT NOT NULL,
    url                  TEXT NOT NULL DEFAULT '',
    feed_type            TEXT NOT NULL DEFAULT 'stix',
    ioc_type             TEXT NOT NULL DEFAULT 'ip',
    description          TEXT NOT NULL DEFAULT '',
    is_active            BOOLEAN NOT NULL DEFAULT true,
    last_sync_at         TIMESTAMPTZ,
    last_count           INTEGER NOT NULL DEFAULT 0,
    sync_interval_hours  INTEGER NOT NULL DEFAULT 24,
    headers              JSONB NOT NULL DEFAULT '{}',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_feeds_is_active ON threat_feeds(is_active);

-- ─── Endpoint Software Inventory ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS endpoint_software (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id     UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    version      TEXT,
    vendor       TEXT,
    install_date TEXT,
    install_path TEXT,
    reported_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (agent_id, name, version)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_software_agent_id ON endpoint_software(agent_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_software_name     ON endpoint_software(name);

-- ─── Notification History ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS notification_history (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id   UUID REFERENCES notification_channels(id) ON DELETE SET NULL,
    channel_name TEXT,
    channel_type TEXT,
    subject      TEXT,
    body         TEXT,
    status       TEXT NOT NULL DEFAULT 'sent'
                     CHECK (status IN ('sent','failed')),
    error_msg    TEXT,
    sent_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notification_history_sent_at    ON notification_history(sent_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_history_channel_id ON notification_history(channel_id) WHERE channel_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notification_history_status     ON notification_history(status);
