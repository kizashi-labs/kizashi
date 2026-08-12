-- Migration 245: Remediation exclusion list persistence
--
-- The remediation engine supports an exclusion list (hostname glob patterns)
-- that prevents auto-remediation from firing on critical infrastructure hosts
-- (e.g. domain controllers, production DBs).  Previously this list lived only
-- in memory and was lost on every server restart, creating a safety risk.
--
-- This migration adds a dedicated table so exclusions survive restarts.

CREATE TABLE IF NOT EXISTS remediation_exclusions (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname_pattern TEXT    NOT NULL,
    reason       TEXT        NOT NULL DEFAULT '',
    created_by   TEXT        NOT NULL DEFAULT 'system',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS remediation_exclusions_pattern_key
    ON remediation_exclusions (hostname_pattern);
