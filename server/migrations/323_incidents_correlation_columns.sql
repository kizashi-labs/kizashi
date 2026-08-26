-- Migration 323: add the correlation-engine columns to `incidents`.
--
-- The correlation engine (internal/correlation) both writes (persistIncident)
-- and reads (fetchIncidentsFromDB) these columns, but they never existed on the
-- live table: migration 010 created `incidents` first, so migration 175's
-- `CREATE TABLE IF NOT EXISTS incidents (... alert_ids ...)` was a no-op. As a
-- result every correlation-incident persist/fetch errored (silently caught) and
-- auto-correlated incidents were never stored or listed.
--
-- Add the columns additively; the manual incident-management columns
-- (assigned_to, external_ticket_*, …) are untouched.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS alert_ids           UUID[] DEFAULT '{}';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS agent_ids           UUID[] DEFAULT '{}';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS mitre_tactic        TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS mitre_tech          TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS correlation_rule_id TEXT;
