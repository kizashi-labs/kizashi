-- Migration 382: bring four tables into the migration history
--
-- These four existed only because some code path happened to run a
-- `CREATE TABLE IF NOT EXISTS` first:
--
--   endpoint_tags        internal/api/handlers/endpoint_tag_handler.go
--   remediation_actions  internal/api/handlers/auto_remediation_handler.go
--   sandbox_submissions  internal/api/handlers/sandbox_handler.go
--   retro_rule_state     internal/scheduler/retro_rule_hunter.go
--
-- Every reader of them had to remember to call ensureTable/ensureState first,
-- and the schema of a live deployment therefore depended on which endpoint an
-- operator opened, in what order. This is not hypothetical: a test in this
-- repository failed with `relation "endpoint_tags" does not exist` because it
-- seeded rows before any handler had created the table.
--
-- It also hides them from everything that reads the migration history — the
-- schema check that prepares every SELECT in the tree can only verify a
-- statement whose table exists, so those readers were being checked against
-- whatever a previous run had left behind rather than against a declared
-- schema.
--
-- The DDL below is copied from the runtime statements verbatim. The
-- ensureTable calls stay: they are idempotent, and removing them in the same
-- change would make a rollback of this migration take the tables with it.

-- ── endpoint_tags ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS endpoint_tags (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID NOT NULL,
  tag TEXT NOT NULL,
  color TEXT NOT NULL DEFAULT '#6b7280',
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(agent_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_tags_agent ON endpoint_tags(agent_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_tags_tag ON endpoint_tags(tag);

-- ── remediation_actions ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS remediation_actions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID NOT NULL,
  action_type TEXT NOT NULL,
  target TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'dispatched',
  result TEXT NOT NULL DEFAULT '',
  executed_by UUID,
  executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── sandbox_submissions ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sandbox_submissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  file_hash TEXT NOT NULL,
  file_name TEXT NOT NULL,
  agent_id UUID,
  status TEXT NOT NULL DEFAULT 'queued',
  verdict TEXT,
  score INT,
  result JSONB,
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

-- ── retro_rule_state ─────────────────────────────────────────────────────────
--
-- One row, id = 1, holding how far back the retro rule hunter has already
-- searched. The hunter inserts it on start; seeding it here means the first
-- pass after a fresh deploy starts from a watermark that exists rather than
-- from a SELECT that finds no row and returns early.
CREATE TABLE IF NOT EXISTS retro_rule_state (
  id INT PRIMARY KEY DEFAULT 1,
  last_rule_ts TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO retro_rule_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
