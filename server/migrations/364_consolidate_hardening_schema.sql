-- Migration 364: consolidate the two hardening schemas onto the richer 171 one.
--
-- There were two parallel, both-dormant hardening subsystems:
--   * 171 `hardening_baselines` / `hardening_assessments` — read by the admin
--     endpoint-hardening UI + handler, but nothing ever populated them.
--   * 363 `endpoint_hardening_baselines` / `endpoint_hardening_assessments` —
--     populated by the agent hardening reporter and read by the compliance
--     scorer, but with no UI.
-- The agent's data (a benchmark + per-check pass/fail with details) maps cleanly
-- onto the richer 171 schema (baseline = policy + checks JSONB, assessment =
-- per-agent score + findings JSONB). Consolidate on 171: the report endpoint and
-- scorer now target hardening_*, the pre-built UI lights up, and the redundant
-- 363 tables are dropped.

-- Support ON CONFLICT(name) find-or-create of builtin baselines.
CREATE UNIQUE INDEX IF NOT EXISTS uq_hardening_baselines_name ON hardening_baselines(name);

-- Drop the now-redundant 363 tables (created hours earlier in #587, no durable data).
DROP TABLE IF EXISTS endpoint_hardening_assessments;
DROP TABLE IF EXISTS endpoint_hardening_baselines;
