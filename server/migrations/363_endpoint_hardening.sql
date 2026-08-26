-- Migration 363: endpoint hardening baseline assessments.
--
-- The compliance scorer (internal/scorecard) checks `COUNT(*) FROM
-- endpoint_hardening_baselines` and the pass-rate over
-- `endpoint_hardening_assessments` for control PR.IP-1 ("A baseline
-- configuration of IT systems is created and maintained"), but neither table
-- existed so the control was stuck at the non_compliant score.
--
-- These are populated by the agent's hardening reporter, which runs a set of
-- lightweight CIS-style configuration checks (SSH policy, firewall, password
-- aging, world-writable files, …) and POSTs the results to
-- /api/v1/agents/:id/hardening/report. One baseline row per (agent, benchmark)
-- with roll-up counts, plus one assessment row per individual check.
CREATE TABLE IF NOT EXISTS endpoint_hardening_baselines (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id   UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  benchmark  TEXT NOT NULL,          -- e.g. "CIS Linux (agent builtin) v1"
  passed     INT  NOT NULL DEFAULT 0,
  failed     INT  NOT NULL DEFAULT 0,
  total      INT  NOT NULL DEFAULT 0,
  scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (agent_id, benchmark)
);

CREATE TABLE IF NOT EXISTS endpoint_hardening_assessments (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  baseline_id UUID REFERENCES endpoint_hardening_baselines(id) ON DELETE CASCADE,
  check_id    TEXT NOT NULL,         -- stable identifier, e.g. "ssh_root_login"
  title       TEXT,
  passed      BOOLEAN NOT NULL,
  details     TEXT,
  scanned_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hardening_assess_agent   ON endpoint_hardening_assessments(agent_id);
CREATE INDEX IF NOT EXISTS idx_hardening_assess_passed  ON endpoint_hardening_assessments(passed);
CREATE INDEX IF NOT EXISTS idx_hardening_baseline_agent ON endpoint_hardening_baselines(agent_id);
