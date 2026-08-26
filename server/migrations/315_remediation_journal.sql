-- Migration 315: remediation_journal — the incident→file-change ledger that backs
-- the rollback (SentinelOne Storyline–equivalent) feature.
--
-- Each row is one reversible file-system change attributed to an incident/alert on
-- an endpoint. RollbackService reads these per incident and the pure planner
-- (internal/rollback.Plan) reconstructs the inverse operations that restore the
-- pre-incident state (restore pre-image content / delete attacker-created files).
-- backup_ref points at the agent-side copy-on-write pre-image backup (empty when
-- no pre-image was captured → the plan flags that path NeedsManual).
--
-- Design: docs/design/ロールバック(Storyline相当)設計.md. Idempotent.

CREATE TABLE IF NOT EXISTS remediation_journal (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    incident_id TEXT NOT NULL,
    alert_id    TEXT,
    agent_id    TEXT NOT NULL,
    path        TEXT NOT NULL,
    operation   TEXT NOT NULL CHECK (operation = ANY (ARRAY['create', 'modify', 'delete', 'rename'])),
    backup_ref  TEXT,                                  -- agent-side pre-image backup id (modify/delete)
    old_path    TEXT,                                  -- rename source
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),    -- decides the FIRST op per path (inverse basis)
    reverted    BOOLEAN NOT NULL DEFAULT FALSE,
    reverted_at TIMESTAMPTZ
);

-- Primary access path: pending (un-reverted) changes for one incident, ordered by time.
CREATE INDEX IF NOT EXISTS idx_remediation_journal_incident_pending
    ON remediation_journal (incident_id, occurred_at)
    WHERE reverted = FALSE;

CREATE INDEX IF NOT EXISTS idx_remediation_journal_agent
    ON remediation_journal (agent_id);
