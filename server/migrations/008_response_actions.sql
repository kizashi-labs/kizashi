-- Response actions log: records every agent action (isolate, unisolate, scan, kill_process, quarantine)
CREATE TABLE IF NOT EXISTS response_actions (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    agent_id     TEXT NOT NULL,
    action_type  TEXT NOT NULL,          -- isolate | unisolate | scan | kill_process | quarantine
    status       TEXT NOT NULL DEFAULT 'success',  -- success | failed | pending
    triggered_by TEXT,                   -- user_id
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    error        TEXT,
    details      JSONB
);

CREATE INDEX IF NOT EXISTS idx_response_actions_agent_id ON response_actions(agent_id);
CREATE INDEX IF NOT EXISTS idx_response_actions_executed_at ON response_actions(executed_at DESC);
