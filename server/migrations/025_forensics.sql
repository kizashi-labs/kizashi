-- Migration 025: Forensics jobs table
-- Stores forensics collection tasks dispatched to agents.

CREATE TABLE IF NOT EXISTS forensics_jobs (
    id            TEXT PRIMARY KEY,
    agent_id      UUID NOT NULL,
    type          TEXT NOT NULL,               -- memory_dump | process_list | artifact_collect
    process_id    INT  NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending | running | done | failed
    artifact_data BYTEA,
    created_by    UUID,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS forensics_jobs_agent_idx  ON forensics_jobs(agent_id);
CREATE INDEX IF NOT EXISTS forensics_jobs_status_idx ON forensics_jobs(status);
