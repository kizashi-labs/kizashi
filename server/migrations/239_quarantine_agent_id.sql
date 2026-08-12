-- Track the agent-local quarantine identifier so the server can issue
-- restore commands keyed to the agent's local index. Without this, the
-- server only knows its own UUID for a quarantine record, which the
-- agent's FileQuarantine implementation does not recognize.

ALTER TABLE quarantined_files
    ADD COLUMN IF NOT EXISTS agent_quarantine_id TEXT;

COMMENT ON COLUMN quarantined_files.agent_quarantine_id IS
    'Agent-local identifier returned by FileQuarantine.Quarantine. Required by Restore so the agent can locate the quarantined file in its index.';
