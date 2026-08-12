-- 059_live_response_commands.sql
CREATE TABLE IF NOT EXISTS live_response_commands (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id     UUID NOT NULL,
    session_id   UUID,
    command_type TEXT NOT NULL CHECK (command_type IN ('shell','file_list','file_get','file_put','process_list','process_kill','network_list','reg_query')),
    command      TEXT NOT NULL,
    args         JSONB NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','timeout')),
    output       TEXT,
    exit_code    INTEGER,
    created_by   UUID,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    timeout_at   TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '5 minutes'
);

-- Add columns that 017_live_response.sql did not include
ALTER TABLE live_response_commands ADD COLUMN IF NOT EXISTS agent_id     UUID;
ALTER TABLE live_response_commands ADD COLUMN IF NOT EXISTS command_type TEXT;
ALTER TABLE live_response_commands ADD COLUMN IF NOT EXISTS command      TEXT;
ALTER TABLE live_response_commands ADD COLUMN IF NOT EXISTS args         JSONB NOT NULL DEFAULT '{}';
ALTER TABLE live_response_commands ADD COLUMN IF NOT EXISTS created_by   UUID;
ALTER TABLE live_response_commands ADD COLUMN IF NOT EXISTS created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE live_response_commands ADD COLUMN IF NOT EXISTS started_at   TIMESTAMPTZ;
ALTER TABLE live_response_commands ADD COLUMN IF NOT EXISTS timeout_at   TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '5 minutes';

CREATE INDEX IF NOT EXISTS idx_lr_commands_agent_status ON live_response_commands(agent_id, status);
CREATE INDEX IF NOT EXISTS idx_lr_commands_session ON live_response_commands(session_id);
CREATE INDEX IF NOT EXISTS idx_lr_commands_created ON live_response_commands(created_at DESC);
