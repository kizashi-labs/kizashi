CREATE TABLE IF NOT EXISTS live_response_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'closed', 'expired')),
    started_by TEXT NOT NULL DEFAULT 'system',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at TIMESTAMPTZ,
    last_activity TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS live_response_commands (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES live_response_sessions(id) ON DELETE CASCADE,
    input TEXT NOT NULL,
    output TEXT DEFAULT '',
    exit_code INT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'error', 'timeout')),
    submitted_by TEXT NOT NULL DEFAULT 'system',
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_lr_sessions_agent ON live_response_sessions(agent_id);
CREATE INDEX IF NOT EXISTS idx_lr_sessions_token ON live_response_sessions(token);
CREATE INDEX IF NOT EXISTS idx_lr_commands_session ON live_response_commands(session_id, submitted_at);
CREATE INDEX IF NOT EXISTS idx_lr_commands_status ON live_response_commands(session_id, status) WHERE status = 'pending';
