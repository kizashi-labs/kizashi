CREATE TABLE IF NOT EXISTS packet_captures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending/running/completed/failed/cancelled
    filter TEXT DEFAULT '',
    interface_name TEXT DEFAULT '',
    max_packets INTEGER DEFAULT 10000,
    max_size_mb INTEGER DEFAULT 100,
    duration_seconds INTEGER DEFAULT 300,
    file_path TEXT,
    file_size_bytes BIGINT,
    packet_count INTEGER,
    error_msg TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID
);
CREATE INDEX IF NOT EXISTS idx_packet_captures_agent_id ON packet_captures(agent_id);
CREATE INDEX IF NOT EXISTS idx_packet_captures_status ON packet_captures(status);
