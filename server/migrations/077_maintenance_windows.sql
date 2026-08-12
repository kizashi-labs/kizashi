CREATE TABLE IF NOT EXISTS maintenance_windows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    recurring BOOLEAN NOT NULL DEFAULT FALSE,
    recurrence_pattern TEXT DEFAULT '',  -- 'weekly:monday', 'daily', 'monthly:1'
    suppress_alerts BOOLEAN NOT NULL DEFAULT TRUE,
    suppress_notifications BOOLEAN NOT NULL DEFAULT TRUE,
    affected_agents TEXT[] DEFAULT '{}',  -- empty = all agents
    affected_groups TEXT[] DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_maintenance_windows_start ON maintenance_windows(start_time);
CREATE INDEX IF NOT EXISTS idx_maintenance_windows_enabled ON maintenance_windows(enabled);
