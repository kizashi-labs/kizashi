-- 156: quarantine actions
CREATE TABLE IF NOT EXISTS quarantine_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    initiated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','released','failed')),
    reason TEXT,
    network_isolated BOOLEAN NOT NULL DEFAULT true,
    process_killed BOOLEAN NOT NULL DEFAULT false,
    files_quarantined TEXT[] DEFAULT '{}',
    started_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_quarantine_agent ON quarantine_actions(agent_id);
CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_actions(status);
CREATE INDEX IF NOT EXISTS idx_quarantine_created ON quarantine_actions(created_at DESC);
