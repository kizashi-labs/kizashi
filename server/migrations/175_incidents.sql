CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    description TEXT,
    severity INTEGER DEFAULT 5,
    status TEXT DEFAULT 'open' CHECK (status IN ('open','investigating','resolved','closed')),
    alert_ids UUID[] DEFAULT '{}',
    agent_ids UUID[] DEFAULT '{}',
    mitre_tactic TEXT,
    mitre_tech TEXT,
    correlation_rule_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC);
