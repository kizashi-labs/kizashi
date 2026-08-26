CREATE TABLE IF NOT EXISTS compliance_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id TEXT NOT NULL,
    framework TEXT NOT NULL DEFAULT 'CIS' CHECK (framework IN ('CIS', 'NIST', 'SOC2')),
    score INT NOT NULL CHECK (score BETWEEN 0 AND 100),
    total_checks INT NOT NULL DEFAULT 0,
    passed_checks INT NOT NULL DEFAULT 0,
    details JSONB NOT NULL DEFAULT '{}',
    -- details: {"checks": [{"id": "CIS-1.1", "title": "...", "passed": true, "severity": "high"}, ...]}
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(agent_id, framework)
);
CREATE INDEX IF NOT EXISTS idx_compliance_scores_agent ON compliance_scores(agent_id);
