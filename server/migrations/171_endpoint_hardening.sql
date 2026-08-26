-- 171: endpoint hardening baselines and checks
CREATE TABLE IF NOT EXISTS hardening_baselines (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    os_type TEXT NOT NULL DEFAULT 'windows' CHECK (os_type IN ('windows','linux','macos','all')),
    framework TEXT NOT NULL DEFAULT 'cis' CHECK (framework IN ('cis','stig','nist','custom')),
    version TEXT,
    checks JSONB NOT NULL DEFAULT '[]',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS hardening_assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    baseline_id UUID REFERENCES hardening_baselines(id) ON DELETE SET NULL,
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    passed_checks INT NOT NULL DEFAULT 0,
    failed_checks INT NOT NULL DEFAULT 0,
    skipped_checks INT NOT NULL DEFAULT 0,
    score NUMERIC(5,2) NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed')),
    findings JSONB DEFAULT '[]',
    assessed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_hardening_assessments_agent ON hardening_assessments(agent_id);
CREATE INDEX IF NOT EXISTS idx_hardening_assessments_baseline ON hardening_assessments(baseline_id);
CREATE INDEX IF NOT EXISTS idx_hardening_assessments_score ON hardening_assessments(score DESC);
CREATE INDEX IF NOT EXISTS idx_hardening_assessments_created ON hardening_assessments(created_at DESC);
