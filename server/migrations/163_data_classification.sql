-- 163: data classification policies and findings
CREATE TABLE IF NOT EXISTS data_classification_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    classification_level TEXT NOT NULL DEFAULT 'internal' CHECK (classification_level IN ('public','internal','confidential','restricted','top_secret')),
    patterns TEXT[] DEFAULT '{}',
    file_extensions TEXT[] DEFAULT '{}',
    actions JSONB DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS data_classification_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id UUID REFERENCES data_classification_policies(id) ON DELETE SET NULL,
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    classification_level TEXT NOT NULL,
    match_count INT NOT NULL DEFAULT 1,
    file_size BIGINT,
    last_modified TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','reviewed','resolved','false_positive')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dc_findings_agent ON data_classification_findings(agent_id);
CREATE INDEX IF NOT EXISTS idx_dc_findings_level ON data_classification_findings(classification_level);
CREATE INDEX IF NOT EXISTS idx_dc_findings_status ON data_classification_findings(status);
