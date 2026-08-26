CREATE TABLE IF NOT EXISTS memory_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID,
    hostname TEXT,
    process_name TEXT,
    pid INTEGER,
    artifact_type TEXT,
    confidence FLOAT DEFAULT 0,
    indicators TEXT[] DEFAULT '{}',
    memory_region TEXT,
    risk_score INTEGER DEFAULT 0,
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    mitre_tech TEXT,
    raw_data JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_memory_artifacts_agent ON memory_artifacts(agent_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_memory_artifacts_risk ON memory_artifacts(risk_score DESC);
