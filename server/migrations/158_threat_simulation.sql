-- 158: threat simulation / breach and attack simulation
CREATE TABLE IF NOT EXISTS simulation_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL DEFAULT 'generic',
    mitre_tactics TEXT[] DEFAULT '{}',
    mitre_techniques TEXT[] DEFAULT '{}',
    steps JSONB NOT NULL DEFAULT '[]',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS simulation_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    template_id UUID REFERENCES simulation_templates(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    target_agents UUID[] DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','cancelled')),
    started_by UUID REFERENCES users(id) ON DELETE SET NULL,
    results JSONB DEFAULT '{}',
    detections_count INT DEFAULT 0,
    missed_count INT DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sim_runs_status ON simulation_runs(status);
CREATE INDEX IF NOT EXISTS idx_sim_runs_created ON simulation_runs(created_at DESC);
