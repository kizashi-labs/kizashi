-- 150: Risk Scoring Engine
CREATE TABLE IF NOT EXISTS risk_scoring_models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    entity_type VARCHAR(50) NOT NULL CHECK (entity_type IN ('endpoint','user','network','application','cloud')),
    version VARCHAR(20) NOT NULL DEFAULT '1.0',
    factors JSONB NOT NULL DEFAULT '[]',
    weights JSONB NOT NULL DEFAULT '{}',
    thresholds JSONB NOT NULL DEFAULT '{"low":30,"medium":60,"high":80,"critical":90}',
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_id UUID REFERENCES risk_scoring_models(id) ON DELETE CASCADE,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(255) NOT NULL,
    entity_name VARCHAR(255),
    score NUMERIC(5,2) NOT NULL DEFAULT 0.0,
    previous_score NUMERIC(5,2),
    risk_level VARCHAR(20) NOT NULL DEFAULT 'low',
    contributing_factors JSONB DEFAULT '[]',
    trend VARCHAR(20) DEFAULT 'stable' CHECK (trend IN ('increasing','decreasing','stable')),
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(model_id, entity_id)
);

CREATE INDEX IF NOT EXISTS idx_risk_scoring_models_tenant ON risk_scoring_models(tenant_id);
CREATE INDEX IF NOT EXISTS idx_risk_scores_entity ON risk_scores(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_risk_scores_score ON risk_scores(score DESC);
CREATE INDEX IF NOT EXISTS idx_risk_scores_tenant ON risk_scores(tenant_id);
