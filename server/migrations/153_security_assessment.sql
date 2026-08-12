-- 153: Security Assessment
CREATE TABLE IF NOT EXISTS security_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    assessment_type VARCHAR(50) NOT NULL DEFAULT 'gap_analysis' CHECK (assessment_type IN ('gap_analysis','maturity','risk','penetration','compliance','custom')),
    framework VARCHAR(100),
    status VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','in_progress','review','completed','archived')),
    scope TEXT,
    assessor VARCHAR(255),
    scheduled_date DATE,
    completed_date DATE,
    overall_score NUMERIC(5,2),
    findings JSONB DEFAULT '[]',
    recommendations JSONB DEFAULT '[]',
    evidence JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS assessment_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID REFERENCES security_assessments(id) ON DELETE CASCADE,
    category VARCHAR(100) NOT NULL,
    control_id VARCHAR(100),
    question TEXT NOT NULL,
    response VARCHAR(20) CHECK (response IN ('yes','no','partial','na','unknown')),
    score NUMERIC(4,2),
    weight NUMERIC(4,2) DEFAULT 1.0,
    notes TEXT,
    evidence_refs TEXT[] DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_security_assessments_tenant ON security_assessments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_assessment_items_assessment ON assessment_items(assessment_id);
