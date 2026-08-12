-- 155: Security Training Management
CREATE TABLE IF NOT EXISTS training_programs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    program_type VARCHAR(50) NOT NULL DEFAULT 'awareness' CHECK (program_type IN ('awareness','technical','compliance','leadership','phishing')),
    target_audience TEXT[] DEFAULT '{}',
    required_for_roles TEXT[] DEFAULT '{}',
    duration_hours NUMERIC(5,2),
    passing_score INTEGER DEFAULT 80,
    certification_valid_days INTEGER DEFAULT 365,
    modules JSONB DEFAULT '[]',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS training_enrollments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    program_id UUID REFERENCES training_programs(id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL,
    username VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'enrolled' CHECK (status IN ('enrolled','in_progress','completed','failed','expired')),
    score NUMERIC(5,2),
    progress_pct INTEGER DEFAULT 0,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    attempts INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_training_programs_tenant ON training_programs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_training_enrollments_program ON training_enrollments(program_id);
CREATE INDEX IF NOT EXISTS idx_training_enrollments_user ON training_enrollments(user_id);
