-- 140: Compliance auto-remediation
CREATE TABLE IF NOT EXISTS compliance_remediation_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    framework VARCHAR(100) NOT NULL,
    control_id VARCHAR(100) NOT NULL,
    violation_pattern JSONB NOT NULL DEFAULT '{}',
    remediation_type VARCHAR(50) NOT NULL DEFAULT 'manual' CHECK (remediation_type IN ('auto','semi-auto','manual')),
    remediation_steps JSONB NOT NULL DEFAULT '[]',
    auto_approve BOOLEAN NOT NULL DEFAULT false,
    approval_required_role VARCHAR(100),
    enabled BOOLEAN NOT NULL DEFAULT true,
    execution_count INTEGER DEFAULT 0,
    success_rate NUMERIC(5,2) DEFAULT 0.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_remediation_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID REFERENCES compliance_remediation_rules(id) ON DELETE CASCADE,
    violation_id UUID,
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','running','completed','failed','rejected')),
    approved_by VARCHAR(255),
    approved_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result JSONB DEFAULT '{}',
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_compliance_rem_rules_tenant ON compliance_remediation_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_compliance_rem_exec_rule ON compliance_remediation_executions(rule_id);
