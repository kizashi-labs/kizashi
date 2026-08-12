-- 136: Forensics automation
CREATE TABLE IF NOT EXISTS forensics_automation_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    trigger_type VARCHAR(50) NOT NULL CHECK (trigger_type IN ('manual','alert','schedule','incident')),
    trigger_condition JSONB DEFAULT '{}',
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','cancelled')),
    priority VARCHAR(20) NOT NULL DEFAULT 'medium' CHECK (priority IN ('low','medium','high','critical')),
    target_assets JSONB DEFAULT '[]',
    collection_modules JSONB DEFAULT '[]',
    findings JSONB DEFAULT '[]',
    evidence_count INTEGER DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    assigned_analyst VARCHAR(255),
    chain_of_custody JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS forensics_evidence_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID REFERENCES forensics_automation_jobs(id) ON DELETE CASCADE,
    evidence_type VARCHAR(50) NOT NULL,
    source_path TEXT,
    hash_md5 VARCHAR(32),
    hash_sha256 VARCHAR(64),
    file_size BIGINT,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}',
    tags TEXT[] DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_forensics_jobs_status ON forensics_automation_jobs(status);
CREATE INDEX IF NOT EXISTS idx_forensics_jobs_tenant ON forensics_automation_jobs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_forensics_evidence_job ON forensics_evidence_items(job_id);
