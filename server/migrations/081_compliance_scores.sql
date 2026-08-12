CREATE TABLE IF NOT EXISTS compliance_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework TEXT NOT NULL,   -- mitre/cis/nist/iso27001
    score NUMERIC(5,2) NOT NULL,
    details JSONB DEFAULT '{}',
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- 042 created compliance_scores with computed_at; add calculated_at as alias
ALTER TABLE compliance_scores ADD COLUMN IF NOT EXISTS calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_compliance_scores_framework ON compliance_scores(framework);
CREATE INDEX IF NOT EXISTS idx_compliance_scores_calculated ON compliance_scores(calculated_at);
