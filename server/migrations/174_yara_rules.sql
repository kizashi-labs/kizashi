CREATE TABLE IF NOT EXISTS yara_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    tags TEXT[] DEFAULT '{}',
    rule_yaml TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    severity INTEGER DEFAULT 5,
    scan_count INTEGER DEFAULT 0,
    match_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_yara_rules_enabled ON yara_rules(enabled);
