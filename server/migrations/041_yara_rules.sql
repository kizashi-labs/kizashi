CREATE TABLE IF NOT EXISTS yara_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    content TEXT NOT NULL,  -- the raw YARA rule text
    tags TEXT[] NOT NULL DEFAULT '{}',
    enabled BOOL NOT NULL DEFAULT true,
    severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    last_match_count INT NOT NULL DEFAULT 0,
    last_matched_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
