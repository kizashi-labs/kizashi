CREATE TABLE IF NOT EXISTS license_info (
    id INTEGER PRIMARY KEY DEFAULT 1,
    organization_name TEXT DEFAULT 'Default Organization',
    plan TEXT DEFAULT 'enterprise',
    agent_limit INTEGER DEFAULT 10000,
    user_limit INTEGER DEFAULT 1000,
    features TEXT[] DEFAULT ARRAY['basic_detection','alerts','threat_hunting','reports','ml_detection','yara','siem_integration','threat_intel','multi_tenant','ai_assistant','compliance','api_access'],
    valid_from TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '10 years',
    license_key TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
INSERT INTO license_info(id) VALUES(1) ON CONFLICT DO NOTHING;
