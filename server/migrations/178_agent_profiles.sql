CREATE TABLE IF NOT EXISTS agent_config_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    os_type TEXT DEFAULT 'all',
    config JSONB NOT NULL DEFAULT '{}',
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
