CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    plan TEXT DEFAULT 'free',
    agent_limit INTEGER DEFAULT 10,
    user_limit INTEGER DEFAULT 5,
    enabled BOOLEAN DEFAULT true,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
INSERT INTO organizations (id, name, slug, plan, agent_limit, user_limit)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default Organization', 'default', 'enterprise', 10000, 1000)
ON CONFLICT (slug) DO NOTHING;
