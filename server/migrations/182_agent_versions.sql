-- Migration 182: Agent version distribution and auto-update policy
CREATE TABLE IF NOT EXISTS agent_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version TEXT NOT NULL,
    platform TEXT NOT NULL,
    arch TEXT DEFAULT 'amd64',
    download_url TEXT,
    checksum TEXT,
    release_notes TEXT,
    is_latest BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_versions_latest ON agent_versions(platform, arch) WHERE is_latest = true;

CREATE TABLE IF NOT EXISTS update_policy (
    id INTEGER PRIMARY KEY DEFAULT 1,
    auto_update BOOLEAN DEFAULT false,
    target_version TEXT,
    rollout_percent INTEGER DEFAULT 100,
    maintenance_window TEXT DEFAULT '0 2 * * 0',
    allow_downgrade BOOLEAN DEFAULT false,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
INSERT INTO update_policy(id) VALUES(1) ON CONFLICT DO NOTHING;
