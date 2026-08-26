-- Migration 188: Backup manifests table
CREATE TABLE IF NOT EXISTS backup_manifests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    version TEXT,
    tables TEXT[],
    record_count JSONB DEFAULT '{}',
    size_bytes BIGINT DEFAULT 0,
    status TEXT DEFAULT 'completed',
    file_path TEXT
);
