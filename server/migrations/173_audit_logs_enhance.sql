-- 173: ensure audit_logs table is complete
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id TEXT,
    user_role TEXT,
    method TEXT NOT NULL,
    path TEXT,
    request_uri TEXT,
    status_code INT,
    source_ip TEXT,
    user_agent TEXT,
    request_body TEXT,
    duration_ms BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- 006 created audit_logs without method or created_at; add them before indexing
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS method     TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_method ON audit_logs(method);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status_code);

-- Add missing columns to existing audit_logs table if they don't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_logs' AND column_name='user_role') THEN
        ALTER TABLE audit_logs ADD COLUMN user_role TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_logs' AND column_name='path') THEN
        ALTER TABLE audit_logs ADD COLUMN path TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_logs' AND column_name='request_uri') THEN
        ALTER TABLE audit_logs ADD COLUMN request_uri TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_logs' AND column_name='source_ip') THEN
        ALTER TABLE audit_logs ADD COLUMN source_ip TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_logs' AND column_name='user_agent') THEN
        ALTER TABLE audit_logs ADD COLUMN user_agent TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_logs' AND column_name='request_body') THEN
        ALTER TABLE audit_logs ADD COLUMN request_body TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_logs' AND column_name='duration_ms') THEN
        ALTER TABLE audit_logs ADD COLUMN duration_ms BIGINT;
    END IF;
END$$;
