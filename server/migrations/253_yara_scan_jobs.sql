-- 253: YARAスキャンジョブキュー
CREATE TABLE IF NOT EXISTS yara_scan_jobs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    UUID,                           -- NULL = 全エージェント対象
    scan_path   TEXT NOT NULL DEFAULT '/',       -- スキャン対象パス
    status      TEXT NOT NULL DEFAULT 'pending', -- pending | running | done | failed
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at  TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    match_count INT NOT NULL DEFAULT 0,
    error_msg   TEXT
);

CREATE INDEX IF NOT EXISTS idx_yara_scan_jobs_status    ON yara_scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_yara_scan_jobs_agent     ON yara_scan_jobs(agent_id);
CREATE INDEX IF NOT EXISTS idx_yara_scan_jobs_requested ON yara_scan_jobs(requested_at DESC);
