-- 監査ログ: 管理者アクションの追跡
CREATE TABLE IF NOT EXISTS audit_logs (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id     TEXT,
    user_email  TEXT,
    action      TEXT NOT NULL,        -- e.g. "POST /api/v1/agents/:id/isolate"
    resource_id TEXT,                 -- resolved :id param if present
    ip_address  TEXT,
    status_code INT,
    details     JSONB
);

CREATE INDEX IF NOT EXISTS audit_logs_timestamp_idx ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS audit_logs_user_idx ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS audit_logs_action_idx ON audit_logs(action);
