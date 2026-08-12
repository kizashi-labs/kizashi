-- SOAR連携 (Jira / ServiceNow)
CREATE TABLE IF NOT EXISTS soar_configs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    type        TEXT NOT NULL CHECK (type IN ('jira', 'servicenow')),
    enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    config      JSONB NOT NULL DEFAULT '{}',  -- URL, credentials (暗号化済み)
    -- トリガー設定
    min_severity SMALLINT NOT NULL DEFAULT 7,
    auto_create  BOOLEAN NOT NULL DEFAULT FALSE,  -- インシデント自動起票
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- incidents テーブルに外部チケット情報を追加
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS external_ticket_id   TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS external_ticket_url  TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS external_system      TEXT;  -- 'jira' | 'servicenow'

CREATE INDEX idx_soar_configs_type ON soar_configs(type) WHERE enabled;
