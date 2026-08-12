-- 251: 保存済み検索の永続化テーブル
CREATE TABLE IF NOT EXISTS saved_searches (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     TEXT NOT NULL,
    name        TEXT NOT NULL,
    query       TEXT NOT NULL DEFAULT '',
    filters     JSONB NOT NULL DEFAULT '{}',
    page        TEXT NOT NULL DEFAULT 'alerts',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_saved_searches_user ON saved_searches(user_id);
