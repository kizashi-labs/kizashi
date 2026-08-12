-- 065_user_preferences.sql
CREATE TABLE IF NOT EXISTS user_preferences (
    user_id         UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    theme           TEXT NOT NULL DEFAULT 'dark' CHECK (theme IN ('dark','light','system')),
    language        TEXT NOT NULL DEFAULT 'ja' CHECK (language IN ('ja','en')),
    timezone        TEXT NOT NULL DEFAULT 'Asia/Tokyo',
    notifications   JSONB NOT NULL DEFAULT '{"email":true,"browser":true,"digest":false}',
    dashboard_prefs JSONB NOT NULL DEFAULT '{}',
    sidebar_collapsed BOOLEAN NOT NULL DEFAULT false,
    items_per_page  INTEGER NOT NULL DEFAULT 20,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
