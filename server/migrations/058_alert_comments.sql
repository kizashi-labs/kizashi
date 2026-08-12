-- 058_alert_comments.sql
-- Ensure alert_comments table exists with author_name column.
-- The table was created in 001_init_schema.sql with user_id/content.
-- This migration adds the author_name column if missing and adds indexes.

CREATE TABLE IF NOT EXISTS alert_comments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id    UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    author_id   UUID NOT NULL,
    author_name TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL CHECK (char_length(content) > 0),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add columns to existing table created by 001_init_schema.sql
ALTER TABLE alert_comments ADD COLUMN IF NOT EXISTS author_name TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_comments ADD COLUMN IF NOT EXISTS author_id   UUID;
ALTER TABLE alert_comments ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_alert_comments_alert_id   ON alert_comments(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_comments_author_id  ON alert_comments(author_id);
