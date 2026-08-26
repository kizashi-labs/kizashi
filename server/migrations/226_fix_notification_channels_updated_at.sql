-- 226_fix_notification_channels_updated_at.sql
-- Add missing updated_at column and fix type constraint on notification_channels

ALTER TABLE notification_channels
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Drop the old CHECK constraint on type and replace with the current valid set
ALTER TABLE notification_channels DROP CONSTRAINT IF EXISTS notification_channels_type_check;
ALTER TABLE notification_channels
    ADD CONSTRAINT notification_channels_type_check
    CHECK (type IN ('webhook_slack', 'webhook_teams', 'webhook_generic', 'email', 'slack', 'webhook', 'teams'));

-- Backfill updated_at from created_at for existing rows
UPDATE notification_channels SET updated_at = created_at WHERE updated_at = NOW() AND created_at < NOW();
