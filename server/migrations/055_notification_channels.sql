-- 055_notification_channels.sql
CREATE TABLE IF NOT EXISTS notification_channels (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    type        TEXT NOT NULL CHECK (type IN ('webhook_slack','webhook_teams','webhook_generic','email')),
    config      JSONB NOT NULL DEFAULT '{}',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notification_channels_enabled ON notification_channels(enabled);
