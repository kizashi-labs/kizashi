-- Migration 039: per-user email notification preferences
CREATE TABLE IF NOT EXISTS notification_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email_enabled BOOL NOT NULL DEFAULT false,
    email_address TEXT,
    min_severity TEXT NOT NULL DEFAULT 'critical' CHECK (min_severity IN ('critical', 'high', 'medium', 'low')),
    notify_incidents BOOL NOT NULL DEFAULT true,
    notify_agent_offline BOOL NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id)
);
