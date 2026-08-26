-- Migration 040: per-user dashboard widget preferences
CREATE TABLE IF NOT EXISTS dashboard_preferences (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    widgets JSONB NOT NULL DEFAULT '[]',
    -- widgets: [{"id": "endpoint-status", "visible": true, "order": 0}, ...]
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id)
);
