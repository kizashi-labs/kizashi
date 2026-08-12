-- Migration 045: Password Policy
-- Adds a singleton configuration table for password complexity, length and expiry rules.

CREATE TABLE IF NOT EXISTS password_policy (
    id                INT          PRIMARY KEY DEFAULT 1,  -- singleton row
    min_length        INT          NOT NULL DEFAULT 8,
    require_uppercase BOOL         NOT NULL DEFAULT false,
    require_lowercase BOOL         NOT NULL DEFAULT false,
    require_number    BOOL         NOT NULL DEFAULT true,
    require_special   BOOL         NOT NULL DEFAULT false,
    max_age_days      INT          NOT NULL DEFAULT 0,      -- 0 = no expiry
    history_count     INT          NOT NULL DEFAULT 0,      -- 0 = no history check
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Ensure the singleton row exists; do nothing if it is already there.
INSERT INTO password_policy DEFAULT VALUES ON CONFLICT DO NOTHING;
