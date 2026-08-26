-- Migration 208: Align api_keys table with manager.go expectations
-- Migration 048 created the table with old schema; migration 186 was skipped (IF NOT EXISTS).
-- This adds the missing columns and makes user_id nullable.

-- Add role column if missing
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'analyst';

-- Add enabled column if missing (maps from old revoked column)
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true;

-- Sync enabled from revoked if revoked column exists
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'api_keys' AND column_name = 'revoked'
  ) THEN
    UPDATE api_keys SET enabled = NOT revoked;
  END IF;
END $$;

-- Add last_used column if missing (old schema uses last_used_at)
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS last_used TIMESTAMPTZ;

-- Sync last_used from last_used_at if it exists
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'api_keys' AND column_name = 'last_used_at'
  ) THEN
    UPDATE api_keys SET last_used = last_used_at WHERE last_used IS NULL;
  END IF;
END $$;

-- Make user_id nullable (old schema had NOT NULL)
ALTER TABLE api_keys ALTER COLUMN user_id DROP NOT NULL;

-- Add indexes for new columns
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
