-- Migration 247: User Favorites
ALTER TABLE user_preferences
  ADD COLUMN IF NOT EXISTS favorites JSONB NOT NULL DEFAULT '[]';

COMMENT ON COLUMN user_preferences.favorites IS 'User-pinned page favorites (max 20), stored as [{href, label}]';
