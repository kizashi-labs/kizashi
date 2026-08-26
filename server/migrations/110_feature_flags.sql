CREATE TABLE IF NOT EXISTS feature_flags (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  enabled BOOL NOT NULL DEFAULT FALSE,
  rollout_percentage INT NOT NULL DEFAULT 0 CHECK (rollout_percentage BETWEEN 0 AND 100),
  target_roles JSONB NOT NULL DEFAULT '[]',
  target_users JSONB NOT NULL DEFAULT '[]',
  metadata JSONB NOT NULL DEFAULT '{}',
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed some default flags
INSERT INTO feature_flags (name, description, enabled, rollout_percentage) VALUES
  ('new_dashboard', '新しいダッシュボードレイアウト', false, 0),
  ('ai_threat_detection', 'AI脅威検知エンジン (ベータ)', false, 0),
  ('dark_mode_v2', 'ダークモードV2', true, 100),
  ('advanced_reporting', '高度レポート機能', false, 25)
ON CONFLICT (name) DO NOTHING;
