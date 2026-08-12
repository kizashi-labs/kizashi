-- Add hit_count to suppression_rules to track how many alerts each rule has suppressed.
ALTER TABLE suppression_rules
  ADD COLUMN IF NOT EXISTS hit_count INT NOT NULL DEFAULT 0;
