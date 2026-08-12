-- Migration 200: Extend response_actions for new features
-- Adds details (jsonb) and status_text columns, updates CHECK constraint

ALTER TABLE response_actions ADD COLUMN IF NOT EXISTS details jsonb;
ALTER TABLE response_actions ADD COLUMN IF NOT EXISTS status_text text;

-- Update CHECK constraint to allow scan_result
ALTER TABLE response_actions DROP CONSTRAINT IF EXISTS response_actions_action_type_check;
ALTER TABLE response_actions ADD CONSTRAINT response_actions_action_type_check
  CHECK (action_type = ANY (ARRAY[
    'isolate'::text, 'unisolate'::text, 'kill_process'::text,
    'quarantine_file'::text, 'restore_file'::text,
    'collect_artifact'::text, 'scan'::text, 'scan_result'::text
  ]));
