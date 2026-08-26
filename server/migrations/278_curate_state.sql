-- 278: curate lifecycle state for SigmaHQ-synced rules.
--
-- Staged curate (roadmap P1) turns synced rules on incrementally behind a field-
-- support gate. Until now the only signal a rule carried was the boolean
-- `enabled`, so we could not tell apart the reasons a synced rule is OFF:
--   * pending      — field-unsupported, enabling it is a "false green" (never on)
--   * deferred     — supported but over this round's per-category cap (next round)
--   * quarantined  — was curate-enabled but auto-disabled by the FP monitor
-- and we could not scope the FP monitor to "rules curate turned on" vs seeded /
-- custom / manually-enabled rules. These columns make the lifecycle explicit so
-- the curate API/scheduler can advance rounds, the FP monitor can auto-quarantine
-- noisy rules without touching operator-enabled ones, and the UI can show why a
-- synced rule is off. NULL = not a curate-managed rule (seeded/custom/builtin).

ALTER TABLE rules ADD COLUMN IF NOT EXISTS curate_state      TEXT;
ALTER TABLE rules ADD COLUMN IF NOT EXISTS curated_at        TIMESTAMPTZ;
ALTER TABLE rules ADD COLUMN IF NOT EXISTS quarantined_at    TIMESTAMPTZ;
ALTER TABLE rules ADD COLUMN IF NOT EXISTS quarantine_reason TEXT;

ALTER TABLE rules DROP CONSTRAINT IF EXISTS rules_curate_state_check;
ALTER TABLE rules ADD CONSTRAINT rules_curate_state_check
    CHECK (curate_state IS NULL OR curate_state = ANY (ARRAY[
        'pending'::text,
        'deferred'::text,
        'enabled'::text,
        'quarantined'::text
    ]));

-- Curate round/status queries scan synced rules; the FP monitor scans the
-- curate-enabled subset. Partial index keeps both off the full rules table.
CREATE INDEX IF NOT EXISTS idx_rules_curate
    ON rules (curate_state, enabled)
    WHERE source = 'sigmahq';

-- The FP monitor counts recent alerts per curate-enabled rule
-- (alerts.rule_id → rules.id). Without this it is a seq scan over alerts.
CREATE INDEX IF NOT EXISTS idx_alerts_rule_created
    ON alerts (rule_id, created_at)
    WHERE rule_id IS NOT NULL;
