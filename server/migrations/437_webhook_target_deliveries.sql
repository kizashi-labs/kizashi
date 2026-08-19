-- Migration 376: delivery history for webhook_targets.
--
-- GET /api/v1/webhooks/:id/deliveries read webhook_deliveries, selecting
-- event_type, attempt and created_at. Measured against the migrated schema:
--
--   webhook_deliveries.event          exists=true
--   webhook_deliveries.event_type     exists=false
--   webhook_deliveries.attempt        exists=false
--   webhook_deliveries.attempted_at   exists=true
--   webhook_deliveries.created_at     exists=false
--   webhook_deliveries.webhook_id references: webhook_configs
--
--   GET /webhooks/<real webhook_targets id>/deliveries -> 500
--
-- Three of the selected columns do not exist, so every call was 42703 -> 500.
-- Renaming them would not have been enough: webhook_deliveries belongs to the
-- other webhook subsystem (internal/webhooks, keyed to webhook_configs), and
-- the :id on this route is a webhook_targets id. A corrected query against
-- that table would have matched no row for any id this endpoint can be given,
-- turning a 500 into an empty 200 that looks like "no deliveries yet".
--
-- Nothing recorded per-attempt history for webhook_targets at all —
-- internal/notification only stamped last_status on the target itself. This
-- table is that missing history, and it is what makes the retry policy added
-- in migration 375 observable: an operator can see 502, 502, 200 rather than
-- guessing from a single final status.
CREATE TABLE IF NOT EXISTS webhook_target_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id UUID NOT NULL REFERENCES webhook_targets(id) ON DELETE CASCADE,
    event TEXT NOT NULL DEFAULT '',
    -- 1-based, so the first attempt of a delivery reads as attempt 1.
    attempt INTEGER NOT NULL DEFAULT 1,
    -- 0 when nobody answered (transport error / timeout); error carries why.
    status_code INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    -- Whether this attempt was accepted. A delivery that succeeded on its
    -- third attempt leaves two rows false and one true.
    delivered BOOLEAN NOT NULL DEFAULT false,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Serves both the read (most recent first, per webhook) and the retention
-- prune, which walks the same order.
CREATE INDEX IF NOT EXISTS idx_webhook_target_deliveries_webhook
    ON webhook_target_deliveries(webhook_id, attempted_at DESC);
