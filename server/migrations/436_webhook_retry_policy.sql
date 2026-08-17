-- webhook_targets retry policy — the columns PUT /webhooks/:id/retry-policy has
-- always claimed to write.
--
-- Measured against the migrated schema before this migration:
--
--   webhook_targets.max_retries          exists=false
--   webhook_targets.retry_delay_seconds  exists=false
--   webhook_targets.timeout_seconds      exists=false
--   webhook_targets.system_metadata      exists=false
--
--   PUT /webhooks/<real id>/retry-policy    -> 200 {"max_retries":7,...}
--   PUT /webhooks/<unknown id>/retry-policy -> 200 {"max_retries":7,...}
--
-- The handler checked for max_retries, fell back to system_metadata, checked for
-- that too, and when neither existed returned 200 echoing the request body back.
-- The response is indistinguishable from a stored value, so the policy looked
-- saved and was discarded on every call — including for a webhook that does not
-- exist.
--
-- The defaults match what internal/notification hardcoded before it learned to
-- read these: a 10 second timeout. max_retries defaults to 3 because that is
-- what the sibling dispatcher (internal/webhooks, webhook_configs.retry_count)
-- has always used; the two webhook subsystems should not disagree about how
-- many times a SOC integration is retried.
--
-- The bounds are enforced in the database as well as the handler: a retry
-- policy is reachable from more than one code path, and an unbounded delay or
-- retry count turns a failing endpoint into an unbounded backlog of goroutines.

ALTER TABLE webhook_targets
    ADD COLUMN IF NOT EXISTS max_retries         INTEGER NOT NULL DEFAULT 3,
    ADD COLUMN IF NOT EXISTS retry_delay_seconds INTEGER NOT NULL DEFAULT 5,
    ADD COLUMN IF NOT EXISTS timeout_seconds     INTEGER NOT NULL DEFAULT 10;

ALTER TABLE webhook_targets
    DROP CONSTRAINT IF EXISTS webhook_targets_retry_policy_bounds;

ALTER TABLE webhook_targets
    ADD CONSTRAINT webhook_targets_retry_policy_bounds CHECK (
        max_retries         BETWEEN 0 AND 10
    AND retry_delay_seconds BETWEEN 0 AND 300
    AND timeout_seconds     BETWEEN 1 AND 120
    );
