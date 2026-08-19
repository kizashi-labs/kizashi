-- Migration 378: why an API key was disabled.
--
-- api_keys.disabled_reason is the column APIKeyRotator writes when it retires a
-- key unused for 90 days, and no migration created it. Measured before this
-- change: the column is absent, so the rotator's existence probe fell through to
-- a second copy of the same UPDATE without the reason. Keys were disabled
-- correctly and silently.
--
-- Two paths disable a key — the rotator, and Manager.Revoke when an operator
-- does it deliberately — and neither left any record of which. A key that stops
-- working is exactly when someone has to decide whether to re-enable it or go
-- looking for a compromise, and "enabled = false" answers neither question.
--
-- Nullable with no default: NULL means still enabled, or disabled before this
-- column existed. Backfilling a guess for the second case would put a reason on
-- record that nobody established.
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS disabled_reason TEXT;

COMMENT ON COLUMN api_keys.disabled_reason IS
    'なぜ無効化されたか: revoked (手動) / inactive_90_days (ローテーター). NULL は有効、または本カラム追加以前に無効化されたもの。';
