-- Migration 270: add alerts.source so the batch behavioral detectors can
-- attribute an alert's origin.
--
-- The insider-threat and network-anomaly schedulers
-- (internal/scheduler/*_detector.go) INSERT into alerts with a `source` column
-- ('insider_threat_detector' / 'network_anomaly'), but the alerts table never
-- had one — so those INSERTs failed and the detectors produced nothing. This is
-- why they were left unwired. Adding the column (default 'custom' for existing
-- engine alerts) lets them be enabled. Idempotent.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source TEXT DEFAULT 'custom';
