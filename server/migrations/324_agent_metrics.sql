-- Migration 324: persist agent CPU/memory metrics reported via Heartbeat.
--
-- HeartbeatRequest already carries cpu_usage (%) and memory_usage_mb, but the
-- server discarded them (UpdateLastSeen never received them) and the fleet
-- health alerter read a non-existent `agents.settings` JSONB column — so the
-- high-CPU/high-memory alert never fired. Store the metrics on the agent row.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS cpu_usage          DOUBLE PRECISION;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS memory_usage_mb    DOUBLE PRECISION;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS metrics_updated_at TIMESTAMPTZ;
