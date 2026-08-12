-- Migration 197: AI Auto-Investigation columns on alerts table
--
-- Adds three columns that the investigation package writes after running an
-- automatic or manual LLM-powered alert investigation:
--
--   ai_summary          – Free-text investigation summary from the LLM.
--   ai_investigated_at  – Timestamp of the most recent investigation run.
--   ai_model            – Model identifier used (e.g. "gpt-4o" or
--                         "claude-haiku-4-5-20251001").
--
-- All columns are nullable so existing rows are unaffected.

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS ai_investigated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS ai_model            VARCHAR(64);

-- ai_summary already exists on the alerts table (added by an earlier migration
-- and used by the AI triage feature).  Only add it when absent to keep the
-- migration idempotent.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   information_schema.columns
        WHERE  table_name  = 'alerts'
          AND  column_name = 'ai_summary'
    ) THEN
        ALTER TABLE alerts ADD COLUMN ai_summary TEXT;
    END IF;
END;
$$;
