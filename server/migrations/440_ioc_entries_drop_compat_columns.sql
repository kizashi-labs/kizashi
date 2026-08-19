-- Migration 379: drop the ioc_entries compatibility columns.
--
-- 203 added ioc_type, enabled and threat_level, saying so plainly:
--
--   "Add compatibility columns to ioc_entries expected by ioc_matcher and
--    ioc_enrichment_handler. 009 created the table with type/is_active; the Go
--    code uses ioc_type/enabled/threat_level."
--
-- It back-filled them once and nothing kept them in step afterwards, so the
-- table carried two answers to each of three questions and readers picked
-- different ones. What that cost, measured:
--
--   * ioc_type is nullable and four of the six writers never set it. A NULL
--     fails Scan, pgx ends iteration on a scan error, and RetroIOCHunter
--     therefore aborted its whole batch on one manually-added indicator.
--   * enabled is never updated after insert, while store.SetActive clears
--     is_active — so deactivating an indicator did not stop enrichment,
--     sandbox correlation or retro hunting reporting it.
--   * threat_level defaults to 5 and severity is what importers set, so alerts
--     and enrichment reported a fixed middle threat for every indicator.
--
-- Every reader and both writers now use type, is_active and severity. This
-- removes the other half so they cannot drift apart again.
--
-- threat_level is the only one holding anything unique: the enrichment
-- handler's cache wrote live.Score/10 there while leaving severity at its
-- default of 7. Those rows are carried across before the column goes. A
-- threat_level still at its own default of 5 says nothing that severity does
-- not already say, so it is left alone rather than overwriting a severity an
-- importer set deliberately.
--
-- ioc_type and enabled hold nothing unique: ioc_type was back-filled from type
-- and both writers that set it wrote type's value, and nothing has ever set
-- enabled to anything but its default.
--
-- This is not reversible. The columns are dropped rather than left in place
-- because a compatibility shim that no code reads is not compatibility — it is
-- a second answer waiting to be believed.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'ioc_entries'
          AND column_name = 'threat_level'
    ) THEN
        -- severity's CHECK is 1..10; threat_level was written as score/10 and
        -- can be 0.
        UPDATE ioc_entries
           SET severity = GREATEST(LEAST(threat_level, 10), 1)
         WHERE threat_level <> 5;
    END IF;
END;
$$;

DROP INDEX IF EXISTS idx_ioc_entries_ioc_type;
DROP INDEX IF EXISTS idx_ioc_entries_enabled;

ALTER TABLE ioc_entries DROP COLUMN IF EXISTS ioc_type;
ALTER TABLE ioc_entries DROP COLUMN IF EXISTS enabled;
ALTER TABLE ioc_entries DROP COLUMN IF EXISTS threat_level;
