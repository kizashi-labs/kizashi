-- 276: allow 'sigmahq' as a rules.source value.
--
-- The SigmaHQ auto-sync importer (internal/sync/sigmahq.go) inserts rules with
-- source = 'sigmahq', but the rules_source_check CHECK constraint did not list
-- it — so EVERY imported rule violated the constraint and the sync silently
-- recorded failed=N, imported=0. The sync had never been enabled in production,
-- so this was never observed until SigmaHQ breadth sync was turned on
-- (2026-06-25). Add 'sigmahq' so synced public rules can be stored; the distinct
-- source also lets the importer's `ON CONFLICT (id) ... WHERE source='sigmahq'`
-- scope updates to synced rules without clobbering seeded/custom rules.
ALTER TABLE rules DROP CONSTRAINT IF EXISTS rules_source_check;
ALTER TABLE rules ADD CONSTRAINT rules_source_check
    CHECK (source = ANY (ARRAY[
        'community'::text,
        'custom'::text,
        'threat-intel'::text,
        'ai-generated'::text,
        'builtin'::text,
        'sigmahq'::text
    ]));
