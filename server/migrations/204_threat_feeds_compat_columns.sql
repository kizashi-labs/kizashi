-- 204: Add compatibility columns to threat_feeds expected by threat_feed_importer.
-- 016 created the table with is_active/source_format; the importer queries enabled/format.

ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS format  TEXT    NOT NULL DEFAULT '';
ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT true;

-- Back-fill from existing columns
UPDATE threat_feeds SET format  = COALESCE(source_format, ''),
                        enabled = is_active;
