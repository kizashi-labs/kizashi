-- Migration 248: Add UNIQUE constraint on yara_rules.name
-- Enables atomic ON CONFLICT upsert and prevents duplicate rule names.
-- Duplicate names (if any) are resolved by keeping the most recently updated record.

DELETE FROM yara_rules
WHERE id NOT IN (
    SELECT DISTINCT ON (name) id
    FROM yara_rules
    ORDER BY name, updated_at DESC
);

ALTER TABLE yara_rules ADD CONSTRAINT yara_rules_name_unique UNIQUE (name);
