-- Migration 249: Enable recommended YARA rules that are already in the database.
-- Recommended rules: CVE-specific rules, webshell detectors, and critical-severity rules.
UPDATE yara_rules
SET enabled = TRUE, updated_at = NOW()
WHERE enabled = FALSE
  AND (
    name ILIKE '%CVE%'
    OR name ILIKE '%webshell%'
    OR severity = 'critical'
  );
