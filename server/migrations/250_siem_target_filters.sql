-- Migration 250: Add advanced filter fields to siem_targets.
-- filter_rules:     whitelist of rule names (empty array = all rules)
-- filter_hostnames: whitelist of endpoint hostnames (empty array = all)
-- filter_mitre:     whitelist of MITRE ATT&CK technique IDs (empty array = all)
ALTER TABLE siem_targets
  ADD COLUMN IF NOT EXISTS filter_rules     TEXT[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS filter_hostnames TEXT[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS filter_mitre     TEXT[] NOT NULL DEFAULT '{}';
