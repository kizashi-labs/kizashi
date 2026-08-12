-- P4: enable the free public threat-intel feeds that migration 028 seeded as
-- disabled, so the FeedScheduler auto-imports them out of the box. The intel
-- importer now parses each source's real schema (feed_scheduler delegates
-- urlhaus_csv/malwarebazaar_csv/feodo_csv/otx_reputation to internal/intel).
--
-- Feodo Tracker and AlienVault OTX reputation are keyless. abuse.ch URLhaus/
-- MalwareBazaar may require an Auth-Key on some networks; a failed fetch imports
-- 0 IOCs and advances last_sync (no tight retry loop), and an operator can add an
-- API key via the threat-feeds API later. Idempotent (only flips disabled rows).
UPDATE threat_feeds
SET is_active = TRUE, updated_at = NOW()
WHERE source_format IN ('feodo_csv', 'otx_reputation', 'urlhaus_csv', 'malwarebazaar_csv')
  AND is_active = FALSE;
