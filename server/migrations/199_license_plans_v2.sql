-- Migration 199: Update license plan names to Starter/Business/Enterprise
-- Aligns license_info with the new plan constants in server/internal/license/manager.go

-- 1. Update current plan names (free→starter, pro→business, enterprise stays)
UPDATE license_info
SET plan = CASE
    WHEN plan = 'free'       THEN 'starter'
    WHEN plan = 'pro'        THEN 'business'
    ELSE plan  -- starter / business / enterprise are already correct
END
WHERE id = 1;

-- 2. Update features array to match the new plan feature sets
UPDATE license_info
SET features = ARRAY[
    'basic_detection',
    'alerts',
    'reports',
    'ai_investigation',
    'siem_integration',
    'playbooks',
    'threat_intel',
    'yara',
    'ml_detection',
    'threat_hunting',
    'multi_tenant',
    'compliance',
    'api_access',
    'xdr',
    'deception',
    'forensics',
    'soar'
]
WHERE id = 1
  AND plan = 'enterprise';

UPDATE license_info
SET features = ARRAY[
    'basic_detection',
    'alerts',
    'reports',
    'ai_investigation',
    'siem_integration',
    'playbooks',
    'threat_intel',
    'yara',
    'ml_detection',
    'threat_hunting'
]
WHERE id = 1
  AND plan = 'business';

UPDATE license_info
SET features = ARRAY[
    'basic_detection',
    'alerts',
    'reports'
]
WHERE id = 1
  AND plan = 'starter';

-- 3. Fix agent_limit / user_limit to match new plan defaults
--    (enterprise = unlimited = 0, business = 299/50, starter = 49/10)
UPDATE license_info
SET
    agent_limit = CASE
        WHEN plan = 'enterprise'   THEN 0
        WHEN plan = 'professional' THEN 999
        WHEN plan = 'business'     THEN 999
        WHEN plan = 'starter'      THEN 199
        WHEN plan = 'lite'         THEN 45
        ELSE agent_limit
    END,
    user_limit = CASE
        WHEN plan = 'enterprise'   THEN 0
        WHEN plan = 'professional' THEN 50
        WHEN plan = 'business'     THEN 50
        WHEN plan = 'starter'      THEN 10
        WHEN plan = 'lite'         THEN 3
        ELSE user_limit
    END
WHERE id = 1;

-- 4. Add a comment to the table for documentation
COMMENT ON TABLE license_info IS
    'Platform license. Plans: lite (¥500/endpoint/mo, 5-45 endpoints), '
    'starter (¥1,800/endpoint/mo, 50-199 endpoints), '
    'professional (¥2,800/endpoint/mo, 200-999 endpoints), '
    'enterprise (custom pricing, 1000+ endpoints, unlimited users).';
