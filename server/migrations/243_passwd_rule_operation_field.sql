-- Migration 243: Fix /etc/passwd Sigma rule — correct field name is 'operation'
-- The ingestion service normalizes FileEvent.Action to 'operation' in raw_data.
-- Migration 242 used 'action' which is wrong; the flat map key is 'operation'.
-- Value examples: "FILE_ACTION_MODIFY", "FILE_ACTION_CREATE", "FILE_ACTION_DELETE"
-- sigma-go contains modifier is case-insensitive, so 'modify' matches FILE_ACTION_MODIFY.

UPDATE rules
SET content = $$title: Linux Password File Modification
status: stable
description: Detects writes to /etc/passwd or /etc/shadow indicating credential tampering
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains:
            - '/etc/passwd'
            - '/etc/shadow'
            - '/etc/sudoers'
        operation|contains:
            - 'modify'
            - 'create'
    condition: selection
falsepositives:
    - Legitimate user management (useradd, passwd commands)
level: critical$$
WHERE name IN (
    'Linux /etc/passwd or /etc/shadow Write',
    '/etc/passwd or /etc/shadow Modification'
)
  AND type = 'sigma';
