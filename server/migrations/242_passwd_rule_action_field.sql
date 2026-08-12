-- Migration 242: Fix /etc/passwd Sigma rule to use 'action' field
-- The detection engine's flat map has key 'action' (e.g. "FILE_ACTION_MODIFY")
-- not 'Operation'. Migration 241 used 'Operation' which is only available after
-- the engine.go alias is deployed. This migration switches to 'action' so the
-- rule works with the currently deployed detection container (v1.3.9).

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
        action|contains:
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
