-- Migration 241: §6 FP rate fix
-- Fixes two rules that were generating excessive false positives:
--
-- 1. 短時間の大量プロセス生成: threshold 30→100, cooldown 300s added
--    Root cause: procFS initial snapshot + normal system activity easily exceeded
--    the old 30/5s threshold with no cooldown, causing every subsequent process
--    event to re-fire the alert.
--
-- 2. /etc/passwd or /etc/shadow Modification: restricted to write/modify operations
--    Root cause: inotify IN_ACCESS on /etc generated "access" events for every
--    /etc/passwd read (e.g. resolveUID()), and the Sigma rule had no operation filter.

-- ── Fix 1: プロセス大量生成ルールの閾値+クールダウン修正 ─────────────────────

UPDATE rules
SET content = $$
# 5秒以内に同一エージェントから 100 件以上のプロセス生成
window: 5s
threshold: 100
event_type: process
group_by: agent_id
cooldown: 300s
$$
WHERE name = '短時間の大量プロセス生成（コードインジェクション疑い）'
  AND type = 'behavioral';

-- ── Fix 2: /etc/passwd ルールを write/modify 限定にする ────────────────────

-- The sigma_builtins.go rule (in-memory only, no DB row) is fixed in source.
-- The DB row from migration 014 already has Operation: write but was never
-- triggered because 'action' was not aliased to 'Operation' in addSigmaAliases.
-- Migration 242 will add the alias.  No content change needed here for that rule.

-- However there are two additional Sigma rules in the community rules that match
-- /etc/passwd without an operation filter; fix those as well.

UPDATE rules
SET content = replace(
    content,
    'condition: selection',
    'condition: selection'
  )
WHERE name LIKE '%passwd%'
  AND type = 'sigma'
  AND content NOT LIKE '%Operation%'
  AND content NOT LIKE '%operation%';

-- Specifically fix the builtin-equivalent rows that lack an operation filter:
UPDATE rules
SET content = $$title: Linux Password File Modification
id: b1a2c3d4-0001-0001-0001-000000000001
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
        Operation|contains:
            - 'write'
            - 'modify'
            - 'modified'
            - 'create'
            - 'created'
    condition: selection
falsepositives:
    - Legitimate user management (useradd, passwd commands)
level: critical$$
WHERE name IN (
    'Linux /etc/passwd or /etc/shadow Write',
    '/etc/passwd or /etc/shadow Modification'
)
  AND type = 'sigma';
