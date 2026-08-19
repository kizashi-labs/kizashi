-- 347: 未活用の認証テレメトリ(auth_method / failure_reason)を活用。
-- ingestion は auth イベントを {username, action, success, source_ip, auth_method,
-- failure_reason} に正規化済みだが、auth_method / failure_reason を使う検知が皆無。
-- auth_method は Windows の LogonType 由来の文字列(logonTypeToMethod):
--   interactive(2)/network(3)/batch(4)/service(5)/unlock(7)/network_cleartext(8)/
--   new_credentials(9)/remote_interactive(10)/cached_interactive(11)。
-- failure_reason は 4625 の FailureReason 文字列 or SubStatus 16進コード。
-- 注: SigmaEvaluator は logsource の product(プラットフォーム)でのみ絞り category は
-- 説明用のため、これらのフィールドを持つ auth イベントに対して評価される。

-- ── T1078 : ネットワーク経由の平文資格情報ログオン(LogonType 8) ──────────
-- network_cleartext は資格情報が平文でネットワーク送信されたことを示す。傍受・
-- 漏洩リスクが高く、正規環境ではまれ(旧IIS Basic 認証や攻撃者ツール)。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Cleartext Credentials over Network Logon (LogonType 8)', 'sigma', ARRAY['windows'], 6,
$SIGMA$
title: Cleartext Credentials over Network Logon (LogonType 8)
description: Detects a network logon that transmitted credentials in cleartext (Windows LogonType 8 / network_cleartext). Cleartext credential transmission is rare on a hardened host and exposes passwords to interception; it appears with legacy Basic-auth services and some credential-relay / brute-force tooling (T1078).
status: stable
level: medium
tags:
  - attack.t1078
  - attack.credential_access
logsource:
  category: authentication
detection:
  selection:
    auth_method: network_cleartext
  condition: selection
falsepositives:
  - Legacy applications that legitimately use Basic authentication (scope by host)
$SIGMA$,
'community', ARRAY['T1078'],
'Untapped telemetry (auth_method): cleartext network logon', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Cleartext Credentials over Network Logon (LogonType 8)');

-- ── T1550.002 / T1078 : 明示的資格情報ログオン(runas /netonly, LogonType 9) ──
-- new_credentials は現行トークンとは別の資格情報でネットワーク先へ認証する
-- (runas /netonly)。攻撃者が窃取した資格情報で横移動する際の典型パターン。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Explicit-Credential Logon via runas netonly (LogonType 9)', 'sigma', ARRAY['windows'], 5,
$SIGMA$
title: Explicit-Credential Logon via runas netonly (LogonType 9)
description: Detects a logon performed with alternate explicit credentials (Windows LogonType 9 / new_credentials — the runas /netonly pattern). It lets a process authenticate to remote systems as a different identity while keeping the local token, a common lateral-movement step with stolen credentials (T1550.002 / T1078).
status: experimental
level: medium
tags:
  - attack.t1550.002
  - attack.t1078
  - attack.lateral_movement
logsource:
  category: authentication
detection:
  selection:
    auth_method: new_credentials
  condition: selection
falsepositives:
  - Administrators using runas /netonly for cross-domain management (scope by account/host)
$SIGMA$,
'community', ARRAY['T1550.002'],
'Untapped telemetry (auth_method): explicit-credential (runas netonly) logon', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Explicit-Credential Logon via runas netonly (LogonType 9)');

-- ── T1078.002 / T1110 : 無効/ロック/期限切れアカウントへの認証試行 ────────
-- FailureReason/SubStatus が「アカウント無効(0xC0000072)/ロックアウト(0xC0000234)/
-- 期限切れ(0xC0000193)/ワークステーション制限(0xC0000070)」を示す失敗は、単なる
-- パスワード誤りと異なり、無効化済みアカウントの狙い撃ちや制限回避の探索を示す。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Authentication Attempt Against Disabled or Locked Account', 'sigma', ARRAY['windows'], 5,
$SIGMA$
title: Authentication Attempt Against Disabled or Locked Account
description: Detects failed logons whose FailureReason/SubStatus indicates the target account is disabled (0xC0000072), locked out (0xC0000234), expired (0xC0000193), or blocked by a workstation/logon-hours restriction (0xC0000070 / 0xC000006F). Unlike a plain bad-password failure, these signal targeting of dormant/blocked accounts — account-state probing during brute force or a return to a disabled backdoor account (T1078.002 / T1110).
status: stable
level: medium
tags:
  - attack.t1078.002
  - attack.t1110
  - attack.credential_access
logsource:
  category: authentication
detection:
  reason:
    failure_reason|contains:
      - '0xC0000072'
      - '0xC0000234'
      - '0xC0000193'
      - '0xC0000070'
      - '0xC000006F'
      - 'account is currently disabled'
      - 'account is locked'
  condition: reason
falsepositives:
  - A user whose account was just disabled/locked still retrying (usually low volume)
$SIGMA$,
'community', ARRAY['T1078.002'],
'Untapped telemetry (failure_reason): auth against disabled/locked/expired accounts', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Authentication Attempt Against Disabled or Locked Account');
