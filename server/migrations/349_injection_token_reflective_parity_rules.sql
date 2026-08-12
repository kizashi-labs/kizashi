-- 349: detection-server (DB RuleEngine) パリティ 第32弾 — 注入/インメモリ実行/トークン操作。
--
-- api-server ビルトインにあるが DB 未移植の防御回避3種を移植する:
--   T1055.001 DLL Injection (mavinject)     — mavinject INJECTRUNNING
--   T1134     Access Token Manipulation     — runas /netonly, getsystem, incognito 等
--   T1620     Reflective Code Loading        — [Reflection.Assembly]::Load 等のインメモリロード
-- いずれもコマンドライン主体で、mavinject のみ Image アンカーを
-- CommandLine|contains|all の mavinject 語に置換する。
--
-- 備考: なりすまし T1036.003(システムプロセス名 × 非標準パス)は Image パス +
-- not 演算子ベースで CommandLine のみの DB エンジンへ忠実移植できないため除外。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1055.001 : Mavinject プロセス注入 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Mavinject Process Injection (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Mavinject Process Injection (DB)
description: Detects mavinject.exe injecting a DLL into a running process (INJECTRUNNING) — a LOLBin injection technique.
status: stable
level: high
tags:
  - attack.t1055.001
  - attack.defense_evasion
  - attack.privilege_escalation
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - "mavinject"
      - "INJECTRUNNING"
  condition: selection
falsepositives:
  - None expected outside App-V environments
$$,
'builtin-parity', ARRAY['T1055.001'],
'Two-engine parity: mavinject process injection', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Mavinject Process Injection (DB)');

-- ── T1134 : アクセストークン操作 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Access Token Manipulation (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Access Token Manipulation (DB)
description: Detects token theft/impersonation tradecraft — Invoke-TokenManipulation, incognito, runas /netonly, getsystem, token-duplication APIs.
status: stable
level: high
tags:
  - attack.t1134
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "Invoke-TokenManipulation"
      - " incognito"
      - "runas /netonly"
      - "getsystem"
      - "steal_token"
      - "make_token"
      - "ImpersonateLoggedOnUser"
      - "DuplicateTokenEx"
  condition: selection
falsepositives:
  - Rare legitimate use of runas /netonly by administrators
$$,
'builtin-parity', ARRAY['T1134'],
'Two-engine parity: access token manipulation', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Access Token Manipulation (DB)');

-- ── T1620 : 反射的コードロード(インメモリアセンブリ)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Reflective Code Loading (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Reflective Code Loading (DB)
description: Detects loading code directly into memory (reflective .NET assembly load) bypassing on-disk AV inspection.
status: stable
level: high
tags:
  - attack.t1620
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "[Reflection.Assembly]::Load"
      - "[System.Reflection.Assembly]::Load"
      - "Assembly]::Load("
      - "System.Reflection.Assembly]::LoadWithPartialName"
      - "[AppDomain]::CurrentDomain.Load"
      - "InvokeReturnAsIs"
  condition: selection
falsepositives:
  - Some .NET developer / build automation
$$,
'builtin-parity', ARRAY['T1620'],
'Two-engine parity: reflective code loading (in-memory assembly)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Reflective Code Loading (DB)');
