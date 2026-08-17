-- 384: 検知できていなかった技法を塞ぐ（第 1 波 / 5 ルール）
--
-- 出所は P4-12（docs/debt/P4.md）。クローズした #525 のブランチにしか無かった
-- 検知ルール 34 件のうち、**main で技法ごと完全に暗かった**ものだけを移す。
-- ルール本文は移設元から逐語で持ってきており、id も変えていない（将来 #525 の
-- ブランチと突き合わせる人が同じものだと分かるように）。
--
-- 塞ぐ技法:
--   T1134.001 / T1134.002  トークン窃取・盗んだトークンでのプロセス生成
--   T1134.005              SID-History 注入（mimikatz sid:: / DCShadow）
--   T1484.001 / T1484.002  ドメインポリシー・信頼関係の改変
--   T1491.001              内部デフェイス（壁紙改ざん）
--   T1548.002              自動昇格バイナリ経由の UAC バイパス（SYSTEM 実行の側面）
--
-- ── なぜこの 5 件だけなのか ──
--
-- 34 件を一度に入れない。FP ソークの総量が動いたとき、どのルールが原因か
-- 特定できなくなるためである（`-new-rule-floor` は新規ルール 1 件あたりで効くが、
-- 総量の較正は波ごとでないと 読めない）。第 2 波は Windows の残り 13 件、
-- 第 3 波は macOS 9 件＋クロス OS 3 件＋Exfiltration 3 件。
--
-- ── 第 1 波から外した 1 件（重要） ──
--
-- `SID-History Added to Account (Security Event 4765/4766)` は移していない。
-- フィールド解決の検査は通る（`EventID` は既知の名前）が、**値が永久に来ない**:
--
--   1. agent/internal/platform/windows/auth_query.go の購読述語は
--      "EventID=4624 or 4625 or 4634 or 4672" で、4765/4766 を含まない
--   2. auth_parse.go の switch は未知の EventID をエラーにして捨てる
--   3. そもそも auth_parse.go のコメントが明言している——
--      「auth events carry no EventID field」。AuthEvent はワイヤ上に EventID を
--      持たないので、購読と parse を直しても `EventID: 4765` は一致しない
--
-- 有効化には proto 変更（agent + proto + server の正規化層）が要る。ルールだけ
-- 先に入れると、**フィールド検査が緑のまま永久に発火しないルール**が 1 件増える。
-- それは本リポジトリが P5-5 / P5-7 で繰り返し潰してきた形そのものなので入れない。
--
-- 移設元ブランチ: fix/migration-323-additive-constraint @ cb9a94e9

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  '71340000-0318-0001-0001-000000000001',
  'SID-History Injection via Offensive Tooling',
  'sigma',
  ARRAY['windows'],
  9,
  $SIGMA$title: SID-History Injection via Offensive Tooling
id: 71340000-0318-0001-0001-000000000001
status: stable
description: Detects SID-History injection tradecraft (mimikatz sid module or DCShadow) used to persist elevated or cross-domain access by grafting a privileged SID onto an account
references:
  - https://attack.mitre.org/techniques/T1134/005/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'sid::add'
      - 'sid::patch'
      - 'misc::addsid'
      - 'lsadump::dcshadow'
  condition: selection
falsepositives:
  - Authorized red-team or AD migration tooling manipulating SID history
level: critical$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1134.005'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  '71340000-0318-0003-0003-000000000003',
  'Token Impersonation via Mimikatz token Module or CreateProcessWithToken',
  'sigma',
  ARRAY['windows'],
  8,
  $SIGMA$title: Token Impersonation via Mimikatz token Module or CreateProcessWithToken
id: 71340000-0318-0003-0003-000000000003
status: stable
description: Detects token impersonation and create-process-with-token tradecraft via the mimikatz token module or the CreateProcessWithTokenW API, complementing the builtin token-manipulation coverage
references:
  - https://attack.mitre.org/techniques/T1134/001/
  - https://attack.mitre.org/techniques/T1134/002/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'token::elevate'
      - 'token::run'
      - 'token::list'
      - 'CreateProcessWithTokenW'
      - 'CreateProcessWithToken'
  condition: selection
falsepositives:
  - Authorized red-team tooling exercising token APIs
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1134.001', 'T1134.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'd0a10000-0321-0001-0001-000000000001',
  'Domain or Group Policy Modification',
  'sigma',
  ARRAY['windows'],
  8,
  $SIGMA$title: Domain or Group Policy Modification
id: d0a10000-0321-0001-0001-000000000001
status: stable
description: Detects modification of Group Policy or domain trust and directory objects via GroupPolicy cmdlets, PowerView domain-object tampering, SharpGPOAbuse, or netdom trust, used to escalate privileges or weaken security domain-wide
references:
  - https://attack.mitre.org/techniques/T1484/001/
  - https://attack.mitre.org/techniques/T1484/002/
logsource:
  product: windows
  category: process_creation
detection:
  gpo_cmdlets:
    CommandLine|contains:
      - Set-GPRegistryValue
      - Set-GPPrefRegistryValue
      - New-GPLink
      - Set-GPLink
      - New-GPO
  gpo_abuse:
    CommandLine|contains:
      - SharpGPOAbuse
      - Set-DomainObject
      - Add-DomainObjectAcl
      - Add-DomainGroupMember
  trust_mod:
    CommandLine|contains:
      - 'netdom trust'
      - New-ADTrust
  condition: gpo_cmdlets or gpo_abuse or trust_mod
falsepositives:
  - Legitimate Group Policy administration by domain admins
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1484.001', 'T1484.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0328-0003-0003-000000000003',
  'Desktop Wallpaper Defacement',
  'sigma',
  ARRAY['windows'],
  5,
  $SIGMA$title: Desktop Wallpaper Defacement
id: f1a0c0de-0328-0003-0003-000000000003
status: stable
description: Detects programmatic changes to the desktop wallpaper via reg.exe or PowerShell often used by ransomware to display a ransom note as the background
references:
  - https://attack.mitre.org/techniques/T1491/001/
logsource:
  product: windows
  category: process_creation
detection:
  sel_reg:
    Image|endswith: \reg.exe
    CommandLine|contains|all:
      - Control Panel\Desktop
      - Wallpaper
      - ' /d '
  sel_ps:
    Image|endswith:
      - \powershell.exe
      - \pwsh.exe
    CommandLine|contains|all:
      - Wallpaper
      - Control Panel\Desktop
      - Set-Item
  condition: sel_reg or sel_ps
falsepositives:
  - Enterprise desktop management setting a corporate wallpaper
level: medium$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1491.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0335-0001-0001-000000000001',
  'SYSTEM Integrity Process from User Profile Path',
  'sigma',
  ARRAY['windows'],
  9,
  $SIGMA$title: SYSTEM Integrity Process from User Profile Path
id: f1a0c0de-0335-0001-0001-000000000001
status: stable
description: Detects a process running at SYSTEM integrity from within a user profile directory which is highly abnormal because legitimate SYSTEM processes run from system directories and indicates token theft or service abuse followed by execution of a dropped payload
references:
  - https://attack.mitre.org/techniques/T1134/
  - https://attack.mitre.org/techniques/T1548/002/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    IntegrityLevel: System
  user_path:
    Image|contains: \Users\
  condition: selection and user_path
falsepositives:
  - Rare SYSTEM-context installer custom actions staged under a user profile
level: critical$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1134', 'T1548.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;
