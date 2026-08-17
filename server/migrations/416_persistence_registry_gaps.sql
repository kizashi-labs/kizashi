-- 322: Persistence 残穴のレジストリ系補完(T1037.001 / T1546.001)。
--
-- 実測再監査の Persistence 残穴のうち、レジストリテレメトリで高シグナル低FPに検知
-- できる2件を補完。注意: 旧監査の「T1546.001(AppInit)」は技術IDの誤りで、AppInit_DLLs は
-- 実際には T1546.010 で builtin 被覆済み。真の T1546.001 は「デフォルトファイル関連付けの
-- 変更」で未カバーだったためこれを補完する。
--   - T1037.001 ログオンスクリプト(HKCU\Environment\UserInitMprLogonScript) — 正規利用
--     ほぼ皆無の高シグナル
--   - T1546.001 デフォルトファイル関連付けの改変(\shell\open\command にスクリプト/一時パス
--     ペイロード)
-- 見送り(別対応): T1574.001 は既存 T1574.002(DLLサイドロード, migration 019)と近接重複
-- のため個別追加せず。T1554(クライアントバイナリ汚染)はハッシュレピュテーション/ベース
-- ライン照合が前提でSigma単発では信頼検知不可。
--
-- レジストリルールは alert_pipeline の別名層(key_path→TargetObject, value_data→Details)
-- 経由で発火。description にコロン+スペースを含めない。冪等: ON CONFLICT DO NOTHING。

-- ── T1037.001 — Logon Script (Windows, UserInitMprLogonScript) ────────
INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'bea70000-0322-0001-0001-000000000001',
  'Logon Script Persistence via UserInitMprLogonScript',
  'sigma',
  ARRAY['windows'],
  8,
  $SIGMA$title: Logon Script Persistence via UserInitMprLogonScript
id: bea70000-0322-0001-0001-000000000001
status: stable
description: Detects setting a logon script via the HKCU Environment UserInitMprLogonScript value, a stealthy persistence mechanism that runs an arbitrary command at every interactive logon and has near-zero legitimate use
references:
  - https://attack.mitre.org/techniques/T1037/001/
logsource:
  product: windows
  category: registry_set
detection:
  selection:
    TargetObject|contains:
      - \Environment\UserInitMprLogonScript
      - \Environment\UserInitLogonScript
  condition: selection
falsepositives:
  - Rare legacy logon-script deployment via the registry
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1037.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ── T1546.001 — Change Default File Association ───────────────────────
INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'bea70000-0322-0002-0002-000000000002',
  'Default File Association Hijack',
  'sigma',
  ARRAY['windows'],
  7,
  $SIGMA$title: Default File Association Hijack
id: bea70000-0322-0002-0002-000000000002
status: stable
description: Detects modification of a file-type open command (shell open command) to point at a script host or a user-writable payload path, hijacking the default handler so opening a common file type executes attacker code at each use
references:
  - https://attack.mitre.org/techniques/T1546/001/
logsource:
  product: windows
  category: registry_set
detection:
  assoc_key:
    TargetObject|contains: \shell\open\command
  suspicious_payload:
    Details|contains:
      - powershell
      - 'cmd.exe /c'
      - 'cmd /c'
      - wscript
      - cscript
      - mshta
      - .vbs
      - .js
      - \AppData\
      - \Temp\
      - \Users\Public\
  condition: assoc_key and suspicious_payload
falsepositives:
  - Legitimate application installers registering their own file handlers
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1546.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;
