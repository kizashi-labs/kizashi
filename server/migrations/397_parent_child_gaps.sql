-- 333: 親子プロセス相関の残穴補完(未活用の ParentImage テレメトリ活用)。
--
-- 2026-07-20 の検知率深掘りで、parentResolver が parent_process(→ParentImage)を
-- 注入済みで Office/WMI/MMC/SQL/Web サーバ/アクセシビリティ等は親子ルールで
-- カバー済みだが、以下2つが未カバーと判明:
--   1. UAC バイパスは fodhelper のみ(migration 019)。他の自動昇格 LOLBin が未カバー。
--   2. ブラウザ→シェル(T1203 ドライブバイ/エクスプロイト)は皆無。
-- いずれも高シグナル・低FP(正規ブラウザは cmd/powershell を子に持たない、
-- eventvwr の正規子は mmc であり cmd/powershell ではない)。
-- process_creation。description にコロン+スペース無し。冪等: ON CONFLICT DO NOTHING。

-- ── T1548.002 — UAC Bypass via auto-elevating LOLBin (fodhelper 以外) ──
INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0333-0001-0001-000000000001',
  'UAC Bypass via Auto-Elevating Binary',
  'sigma',
  ARRAY['windows'],
  8,
  $SIGMA$title: UAC Bypass via Auto-Elevating Binary
id: f1a0c0de-0333-0001-0001-000000000001
status: stable
description: Detects a command shell or script host spawned by a known auto-elevating UAC bypass binary such as eventvwr sdclt computerdefaults wsreset or slui which indicates a User Account Control bypass
references:
  - https://attack.mitre.org/techniques/T1548/002/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
      - \eventvwr.exe
      - \sdclt.exe
      - \computerdefaults.exe
      - \wsreset.exe
      - \slui.exe
      - \fodhelper.exe
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \wscript.exe
      - \cscript.exe
      - \mshta.exe
      - \rundll32.exe
      - \regsvr32.exe
  condition: selection
falsepositives:
  - Rare administrative scripts intentionally launched through these utilities
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1548.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ── T1203 — Browser spawning a command shell (exploitation/drive-by) ──
INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0333-0002-0002-000000000002',
  'Web Browser Spawning a Command Shell',
  'sigma',
  ARRAY['windows'],
  8,
  $SIGMA$title: Web Browser Spawning a Command Shell
id: f1a0c0de-0333-0002-0002-000000000002
status: stable
description: Detects a web browser process spawning a command shell or script host which is highly abnormal and indicates browser exploitation or a drive-by compromise
references:
  - https://attack.mitre.org/techniques/T1203/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
      - \chrome.exe
      - \firefox.exe
      - \msedge.exe
      - \iexplore.exe
      - \brave.exe
      - \opera.exe
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \wscript.exe
      - \cscript.exe
      - \mshta.exe
  condition: selection
falsepositives:
  - Enterprise browser management scripts (rare)
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1203'],
  NOW()
) ON CONFLICT (id) DO NOTHING;
