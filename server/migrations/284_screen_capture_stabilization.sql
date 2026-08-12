-- 284: Caldera 多段エミュレーション採点(Super Spy, 2026-06-29)で「一部のみTechnique検知で
-- 不安定」と判明した T1113 Screen Capture の安定化ルール。
--
-- 現状確認(EC2 実DB照会)の結論: T1113 のライブ検知は sigmahq 同期ルール
-- "Windows Screen Capture with CopyFromScreen" 1本に依存していたが、これは
--   logsource.category: ps_script
--   detection: ScriptBlockText|contains: '.CopyFromScreen'
-- という ScriptBlockText(PowerShell ScriptBlock / PS4104 ETW)単一ソース依存で、
-- `powershell -c "...CopyFromScreen..."` のように process_creation の CommandLine に
-- 乗った場合も、BitBlt / VirtualScreen+Bitmap も捕捉できなかった。これが不安定の真因。
--
-- 本ルールは CommandLine と ScriptBlockText の両方を見て、CopyFromScreen / BitBlt /
-- VirtualScreen+Bitmap / nircmd savescreenshot を捕捉する。スクリーンショットのコードが
-- インラインのコマンドラインに乗っても、スクリプトブロック・ロギングにしか乗らなくても
-- 安定して検知できる(既存の ps_script 専用ルールの欠落=CommandLine 経路を補完)。
--
-- rules.name に一意制約が無いため INSERT は WHERE NOT EXISTS で冪等化する。LIVE 検知は
-- cmd/detection の RuleEngine が rules テーブル(enabled=true)からロードする経路。
-- 注: 本番 RuleEngine の FieldMappings は ScriptBlockText を持たないが、検知サーバの
-- flatten(addPipelineSigmaAliases)が script_block_text → ScriptBlockText を補完するため、
-- sigma-go はリテラルキーで解決できる。CommandLine は FieldMappings 済みで確実に解決される。

-- ── T1113 : Screen Capture via Graphics API ─────────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Screen Capture via Graphics API (CopyFromScreen/BitBlt)', 'sigma', ARRAY['windows'], 5,
$$
title: Screen Capture via Graphics API (CopyFromScreen/BitBlt)
description: Detects desktop screen capture via the .NET Graphics.CopyFromScreen / GDI BitBlt APIs or a VirtualScreen-sized Bitmap — the canonical PowerShell/Caldera screenshot tradecraft. Matches BOTH the process command line and the PS4104 script-block text, so detection is stable whether the screenshot code arrives inline on the command line or only via script-block logging. Complements the synced ps_script-only CopyFromScreen rule, which misses the command-line path.
status: stable
level: medium
tags:
  - attack.t1113
  - attack.collection
logsource:
  product: windows
  category: process_creation
detection:
  api_cmd:
    CommandLine|contains:
      - CopyFromScreen
      - BitBlt
  api_script:
    ScriptBlockText|contains:
      - CopyFromScreen
      - BitBlt
  bitmap_cmd:
    CommandLine|contains|all:
      - VirtualScreen
      - Bitmap
  bitmap_script:
    ScriptBlockText|contains|all:
      - VirtualScreen
      - Bitmap
  nircmd:
    Image|endswith: \nircmd.exe
    CommandLine|contains: savescreenshot
  condition: api_cmd or api_script or bitmap_cmd or bitmap_script or nircmd
falsepositives:
  - Legitimate screenshot or remote-support tooling
$$,
'community', ARRAY['T1113'],
'Caldera gap-fill: stabilize screen capture detection across CommandLine and ScriptBlockText', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Screen Capture via Graphics API (CopyFromScreen/BitBlt)');
