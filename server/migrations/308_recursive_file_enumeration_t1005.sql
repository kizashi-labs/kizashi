-- 308: T1005(Data from Local System / "Find files")のギャップ埋め。
--
-- 背景: Caldera 実走(2026-07-04)の残ギャップ精査で、Discovery 群は探索バースト
--   (migration 307)で Technique 化できたが、T1005 "Find files" だけは Tactic 止まり
--   だった。実コマンド(Caldera ability 90c2efaa)は PowerShell の
--     Get-ChildItem C:\Users -Recurse -Include *.yml -ErrorAction 'SilentlyContinue'
--       | foreach {$_.FullName} | Select-Object -first 5
--   で、拡張子(*.yml/*.png/*.wav …)を変えて連続実行し、機微ファイルを再帰列挙する。
--   `dir` / `Get-ChildItem` はプロセス化されず process バーストでは拾えないため、
--   PowerShell スクリプト内容(PS4104 ScriptBlockText)/コマンドラインで検知する。
--
-- 署名: 再帰列挙(-Recurse + -Include)× パス出力/件数制限(.FullName / Select-Object)。
--   単発の Get-ChildItem -Recurse はノイズだが、Include フィルタ付き再帰列挙の結果を
--   FullName で吐き出す/先頭N件に絞るのは、収集前の機微ファイル探索に典型的。
--   CommandLine と ScriptBlockText の両経路を見て、インライン実行でも
--   スクリプトブロック・ロギングにしか乗らなくても安定して捕捉する(284 と同方針)。
--
-- rules.name に一意制約が無いため INSERT は WHERE NOT EXISTS で冪等化する。LIVE 検知は
-- cmd/detection の RuleEngine が rules テーブル(enabled=true)からロードする経路。
-- 検知サーバの flatten(addPipelineSigmaAliases)が script_block_text → ScriptBlockText を
-- 補完するため sigma-go はリテラルキーで解決でき、CommandLine は FieldMappings 済み。
-- severity=4(低め)= 自動隔離しきい値未満に留め、FP時の巻き込みを避ける。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Recursive Sensitive File Enumeration (Collection)', 'sigma', ARRAY['windows'], 4,
$$
title: Recursive Sensitive File Enumeration (Collection)
description: Detects recursive, extension-filtered file enumeration whose results are projected to full paths or capped to the first N — the canonical pre-collection "find sensitive files" tradecraft (e.g. Caldera ability 90c2efaa "Locate files deemed sensitive"). Matches BOTH the process command line and the PS4104 script-block text so it fires whether the search runs inline or only surfaces via script-block logging. A lone Get-ChildItem -Recurse is intentionally NOT matched.
status: stable
level: medium
tags:
  - attack.t1005
  - attack.collection
logsource:
  product: windows
  category: ps_script
detection:
  enum_cmd:
    CommandLine|contains|all:
      - '-Recurse'
      - '-Include'
  out_cmd:
    CommandLine|contains:
      - '.FullName'
      - 'Select-Object -First'
  enum_script:
    ScriptBlockText|contains|all:
      - '-Recurse'
      - '-Include'
  out_script:
    ScriptBlockText|contains:
      - '.FullName'
      - 'Select-Object -First'
  condition: (enum_cmd and out_cmd) or (enum_script and out_script)
falsepositives:
  - Backup, inventory or search scripts that recursively enumerate files by extension and print their full paths
$$,
'community', ARRAY['T1005'],
'Caldera gap-fill: recursive sensitive-file enumeration (T1005) across CommandLine and ScriptBlockText', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Recursive Sensitive File Enumeration (Collection)');
