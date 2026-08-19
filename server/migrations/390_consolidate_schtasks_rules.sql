-- 326: schtasks スケジュールタスク作成ルールの重複整理 + FP是正。
--
-- 2026-07-12 の medium-sev FP調査で、T1053.005(schtasks /create)に3ルールが存在し、
-- 正規のタスク作成で重複発火 + FP していた:
--   (A) builtin "Scheduled Task Creation via schtasks"(sigma_builtins.go, AlertPipeline経路)
--       — フィルタ無しで全 /create に発火(最悪)。→ ソース側で filter_legit を追加済み。
--   (B) migration 014 "Scheduled Task Creation via schtasks"(rules テーブル, RuleEngine経路)
--       — (C)とほぼ同一の重複(Microsoft/Windows/Adobe 除外)。
--   (C) migration 019 "Scheduled Task Creation via schtasks.exe"(rules テーブル, 同経路)
--       — SYSTEM+Microsoft のみ除外(弱いフィルタ)。
-- builtin(A)は AlertPipeline、014/019 は RuleEngine と別経路だが、014 と 019 は同一
-- テーブル・同一経路の重複。整理:
--   - 014(B) を無効化(019 と重複)。名前 'Scheduled Task Creation via schtasks'(exe 無し)で
--     一意に特定(019 は '...schtasks.exe')。builtin は rules テーブルに無いため無影響。
--   - 019(C) の filter を包括版(Program Files/System32/Microsoft ディレクトリ + 既知の
--     正規アップデータ)に更新。019 ソースも同内容に修正済み。
-- 結果: RuleEngine 経路は 019 のみ(強化済)、AlertPipeline は builtin(強化済)= FP 解消 + 重複解消。
-- 冪等。

-- (B) 014 の重複を無効化。
UPDATE rules
SET enabled = FALSE, updated_at = NOW()
WHERE type = 'sigma'
  AND name = 'Scheduled Task Creation via schtasks'
  AND enabled = TRUE;

-- (C) 019 の filter を包括版に更新(既存DBの content を前方修正)。
UPDATE rules
SET content = $SIGMA$title: Scheduled Task Creation via schtasks.exe
id: a1b2c3d4-0003-0003-0003-000000000012
status: stable
description: Detects creation of scheduled tasks via schtasks.exe that may be used for persistence or privilege escalation, excluding tasks whose action runs a binary from a standard program directory
references:
  - https://attack.mitre.org/techniques/T1053/005/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: '/create'
  filter_legit:
    CommandLine|contains:
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
      - 'C:\Windows\System32\'
      - '\Microsoft\'
      - 'OneDrive'
      - 'GoogleUpdate'
      - 'MicrosoftEdge'
  condition: selection and not filter_legit
falsepositives:
  - Administrative or installer tasks whose action runs a binary from a standard program directory
level: medium$SIGMA$,
    updated_at = NOW()
WHERE id = 'a1b2c3d4-0003-0003-0003-000000000012';
