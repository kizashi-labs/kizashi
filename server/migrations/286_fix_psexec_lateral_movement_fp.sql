-- Migration 286: PsExec Lateral Movement ルールの誤検知(FP)修正
--
-- 019 の seed は selection_cmdline に ' -s ' / ' /s ' / ' \\ ' という汎用トークンを
-- 単独 selection として持ち、condition が
--   selection_image or (selection_cmdline and not filter_legitimate)
-- だったため、image が psexec でなくても cmdline が上記に触れれば発火した。
-- Linux の `curl -s -o /tmp/x https://...`(` -s ` を含む)が PsExec 横展開として
-- 誤検知することを実測(V1 スコアカード docs/results/live-20260701-linux-v2.md、
-- V1#1/#2 両方で sev7 発火)。RuleEngine(cmd/detection)は platform 配列で
-- ゲートせず全ルールを評価する(migration 285 のコメント参照)ため、ルール側で
-- FP を潰す必要がある。
--
-- 修正: 汎用フラグ(' -s ' / ' /s ' / ' \\ ')と filter_legitimate を撤去し、
-- PsExec 固有シグナルに限定する:
--   - selection_image: psexec.exe / psexec64.exe / paexec.exe / psexesvc.exe
--   - selection_artifact: CommandLine に '-accepteula'(Sysinternals 固有)または
--     'PSEXESVC'(PsExec のサービス/名前付きパイプ)を含む
-- これで curl 等の一般コマンドには当たらず、実 PsExec は image か固有アーティファクトで
-- 捕捉できる。compiled を NULL に戻して RuleEngine/SigmaEvaluator が再コンパイルする。
--
-- ★このYAMLは server/internal/detection/psexec_fp_test.go と一致させること
--   (テストが「curl 不発火 / psexec 発火」を担保している)。

UPDATE rules
SET content = $$title: PsExec Lateral Movement
id: a1b2c3d4-0001-0001-0001-000000000001
status: stable
description: Detects PsExec (and common clones) used for lateral movement — via the PsExec client/service binary, the PSEXESVC service artifact, or the -accepteula first-run flag. Narrowed from a prior version whose overly generic single-letter command-line flag tokens false-matched benign commands such as curl.
references:
  - https://attack.mitre.org/techniques/T1021/002/
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith:
      - '\psexec.exe'
      - '\psexec64.exe'
      - '\paexec.exe'
      - '\psexesvc.exe'
  selection_artifact:
    CommandLine|contains:
      - '-accepteula'
      - 'PSEXESVC'
  condition: selection_image or selection_artifact
falsepositives:
  - Legitimate administrative use of PsExec
level: high
tags:
  - attack.t1021.002
  - attack.lateral_movement
$$,
    compiled = NULL,
    updated_at = now()
WHERE id = 'a1b2c3d4-0001-0001-0001-000000000001';
