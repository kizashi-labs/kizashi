-- 324: "Registry Run Key Persistence"(migration 019, id ...011) の高重大度FPを是正。
--
-- 2026-07-12 のFPカナリア(fp_canary_test.go)が検出: 019 の Run キー永続化ルールは
-- Run/RunOnce への書込みを、ごく小さな許可リスト(MicrosoftEdge/OneDrive/SecurityHealth)
-- 以外はすべて level=high で発火させ、**値データ(Details)のパスを見ない**。このため
-- `C:\Program Files\Vendor\app.exe` のような正規インストールソフトの自動起動登録ごとに
-- 高重大度の誤検知を出していた(builtin の "Registry Run Key Persistence to Suspicious
-- Location" は Details が AppData/Temp 等の疑わしいパスの時だけ発火するよう適切にゲート
-- 済みなのと対照的)。
--
-- 是正: Details が Program Files/System32/SysWOW64/ProgramData\Microsoft の正規パスの
-- 場合を除外するフィルタを追加(condition に and not filter_legit_path)。ユーザ書込み可能
-- パス等への Run キー登録は引き続き high で発火する。019 のソースも同内容に修正済み。
-- 冪等: 同一 content への UPDATE は無害。
--
-- 注意: 正規名(Edge/OneDrive/...)と正規パスを **単一の filter_legit にまとめ**、
-- condition は `selection and not filter_legit`(NOT は1つ)にしている。レジストリ
-- ルールを評価する AlertPipeline 側の自作 Sigma 評価器(sigma_evaluator.go
-- compileConditionExpr)は `A and not B and not C`(NOT が2つ)を正しく扱えず、2つ目の
-- NOT を無視して除外が効かない(FP カナリアで実測)。2フィルタに分割し直さないこと。

UPDATE rules
SET content = $SIGMA$title: Registry Run Key Persistence
id: a1b2c3d4-0003-0003-0003-000000000011
status: stable
description: Detects modification of registry run keys commonly used for persistence
references:
  - https://attack.mitre.org/techniques/T1547/001/
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains:
      - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
      - '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
      - '\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
      - '\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
  filter_legit:
    Details|contains:
      - 'MicrosoftEdge'
      - 'OneDrive'
      - 'SecurityHealth'
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
      - 'C:\ProgramData\Microsoft\'
  condition: selection and not filter_legit
falsepositives:
  - Legitimate software installations adding startup entries
level: high$SIGMA$
WHERE id = 'a1b2c3d4-0003-0003-0003-000000000011';
