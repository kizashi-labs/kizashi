-- 315: 死蔵していた Sigma ルール "Linux Reverse Shell via Bash" (T1059.004) を復活させる。
--
-- 2026-07-12 の死蔵ルール横断監査で発見。migration 019 のルール
-- id=a1b2c3d4-0007-0007-0007-000000000034 の content は、`description:` の値に
--   「... Linux systems. NOTE: auto_isolate is disabled ...」
-- という引用符なしの `: `（コロン+スペース）を含んでいた。YAML はこれをマッピング区切りと
-- 解釈するため `yaml: line 4: mapping values are not allowed in this context` で
-- パースに失敗し、RuleEngine が sigma.ParseRule 時にコンパイルを捨てていた。
-- 結果、enabled=true でありながら一度も評価されない＝T1059.004(リバースシェル)が実質未検知。
--
-- これは migration 313 が確立した「detection ロード時 failed=0」基準より後に、
-- auto_isolate 無効化の編集と同時に description 行が追記されて混入した新規のサイレント死蔵。
-- 修正は description をダブルクオートで囲みYAMLとして妥当にするのみ（検知ロジックは不変）。
-- migration 019 のソースも同じ内容に修正済み（新規DB向け）。本マイグレーションは
-- 既に 019 を適用済みの本番DBの content を前方修正する。冪等（同値UPDATEは無害）。

UPDATE rules
SET content = $SIGMA$title: Linux Reverse Shell via Bash
id: a1b2c3d4-0007-0007-0007-000000000034
status: stable
description: "Detects common bash reverse shell techniques used to establish C2 connections on Linux systems. NOTE: auto_isolate is disabled to prevent false positives from legitimate network diagnostic tools using /dev/tcp/."
references:
  - https://attack.mitre.org/techniques/T1059.004/
logsource:
  category: process_creation
  product: linux
detection:
  selection_bash:
    CommandLine|contains:
      - '/dev/tcp/'
      - '/dev/udp/'
      - 'bash -i'
  selection_nc:
    Image|contains: '/nc'
    CommandLine|contains:
      - '-e /bin/bash'
      - '-e /bin/sh'
  condition: selection_bash or selection_nc
falsepositives:
  - Network testing utilities
level: critical$SIGMA$,
    updated_at = NOW()
WHERE id = 'a1b2c3d4-0007-0007-0007-000000000034';
