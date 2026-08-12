-- 316: 死蔵(dark)ルール "Linux Reverse Shell via Bash" (T1059.004) の是正。
--
-- 019_sigma_community_rules.sql が投入した本ルールの content は、YAML の description
-- 値に「NOTE: auto_isolate ...」というコロン+空白を含む未クォート文字列を持つため、
-- sigma-go のパースが必ず失敗する（"mapping values are not allowed in this context"）。
-- 結果、このルールは enabled=true でも production の RuleEngine で一度も評価されない
-- ＝死蔵。Linux リバースシェル(/dev/tcp, bash -i, nc -e)という critical 技法の検知が
-- 実際には無効だった。
--
-- 019 の ON CONFLICT (id) DO UPDATE は auto_isolate しか更新しないため、既存デプロイの
-- content は壊れたまま。ここで description をクォートした正しい content に置き換える。
-- 019 の原文も同時に修正済み(新規インストールはこのマイグレーション不要だが冪等)。
-- migration_rules_test.go の TestAllMigrationSigmaRulesCompile が以後の再発を回帰固定する。

UPDATE rules
SET content = $$title: Linux Reverse Shell via Bash
id: a1b2c3d4-0007-0007-0007-000000000034
status: stable
description: 'Detects common bash reverse shell techniques used to establish C2 connections on Linux systems. NOTE: auto_isolate is disabled to prevent false positives from legitimate network diagnostic tools using /dev/tcp/.'
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
level: critical$$,
    updated_at = NOW()
WHERE id = 'a1b2c3d4-0007-0007-0007-000000000034'
  AND type = 'sigma';
