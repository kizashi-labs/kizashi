-- 427: 履歴ファイルの閲覧そのものでは鳴らないようにする（T1552.003）
--
-- migration 386 で入れた `Credential Harvesting from Shell or DB History` の
-- 条件を狭める。旧条件は
--
--     reader (cat/less/more/grep/head/tail/strings) and history_file
--
-- で、**履歴を読むこと自体**を発火条件にしていた。
--
-- ── なぜ直すか ──
--
-- macOS プロファイルを FP ソークに足した計測（CI run 31707086634）で、この技法は
-- **10 件 / 5999.94 件（1000ホスト/日）** を出し、Sigma ルール中で最多タイだった。
-- 鳴っていたのは以下で、いずれも「前に叩いたあのコマンド何だっけ」という日常操作:
--
--     grep -n docker  /home/<user>/.bash_history    （dev-machine）
--     grep -n kubectl /Users/<user>/.zsh_history    （macbook）
--     grep docker     /Users/<user>/.zsh_history    （macbook）
--
-- **履歴を読むことは攻撃ではない。** T1552.003 が指すのは履歴から*資格情報を収穫する*
-- ことなので、識別子は「何を検索したか」と「ファイルをどこへ持ち出すか」にある。
--
-- ── なぜ 2 か所直すのか ──
--
-- 同じ技法のルールが builtin (`Shell History Credential Search`,
-- sigma_builtins.go) にもあり、`dedup.deduplicateByTechnique` が
-- mitre_technique で束ねるためスコアカードには 1 行としてしか現れない。
-- **片方だけ直しても誤検知は消えない**ので、同じ条件に揃える
-- （CLAUDE.md「検知ルールの二重管理」の実例）。
--
-- ── 検知能力を削っていないこと ──
--
-- 固定されている攻撃ケースはいずれも資格情報の語を含むので緑のまま:
--
--     attack_coverage_test.go:175      grep -i -E 'pass|token|secret' ~/.bash_history
--     migration_parity_test.go:287     cat ~/.bash_history | grep -i pass
--     linux_builtins_test.go:70        grep -i password ~/.bash_history
--     dark_technique_wave3_test.go:33  grep -i password /home/v/.bash_history
--
-- cat / less / grep 自体は発火側に置かない。linux_measurement_rules_test.go:122 が
-- `cat ~/.bash_history` を良性の対照として既に固定しており、既存判断と揃う。

UPDATE rules
SET content = $$title: Credential Harvesting from Shell or DB History
id: c4ed0000-0319-0003-0003-000000000003
status: experimental
description: Detects harvesting of credentials from shell or database history files (bash/zsh/mysql/psql/redis) — searching them for secret-bearing terms, or copying them off the host. Reading one's own history is ordinary recall and is deliberately NOT matched.
references:
  - https://attack.mitre.org/techniques/T1552/003/
logsource:
  category: process_creation
detection:
  history_file:
    CommandLine|contains:
      - .bash_history
      - .zsh_history
      - .mysql_history
      - .psql_history
      - .rediscli_history
      - .dbshell
  credential_terms:
    CommandLine|contains:
      - pass
      - token
      - secret
      - credential
      - api_key
      - apikey
      - api-key
      - access_key
      - accesskey
      - aws_
      - private_key
      - id_rsa
      - bearer
      - authorization
  exfil_verbs:
    CommandLine|contains:
      - base64
      - 'strings '
      - 'cp '
      - 'mv '
      - 'tar '
      - curl
      - wget
      - 'nc -'
  condition: history_file and (credential_terms or exfil_verbs)
falsepositives:
  - An administrator auditing history files for leaked secrets as part of a cleanup
level: medium$$,
    updated_at = now()
WHERE name = 'Credential Harvesting from Shell or DB History';

-- ── 4 本目：migration 350 の builtin-parity 行 ──
--
-- `Shell History Credential Search (DB)`（source='builtin-parity'）も条件が
-- `history_file` のみで、builtin の旧条件と同一である。
--
-- **この 1 本は最初の調査で見落とした。** 技法 dedup がスコアカードを 1 行に
-- まとめるため、builtin 側を狭めるまで存在が見えなかった——狭めた直後の計測
-- （CI run 31718937863）で `[Sigma] Shell History Credential Search (DB)` が
-- **新規 6 件**として現れて初めて分かった。
--
-- 教訓は「ルールを狭めるときは技法で横断的に洗うこと」である。タイトルで探すと
-- 同名別置きを取りこぼす。T1552.003 を持つのは以下の 4 本で、これで全部である
-- （対照として存在しない語で検索して 0 件を確認済み）:
--
--   Shell History Credential Search                 sigma_builtins.go
--   Credential Search in Shell History              sigma_builtins.go
--   Credential Harvesting from Shell or DB History  migration 386 → 本 migration
--   Shell History Credential Search (DB)            migration 350 → 本 migration
--
-- なお migration 306 / 309 / 352 も履歴ファイルを見るが、いずれも T1070.003
-- （履歴の消去）で `rm` / `truncate` / `history -c` を要求するため、閲覧では鳴らない。

UPDATE rules
SET content = $$title: Shell History Credential Search (DB)
description: Detects harvesting of credentials from shell and client history files — searching them for secret-bearing terms, or copying them off the host. Reading one's own history is ordinary recall and is deliberately NOT matched.
status: stable
level: medium
tags:
  - attack.t1552.003
  - attack.credential_access
logsource:
  category: process_creation
detection:
  history_file:
    CommandLine|contains:
      - ".bash_history"
      - ".zsh_history"
      - ".sh_history"
      - ".mysql_history"
      - ".psql_history"
      - ".rediscli_history"
  credential_terms:
    CommandLine|contains:
      - "pass"
      - "token"
      - "secret"
      - "credential"
      - "api_key"
      - "apikey"
      - "api-key"
      - "access_key"
      - "accesskey"
      - "aws_"
      - "private_key"
      - "id_rsa"
      - "bearer"
      - "authorization"
  exfil_verbs:
    CommandLine|contains:
      - "base64"
      - "strings "
      - "cp "
      - "mv "
      - "tar "
      - "curl"
      - "wget"
      - "nc -"
  condition: history_file and (credential_terms or exfil_verbs)
falsepositives:
  - An administrator auditing history files for leaked secrets as part of a cleanup
$$,
    updated_at = now()
WHERE name = 'Shell History Credential Search (DB)';
