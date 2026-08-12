-- 371: rules テーブルの Sigma ルール 4 件から、重複した YAML マッピングキーを取り除く。
--
-- 4 ルールが同じ selection 内で `CommandLine|contains` を 2 回定義していた。YAML では
-- 重複キーは不正であり、受け付けるパーサでは **後勝ち**になる。つまり 1 つ目のキー——
-- どの例でも「どのバイナリか」を決める弁別条件——が黙って捨てられ、2 つ目の OR リスト
-- だけが残っていた。
--
-- 効果は「ルールが緩くなる」ではなく「別のルールになる」である:
--
--   Archive Collected Data (Linux)
--     意図: 'tar ' かつ (作成フラグ)
--     実際: (作成フラグ) のみ。' cf ' や '--create' を含む任意のコマンドラインで発火する
--
--   Suspicious chmod of Executable in /tmp
--     意図: /chmod かつ (+x|755|777) かつ (/tmp/|/dev/shm/)
--     実際: /chmod かつ (/tmp/|/dev/shm/)。モードビットの条件が消えるので
--           `chmod -R g+w /tmp/build` のような無害な操作でも発火する
--
--   Suspicious wscript/cscript Execution
--     意図: スクリプトホスト かつ (スクリプト拡張子) かつ (ユーザ書込可能ディレクトリ)
--     実際: スクリプトホスト かつ (ディレクトリ)。拡張子の条件が消える
--
--   Data Exfiltration via curl/wget Upload (Linux)
--     意図: 'curl' かつ (アップロードフラグ) / 'wget' かつ (POST フラグ)
--     実際: (アップロードフラグ) / (POST フラグ) のみ。' -T ' や ' -d @' は汎用的すぎる
--
-- ★ 誤検知への効果は測定の結果ゼロだった。修正前後の FP ソークで
--   Archive Collected Data は 17 件のまま、chmod も 12 件のままである
--   (総数 439→436 の差は、キルチェーンや RDP ブルートフォース等の
--    ステートフル検知器の run 間ばらつきであって本修正の効果ではない)。
--
--   当初「この 2 件が誤検知 439 件のうち 29 件を出している」と見立てたが、
--   発火経路を確認せずルールが FP 一覧に載っていることから推測したもので、
--   誤りだった。実際の発火理由は測定後に特定した:
--
--     chmod   … 良性プロファイル (dev-machine.toml:136) の
--               `chmod +x /tmp/installer-{{rand}}.sh` が、**修正後の意図どおりの
--               ルール**に完全一致する。開発者が日常的に行う操作であり、
--               これは YAML 欠陥ではなくルール設計そのものの非弁別性である。
--     Archive … 良性プロファイル (backup-server.toml:60) の
--               `tar --zstd -cf /vault/...` が、本修正で触っていない
--               `ziptools` 分岐 (`zstd ` 等が単独で十分) で発火している。
--
--   本修正はルールを意図どおりの意味に戻すもので、それ自体は正しい。
--   ただし誤検知削減を目的とした変更ではない (P5-22 に測定結果を記録)。
--
-- 修正は #592 / #604 の LOLBin ルールと同じ形——1 つの selection に押し込まず、
-- 名前付きセレクションに分けて condition で AND する——にした。Sigma でこれを
-- 1 マップに書く方法は無い。同じキーを 2 回書けばこの欠陥に戻る。
--
-- なお api-server の SigmaEvaluator (Go yaml.v3) はこの YAML を **パース拒否**する。
-- server-detect の sigma-go は受け付ける。つまり修正前のこれらは「片方のエンジンでは
-- 存在しないルール、もう片方では弁別条件を失ったルール」として動いていた。
-- 再発防止は server/internal/detection/migration_sigma_parse_test.go
-- (migration 投入の Sigma を本番の SigmaEvaluator に通す CI ゲート)。

UPDATE rules SET content = $$
title: Archive Collected Data via Compression Utility (Linux)
description: Detects packaging of collected/staged data into an archive on Linux using tar with a create flag, or gzip/bzip2/xz/zstd/zip/7z/rar — a common pre-exfiltration step. Complements the Windows Compress-Archive rule, which does not match Linux archive tooling.
status: stable
level: medium
tags:
  - attack.t1560.001
  - attack.collection
logsource:
  product: linux
  category: process_creation
detection:
  tar_bin:
    CommandLine|contains: 'tar '
  tar_create:
    CommandLine|contains:
      - 'zcf'
      - 'czf'
      - 'cvf'
      - 'jcf'
      - 'Jcf'
      - 'tcf'
      - ' cf '
      - ' czf '
      - ' cvf '
      - '--create'
  ziptools:
    CommandLine|contains:
      - 'gzip '
      - 'bzip2 '
      - 'zip '
      - 'xz '
      - 'zstd '
      - '7z '
      - '7za '
      - 'rar '
  condition: (tar_bin and tar_create) or ziptools
falsepositives:
  - Legitimate backup or packaging jobs that tar/gzip directories
$$
WHERE name = 'Archive Collected Data via Compression Utility (Linux)';

UPDATE rules SET content = $$
title: Data Exfiltration via curl/wget Upload (Linux)
description: Detects outbound file upload on Linux via curl multipart/upload flags, wget POST-file flags, or scp — the transfer step that follows staging and archiving.
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
  scp_out:
    CommandLine|contains: 'scp '
  condition: (curl_bin and curl_upload) or (wget_bin and wget_post) or scp_out
falsepositives:
  - Legitimate deployment or backup scripts that upload artifacts
$$
WHERE name = 'Data Exfiltration via curl/wget Upload (Linux)';

UPDATE rules SET content = $$
title: Suspicious chmod of Executable in /tmp
description: Detects chmod granting execute permission to a file staged in a world-writable directory (/tmp, /dev/shm) — the step that makes a downloaded payload runnable.
status: stable
level: high
tags:
  - attack.t1222.002
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  chmod_bin:
    Image|contains: '/chmod'
  mode_bits:
    CommandLine|contains:
      - '+x'
      - '755'
      - '777'
  staging_dir:
    CommandLine|contains:
      - '/tmp/'
      - '/dev/shm/'
  condition: chmod_bin and mode_bits and staging_dir
falsepositives:
  - Build and packaging jobs that mark scripts executable under /tmp
$$
WHERE name = 'Suspicious chmod of Executable in /tmp';

UPDATE rules SET content = $$
title: Suspicious wscript/cscript Execution
description: Detects the Windows Script Host running a script file from a user-writable directory — the delivery step for VBS/JS droppers.
status: stable
level: high
tags:
  - attack.t1059.005
  - attack.t1059.007
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  script_host:
    Image|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
  script_ext:
    CommandLine|contains:
      - '.vbs'
      - '.js'
      - '.jse'
      - '.vbe'
      - '.wsf'
  user_writable:
    CommandLine|contains:
      - '\Temp\'
      - '\AppData\'
      - '\Users\Public\'
  condition: script_host and script_ext and user_writable
falsepositives:
  - Vendor installers and login scripts that run signed VBS from AppData
$$
WHERE name = 'Suspicious wscript/cscript Execution';
