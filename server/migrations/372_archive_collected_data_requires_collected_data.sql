-- 372: "Archive Collected Data via Compression Utility (Linux)" が、圧縮コマンドなら
-- 何でも発火する非弁別セレクタになっていたのを是正する。
--
-- 371 で YAML の重複キーを直したが、FP ソークで測ったところ誤検知は 17 件のまま
-- 動かなかった。原因は重複キーではなく `ziptools` 分岐だった:
--
--   ziptools: ['gzip ','bzip2 ','zip ','xz ','zstd ','7z ','7za ','rar ']
--
-- これは「そのツールを起動したか」であって「技術が使われたか」ではない。P5-17 の
-- LOLBin ルールで是正したのと同じ形——「実行ファイルなら必ず付くトークン」が
-- 単独で十分になっている——が、別の分岐に残っていた。
--
-- 実測 (tests/fpsoak/profiles):
--   tar --zstd -cf /vault/archive-{{date}}.tar.zst /srv/data/share   ← zstd で発火
--   tar -czf /tmp/artifact-{{rand}}.tar.gz ./dist                    ← czf で発火
-- バックアップサーバが業務データを保管庫に固めるのも、開発機がビルド成果物を
-- 固めるのも、この技術ではない。
--
-- ★ 弁別子は「圧縮したか」ではなく「収集した機微データを固めたか」である。
-- T1560.001 は Archive **Collected Data** であり、収集・ステージングされた
-- 機微情報が対象であることが技術の要件である。そこで「アーカイブ作成の動作」に
-- 加えて「対象が機微パスであること」を要求する形にした。
--
-- 真陽性 (Caldera Thief 実測、linux_collection_rule_test.go) は両方とも通る:
--   tar -P -zcf /home/ubuntu/staged.tar.gz /home/ubuntu/staged  → tar 作成 + /home/
--   gzip -9 /home/ubuntu/loot/dump.sql                          → 圧縮器 + /home/
--
-- gzip/bzip2/xz/zstd は既定動作が圧縮なので作成フラグを要求しない (上の TP が
-- `-9` しか持たない)。逆に tar/zip/7z/rar は展開もできるので作成動作を要求する。
-- 展開系 (-d/--decompress/gunzip/unzip/-x) は除外する。
--
-- 精度と再現率のトレードオフは承知のうえである。機微パス一覧に無い場所からの
-- アーカイブ (例: /opt/app/secrets) は取り逃す。ただし現状は任意の圧縮コマンドで
-- 発火するため、アラートとして読まれなくなっている方が損失が大きい。
-- 一覧は運用で追加できる。

UPDATE rules SET content = $$
title: Archive Collected Data via Compression Utility (Linux)
description: Detects archiving of collected or staged sensitive data on Linux — the packaging step before exfiltration (T1560.001). Keyed on the archive target being credential/user/system data rather than on the mere use of a compression tool, because backup and build jobs run tar/gzip/zstd constantly and firing on those makes the alert unreadable.
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
      - ' cf '
      - ' czf '
      - ' cvf '
      - '-cf '
      - '--create'
  compressor:
    CommandLine|contains:
      - 'gzip '
      - 'bzip2 '
      - 'xz '
      - 'zstd '
  archiver_add:
    CommandLine|contains:
      - 'zip -r'
      - 'zip -P'
      - 'zip --password'
      - '7z a'
      - '7za a'
      - 'rar a'
  collected_data:
    CommandLine|contains:
      - '/home/'
      - '/root/'
      - '/etc/'
      - '/var/mail'
      - '.ssh'
      - '.gnupg'
      - '.aws'
      - '.kube'
      - 'Documents'
      - 'staged'
      - 'staging'
      - 'loot'
      - 'exfil'
  extracting:
    CommandLine|contains:
      - ' -d '
      - ' --decompress'
      - 'gunzip '
      - 'unzip '
      - ' -x'
  condition: ((tar_bin and tar_create) or compressor or archiver_add) and collected_data and not extracting
falsepositives:
  - Administrative backups that archive /home or /etc directly
$$
WHERE name = 'Archive Collected Data via Compression Utility (Linux)';
