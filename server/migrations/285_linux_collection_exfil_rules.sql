-- 285: Linux の収集→ステージング→アーカイブ→C2持ち出し検知ルール。
--
-- Caldera Thief(adversary 1a98b8e6)を Linux エンドポイント(eBPFプロセステレメトリ
-- 復活後)に対し実行した実測で、telemetry はあるが以下がアラート化されない/精度不足:
--   T1041 Exfil staged directory(curl -F アップロード)= 未検知(Telemetry止まり)
--   T1560.001 Compress staged directory(tar -zcf)= staging ルールに巻き込まれ Tactic 止まり
-- Windows 用ルール(283: Compress-Archive / PowerShell HttpClient)は Linux の
-- tar / curl コマンドに当たらないため、Linux 固有のコマンド形に合わせた専用ルールを追加。
--
-- 実測した実コマンド(eBPF process イベントの command_line):
--   tar  -P -zcf /home/ubuntu/staged.tar.gz /home/ubuntu/staged
--   curl -F data=@/home/ubuntu/staged.tar.gz --header X-Request-ID:... http://.../file/upload
--   cp   /home/ubuntu/edr-platform/docker-compose.yml /home/ubuntu/staged   /   mkdir -p staged
--
-- rules.name に一意制約が無いため INSERT は WHERE NOT EXISTS で冪等化。LIVE 検知は
-- cmd/detection の RuleEngine(bradleyjkemp/sigma-go)が rules テーブル(enabled=true)から
-- ロード。RuleEngine は platform 配列でゲートせず全ルールを評価する(Windows ルールが
-- Linux イベントで発火する実績あり)が、ラベルとして platform=linux を付与する。

-- ── T1560.001 : Archive Collected Data via Utility (Linux) ───────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Archive Collected Data via Compression Utility (Linux)', 'sigma', ARRAY['linux'], 5,
$$
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
  tar_create:
    CommandLine|contains: 'tar '
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
  condition: tar_create or ziptools
falsepositives:
  - Legitimate backup or packaging jobs that tar/gzip directories
$$,
'community', ARRAY['T1560.001'],
'Linux gap-fill: archive/compress collected data before exfil (tar/gzip/zip)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Archive Collected Data via Compression Utility (Linux)');

-- ── T1041 : Exfiltration Over C2/Web Channel (Linux) ────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Data Exfiltration via curl/wget Upload (Linux)', 'sigma', ARRAY['linux'], 7,
$$
title: Data Exfiltration via curl/wget Upload (Linux)
description: Detects file upload/exfiltration from Linux shells — curl multipart/form or upload-file (-F/--form/-T/--upload-file/--data-binary @), wget --post-file/--body-file, or scp — used to transfer collected/staged archives over a C2 or web channel.
status: stable
level: high
tags:
  - attack.t1041
  - attack.exfiltration
logsource:
  product: linux
  category: process_creation
detection:
  curl_upload:
    CommandLine|contains: 'curl'
    CommandLine|contains:
      - ' -F '
      - ' --form'
      - ' -T '
      - ' --upload-file'
      - ' --data-binary @'
      - ' -d @'
  wget_post:
    CommandLine|contains: 'wget'
    CommandLine|contains:
      - ' --post-file'
      - ' --body-file'
  scp_out:
    CommandLine|contains: 'scp '
  condition: curl_upload or wget_post or scp_out
falsepositives:
  - Legitimate upload/deployment scripts or backups using curl/scp
$$,
'community', ARRAY['T1041'],
'Linux gap-fill: C2/web exfil of staged archive (curl -F / wget --post-file / scp)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Data Exfiltration via curl/wget Upload (Linux)');

-- ── T1074.001 : Local Data Staging (Linux) ──────────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Local Data Staging via File Copy (Linux)', 'sigma', ARRAY['linux'], 5,
$$
title: Local Data Staging via File Copy (Linux)
description: Detects staging of files for exfiltration on Linux — creating a staging directory (mkdir) or copying files into one named staged/staging/exfil/loot/collected via cp/mv/rsync/install.
status: stable
level: medium
tags:
  - attack.t1074.001
  - attack.collection
logsource:
  product: linux
  category: process_creation
detection:
  copy_cmd:
    CommandLine|contains:
      - 'cp '
      - 'mv '
      - 'rsync '
      - 'install '
  stage_dir:
    CommandLine|contains:
      - '/staged'
      - '/staging'
      - '/exfil'
      - '/loot'
      - '/collected'
  mkdir_stage:
    CommandLine|contains: 'mkdir'
  stage_name:
    CommandLine|contains:
      - 'staged'
      - 'staging'
      - 'exfil'
      - 'loot'
  condition: (copy_cmd and stage_dir) or (mkdir_stage and stage_name)
falsepositives:
  - Legitimate file organisation into folders with these names
$$,
'community', ARRAY['T1074.001'],
'Linux gap-fill: local data staging directory + file copy (cp/mv/rsync/mkdir)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Local Data Staging via File Copy (Linux)');
