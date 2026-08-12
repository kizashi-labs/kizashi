-- 283: Caldera 多段エミュレーション採点(Super Spy/Ransack, 2026-06-29)で判明した
-- 収集→ステージング→アーカイブ→C2持ち出しの検知ギャップを埋める Sigma ルール3件。
--
-- 実機採点で、これらの技法は「テレメトリは捕捉するがアラート化しない」MISSだった:
--   T1074.001 Local Data Staging  / T1560.001 Archive via Utility / T1041 Exfil over C2
-- 本 migration 投入後、Super Spy チェーンの検知率は 57.9% → 100%(MISS 0) に改善(実測)。
--
-- rules.name に一意制約が無いため、各 INSERT は WHERE NOT EXISTS で冪等化する
-- (既存環境で手動投入済みの同名ルールを二重登録しない)。LIVE 検知は
-- cmd/detection の RuleEngine が rules テーブル(enabled=true)からロードする経路。

-- ── T1560.001 : Archive Collected Data via Utility ──────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Archive Collected Data via Compression Utility', 'sigma', ARRAY['windows'], 5,
$$
title: Archive Collected Data via Compression Utility
description: Detects packaging of collected/staged data into an archive — PowerShell Compress-Archive or archive LOLBins (7-Zip, WinRAR, makecab) — a common pre-exfiltration step before staging/transfer.
status: stable
level: medium
tags:
  - attack.t1560.001
  - attack.collection
logsource:
  product: windows
  category: process_creation
detection:
  powershell:
    CommandLine|contains: Compress-Archive
  archivers:
    Image|endswith:
      - \7z.exe
      - \7za.exe
      - \rar.exe
      - \winrar.exe
      - \makecab.exe
  condition: powershell or archivers
falsepositives:
  - Legitimate backup or software packaging using archive utilities
$$,
'community', ARRAY['T1560.001'],
'Caldera gap-fill: archive/compress collected data before exfil', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Archive Collected Data via Compression Utility');

-- ── T1074.001 : Local Data Staging ──────────────────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Local Data Staging to Collection Directory', 'sigma', ARRAY['windows'], 5,
$$
title: Local Data Staging to Collection Directory
description: Detects staging of files for exfiltration — creating a staging directory or copying files into one named staged/staging/exfil/loot/collected.
status: experimental
level: medium
tags:
  - attack.t1074.001
  - attack.collection
logsource:
  product: windows
  category: process_creation
detection:
  copy_cmd:
    CommandLine|contains:
      - Copy-Item
      - xcopy
      - robocopy
  staging_dir:
    CommandLine|contains:
      - \staged
      - \staging
      - \exfil
      - \loot
      - \collected
  mkdir_cmd:
    CommandLine|contains:
      - New-Item
      - mkdir
  staging_name:
    CommandLine|contains:
      - staged
      - staging
      - exfil
      - loot
  condition: (copy_cmd and staging_dir) or (mkdir_cmd and staging_name)
falsepositives:
  - Legitimate file organisation into folders with these names
$$,
'community', ARRAY['T1074.001'],
'Caldera gap-fill: local data staging directory + file copy', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Local Data Staging to Collection Directory');

-- ── T1041 : Exfiltration Over C2/Web Channel ────────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Data Exfiltration via PowerShell HTTP Upload', 'sigma', ARRAY['windows'], 7,
$$
title: Data Exfiltration via PowerShell HTTP Upload
description: Detects file upload/exfiltration from PowerShell — .NET HttpClient multipart upload, WebClient.UploadFile/UploadData, or Invoke-WebRequest/RestMethod with -InFile — used to transfer collected/staged data over a C2 or web channel.
status: experimental
level: high
tags:
  - attack.t1041
  - attack.exfiltration
logsource:
  product: windows
  category: process_creation
detection:
  multipart:
    CommandLine|contains: MultipartFormDataContent
  httpclient_read:
    CommandLine|contains|all:
      - System.Net.Http
      - OpenRead
  webclient_upload:
    CommandLine|contains:
      - .UploadFile(
      - .UploadData(
  invoke_infile:
    CommandLine|contains|all:
      - Invoke-
      - -InFile
  condition: multipart or httpclient_read or webclient_upload or invoke_infile
falsepositives:
  - Legitimate file-upload automation or deployment scripts
$$,
'community', ARRAY['T1041'],
'Caldera gap-fill: C2/web exfil of staged archive', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Data Exfiltration via PowerShell HTTP Upload');
