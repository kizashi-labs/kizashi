-- 345: PE VERSIONINFO の Company / Description を使ったマスカレード検知(T1036.005)。
--
-- migration 332 は OriginalFileName を使う。ここでは配線済みだが未使用の Company
-- (company_name→Company) と Description(file_description→Description) を活用する。
-- いずれの selection も「当該メタデータが存在すること」を要求する（|contains で
-- マッチ）ため、Windows で VERSIONINFO 読み取り失敗や非Windowsでフィールドが空の
-- 場合には発火しない＝absent-field による誤検知を構造的に回避している。

-- ── T1036.005 : Microsoft 著者を騙るバイナリが疑わしいパスから実行 ────────
-- 正規の Microsoft 署名バイナリは System32 / Program Files に置かれる。CompanyName に
-- Microsoft を主張しつつ Temp/AppData/Downloads/Public 等のユーザ書き込み可能パスから
-- 動くのは、署名メタデータだけ真似た偽物の典型。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Binary Falsely Claiming Microsoft Authorship from User-Writable Path', 'sigma', ARRAY['windows'], 7,
$SIGMA$
title: Binary Falsely Claiming Microsoft Authorship from User-Writable Path
description: Detects a process whose PE CompanyName claims Microsoft while it runs from a user- or world-writable directory (Temp, AppData, Downloads, Public, ProgramData, Windows\Temp). Genuine Microsoft binaries execute from System32 / Program Files; a Microsoft-claiming binary launched from a drop location is a masquerading implant (T1036.005). Requires CompanyName to be present, so absent version-info never false-fires.
status: experimental
level: high
tags:
  - attack.t1036.005
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  claims_ms:
    Company|contains: 'Microsoft'
  drop_path:
    Image|contains:
      - '\AppData\Local\Temp\'
      - '\AppData\Roaming\'
      - '\Downloads\'
      - '\Users\Public\'
      - '\ProgramData\'
      - '\Windows\Temp\'
      - '\$Recycle.Bin\'
  condition: claims_ms and drop_path
falsepositives:
  - Rare Microsoft-authored installers that stage a helper under Temp (review the signer/hash)
$SIGMA$,
'community', ARRAY['T1036.005'],
'Untapped telemetry (Company): Microsoft-claiming binary from a drop path', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Binary Falsely Claiming Microsoft Authorship from User-Writable Path');

-- ── T1036.005 : リネームされた PowerShell を PE Description で捕捉 ──────────
-- powershell.exe を別名にリネームして名前ベース検知を回避しても、VERSIONINFO の
-- FileDescription("Windows PowerShell") は残る。Image 名が powershell/pwsh 以外なのに
-- Description が PowerShell を示すのはリネーム LOLBin の強いシグナル。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Renamed PowerShell by PE Description', 'sigma', ARRAY['windows'], 7,
$SIGMA$
title: Renamed PowerShell by PE Description
description: Detects a renamed PowerShell binary by its embedded PE FileDescription (Windows PowerShell / PowerShell Core) while the on-disk image name is not powershell.exe/pwsh.exe. Renaming to evade name-based controls leaves the version-info Description intact (T1036.005). Complements the OriginalFileName masquerade rules by catching binaries whose OriginalFileName was stripped but Description remains.
status: experimental
level: high
tags:
  - attack.t1036.005
  - attack.defense_evasion
  - attack.execution
logsource:
  category: process_creation
detection:
  desc_ps:
    Description|contains:
      - 'Windows PowerShell'
      - 'PowerShell Core'
  real_ps:
    Image|endswith:
      - \powershell.exe
      - \pwsh.exe
      - \powershell_ise.exe
  condition: desc_ps and not real_ps
falsepositives:
  - Third-party PowerShell host wrappers that copy the version resource (rare)
$SIGMA$,
'community', ARRAY['T1036.005'],
'Untapped telemetry (Description): renamed PowerShell LOLBin by PE FileDescription', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Renamed PowerShell by PE Description');
