-- 350: 0カバレッジだった LOLBin / 防御回避 / 収集テクニックの補完。
--   T1216 署名済みスクリプトプロキシ実行 / T1220 XSL スクリプト処理 /
--   T1562.004 システムファイアウォール無効化 / T1114.001 ローカルメール収集 /
--   T1027.002 ソフトウェアパッキング。すべて process_creation の CommandLine で
--   低FPに絞る。

-- ── T1216 : 署名済みスクリプトによるプロキシ実行 ───────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Signed Script Proxy Execution (LOLBin VBS/WSF)', 'sigma', ARRAY['windows'], 7,
$SIGMA$
title: Signed Script Proxy Execution (LOLBin VBS/WSF)
description: Detects abuse of Microsoft-signed scripts to proxy arbitrary command execution and bypass application control — SyncAppvPublishingServer.vbs, PubPrn.vbs, manage-bde.wsf, winrm.vbs, slmgr.vbs, pester.bat. These signed helpers are rarely run interactively and are a classic AppLocker/WDAC bypass (T1216).
status: stable
level: high
tags:
  - attack.t1216
  - attack.defense_evasion
  - attack.execution
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'SyncAppvPublishingServer'
      - 'PubPrn.vbs'
      - 'manage-bde.wsf'
      - 'winrm.vbs'
      - 'pester.bat'
      - 'cscript //nologo //e:vbscript'
  condition: selection
falsepositives:
  - Rare legitimate administrative use (review the arguments passed to the script)
$SIGMA$,
'community', ARRAY['T1216'],
'Coverage gap fill: signed-script proxy execution LOLBins (was uncovered)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Signed Script Proxy Execution (LOLBin VBS/WSF)');

-- ── T1220 : XSL スクリプト処理 ────────────────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'XSL Script Processing via msxsl or WMIC Format', 'sigma', ARRAY['windows'], 7,
$SIGMA$
title: XSL Script Processing via msxsl or WMIC Format
description: Detects execution of embedded JScript/VBScript through XSL transforms — msxsl.exe running a stylesheet, or wmic with a /format switch that points at a remote or .xsl payload. Both run script outside the usual interpreters to evade application control (T1220).
status: stable
level: high
tags:
  - attack.t1220
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  msxsl:
    Image|endswith: \msxsl.exe
  wmic_img:
    Image|endswith: \WMIC.exe
  wmic_fmt:
    CommandLine|contains: '/format:'
  wmic_payload:
    CommandLine|contains:
      - 'http'
      - '.xsl'
  condition: msxsl or (wmic_img and wmic_fmt and wmic_payload)
falsepositives:
  - Legacy tooling that legitimately transforms XML via msxsl (rare)
$SIGMA$,
'community', ARRAY['T1220'],
'Coverage gap fill: XSL script processing (was uncovered)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'XSL Script Processing via msxsl or WMIC Format');

-- ── T1562.004 : システムファイアウォールの無効化/改変 ────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'System Firewall Disabled or Flushed', 'sigma', ARRAY['windows','linux'], 6,
$SIGMA$
title: System Firewall Disabled or Flushed
description: Detects disabling or flushing of the host firewall — netsh advfirewall set allprofiles state off, Set-/Disable-NetFirewall*, or Linux ufw disable / iptables -F / iptables -P ... ACCEPT / systemctl stop firewalld. Turning off the firewall opens the host for inbound C2, lateral movement, or exfil (T1562.004).
status: stable
level: medium
tags:
  - attack.t1562.004
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  win:
    CommandLine|contains:
      - 'advfirewall set allprofiles state off'
      - 'netsh firewall set opmode disable'
      - 'Set-NetFirewallProfile -Enabled False'
      - 'Disable-NetFirewallRule'
  linux:
    CommandLine|contains:
      - 'ufw disable'
      - 'iptables -F'
      - 'iptables -P INPUT ACCEPT'
      - 'systemctl stop firewalld'
      - 'systemctl disable firewalld'
  condition: win or linux
falsepositives:
  - Administrative firewall maintenance (scope by host/operator)
$SIGMA$,
'community', ARRAY['T1562.004'],
'Coverage gap fill: system firewall disable/flush (was uncovered)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'System Firewall Disabled or Flushed');

-- ── T1114.001 : ローカルメールデータ収集 ──────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Local Email Collection from Outlook Data Files', 'sigma', ARRAY['windows'], 5,
$SIGMA$
title: Local Email Collection from Outlook Data Files
description: Detects a non-Outlook process reading or copying Outlook data stores (.pst / .ost) — bulk local email collection for exfiltration (T1114.001). The mail client itself opens these; a shell, script host, or archiver touching them is suspicious.
status: experimental
level: medium
tags:
  - attack.t1114.001
  - attack.collection
logsource:
  category: process_creation
detection:
  reader:
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \7z.exe
      - \rar.exe
      - \robocopy.exe
      - \xcopy.exe
  store:
    CommandLine|contains:
      - '.pst'
      - '.ost'
  condition: reader and store
falsepositives:
  - Backup tooling that archives mail stores (scope by host)
$SIGMA$,
'community', ARRAY['T1114.001'],
'Coverage gap fill: local Outlook .pst/.ost email collection (was uncovered)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Local Email Collection from Outlook Data Files');

-- ── T1027.002 : ソフトウェアパッキング(UPX) ──────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Executable Packing via UPX', 'sigma', ARRAY['windows','linux','macos'], 5,
$SIGMA$
title: Executable Packing via UPX
description: Detects packing of an executable with UPX (upx -9 / --best / --brute / -o on a binary). Packing compresses and obscures a payload to evade static/AV inspection (T1027.002). Legitimate packing exists, so this is medium severity and best paired with drop-location or subsequent-execution context.
status: experimental
level: medium
tags:
  - attack.t1027.002
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  upx:
    Image|endswith:
      - \upx.exe
      - /upx
  packing_args:
    CommandLine|contains:
      - ' -9'
      - ' --best'
      - ' --brute'
      - ' --ultra-brute'
      - ' -o '
  condition: upx and packing_args
falsepositives:
  - Developers legitimately packing their own release binaries (scope by host)
$SIGMA$,
'community', ARRAY['T1027.002'],
'Coverage gap fill: UPX executable packing (was uncovered)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Executable Packing via UPX');
