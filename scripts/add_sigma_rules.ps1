#!/usr/bin/env pwsh
# Adds 25 ATT&CK-mapped Sigma rules to the EDR platform.

$BASE = "https://203-0-113-10.nip.io"

# ─── Login ───
$loginResp = Invoke-RestMethod -Method POST "$BASE/api/v1/auth/login" `
    -ContentType "application/json" `
    -Body '{"email":"admin@example.com","password":"Admin1234!"}'
$TOKEN = $loginResp.token
if (-not $TOKEN) { Write-Error "Login failed"; exit 1 }
Write-Host "Logged in. Token: $($TOKEN.Substring(0,20))..."

$headers = @{ Authorization = "Bearer $TOKEN"; "Content-Type" = "application/json" }

function Add-SigmaRule($Name, $Platform, $Severity, $MitreTags, $Content) {
    $body = @{
        name       = $Name
        type       = "sigma"
        platform   = $Platform
        severity   = $Severity
        content    = $Content
        enabled    = $true
        source     = "custom"
        mitre_tags = $MitreTags
    } | ConvertTo-Json -Depth 5
    try {
        $r = Invoke-RestMethod -Method POST "$BASE/api/v1/rules" -Headers $headers -Body $body -ErrorAction Stop
        Write-Host "  OK  $($r.id.Substring(0,8))... $Name"
        return $true
    } catch {
        $msg = $_.ErrorDetails.Message
        if (-not $msg) { $msg = $_.Exception.Message }
        Write-Host "  ERR $Name : $msg"
        return $false
    }
}

$ok = 0

# 1. T1055 Process Injection
if (Add-SigmaRule "Process Injection via Remote Thread APIs" @("windows") 9 @("attack.defense_evasion","attack.t1055") @"
title: Process Injection via Remote Thread APIs
id: a1b2c3d4-0001-4000-8000-000000000001
status: stable
description: Detects process injection patterns using remote thread APIs
tags:
  - attack.defense_evasion
  - attack.t1055
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'VirtualAllocEx'
      - 'CreateRemoteThread'
      - 'NtQueueApcThread'
  condition: selection
level: high
"@) { $ok++ }

# 2. T1055.001 DLL Injection
if (Add-SigmaRule "DLL Injection via Regsvr32 or RunDLL32" @("windows") 8 @("attack.defense_evasion","attack.t1055.001") @"
title: DLL Injection via Regsvr32 or RunDLL32
id: a1b2c3d4-0002-4000-8000-000000000002
status: stable
description: Detects DLL injection via regsvr32 or rundll32 with remote content
tags:
  - attack.defense_evasion
  - attack.t1055.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\regsvr32.exe'
      - '\rundll32.exe'
    CommandLine|contains:
      - 'scrobj.dll'
      - 'http'
  condition: selection
level: high
"@) { $ok++ }

# 3. T1057 Process Discovery
if (Add-SigmaRule "Process Discovery via Tasklist or WMIC" @("windows") 3 @("attack.discovery","attack.t1057") @"
title: Process Discovery via Tasklist or WMIC
id: a1b2c3d4-0003-4000-8000-000000000003
status: stable
description: Detects process enumeration common in post-exploitation
tags:
  - attack.discovery
  - attack.t1057
logsource:
  category: process_creation
  product: windows
detection:
  tasklist:
    Image|endswith: '\tasklist.exe'
  wmic_process:
    Image|endswith: '\wmic.exe'
    CommandLine|contains: 'process list'
  condition: tasklist or wmic_process
level: informational
"@) { $ok++ }

# 4. T1082 System Information Discovery
if (Add-SigmaRule "System Information Discovery via Systeminfo" @("windows") 3 @("attack.discovery","attack.t1082") @"
title: System Information Discovery
id: a1b2c3d4-0004-4000-8000-000000000004
status: stable
description: Detects system information gathering commands
tags:
  - attack.discovery
  - attack.t1082
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\systeminfo.exe'
      - '\msinfo32.exe'
  condition: selection
level: informational
"@) { $ok++ }

# 5. T1083 File and Directory Discovery
if (Add-SigmaRule "Suspicious File and Directory Discovery" @("windows") 2 @("attack.discovery","attack.t1083") @"
title: Suspicious File and Directory Discovery
id: a1b2c3d4-0005-4000-8000-000000000005
status: stable
description: Detects bulk file enumeration in post-compromise recon
tags:
  - attack.discovery
  - attack.t1083
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\where.exe'
    CommandLine|contains:
      - '/r C:\'
      - '/r D:\'
  condition: selection
level: informational
"@) { $ok++ }

# 6. T1197 BITS Jobs
if (Add-SigmaRule "BITS Job Used for Malicious Download" @("windows") 7 @("attack.defense_evasion","attack.persistence","attack.t1197") @"
title: BITS Job Used for Malicious Download
id: a1b2c3d4-0006-4000-8000-000000000006
status: stable
description: Detects bitsadmin used to download or execute files
tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.t1197
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\bitsadmin.exe'
    CommandLine|contains:
      - '/transfer'
      - '/addfile'
      - '/SetNotifyCmdLine'
  condition: selection
level: medium
"@) { $ok++ }

# 7. T1218.011 Rundll32
if (Add-SigmaRule "Suspicious Rundll32 Proxy Execution" @("windows") 7 @("attack.defense_evasion","attack.t1218.011") @"
title: Suspicious Rundll32 Proxy Execution
id: a1b2c3d4-0007-4000-8000-000000000007
status: stable
description: Detects rundll32 proxy execution with suspicious arguments
tags:
  - attack.defense_evasion
  - attack.t1218.011
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains:
      - 'javascript:'
      - 'vbscript:'
      - ',Control_RunDLL'
      - 'url.dll,FileProtocolHandler'
  condition: selection
level: medium
"@) { $ok++ }

# 8. T1486 Ransomware
if (Add-SigmaRule "Ransomware Behavior: Encrypted File Extensions" @("windows") 10 @("attack.impact","attack.t1486") @"
title: Ransomware File Extension Modification
id: a1b2c3d4-0008-4000-8000-000000000008
status: stable
description: Detects ransomware indicators and ransom note creation
tags:
  - attack.impact
  - attack.t1486
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - '.locked'
      - '.encrypted'
      - '.crypt'
      - 'README_DECRYPT'
      - 'YOUR_FILES_ARE_ENCRYPTED'
  condition: selection
level: critical
"@) { $ok++ }

# 9. T1490 Inhibit System Recovery
if (Add-SigmaRule "Shadow Copy Deletion" @("windows") 10 @("attack.impact","attack.t1490") @"
title: Shadow Copy Deletion
id: a1b2c3d4-0009-4000-8000-000000000009
status: stable
description: Detects deletion of shadow copies to prevent system recovery
tags:
  - attack.impact
  - attack.t1490
logsource:
  category: process_creation
  product: windows
detection:
  vssadmin:
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains: 'delete shadows'
  wmic_shadow:
    Image|endswith: '\wmic.exe'
    CommandLine|contains: 'shadowcopy delete'
  bcdedit:
    Image|endswith: '\bcdedit.exe'
    CommandLine|contains: 'recoveryenabled no'
  condition: vssadmin or wmic_shadow or bcdedit
level: critical
"@) { $ok++ }

# 10. T1505.003 Web Shell
if (Add-SigmaRule "Web Shell Deployed in Web Root" @("windows","linux") 9 @("attack.persistence","attack.t1505.003") @"
title: Web Shell Deployed in Web Root
id: a1b2c3d4-0010-4000-8000-000000000010
status: stable
description: Detects web shell files in common web server directories
tags:
  - attack.persistence
  - attack.t1505.003
logsource:
  category: file_event
  product: windows
detection:
  webroot:
    TargetFilename|contains:
      - '\inetpub\wwwroot\'
      - '/var/www/'
  webshell_ext:
    TargetFilename|endswith:
      - '.php'
      - '.aspx'
      - '.jsp'
  condition: webroot and webshell_ext
level: high
"@) { $ok++ }

# 11. T1543.003 Windows Service
if (Add-SigmaRule "Malicious Windows Service Creation" @("windows") 8 @("attack.persistence","attack.t1543.003") @"
title: Malicious Windows Service Creation
id: a1b2c3d4-0011-4000-8000-000000000011
status: stable
description: Detects creation of Windows services with suspicious binary paths
tags:
  - attack.persistence
  - attack.t1543.003
logsource:
  category: process_creation
  product: windows
detection:
  sc_create:
    Image|endswith: '\sc.exe'
    CommandLine|contains: 'create'
  suspicious_path:
    CommandLine|contains:
      - '\Temp\'
      - '\AppData\'
      - '\Users\Public\'
      - 'binpath= cmd'
      - 'binpath= powershell'
  condition: sc_create and suspicious_path
level: high
"@) { $ok++ }

# 12. T1546.003 WMI Event Subscription
if (Add-SigmaRule "WMI Event Subscription for Persistence" @("windows") 9 @("attack.persistence","attack.t1546.003") @"
title: WMI Event Subscription Persistence
id: a1b2c3d4-0012-4000-8000-000000000012
status: stable
description: Detects WMI event subscriptions used for persistence
tags:
  - attack.persistence
  - attack.t1546.003
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\wmic.exe'
    CommandLine|contains:
      - 'EventFilter'
      - 'EventConsumer'
      - 'FilterToConsumerBinding'
  condition: selection
level: high
"@) { $ok++ }

# 13. T1548.002 UAC Bypass
if (Add-SigmaRule "UAC Bypass via Known Techniques" @("windows") 8 @("attack.privilege_escalation","attack.t1548.002") @"
title: UAC Bypass via Known Techniques
id: a1b2c3d4-0013-4000-8000-000000000013
status: stable
description: Detects common UAC bypass methods using built-in Windows binaries
tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1548.002
logsource:
  category: process_creation
  product: windows
detection:
  fodhelper:
    ParentImage|endswith: '\fodhelper.exe'
  cmstp:
    Image|endswith: '\cmstp.exe'
    CommandLine|contains: '/au'
  eventvwr_bypass:
    ParentImage|endswith: '\eventvwr.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: fodhelper or cmstp or eventvwr_bypass
level: high
"@) { $ok++ }

# 14. T1552.001 Credentials in Files
if (Add-SigmaRule "Credential Search in Configuration Files" @("windows","linux") 8 @("attack.credential_access","attack.t1552.001") @"
title: Credential Harvesting from Config Files
id: a1b2c3d4-0014-4000-8000-000000000014
status: stable
description: Detects processes searching for credentials in configuration files
tags:
  - attack.credential_access
  - attack.t1552.001
logsource:
  category: process_creation
  product: windows
detection:
  findstr_pwd:
    Image|endswith: '\findstr.exe'
    CommandLine|contains:
      - 'password'
      - 'passwd'
      - 'credential'
  config_ext:
    CommandLine|contains:
      - '.config'
      - 'web.config'
      - '.env'
  condition: findstr_pwd and config_ext
level: high
"@) { $ok++ }

# 15. T1560.001 Archive via Utility
if (Add-SigmaRule "Data Staging via Archive Utility" @("windows") 6 @("attack.collection","attack.t1560.001") @"
title: Data Archiving for Exfiltration Staging
id: a1b2c3d4-0015-4000-8000-000000000015
status: stable
description: Detects archive utilities to stage collected data
tags:
  - attack.collection
  - attack.t1560.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\7z.exe'
      - '\7za.exe'
      - '\rar.exe'
      - '\WinRAR.exe'
    CommandLine|contains:
      - ' a '
      - '-hp'
  condition: selection
level: medium
"@) { $ok++ }

# 16. T1569.002 Service Execution
if (Add-SigmaRule "Remote Service Execution via SCM" @("windows") 7 @("attack.execution","attack.lateral_movement","attack.t1569.002") @"
title: Remote Service Execution via SCM
id: a1b2c3d4-0016-4000-8000-000000000016
status: stable
description: Detects lateral movement via service manager on remote hosts
tags:
  - attack.execution
  - attack.lateral_movement
  - attack.t1569.002
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\sc.exe'
    CommandLine|contains:
      - 'start'
      - '\\\\127.'
  condition: selection
level: medium
"@) { $ok++ }

# 17. T1059.003 Windows Command Shell
if (Add-SigmaRule "Suspicious Windows Command Shell Activity" @("windows") 7 @("attack.execution","attack.t1059.003") @"
title: Suspicious Windows Command Shell
id: a1b2c3d4-0017-4000-8000-000000000017
status: stable
description: Detects cmd.exe used for obfuscation or LOLBin abuse
tags:
  - attack.execution
  - attack.t1059.003
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cmd.exe'
    CommandLine|contains:
      - 'certutil -decode'
      - 'certutil -urlcache'
      - 'copy /b'
  condition: selection
level: medium
"@) { $ok++ }

# 18. T1059.005 Visual Basic / MSHTA
if (Add-SigmaRule "MSHTA or WScript Suspicious Execution" @("windows") 8 @("attack.execution","attack.t1059.005") @"
title: MSHTA or WScript Suspicious Execution
id: a1b2c3d4-0018-4000-8000-000000000018
status: stable
description: Detects mshta or wscript used to run remote scripts
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1059.005
logsource:
  category: process_creation
  product: windows
detection:
  mshta_remote:
    Image|endswith: '\mshta.exe'
    CommandLine|contains:
      - 'http'
      - 'javascript:'
      - 'vbscript:'
  wscript_remote:
    Image|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
    CommandLine|contains: 'http'
  condition: mshta_remote or wscript_remote
level: high
"@) { $ok++ }

# 19. T1136.001 Create Local Account
if (Add-SigmaRule "New Local User Account Created" @("windows") 7 @("attack.persistence","attack.t1136.001") @"
title: New Local User Account Created
id: a1b2c3d4-0019-4000-8000-000000000019
status: stable
description: Detects creation of new local user accounts as possible backdoor
tags:
  - attack.persistence
  - attack.t1136.001
logsource:
  category: process_creation
  product: windows
detection:
  net_user_add:
    Image|endswith:
      - '\net.exe'
      - '\net1.exe'
    CommandLine|contains|all:
      - 'user'
      - '/add'
  condition: net_user_add
level: medium
"@) { $ok++ }

# 20. T1021.001 RDP
if (Add-SigmaRule "RDP Lateral Movement via Mstsc" @("windows") 6 @("attack.lateral_movement","attack.t1021.001") @"
title: RDP Lateral Movement
id: a1b2c3d4-0020-4000-8000-000000000020
status: stable
description: Detects mstsc usage indicating RDP lateral movement
tags:
  - attack.lateral_movement
  - attack.t1021.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\mstsc.exe'
    CommandLine|contains: '/v:'
  condition: selection
level: medium
"@) { $ok++ }

# 21. T1070.004 File Deletion
if (Add-SigmaRule "Log and Evidence File Deletion" @("windows") 7 @("attack.defense_evasion","attack.t1070.004") @"
title: Log and Evidence File Deletion
id: a1b2c3d4-0021-4000-8000-000000000021
status: stable
description: Detects deletion of log files to cover tracks
tags:
  - attack.defense_evasion
  - attack.t1070.004
logsource:
  category: process_creation
  product: windows
detection:
  delete_logs:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
    CommandLine|contains:
      - 'del /f /q'
      - 'Remove-Item -Force'
    CommandLine|contains:
      - '.log'
      - '\Logs\'
      - 'Prefetch'
  condition: delete_logs
level: medium
"@) { $ok++ }

# 22. T1016 Network Config Discovery
if (Add-SigmaRule "Network Configuration Discovery" @("windows") 3 @("attack.discovery","attack.t1016") @"
title: Network Configuration Discovery
id: a1b2c3d4-0022-4000-8000-000000000022
status: stable
description: Detects use of network discovery tools
tags:
  - attack.discovery
  - attack.t1016
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\ipconfig.exe'
      - '\arp.exe'
      - '\route.exe'
      - '\netstat.exe'
      - '\nslookup.exe'
  condition: selection
level: informational
"@) { $ok++ }

# 23. T1018 Remote System Discovery
if (Add-SigmaRule "Remote System Discovery via Ping or Nmap" @("windows","linux") 5 @("attack.discovery","attack.t1018") @"
title: Remote System Discovery
id: a1b2c3d4-0023-4000-8000-000000000023
status: stable
description: Detects network scanning activity for host discovery
tags:
  - attack.discovery
  - attack.t1018
logsource:
  category: process_creation
  product: windows
detection:
  nmap:
    Image|endswith: '\nmap.exe'
  nltest:
    Image|endswith: '\nltest.exe'
    CommandLine|contains:
      - '/domain_trusts'
      - '/dclist'
  ping_sweep:
    Image|endswith: '\ping.exe'
    CommandLine|contains: '-n 1'
  condition: nmap or nltest or ping_sweep
level: medium
"@) { $ok++ }

# 24. Linux Reverse Shell T1059.004
if (Add-SigmaRule "Linux Reverse Shell Execution" @("linux") 9 @("attack.execution","attack.t1059.004") @"
title: Linux Reverse Shell Execution
id: a1b2c3d4-0024-4000-8000-000000000024
status: stable
description: Detects reverse shell one-liners on Linux
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  category: process_creation
  product: linux
detection:
  bash_tcp:
    CommandLine|contains:
      - '/dev/tcp/'
      - 'bash -i >&'
  python_socket:
    CommandLine|contains:
      - 'socket.connect'
      - 'import socket,subprocess'
  nc_reverse:
    CommandLine|contains:
      - 'nc -e'
      - 'ncat -e'
      - 'mkfifo /tmp'
  condition: bash_tcp or python_socket or nc_reverse
level: high
"@) { $ok++ }

# 25. T1574.002 DLL Side-Loading
if (Add-SigmaRule "DLL Side-Loading via Legitimate Application" @("windows") 8 @("attack.defense_evasion","attack.t1574.002") @"
title: DLL Side-Loading Detection
id: a1b2c3d4-0025-4000-8000-000000000025
status: stable
description: Detects DLL loaded from suspicious path by trusted process
tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.t1574.002
logsource:
  category: image_load
  product: windows
detection:
  suspicious_dll:
    ImageLoaded|contains:
      - '\AppData\Local\Temp\'
      - '\Users\Public\'
    ImageLoaded|endswith: '.dll'
  trusted_process:
    Image|endswith:
      - '\OneDrive.exe'
      - '\Teams.exe'
      - '\Zoom.exe'
  condition: suspicious_dll and trusted_process
level: high
"@) { $ok++ }

Write-Host ""
Write-Host "========================================"
Write-Host "完了: $ok / 25 ルール追加成功"
