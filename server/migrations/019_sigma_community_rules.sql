-- Migration 019: Insert ~40 SigmaHQ community rules
-- Idempotent: uses ON CONFLICT DO NOTHING

-- ============================================================
-- LATERAL MOVEMENT
-- ============================================================

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0001-0001-0001-000000000001',
  'PsExec Lateral Movement',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: PsExec Lateral Movement
id: a1b2c3d4-0001-0001-0001-000000000001
status: stable
description: Detects PsExec usage for lateral movement via process creation or named pipe activity
references:
  - https://attack.mitre.org/techniques/T1021/002/
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith:
      - '\psexec.exe'
      - '\psexec64.exe'
      - '\PsExec.exe'
  selection_cmdline:
    CommandLine|contains:
      - ' \\\\'
      - ' -s '
      - ' /s '
  filter_legitimate:
    User|contains:
      - 'SYSTEM'
  condition: selection_image or (selection_cmdline and not filter_legitimate)
falsepositives:
  - Legitimate administrative PsExec usage by IT staff
level: high$$,
  true,
  false,
  false,
  ARRAY['T1021.002', 'T1570'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0001-0001-0001-000000000002',
  'WMI Remote Execution',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: WMI Remote Execution
id: a1b2c3d4-0001-0001-0001-000000000002
status: stable
description: Detects remote WMI execution which is commonly used for lateral movement
references:
  - https://attack.mitre.org/techniques/T1047/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\cscript.exe'
      - '\wscript.exe'
      - '\mshta.exe'
      - '\certutil.exe'
  condition: selection
falsepositives:
  - Legitimate WMI-based management tools
  - Configuration management software (SCCM, etc.)
level: high$$,
  true,
  false,
  false,
  ARRAY['T1047', 'T1021'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0001-0001-0001-000000000003',
  'RDP Lateral Movement via xfreerdp or mstsc',
  'sigma',
  ARRAY['windows'],
  5,
  $$title: RDP Lateral Movement via xfreerdp or mstsc
id: a1b2c3d4-0001-0001-0001-000000000003
status: stable
description: Detects RDP client usage that may indicate lateral movement activity
references:
  - https://attack.mitre.org/techniques/T1021/001/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\mstsc.exe'
    CommandLine|contains:
      - ' /v:'
  selection_foreign:
    Image|endswith:
      - '\xfreerdp.exe'
      - '\rdesktop.exe'
  condition: selection or selection_foreign
falsepositives:
  - Legitimate remote desktop usage by administrators
level: medium$$,
  true,
  false,
  false,
  ARRAY['T1021.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0001-0001-0001-000000000004',
  'SMB Lateral Movement - Admin Share Access',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: SMB Lateral Movement - Admin Share Access
id: a1b2c3d4-0001-0001-0001-000000000004
status: stable
description: Detects access to administrative shares (ADMIN$, C$, IPC$) which is commonly used for lateral movement
references:
  - https://attack.mitre.org/techniques/T1021/002/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5140
    ShareName|contains:
      - 'ADMIN$'
      - 'C$'
      - 'D$'
      - 'IPC$'
  filter_legitimate:
    SubjectUserName|endswith: '$'
  condition: selection and not filter_legitimate
falsepositives:
  - Backup software accessing admin shares
  - Legitimate administrative tasks
level: high$$,
  true,
  false,
  false,
  ARRAY['T1021.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0001-0001-0001-000000000005',
  'Pass-the-Hash via Mimikatz sekurlsa::pth',
  'sigma',
  ARRAY['windows'],
  9,
  $$title: Pass-the-Hash via Mimikatz sekurlsa::pth
id: a1b2c3d4-0001-0001-0001-000000000005
status: stable
description: Detects pass-the-hash attacks using Mimikatz sekurlsa::pth module
references:
  - https://attack.mitre.org/techniques/T1550/002/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'sekurlsa::pth'
      - 'sekurlsa::wdigest'
  condition: selection
falsepositives:
  - Security testing or red team operations
level: critical$$,
  true,
  false,
  false,
  ARRAY['T1550.002', 'T1003.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- CREDENTIAL ACCESS
-- ============================================================

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0002-0002-0002-000000000006',
  'Mimikatz Credential Dumping',
  'sigma',
  ARRAY['windows'],
  9,
  $$title: Mimikatz Credential Dumping
id: a1b2c3d4-0002-0002-0002-000000000006
status: stable
description: Detects Mimikatz credential dumping tool execution via common command-line arguments
references:
  - https://attack.mitre.org/techniques/T1003/001/
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|contains:
      - 'mimikatz'
  selection_cmdline:
    CommandLine|contains:
      - 'sekurlsa::'
      - 'lsadump::'
      - 'kerberos::'
      - 'crypto::'
      - 'privilege::debug'
  condition: selection_image or selection_cmdline
falsepositives:
  - Penetration testing or authorized red team engagements
level: critical$$,
  true,
  false,
  false,
  ARRAY['T1003.001', 'T1003'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0002-0002-0002-000000000007',
  'LSASS Memory Dump via Procdump',
  'sigma',
  ARRAY['windows'],
  9,
  $$title: LSASS Memory Dump via Procdump
id: a1b2c3d4-0002-0002-0002-000000000007
status: stable
description: Detects usage of Sysinternals ProcDump tool to dump LSASS process memory for credential extraction
references:
  - https://attack.mitre.org/techniques/T1003/001/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\procdump.exe'
    CommandLine|contains:
      - 'lsass'
  selection_64:
    Image|endswith: '\procdump64.exe'
    CommandLine|contains:
      - 'lsass'
  condition: selection or selection_64
falsepositives:
  - Legitimate debugging of LSASS by security teams
level: critical$$,
  true,
  true,
  false,
  ARRAY['T1003.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0002-0002-0002-000000000008',
  'SAM Database Dump via reg.exe',
  'sigma',
  ARRAY['windows'],
  9,
  $$title: SAM Database Dump via reg.exe
id: a1b2c3d4-0002-0002-0002-000000000008
status: stable
description: Detects attempts to dump the SAM database using reg.exe to extract local account credentials
references:
  - https://attack.mitre.org/techniques/T1003/002/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\reg.exe'
    CommandLine|contains|all:
      - 'save'
      - 'hklm\sam'
  condition: selection
falsepositives:
  - Backup operations that include the SAM hive
level: critical$$,
  true,
  true,
  false,
  ARRAY['T1003.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0002-0002-0002-000000000009',
  'LSASS Access via Task Manager or Comsvcs',
  'sigma',
  ARRAY['windows'],
  9,
  $$title: LSASS Access via Task Manager or Comsvcs
id: a1b2c3d4-0002-0002-0002-000000000009
status: stable
description: Detects LSASS memory dumping via comsvcs.dll MiniDump or Task Manager
references:
  - https://attack.mitre.org/techniques/T1003/001/
logsource:
  category: process_creation
  product: windows
detection:
  selection_comsvcs:
    CommandLine|contains|all:
      - 'comsvcs'
      - 'MiniDump'
  selection_taskmgr:
    Image|endswith: '\taskmgr.exe'
    CommandLine|contains: 'lsass'
  condition: selection_comsvcs or selection_taskmgr
falsepositives:
  - Authorized memory analysis
level: critical$$,
  true,
  true,
  false,
  ARRAY['T1003.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0002-0002-0002-000000000010',
  'Credential Dumping via DCSync',
  'sigma',
  ARRAY['windows'],
  9,
  $$title: Credential Dumping via DCSync
id: a1b2c3d4-0002-0002-0002-000000000010
status: stable
description: Detects DCSync attack which replicates Active Directory credentials by abusing replication rights
references:
  - https://attack.mitre.org/techniques/T1003/006/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
      - '89e95b76-444d-4c62-991a-0facbeda640c'
  filter_legitimate:
    SubjectUserName|endswith: '$'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate domain controller replication
level: critical$$,
  true,
  true,
  false,
  ARRAY['T1003.006'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- PERSISTENCE
-- ============================================================

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0003-0003-0003-000000000011',
  'Registry Run Key Persistence',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: Registry Run Key Persistence
id: a1b2c3d4-0003-0003-0003-000000000011
status: stable
description: Detects modification of registry run keys commonly used for persistence
references:
  - https://attack.mitre.org/techniques/T1547/001/
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains:
      - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
      - '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
      - '\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
      - '\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
  filter_known_legit:
    Details|contains:
      - 'MicrosoftEdge'
      - 'OneDrive'
      - 'SecurityHealth'
  condition: selection and not filter_known_legit
falsepositives:
  - Legitimate software installations adding startup entries
level: high$$,
  true,
  false,
  false,
  ARRAY['T1547.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0003-0003-0003-000000000012',
  'Scheduled Task Creation via schtasks.exe',
  'sigma',
  ARRAY['windows'],
  5,
  $$title: Scheduled Task Creation via schtasks.exe
id: a1b2c3d4-0003-0003-0003-000000000012
status: stable
description: Detects creation of scheduled tasks via schtasks.exe that may be used for persistence or privilege escalation
references:
  - https://attack.mitre.org/techniques/T1053/005/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: '/create'
  filter_system:
    User|contains: 'SYSTEM'
    CommandLine|contains:
      - 'Microsoft'
      - 'Windows'
  condition: selection and not filter_system
falsepositives:
  - Legitimate software creating scheduled tasks during installation
  - Administrative scripts
level: medium$$,
  true,
  false,
  false,
  ARRAY['T1053.005'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0003-0003-0003-000000000013',
  'Malicious Service Installation',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: Malicious Service Installation
id: a1b2c3d4-0003-0003-0003-000000000013
status: stable
description: Detects creation of new services with suspicious binary paths or from unusual locations
references:
  - https://attack.mitre.org/techniques/T1543/003/
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
  filter_legit_paths:
    ImagePath|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
  condition: selection and not filter_legit_paths
falsepositives:
  - Legitimate third-party software installing services from non-standard locations
level: high$$,
  true,
  false,
  false,
  ARRAY['T1543.003'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0003-0003-0003-000000000014',
  'DLL Side-Loading via Suspicious Path',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: DLL Side-Loading via Suspicious Path
id: a1b2c3d4-0003-0003-0003-000000000014
status: stable
description: Detects DLL side-loading by monitoring trusted executables loading DLLs from user-writable directories
references:
  - https://attack.mitre.org/techniques/T1574/002/
logsource:
  category: image_load
  product: windows
detection:
  selection:
    ImageLoaded|contains:
      - '\AppData\Local\'
      - '\AppData\Roaming\'
      - '\Users\Public\'
      - '\Temp\'
    Image|contains:
      - '\Microsoft Office\'
      - '\Program Files\Microsoft'
  condition: selection
falsepositives:
  - Legitimate plugins loaded from user directories
level: high$$,
  true,
  false,
  false,
  ARRAY['T1574.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0003-0003-0003-000000000015',
  'WinLogon Helper DLL Persistence',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: WinLogon Helper DLL Persistence
id: a1b2c3d4-0003-0003-0003-000000000015
status: stable
description: Detects modification of Winlogon helper DLL registry keys used for persistence
references:
  - https://attack.mitre.org/techniques/T1547/004/
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains:
      - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit'
      - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell'
      - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify'
  condition: selection
falsepositives:
  - Legitimate system configuration changes
level: high$$,
  true,
  false,
  false,
  ARRAY['T1547.004'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- DISCOVERY
-- ============================================================

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0004-0004-0004-000000000016',
  'System Discovery via whoami and systeminfo',
  'sigma',
  ARRAY['windows'],
  3,
  $$title: System Discovery via whoami and systeminfo
id: a1b2c3d4-0004-0004-0004-000000000016
status: stable
description: Detects execution of common system discovery commands often used by attackers in the reconnaissance phase
references:
  - https://attack.mitre.org/techniques/T1033/
  - https://attack.mitre.org/techniques/T1082/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\whoami.exe'
      - '\systeminfo.exe'
      - '\hostname.exe'
  condition: selection
falsepositives:
  - IT administrators running diagnostics
  - Automated IT management scripts
level: low$$,
  true,
  false,
  false,
  ARRAY['T1033', 'T1082'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0004-0004-0004-000000000017',
  'Network Discovery via net.exe',
  'sigma',
  ARRAY['windows'],
  3,
  $$title: Network Discovery via net.exe
id: a1b2c3d4-0004-0004-0004-000000000017
status: stable
description: Detects use of net.exe for network and user enumeration, commonly used during the discovery phase
references:
  - https://attack.mitre.org/techniques/T1087/
  - https://attack.mitre.org/techniques/T1069/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\net.exe'
      - '\net1.exe'
    CommandLine|contains:
      - ' user'
      - ' group'
      - ' localgroup'
      - ' accounts'
      - ' share'
      - ' view'
  condition: selection
falsepositives:
  - Legitimate user and group management by administrators
level: low$$,
  true,
  false,
  false,
  ARRAY['T1087.001', 'T1069.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0004-0004-0004-000000000018',
  'Network Configuration Discovery via ipconfig',
  'sigma',
  ARRAY['windows'],
  3,
  $$title: Network Configuration Discovery via ipconfig
id: a1b2c3d4-0004-0004-0004-000000000018
status: stable
description: Detects execution of ipconfig to discover network configuration, commonly used for network reconnaissance
references:
  - https://attack.mitre.org/techniques/T1016/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\ipconfig.exe'
    CommandLine|contains:
      - '/all'
  condition: selection
falsepositives:
  - Routine IT diagnostics
level: low$$,
  true,
  false,
  false,
  ARRAY['T1016'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0004-0004-0004-000000000019',
  'Active Directory Enumeration via AdFind or BloodHound',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: Active Directory Enumeration via AdFind or BloodHound
id: a1b2c3d4-0004-0004-0004-000000000019
status: stable
description: Detects use of AdFind or BloodHound for Active Directory enumeration
references:
  - https://attack.mitre.org/techniques/T1482/
logsource:
  category: process_creation
  product: windows
detection:
  selection_adfind:
    Image|endswith: '\adfind.exe'
  selection_bloodhound:
    Image|endswith:
      - '\SharpHound.exe'
      - '\bloodhound.exe'
  selection_cmdline_adfind:
    CommandLine|contains:
      - 'adfind'
      - '-f objectcategory'
  condition: selection_adfind or selection_bloodhound or selection_cmdline_adfind
falsepositives:
  - Security auditing using legitimate AD tools
level: high$$,
  true,
  false,
  false,
  ARRAY['T1482', 'T1087.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0004-0004-0004-000000000020',
  'Port Scan via nmap or masscan',
  'sigma',
  ARRAY['windows', 'linux'],
  5,
  $$title: Port Scan via nmap or masscan
id: a1b2c3d4-0004-0004-0004-000000000020
status: stable
description: Detects port scanning tools which may indicate network reconnaissance
references:
  - https://attack.mitre.org/techniques/T1046/
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith:
      - '/nmap'
      - '/masscan'
      - '/zmap'
    CommandLine|contains:
      - '-sS'
      - '-sV'
      - '-sC'
      - '--rate'
  condition: selection
falsepositives:
  - Authorized network security scanning
level: medium$$,
  true,
  false,
  false,
  ARRAY['T1046'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- COMMAND & CONTROL
-- ============================================================

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0005-0005-0005-000000000021',
  'PowerShell Download Cradle',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: PowerShell Download Cradle
id: a1b2c3d4-0005-0005-0005-000000000021
status: stable
description: Detects PowerShell download cradles commonly used to download and execute malicious payloads from the internet
references:
  - https://attack.mitre.org/techniques/T1059/001/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - 'DownloadString'
      - 'DownloadFile'
      - 'WebClient'
      - 'Net.WebClient'
      - 'IEX'
      - 'Invoke-Expression'
      - 'Start-BitsTransfer'
      - 'bitsadmin'
  condition: selection
falsepositives:
  - Legitimate PowerShell-based software deployment
  - Administrative automation scripts
level: high$$,
  true,
  false,
  false,
  ARRAY['T1059.001', 'T1105'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0005-0005-0005-000000000022',
  'PowerShell Base64 Encoded Command',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: PowerShell Base64 Encoded Command
id: a1b2c3d4-0005-0005-0005-000000000022
status: stable
description: Detects PowerShell execution with base64 encoded commands, a common obfuscation technique
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1027/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -e '
      - '-encodedcommand'
  condition: selection
falsepositives:
  - Some legitimate management tools use encoded PS commands
level: high$$,
  true,
  false,
  false,
  ARRAY['T1059.001', 'T1027'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0005-0005-0005-000000000023',
  'Suspicious certutil Usage for File Download',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: Suspicious certutil Usage for File Download
id: a1b2c3d4-0005-0005-0005-000000000023
status: stable
description: Detects use of certutil.exe to download files, a known Living-off-the-Land technique
references:
  - https://attack.mitre.org/techniques/T1140/
  - https://attack.mitre.org/techniques/T1105/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - '-decode'
      - '-encode'
      - 'http'
  condition: selection
falsepositives:
  - Legitimate certificate operations
level: high$$,
  true,
  false,
  false,
  ARRAY['T1140', 'T1105'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0005-0005-0005-000000000024',
  'Suspicious Outbound Connection on Non-Standard Port',
  'sigma',
  ARRAY['windows', 'linux'],
  5,
  $$title: Suspicious Outbound Connection on Non-Standard Port
id: a1b2c3d4-0005-0005-0005-000000000024
status: experimental
description: Detects outbound network connections from common system processes on unusual ports that may indicate C2 activity
references:
  - https://attack.mitre.org/techniques/T1571/
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Initiated: 'true'
    Image|endswith:
      - '\svchost.exe'
      - '\lsass.exe'
      - '\winlogon.exe'
      - '\explorer.exe'
  filter_std_ports:
    DestinationPort:
      - 80
      - 443
      - 445
      - 135
      - 139
      - 53
  condition: selection and not filter_std_ports
falsepositives:
  - Legitimate software using non-standard ports
level: medium$$,
  true,
  false,
  false,
  ARRAY['T1571'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0005-0005-0005-000000000025',
  'Cobalt Strike Beacon via Named Pipe',
  'sigma',
  ARRAY['windows'],
  9,
  $$title: Cobalt Strike Beacon via Named Pipe
id: a1b2c3d4-0005-0005-0005-000000000025
status: stable
description: Detects Cobalt Strike Beacon activity via characteristic named pipe patterns
references:
  - https://attack.mitre.org/techniques/T1071/
logsource:
  category: pipe_created
  product: windows
detection:
  selection:
    PipeName|contains:
      - '\postex_'
      - '\mojo.'
      - '\interprocess_'
      - '\msagent_'
      - '\DserNamePipe'
      - '\wkssvc_'
  condition: selection
falsepositives:
  - Some legitimate applications use similar named pipe patterns
level: critical$$,
  true,
  true,
  false,
  ARRAY['T1071', 'T1055'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- DEFENSE EVASION
-- ============================================================

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0006-0006-0006-000000000026',
  'AMSI Bypass via PowerShell',
  'sigma',
  ARRAY['windows'],
  9,
  $$title: AMSI Bypass via PowerShell
id: a1b2c3d4-0006-0006-0006-000000000026
status: stable
description: Detects attempts to bypass the Antimalware Scan Interface (AMSI) via PowerShell commands
references:
  - https://attack.mitre.org/techniques/T1562.001/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - 'amsiInitFailed'
      - '[Ref].Assembly.GetType'
      - 'AmsiUtils'
      - 'amsiContext'
      - 'SetValue($null'
      - 'amsi.dll'
  condition: selection
falsepositives:
  - Security research or authorized testing
level: critical$$,
  true,
  false,
  false,
  ARRAY['T1562.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0006-0006-0006-000000000027',
  'ETW Patching via NtTraceControl',
  'sigma',
  ARRAY['windows'],
  9,
  $$title: ETW Patching via NtTraceControl
id: a1b2c3d4-0006-0006-0006-000000000027
status: experimental
description: Detects attempts to disable Event Tracing for Windows (ETW) by patching NtTraceControl
references:
  - https://attack.mitre.org/techniques/T1562.006/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'NtTraceControl'
      - 'EtwpCreateEtwThread'
      - '[Runtime.InteropServices.Marshal]::Copy'
  condition: selection
falsepositives:
  - Security tooling that patches ETW for performance
level: critical$$,
  true,
  false,
  false,
  ARRAY['T1562.006'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0006-0006-0006-000000000028',
  'Process Hollowing via Suspicious Executable',
  'sigma',
  ARRAY['windows'],
  9,
  $$title: Process Hollowing via Suspicious Executable
id: a1b2c3d4-0006-0006-0006-000000000028
status: experimental
description: Detects process hollowing by identifying processes created in suspended state and then modified
references:
  - https://attack.mitre.org/techniques/T1055/012/
logsource:
  category: create_remote_thread
  product: windows
detection:
  selection:
    TargetImage|endswith:
      - '\svchost.exe'
      - '\explorer.exe'
      - '\notepad.exe'
      - '\regsvr32.exe'
    SourceImage|startswith:
      - 'C:\Users\'
      - 'C:\Temp\'
      - 'C:\ProgramData\'
  condition: selection
falsepositives:
  - Some legitimate injection-based tools
level: critical$$,
  true,
  true,
  false,
  ARRAY['T1055.012'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0006-0006-0006-000000000029',
  'Suspicious Regsvr32 Usage for LOLBin Execution',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: Suspicious Regsvr32 Usage for LOLBin Execution
id: a1b2c3d4-0006-0006-0006-000000000029
status: stable
description: Detects abuse of regsvr32.exe to execute malicious scripts or DLLs bypassing AppLocker
references:
  - https://attack.mitre.org/techniques/T1218.010/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\regsvr32.exe'
    CommandLine|contains:
      - '/s'
      - '/i:'
      - 'scrobj.dll'
      - 'http'
      - '.sct'
  condition: selection
falsepositives:
  - Legitimate COM server registration
level: high$$,
  true,
  false,
  false,
  ARRAY['T1218.010'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0006-0006-0006-000000000030',
  'Windows Defender Exclusion Added',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: Windows Defender Exclusion Added
id: a1b2c3d4-0006-0006-0006-000000000030
status: stable
description: Detects addition of Windows Defender exclusions which may indicate an attempt to evade AV detection
references:
  - https://attack.mitre.org/techniques/T1562.001/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all:
      - 'Add-MpPreference'
      - 'ExclusionPath'
  selection_cmd:
    Image|endswith: '\cmd.exe'
    CommandLine|contains|all:
      - 'MpCmdRun'
      - 'ExclusionPath'
  condition: selection or selection_cmd
falsepositives:
  - Legitimate software requiring AV exclusions during installation
level: high$$,
  true,
  false,
  false,
  ARRAY['T1562.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- LINUX-SPECIFIC
-- ============================================================

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0007-0007-0007-000000000031',
  'Crontab Modification for Persistence',
  'sigma',
  ARRAY['linux'],
  7,
  $$title: Crontab Modification for Persistence
id: a1b2c3d4-0007-0007-0007-000000000031
status: stable
description: Detects modification of crontab files which may be used for persistence on Linux systems
references:
  - https://attack.mitre.org/techniques/T1053/003/
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename|contains:
      - '/etc/cron'
      - '/var/spool/cron'
      - '/etc/crontab'
  filter_root_routine:
    User: 'root'
    ProcessName|contains: 'cron'
  condition: selection and not filter_root_routine
falsepositives:
  - Legitimate cron job management by system administrators
level: high$$,
  true,
  false,
  false,
  ARRAY['T1053.003'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0007-0007-0007-000000000032',
  '/etc/passwd or /etc/shadow Modification',
  'sigma',
  ARRAY['linux'],
  9,
  $$title: /etc/passwd or /etc/shadow Modification
id: a1b2c3d4-0007-0007-0007-000000000032
status: stable
description: Detects unauthorized modification of /etc/passwd or /etc/shadow files which may indicate credential manipulation
references:
  - https://attack.mitre.org/techniques/T1136/001/
  - https://attack.mitre.org/techniques/T1003/008/
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename|contains:
      - '/etc/passwd'
      - '/etc/shadow'
      - '/etc/sudoers'
  filter_legit:
    ProcessName|contains:
      - 'passwd'
      - 'useradd'
      - 'usermod'
      - 'adduser'
  condition: selection and not filter_legit
falsepositives:
  - Legitimate user management operations
level: critical$$,
  true,
  false,
  false,
  ARRAY['T1136.001', 'T1003.008'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0007-0007-0007-000000000033',
  'SSH Authorized Keys Modification',
  'sigma',
  ARRAY['linux'],
  7,
  $$title: SSH Authorized Keys Modification
id: a1b2c3d4-0007-0007-0007-000000000033
status: stable
description: Detects modification of SSH authorized_keys files which may be used to establish persistent access
references:
  - https://attack.mitre.org/techniques/T1098.004/
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename|contains:
      - '/.ssh/authorized_keys'
      - '/.ssh/authorized_keys2'
  condition: selection
falsepositives:
  - Legitimate SSH key management by administrators
level: high$$,
  true,
  false,
  false,
  ARRAY['T1098.004'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0007-0007-0007-000000000034',
  'Linux Reverse Shell via Bash',
  'sigma',
  ARRAY['linux'],
  9,
  $$title: Linux Reverse Shell via Bash
id: a1b2c3d4-0007-0007-0007-000000000034
status: stable
description: 'Detects common bash reverse shell techniques used to establish C2 connections on Linux systems. NOTE: auto_isolate is disabled to prevent false positives from legitimate network diagnostic tools using /dev/tcp/.'
references:
  - https://attack.mitre.org/techniques/T1059.004/
logsource:
  category: process_creation
  product: linux
detection:
  selection_bash:
    CommandLine|contains:
      - '/dev/tcp/'
      - '/dev/udp/'
      - 'bash -i'
  selection_nc:
    Image|contains: '/nc'
    CommandLine|contains:
      - '-e /bin/bash'
      - '-e /bin/sh'
  condition: selection_bash or selection_nc
falsepositives:
  - Network testing utilities
level: critical$$,
  true,
  false,  -- auto_isolate=false: /dev/tcp/ は診断ツールでも使用されるため誤検知を防ぐ
  false,
  ARRAY['T1059.004'],
  NOW()
) ON CONFLICT (id) DO UPDATE SET auto_isolate=false;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0007-0007-0007-000000000035',
  'Suspicious chmod of Executable in /tmp',
  'sigma',
  ARRAY['linux'],
  7,
  $$title: Suspicious chmod of Executable in /tmp
id: a1b2c3d4-0007-0007-0007-000000000035
status: stable
description: Detects making files executable in /tmp directory which is a common technique used to prepare malware for execution
references:
  - https://attack.mitre.org/techniques/T1222.002/
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|contains: '/chmod'
    CommandLine|contains:
      - '+x'
      - '755'
      - '777'
    CommandLine|contains:
      - '/tmp/'
      - '/dev/shm/'
  condition: selection
falsepositives:
  - Legitimate temporary file operations
level: high$$,
  true,
  false,
  false,
  ARRAY['T1222.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- NETWORK DETECTIONS
-- ============================================================

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0008-0008-0008-000000000036',
  'DNS Beaconing to Suspicious TLD',
  'sigma',
  ARRAY['windows', 'linux'],
  5,
  $$title: DNS Beaconing to Suspicious TLD
id: a1b2c3d4-0008-0008-0008-000000000036
status: experimental
description: Detects DNS queries to suspicious top-level domains commonly used for C2 infrastructure
references:
  - https://attack.mitre.org/techniques/T1568/
logsource:
  category: dns
  product: windows
detection:
  selection:
    QueryName|endswith:
      - '.tk'
      - '.ml'
      - '.ga'
      - '.cf'
      - '.gq'
      - '.top'
      - '.xyz'
      - '.pw'
  filter_known_legit:
    QueryName|contains:
      - 'windows.net'
      - 'azure.com'
      - 'microsoft.com'
  condition: selection and not filter_known_legit
falsepositives:
  - Legitimate services using free TLDs
level: medium$$,
  true,
  false,
  false,
  ARRAY['T1568', 'T1071.004'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0008-0008-0008-000000000037',
  'High-Volume DNS Queries Indicating DGA',
  'sigma',
  ARRAY['windows', 'linux'],
  7,
  $$title: High-Volume DNS Queries Indicating DGA
id: a1b2c3d4-0008-0008-0008-000000000037
status: experimental
description: Detects high-entropy domain name lookups that may indicate Domain Generation Algorithm (DGA) activity used for C2
references:
  - https://attack.mitre.org/techniques/T1568.002/
logsource:
  category: dns
  product: windows
detection:
  selection:
    QueryName|re: '^[a-z0-9]{12,}\.(?:com|net|org|info)$'
  condition: selection
falsepositives:
  - CDN or analytics services with long domain names
level: high$$,
  false,
  false,
  false,
  ARRAY['T1568.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0008-0008-0008-000000000038',
  'Suspicious Connection to Tor Exit Node',
  'sigma',
  ARRAY['windows', 'linux'],
  7,
  $$title: Suspicious Connection to Tor Exit Node
id: a1b2c3d4-0008-0008-0008-000000000038
status: experimental
description: Detects connections to known Tor exit nodes on port 9050 or 9001 which may indicate use of Tor for anonymization
references:
  - https://attack.mitre.org/techniques/T1090.003/
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationPort:
      - 9050
      - 9001
      - 9030
  condition: selection
falsepositives:
  - Legitimate use of Tor browser for privacy
level: high$$,
  true,
  false,
  false,
  ARRAY['T1090.003'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0008-0008-0008-000000000039',
  'FTP Data Exfiltration over Non-Standard Port',
  'sigma',
  ARRAY['windows', 'linux'],
  7,
  $$title: FTP Data Exfiltration over Non-Standard Port
id: a1b2c3d4-0008-0008-0008-000000000039
status: experimental
description: Detects potential data exfiltration via FTP protocol on non-standard ports
references:
  - https://attack.mitre.org/techniques/T1048.003/
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Image|endswith:
      - '\ftp.exe'
      - '\wftp.exe'
  filter_std_ports:
    DestinationPort:
      - 21
      - 22
  condition: selection and not filter_std_ports
falsepositives:
  - Legitimate use of non-standard FTP servers
level: high$$,
  true,
  false,
  false,
  ARRAY['T1048.003'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- ADDITIONAL HIGH-VALUE RULES
-- ============================================================

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0009-0009-0009-000000000040',
  'Ransomware File Extension Modification',
  'sigma',
  ARRAY['windows'],
  9,
  $$title: Ransomware File Extension Modification
id: a1b2c3d4-0009-0009-0009-000000000040
status: stable
description: Detects mass file renaming or extension modification that is characteristic of ransomware encryption activity
references:
  - https://attack.mitre.org/techniques/T1486/
logsource:
  category: file_rename
  product: windows
detection:
  selection:
    TargetFilename|endswith:
      - '.locked'
      - '.encrypted'
      - '.crypted'
      - '.crypt'
      - '.enc'
      - '.WNCRY'
      - '.wnry'
      - '.wcry'
      - '.wncrypt'
      - '.ZCRYPT'
      - '.locky'
      - '.zepto'
      - '.thor'
      - '.cerber'
  condition: selection
falsepositives:
  - Encryption software working on user files
level: critical$$,
  true,
  true,
  true,
  ARRAY['T1486'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0009-0009-0009-000000000041',
  'Shadow Copy Deletion via vssadmin or wmic',
  'sigma',
  ARRAY['windows'],
  9,
  $$title: Shadow Copy Deletion via vssadmin or wmic
id: a1b2c3d4-0009-0009-0009-000000000041
status: stable
description: Detects deletion of volume shadow copies which is commonly performed by ransomware to prevent recovery
references:
  - https://attack.mitre.org/techniques/T1490/
logsource:
  category: process_creation
  product: windows
detection:
  selection_vssadmin:
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'shadows'
  selection_wmic:
    Image|endswith: '\wmic.exe'
    CommandLine|contains|all:
      - 'shadowcopy'
      - 'delete'
  selection_powershell:
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all:
      - 'Get-WmiObject'
      - 'Win32_Shadowcopy'
      - 'Delete'
  condition: selection_vssadmin or selection_wmic or selection_powershell
falsepositives:
  - Legitimate backup management operations
level: critical$$,
  true,
  true,
  true,
  ARRAY['T1490'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0009-0009-0009-000000000042',
  'Kerberoasting via Rubeus or Impacket',
  'sigma',
  ARRAY['windows'],
  9,
  $$title: Kerberoasting via Rubeus or Impacket
id: a1b2c3d4-0009-0009-0009-000000000042
status: stable
description: Detects Kerberoasting attacks via known tools like Rubeus or Impacket targeting service account credentials
references:
  - https://attack.mitre.org/techniques/T1558.003/
logsource:
  category: process_creation
  product: windows
detection:
  selection_rubeus:
    CommandLine|contains:
      - 'rubeus'
      - 'kerberoast'
      - 'asreproast'
  selection_event:
    EventID: 4769
    ServiceName|not_startswith: '$'
    TicketEncryptionType: '0x17'
  condition: selection_rubeus or selection_event
falsepositives:
  - Legitimate Kerberos service ticket requests
level: critical$$,
  true,
  false,
  false,
  ARRAY['T1558.003'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0009-0009-0009-000000000043',
  'mshta.exe Executing Remote Script',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: mshta.exe Executing Remote Script
id: a1b2c3d4-0009-0009-0009-000000000043
status: stable
description: Detects mshta.exe executing remote HTA files which is commonly used in phishing attacks and initial access
references:
  - https://attack.mitre.org/techniques/T1218.005/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\mshta.exe'
    CommandLine|contains:
      - 'http'
      - 'ftp'
      - 'javascript'
      - 'vbscript'
  condition: selection
falsepositives:
  - Some web-based enterprise applications
level: high$$,
  true,
  false,
  false,
  ARRAY['T1218.005'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0009-0009-0009-000000000044',
  'Suspicious wscript/cscript Execution',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: Suspicious wscript/cscript Execution
id: a1b2c3d4-0009-0009-0009-000000000044
status: stable
description: Detects suspicious usage of Windows Script Host engines to execute malicious VBScript or JScript files
references:
  - https://attack.mitre.org/techniques/T1059.005/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
    CommandLine|contains:
      - '.vbs'
      - '.js'
      - '.jse'
      - '.vbe'
      - '.wsf'
    CommandLine|contains:
      - '\Temp\'
      - '\AppData\'
      - '\Users\Public\'
  condition: selection
falsepositives:
  - Legitimate business automation scripts
level: high$$,
  true,
  false,
  false,
  ARRAY['T1059.005'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'a1b2c3d4-0009-0009-0009-000000000045',
  'UAC Bypass via Fodhelper',
  'sigma',
  ARRAY['windows'],
  7,
  $$title: UAC Bypass via Fodhelper
id: a1b2c3d4-0009-0009-0009-000000000045
status: stable
description: Detects User Account Control bypass using fodhelper.exe, a well-known UAC bypass technique
references:
  - https://attack.mitre.org/techniques/T1548.002/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\fodhelper.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: selection
falsepositives:
  - None known
level: high$$,
  true,
  false,
  false,
  ARRAY['T1548.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;
