-- Migration 014: Lateral Movement & Persistence Detection Rules
-- Adds Sigma rules for MITRE ATT&CK techniques:
--   T1021 - Remote Services (lateral movement)
--   T1543 - Create or Modify System Process (persistence)
--   T1053 - Scheduled Task/Job (persistence)
--   T1547 - Boot or Logon Autostart Execution (persistence)
--   T1055 - Process Injection
--   T1003 - OS Credential Dumping

INSERT INTO rules (name, type, platform, severity, content, enabled, mitre_tags, description)
VALUES

-- ── Lateral Movement ──────────────────────────────────────────────────────────

(
  'Remote Service Execution via PsExec',
  'sigma', ARRAY['windows'], 8,
  $SIGMA$
title: Remote Service Execution via PsExec
status: stable
description: Detects PsExec execution which is commonly used for lateral movement
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\psexec.exe'
            - '\psexec64.exe'
            - '\PsExec.exe'
        CommandLine|contains:
            - ' \\\\'
    condition: selection
falsepositives:
    - Legitimate administrative use
level: high
$SIGMA$,
  TRUE, ARRAY['T1021.002'], 'PsExecによるリモート実行の検出'
),

(
  'WMI Remote Command Execution',
  'sigma', ARRAY['windows'], 8,
  $SIGMA$
title: WMI Remote Command Execution
status: stable
description: Detects remote command execution via Windows Management Instrumentation
logsource:
    category: process_creation
    product: windows
detection:
    selection_wmic:
        Image|endswith: '\wmic.exe'
        CommandLine|contains:
            - '/node:'
    selection_wmi_spawn:
        ParentImage|endswith: '\WmiPrvSE.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\cscript.exe'
    condition: selection_wmic or selection_wmi_spawn
falsepositives:
    - Legitimate WMI administration
level: high
$SIGMA$,
  TRUE, ARRAY['T1021.006', 'T1047'], 'WMIを使用したリモートコマンド実行の検出'
),

(
  'Lateral Movement via RDP',
  'sigma', ARRAY['windows'], 7,
  $SIGMA$
title: Lateral Movement via RDP
status: stable
description: Detects suspicious RDP usage patterns indicative of lateral movement
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\mstsc.exe'
        CommandLine|contains:
            - '/v:'
    condition: selection
falsepositives:
    - Legitimate remote desktop sessions
level: medium
$SIGMA$,
  TRUE, ARRAY['T1021.001'], 'RDPによる横断的移動の検出'
),

(
  'SMB/Admin Share Access',
  'sigma', ARRAY['windows'], 7,
  $SIGMA$
title: SMB Admin Share Access
status: stable
description: Detects access to administrative shares often used in lateral movement
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort:
            - 445
            - 139
        Image|contains:
            - '\cmd.exe'
            - '\powershell.exe'
    condition: selection
falsepositives:
    - Legitimate file sharing
level: medium
$SIGMA$,
  TRUE, ARRAY['T1021.002'], 'SMB管理共有アクセスの検出'
),

-- ── Persistence ───────────────────────────────────────────────────────────────

(
  'Scheduled Task Creation',
  'sigma', ARRAY['windows'], 7,
  $SIGMA$
title: Scheduled Task Creation via schtasks
status: stable
description: Detects scheduled task creation which may indicate persistence mechanism
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains:
            - '/create'
    filter_legitimate:
        CommandLine|contains:
            - 'Microsoft'
            - 'Windows'
            - 'Adobe'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate software installation
level: medium
$SIGMA$,
  TRUE, ARRAY['T1053.005'], 'スケジュールタスクによる永続化の検出'
),

(
  'Registry Run Key Modification',
  'sigma', ARRAY['windows'], 7,
  $SIGMA$
title: Registry Run Key Persistence
status: stable
description: Detects modification of registry run keys often used for persistence
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue
        TargetObject|contains:
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
            - '\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    condition: selection
falsepositives:
    - Legitimate software installing autostart entries
level: medium
$SIGMA$,
  TRUE, ARRAY['T1547.001'], 'レジストリRunキー永続化の検出'
),

(
  'New Service Created',
  'sigma', ARRAY['windows'], 7,
  $SIGMA$
title: New Service Creation
status: stable
description: Detects creation of new Windows services which may indicate persistence
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\sc.exe'
        CommandLine|contains: 'create'
    condition: selection
falsepositives:
    - Legitimate service installation
level: medium
$SIGMA$,
  TRUE, ARRAY['T1543.003'], 'Windowsサービス作成による永続化の検出'
),

-- ── Credential Access ─────────────────────────────────────────────────────────

(
  'LSASS Memory Access (Credential Dumping)',
  'sigma', ARRAY['windows'], 9,
  $SIGMA$
title: LSASS Memory Access
status: stable
description: Detects access to LSASS memory which indicates credential dumping attempt
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        Image|endswith:
            - '\mimikatz.exe'
            - '\procdump.exe'
            - '\procdump64.exe'
        CommandLine|contains:
            - 'lsass'
    selection_rundll:
        CommandLine|contains:
            - 'comsvcs.dll'
            - 'MiniDump'
    condition: selection_tools or selection_rundll
falsepositives:
    - Legitimate process dump for debugging
level: critical
$SIGMA$,
  TRUE, ARRAY['T1003.001'], 'LSASSメモリアクセスによる認証情報窃取の検出'
),

(
  'SAM Database Access',
  'sigma', ARRAY['windows'], 9,
  $SIGMA$
title: SAM Database Access
status: stable
description: Detects access attempts to the SAM database containing local account hashes
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - '\Windows\System32\config\SAM'
            - '\Windows\System32\config\SYSTEM'
            - '\Windows\System32\config\SECURITY'
    condition: selection
falsepositives:
    - Legitimate backup software
level: critical
$SIGMA$,
  TRUE, ARRAY['T1003.002'], 'SAMデータベースアクセスの検出'
),

-- ── Process Injection ─────────────────────────────────────────────────────────

(
  'Suspicious Process Injection via Rundll32',
  'sigma', ARRAY['windows'], 8,
  $SIGMA$
title: Suspicious Rundll32 Execution
status: stable
description: Detects suspicious rundll32 execution patterns used for process injection
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains:
            - 'javascript:'
            - 'vbscript:'
            - 'http://'
            - 'https://'
    condition: selection
falsepositives:
    - Some legitimate software uses these patterns
level: high
$SIGMA$,
  TRUE, ARRAY['T1055', 'T1218.011'], 'Rundll32を使ったプロセスインジェクションの検出'
),

-- ── Defense Evasion ───────────────────────────────────────────────────────────

(
  'Windows Defender Tampering',
  'sigma', ARRAY['windows'], 9,
  $SIGMA$
title: Windows Defender Tampering
status: stable
description: Detects attempts to disable Windows Defender via PowerShell or registry
logsource:
    category: process_creation
    product: windows
detection:
    selection_ps:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Set-MpPreference'
            - 'DisableRealtimeMonitoring'
            - 'Add-MpPreference'
            - '-ExclusionPath'
    selection_reg:
        Image|endswith: '\reg.exe'
        CommandLine|contains:
            - 'DisableAntiSpyware'
            - 'DisableRealtimeMonitoring'
    condition: selection_ps or selection_reg
falsepositives:
    - Legitimate security software configuration (rare)
level: critical
$SIGMA$,
  TRUE, ARRAY['T1562.001'], 'Windows Defenderの無効化試行の検出'
),

(
  'Shadow Copy Deletion',
  'sigma', ARRAY['windows'], 9,
  $SIGMA$
title: Shadow Copy Deletion
status: stable
description: Detects deletion of volume shadow copies commonly used in ransomware attacks
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\vssadmin.exe'
            - '\wmic.exe'
        CommandLine|contains:
            - 'delete shadows'
            - 'shadowcopy delete'
            - 'Delete Shadows /All'
    condition: selection
falsepositives:
    - Legitimate backup cleanup (extremely rare)
level: critical
$SIGMA$,
  TRUE, ARRAY['T1490'], 'シャドウコピー削除（ランサムウェア手口）の検出'
),

-- ── Linux-specific ────────────────────────────────────────────────────────────

(
  'Linux Crontab Persistence',
  'sigma', ARRAY['linux'], 6,
  $SIGMA$
title: Linux Crontab Modification
status: stable
description: Detects modification of crontab for persistence on Linux systems
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|contains: '/crontab'
        CommandLine|contains: '-e'
    selection2:
        Image|contains:
            - '/bash'
            - '/sh'
        CommandLine|contains:
            - 'crontab'
    condition: selection or selection2
falsepositives:
    - Legitimate cron job management
level: medium
$SIGMA$,
  TRUE, ARRAY['T1053.003'], 'Linuxクローンタブ永続化の検出'
),

(
  'Linux /etc/passwd or /etc/shadow Write',
  'sigma', ARRAY['linux'], 9,
  $SIGMA$
title: Linux Password File Modification
status: stable
description: Detects modifications to /etc/passwd or /etc/shadow indicating credential tampering
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|startswith:
            - '/etc/passwd'
            - '/etc/shadow'
            - '/etc/sudoers'
        Operation: write
    condition: selection
falsepositives:
    - Legitimate user management
level: critical
$SIGMA$,
  TRUE, ARRAY['T1003.008', 'T1136.001'], 'Linuxパスワードファイル改ざんの検出'
)

ON CONFLICT DO NOTHING;
