-- 385: #525 由来の未着地ルール（第 2 波 / Windows 14 件）
--
-- 出所は P4-12。第 1 波（migration 384）が「技法ごと完全に暗かった」5 件を
-- 塞いだのに対し、こちらは**既存ルールが部分被覆している領域**を埋める。
-- したがって第 1 波と性質が違う: 発火ゼロが期待値ではなく、既存ルールとの
-- 重複と誤検知のトレードオフが出る。
--
-- ルール本文は移設元から逐語で、id も変えていない。
--
-- ── 移す前に確認したこと ──
--
-- 14 件が使うフィールドの供給元を 1 つずつ辿った。第 1 波で 1 件を弾いた判定
-- （フィールド名は既知でも値が来ない）を同じ手順でかけている。
--
--   CommandLine / Image        process_creation（自明）
--   OriginalFileName           ingestion/handler.go:1160（PE VERSIONINFO）
--   ImageLoaded                handler.go:1285  "image_loaded" ← il.GetImagePath()
--   SignatureStatus / Signature handler.go:1289-1290 ← GetSignatureStatus/GetSigner
--   TargetObject / Details     handler.go:1249-1251 ← keyPath / value_data
--   ParentImage                alert_pipeline.go の parentResolver が ppid から注入
--
-- ★ ParentImage について: proto の ProcessEvent には親プロセスの実行パスが無く
--   （ppid のみ）、一度は「原理的に埋まらない」と判断しかけた。誤りである。
--   alert_pipeline.go:38 の parentResolver が ppid から親イメージを解決して
--   parent_process を注入し、それが別名表で ParentImage に写る。既存 builtin
--   12 件以上が同じ経路に乗っている。
--
-- ── 申し送り: Renamed Dual-Use Admin Tool の PsExec 検出について ──
--
-- このルールは OriginalFileName|endswith に psexec.exe / psexec64.exe /
-- procdump.exe / procdump64.exe を並べている。**実物の PsExec の PE
-- VERSIONINFO は OriginalFilename が "psexec.c"**（拡張子が .c）であることが
-- 知られており、そうであれば名前を変えた PsExec はこのルールに一致しない。
-- procdump 側は一致するので、ルールが完全に死んでいるわけではない。
--
-- 本 migration では**直していない**。理由は 2 つ:
--   1. 本文は逐語で移す方針で、id も変えていない。将来 #525 のブランチと
--      突き合わせる人が「同じもの」と判断できることを優先した
--   2. psexec.c であることを**このリポジトリ内では裏付けられなかった**。
--      既存 builtin にも migration にも psexec.c / psexec.exe を
--      OriginalFileName として使う先例が無い
--
-- 実機の PsExec で VERSIONINFO を確認したうえで、必要なら別 migration で
-- selection に 'psexec.c' を足すこと（endswith の OR なので純粋な追加であり、
-- 誤りだった場合も一致しないセレクタが 1 つ増えるだけで害は無い）。

-- 移設元ブランチ: fix/migration-323-additive-constraint @ cb9a94e9

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0328-0004-0004-000000000004',
  'Audio Capture Tooling',
  'sigma',
  ARRAY['windows'],
  5,
  $SIGMA$title: Audio Capture Tooling
id: f1a0c0de-0328-0004-0004-000000000004
status: experimental
description: Detects microphone audio capture via ffmpeg DirectShow input or PowerShell audio APIs which may indicate eavesdropping for collection
references:
  - https://attack.mitre.org/techniques/T1123/
logsource:
  product: windows
  category: process_creation
detection:
  sel_ffmpeg:
    CommandLine|contains|all:
      - dshow
      - 'audio='
  sel_ps_audio:
    CommandLine|contains:
      - waveInOpen
      - WindowsAudioDevice
      - Get-AudioDevice
      - NAudio
  condition: sel_ffmpeg or sel_ps_audio
falsepositives:
  - Legitimate audio or video conferencing and recording software
level: medium$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1123'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0332-0002-0002-000000000002',
  'Core System Binary Masquerade by Location',
  'sigma',
  ARRAY['windows'],
  8,
  $SIGMA$title: Core System Binary Masquerade by Location
id: f1a0c0de-0332-0002-0002-000000000002
status: stable
description: Detects a process carrying the PE OriginalFileName of a core Windows system binary while executing from outside the standard system directories which indicates a dropped impersonating binary
references:
  - https://attack.mitre.org/techniques/T1036/005/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    OriginalFileName|endswith:
      - svchost.exe
      - lsass.exe
      - services.exe
      - csrss.exe
      - winlogon.exe
      - smss.exe
      - wininit.exe
      - spoolsv.exe
  filter_system_path:
    Image|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
      - 'C:\Windows\WinSxS\'
      - 'C:\Windows\servicing\'
  condition: selection and not filter_system_path
falsepositives:
  - Rare servicing or side-by-side component locations not covered by the filter
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1036.005'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0336-0001-0001-000000000001',
  'DLL Search-Order Hijack of Commonly-Abused System DLL',
  'sigma',
  ARRAY['windows'],
  8,
  $SIGMA$title: DLL Search-Order Hijack of Commonly-Abused System DLL
id: f1a0c0de-0336-0001-0001-000000000001
status: stable
description: Detects an unsigned or invalidly-signed copy of a frequently hijacked system DLL loaded from outside the standard system directories which is the classic DLL search-order hijacking and side-loading technique
references:
  - https://attack.mitre.org/techniques/T1574/001/
  - https://attack.mitre.org/techniques/T1574/002/
logsource:
  product: windows
  category: image_load
detection:
  hijack_dll:
    ImageLoaded|endswith:
      - \version.dll
      - \dbghelp.dll
      - \dbgcore.dll
      - \wininet.dll
      - \cryptsp.dll
      - \profapi.dll
      - \dwmapi.dll
      - \edputil.dll
      - \msimg32.dll
      - \secur32.dll
      - \userenv.dll
      - \netutils.dll
      - \winmm.dll
      - \textshaping.dll
      - \vftrace.dll
      - \wtsapi32.dll
  untrusted:
    SignatureStatus|contains:
      - unsigned
      - invalid
      - expired
  filter_system:
    ImageLoaded|contains:
      - \Windows\System32\
      - \Windows\SysWOW64\
      - \Windows\WinSxS\
      - \Windows\servicing\
  condition: hijack_dll and untrusted and not filter_system
falsepositives:
  - In-house or niche software shipping an unsigned copy of one of these DLL names in its own directory
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1574.001', 'T1574.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'bea70000-0322-0002-0002-000000000002',
  'Default File Association Hijack',
  'sigma',
  ARRAY['windows'],
  7,
  $SIGMA$title: Default File Association Hijack
id: bea70000-0322-0002-0002-000000000002
status: stable
description: Detects modification of a file-type open command (shell open command) to point at a script host or a user-writable payload path, hijacking the default handler so opening a common file type executes attacker code at each use
references:
  - https://attack.mitre.org/techniques/T1546/001/
logsource:
  product: windows
  category: registry_set
detection:
  assoc_key:
    TargetObject|contains: \shell\open\command
  suspicious_payload:
    Details|contains:
      - powershell
      - 'cmd.exe /c'
      - 'cmd /c'
      - wscript
      - cscript
      - mshta
      - .vbs
      - .js
      - \AppData\
      - \Temp\
      - \Users\Public\
  condition: assoc_key and suspicious_payload
falsepositives:
  - Legitimate application installers registering their own file handlers
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1546.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0328-0001-0001-000000000001',
  'Forced System Shutdown or Reboot',
  'sigma',
  ARRAY['windows'],
  5,
  $SIGMA$title: Forced System Shutdown or Reboot
id: f1a0c0de-0328-0001-0001-000000000001
status: stable
description: Detects forced or immediate system shutdown and reboot commonly used by ransomware and wipers to finalize destruction or lock users out
references:
  - https://attack.mitre.org/techniques/T1529/
logsource:
  product: windows
  category: process_creation
detection:
  sel_shutdown:
    Image|endswith: \shutdown.exe
    CommandLine|contains:
      - ' /s'
      - ' /r'
      - ' -s'
      - ' -r'
  sel_forced:
    CommandLine|contains:
      - ' /f'
      - ' /t 0'
      - ' -t 0'
  sel_ps:
    Image|endswith:
      - \powershell.exe
      - \pwsh.exe
    CommandLine|contains:
      - Restart-Computer
      - Stop-Computer
  sel_ps_force:
    CommandLine|contains: -Force
  sel_wmic:
    Image|endswith: \wmic.exe
    CommandLine|contains|all:
      - os
      - reboot
  condition: (sel_shutdown and sel_forced) or (sel_ps and sel_ps_force) or sel_wmic
falsepositives:
  - Administrative patch or maintenance reboots that force running applications to close
level: medium$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1529'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'c4ed0000-0319-0001-0001-000000000001',
  'Kerberos Golden or Silver Ticket Forging',
  'sigma',
  ARRAY['windows'],
  9,
  $SIGMA$title: Kerberos Golden or Silver Ticket Forging
id: c4ed0000-0319-0001-0001-000000000001
status: stable
description: Detects forging of Kerberos TGT (Golden) or TGS (Silver) tickets via mimikatz kerberos golden, Rubeus, or Impacket ticketer, granting durable domain-wide access. Distinct from Pass-the-Ticket injection and Kerberoasting
references:
  - https://attack.mitre.org/techniques/T1558/001/
  - https://attack.mitre.org/techniques/T1558/002/
logsource:
  product: windows
  category: process_creation
detection:
  mimikatz:
    CommandLine|contains:
      - 'kerberos::golden'
  impacket:
    CommandLine|contains:
      - 'ticketer.py'
      - 'ticketer '
  krbtgt_hash:
    CommandLine|contains:
      - '/krbtgt:'
  rubeus_golden:
    CommandLine|contains|all:
      - 'ubeus'
      - 'golden'
  rubeus_silver:
    CommandLine|contains|all:
      - 'ubeus'
      - 'silver'
  condition: mimikatz or impacket or krbtgt_hash or rubeus_golden or rubeus_silver
falsepositives:
  - Authorized red-team Kerberos abuse simulations
level: critical$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1558.001', 'T1558.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'bea70000-0322-0001-0001-000000000001',
  'Logon Script Persistence via UserInitMprLogonScript',
  'sigma',
  ARRAY['windows'],
  8,
  $SIGMA$title: Logon Script Persistence via UserInitMprLogonScript
id: bea70000-0322-0001-0001-000000000001
status: stable
description: Detects setting a logon script via the HKCU Environment UserInitMprLogonScript value, a stealthy persistence mechanism that runs an arbitrary command at every interactive logon and has near-zero legitimate use
references:
  - https://attack.mitre.org/techniques/T1037/001/
logsource:
  product: windows
  category: registry_set
detection:
  selection:
    TargetObject|contains:
      - \Environment\UserInitMprLogonScript
      - \Environment\UserInitLogonScript
  condition: selection
falsepositives:
  - Rare legacy logon-script deployment via the registry
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1037.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0332-0003-0003-000000000003',
  'Renamed Dual-Use Admin Tool by PE OriginalFileName',
  'sigma',
  ARRAY['windows'],
  7,
  $SIGMA$title: Renamed Dual-Use Admin Tool by PE OriginalFileName
id: f1a0c0de-0332-0003-0003-000000000003
status: stable
description: Detects renamed Sysinternals dual-use tools by matching the PE OriginalFileName while the on-disk name differs which is a common way to smuggle PsExec or procdump past name-based controls
references:
  - https://attack.mitre.org/techniques/T1036/005/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    OriginalFileName|endswith:
      - psexec.exe
      - psexec64.exe
      - procdump.exe
      - procdump64.exe
  filter_correct_name:
    Image|endswith:
      - \psexec.exe
      - \psexec64.exe
      - \procdump.exe
      - \procdump64.exe
  condition: selection and not filter_correct_name
falsepositives:
  - A wrapper that copies the tool under a versioned filename
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1036.005'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0332-0001-0001-000000000001',
  'Renamed Offensive Tool by PE OriginalFileName',
  'sigma',
  ARRAY['windows'],
  9,
  $SIGMA$title: Renamed Offensive Tool by PE OriginalFileName
id: f1a0c0de-0332-0001-0001-000000000001
status: stable
description: Detects offensive security tools by their embedded PE OriginalFileName even when the file on disk has been renamed to evade name-based detection
references:
  - https://attack.mitre.org/techniques/T1036/005/
logsource:
  product: windows
  category: process_creation
detection:
  exact_tool:
    OriginalFileName|endswith:
      - mimikatz.exe
      - rubeus.exe
      - sharphound.exe
      - lazagne.exe
      - seatbelt.exe
      - safetykatz.exe
      - nanodump.exe
      - sharpview.exe
      - certify.exe
      - whisker.exe
      - sharpkatz.exe
  variant_tool:
    OriginalFileName|contains:
      - winpeas
      - koadic
  condition: exact_tool or variant_tool
falsepositives:
  - Security researchers or red teams running the original tools intentionally
  - Defensive tooling whose name merely contains a tool token (endswith on exact PE names avoids this)
level: critical$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1036.005', 'T1588.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'c4ed0000-0319-0002-0002-000000000002',
  'Skeleton Key or In-memory SSP Credential Logging',
  'sigma',
  ARRAY['windows'],
  9,
  $SIGMA$title: Skeleton Key or In-memory SSP Credential Logging
id: c4ed0000-0319-0002-0002-000000000002
status: stable
description: Detects mimikatz misc skeleton (patching LSASS to accept a master password for any account) or misc memssp (injecting an SSP that logs plaintext credentials), a domain-controller authentication backdoor
references:
  - https://attack.mitre.org/techniques/T1556/001/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'misc::skeleton'
      - 'misc::memssp'
  condition: selection
falsepositives:
  - None expected outside authorized red-team exercises
level: critical$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1556.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0337-0001-0001-000000000001',
  'System DLL Name Signed by Non-Microsoft Publisher',
  'sigma',
  ARRAY['windows'],
  7,
  $SIGMA$title: System DLL Name Signed by Non-Microsoft Publisher
id: f1a0c0de-0337-0001-0001-000000000001
status: stable
description: Detects a validly signed module bearing the name of a core Windows system DLL but signed by a publisher other than Microsoft and loaded from outside the system directories which indicates a re-signed fake system DLL used to bypass unsigned-DLL detection during side-loading
references:
  - https://attack.mitre.org/techniques/T1574/001/
  - https://attack.mitre.org/techniques/T1036/
logsource:
  product: windows
  category: image_load
detection:
  hijack_dll:
    ImageLoaded|endswith:
      - \version.dll
      - \wininet.dll
      - \secur32.dll
      - \userenv.dll
      - \cryptsp.dll
      - \profapi.dll
      - \dbgcore.dll
      - \dbghelp.dll
      - \edputil.dll
      - \netutils.dll
      - \wtsapi32.dll
  valid_signed:
    SignatureStatus: valid
  filter_ms_publisher:
    Signature|contains:
      - Microsoft
      - Windows
  filter_system:
    ImageLoaded|contains:
      - \Windows\System32\
      - \Windows\SysWOW64\
      - \Windows\WinSxS\
      - \Windows\servicing\
  condition: hijack_dll and valid_signed and not filter_ms_publisher and not filter_system
falsepositives:
  - A third-party product that ships its own signed DLL sharing one of these core system DLL names
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1574.001', 'T1036'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0333-0001-0001-000000000001',
  'UAC Bypass via Auto-Elevating Binary',
  'sigma',
  ARRAY['windows'],
  8,
  $SIGMA$title: UAC Bypass via Auto-Elevating Binary
id: f1a0c0de-0333-0001-0001-000000000001
status: stable
description: Detects a command shell or script host spawned by a known auto-elevating UAC bypass binary such as eventvwr sdclt computerdefaults wsreset or slui which indicates a User Account Control bypass
references:
  - https://attack.mitre.org/techniques/T1548/002/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
      - \eventvwr.exe
      - \sdclt.exe
      - \computerdefaults.exe
      - \wsreset.exe
      - \slui.exe
      - \fodhelper.exe
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \wscript.exe
      - \cscript.exe
      - \mshta.exe
      - \rundll32.exe
      - \regsvr32.exe
  condition: selection
falsepositives:
  - Rare administrative scripts intentionally launched through these utilities
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1548.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0333-0002-0002-000000000002',
  'Web Browser Spawning a Command Shell',
  'sigma',
  ARRAY['windows'],
  8,
  $SIGMA$title: Web Browser Spawning a Command Shell
id: f1a0c0de-0333-0002-0002-000000000002
status: stable
description: Detects a web browser process spawning a command shell or script host which is highly abnormal and indicates browser exploitation or a drive-by compromise
references:
  - https://attack.mitre.org/techniques/T1203/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
      - \chrome.exe
      - \firefox.exe
      - \msedge.exe
      - \iexplore.exe
      - \brave.exe
      - \opera.exe
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \wscript.exe
      - \cscript.exe
      - \mshta.exe
  condition: selection
falsepositives:
  - Enterprise browser management scripts (rare)
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1203'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'e0f1c0de-0317-0004-0004-000000000004',
  'Windows Data Exfiltration via curl.exe or bitsadmin Upload',
  'sigma',
  ARRAY['windows'],
  7,
  $SIGMA$title: Windows Data Exfiltration via curl.exe or bitsadmin Upload
id: e0f1c0de-0317-0004-0004-000000000004
status: stable
description: Detects file upload via the built-in curl.exe (multipart or upload-file) or a bitsadmin upload transfer, a LOLBin exfiltration channel that avoids PowerShell
references:
  - https://attack.mitre.org/techniques/T1041/
  - https://attack.mitre.org/techniques/T1048/
logsource:
  product: windows
  category: process_creation
detection:
  curl_upload:
    Image|endswith: \curl.exe
    CommandLine|contains:
      - ' -F '
      - ' --form'
      - ' -T '
      - ' --upload-file'
      - ' --data-binary @'
      - ' -d @'
  bitsadmin_upload:
    Image|endswith: \bitsadmin.exe
    CommandLine|contains:
      - /upload
      - -upload
  condition: curl_upload or bitsadmin_upload
falsepositives:
  - Administrative file-transfer automation
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1041', 'T1048'],
  NOW()
) ON CONFLICT (id) DO NOTHING;
