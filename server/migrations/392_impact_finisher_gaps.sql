-- 328: Impact/Collection 末端ギャップの補完（destructive フィニッシャ系）。
--
-- 2026-07-13 の ATT&CK カバレッジ監査ロードマップ #4 に基づく。実測で被覆ゼロだった
-- Impact 末端のうち、コマンドライン/プロセスシグネチャで高シグナル低FPに検知できる
-- ものを補完する:
--   - T1529  System Shutdown/Reboot（ランサム/ワイパーの仕上げ、強制即時シャットダウン）
--   - T1491.001 Internal Defacement（デスクトップ壁紙をランサムノートに差し替え）
--   - T1123  Audio Capture（ffmpeg dshow / PowerShell 音声 API による盗聴ツール）
-- 検知困難でFPが多い T1565(データ操作)/T1039(共有ドライブ収集) は本バッチでは見送り
-- （ATT&CK監査に留保理由を記載）。
--
-- すべて process_creation。platform で OS ゲート対象。description にコロン+スペースを
-- 含めない（migration 019 の YAML 死蔵の再発防止）。冪等: ON CONFLICT (id) DO NOTHING。

-- ── T1529 — Forced System Shutdown or Reboot (Windows) ─────────────────
-- 強制(/f)または即時(/t 0)を伴う shutdown/reboot、および PowerShell の強制再起動/停止。
-- 通常の対話的シャットダウンは強制/即時フラグを伴わないため、destructive 側に寄せる。
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

-- ── T1529 — System Shutdown or Reboot (Linux/macOS) ───────────────────
-- Unix 側は shutdown/reboot/poweroff/halt と systemctl・init 0/6。管理者の再起動が
-- 一定量あるため low（相関・バースト検知の燃料としての情報系）。
INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0328-0002-0002-000000000002',
  'Unix System Shutdown or Reboot',
  'sigma',
  ARRAY['linux', 'macos'],
  3,
  $SIGMA$title: Unix System Shutdown or Reboot
id: f1a0c0de-0328-0002-0002-000000000002
status: stable
description: Detects system shutdown reboot poweroff and halt commands on Linux and macOS which may indicate a destructive action finalizing an intrusion
references:
  - https://attack.mitre.org/techniques/T1529/
logsource:
  product: linux
  category: process_creation
detection:
  sel_bin:
    Image|endswith:
      - /shutdown
      - /reboot
      - /poweroff
      - /halt
  sel_systemctl:
    Image|endswith: /systemctl
    CommandLine|contains:
      - reboot
      - poweroff
      - halt
  sel_init:
    Image|endswith:
      - /init
      - /telinit
    CommandLine|contains:
      - ' 0'
      - ' 6'
  condition: sel_bin or sel_systemctl or sel_init
falsepositives:
  - Administrators rebooting hosts for maintenance
level: low$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1529'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ── T1491.001 — Internal Defacement via Desktop Wallpaper ─────────────
-- ランサムノートを壁紙に差し替える典型手口（reg.exe / PowerShell 経由）。
INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0328-0003-0003-000000000003',
  'Desktop Wallpaper Defacement',
  'sigma',
  ARRAY['windows'],
  5,
  $SIGMA$title: Desktop Wallpaper Defacement
id: f1a0c0de-0328-0003-0003-000000000003
status: stable
description: Detects programmatic changes to the desktop wallpaper via reg.exe or PowerShell often used by ransomware to display a ransom note as the background
references:
  - https://attack.mitre.org/techniques/T1491/001/
logsource:
  product: windows
  category: process_creation
detection:
  sel_reg:
    Image|endswith: \reg.exe
    CommandLine|contains|all:
      - Control Panel\Desktop
      - Wallpaper
      - ' /d '
  sel_ps:
    Image|endswith:
      - \powershell.exe
      - \pwsh.exe
    CommandLine|contains|all:
      - Wallpaper
      - Control Panel\Desktop
      - Set-Item
  condition: sel_reg or sel_ps
falsepositives:
  - Enterprise desktop management setting a corporate wallpaper
level: medium$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1491.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ── T1123 — Audio Capture ─────────────────────────────────────────────
-- ffmpeg の DirectShow 音声取り込みや PowerShell の音声 API による盗聴ツール。
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
