-- 356: detection-server (DB RuleEngine) パリティ 第39弾 — VNC横展開/パスワードマネージャ/Gatekeeper回避。
--
-- api-server ビルトインにあるが DB 未移植の3種を移植する:
--   T1021.005 VNC Remote Access       — vncviewer/winvnc/tvnserver 等の実行
--   T1555.005 Password Managers        — KeePass/1Password/Bitwarden 等の保管庫アクセス
--   T1553.001 Gatekeeper Bypass (macOS) — spctl --master-disable / xattr quarantine 除去
-- ビルトインは Image を併用する。DB エンジンでは コマンドライン中のツール名/対象語 +
-- 攻撃固有フラグの複合条件で捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1021.005 : VNC リモートアクセスツール実行 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'VNC Remote Access Tool Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: VNC Remote Access Tool Execution (DB)
description: Detects VNC clients/servers used for interactive remote control (vncviewer/tvnviewer/winvnc/tvnserver/vncserver).
status: experimental
level: medium
tags:
  - attack.t1021.005
  - attack.lateral_movement
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "vncviewer"
      - "tvnviewer"
      - "winvnc"
      - "tvnserver"
      - "vncserver"
  condition: selection
falsepositives:
  - Sanctioned VNC-based remote administration
$$,
'builtin-parity', ARRAY['T1021.005'],
'Two-engine parity: VNC remote access tool execution', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'VNC Remote Access Tool Execution (DB)');

-- ── T1555.005 : パスワードマネージャ保管庫アクセス ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Password Manager Vault Access (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Password Manager Vault Access (DB)
description: Detects access to password-manager vault files (KeePass .kdbx, 1Password, Bitwarden, KeePassXC) — high-value credential theft.
status: stable
level: high
tags:
  - attack.t1555.005
  - attack.credential_access
logsource:
  category: process_creation
detection:
  reader:
    CommandLine|contains:
      - "cat "
      - "cp "
      - "curl"
      - "powershell"
      - "python"
      - "strings"
  vault:
    CommandLine|contains:
      - ".kdbx"
      - ".kdb"
      - "1Password"
      - "Bitwarden"
      - ".opvault"
      - "keepass"
      - "keepassxc"
  condition: reader and vault
falsepositives:
  - Backup or sync software touching password databases
$$,
'builtin-parity', ARRAY['T1555.005'],
'Two-engine parity: password manager vault access', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Password Manager Vault Access (DB)');

-- ── T1553.001 : macOS Gatekeeper 回避(spctl / xattr quarantine)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'macOS Gatekeeper Bypass (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: macOS Gatekeeper Bypass (DB)
description: Detects disabling Gatekeeper (spctl --master-disable) or stripping com.apple.quarantine (xattr) to run unsigned/downloaded code.
status: stable
level: high
tags:
  - attack.t1553.001
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  spctl:
    CommandLine|contains|all:
      - "spctl"
    CommandLine|contains:
      - "--master-disable"
      - "--global-disable"
  xattr:
    CommandLine|contains|all:
      - "xattr"
      - "com.apple.quarantine"
  condition: spctl or xattr
falsepositives:
  - Developers clearing quarantine on their own builds
$$,
'builtin-parity', ARRAY['T1553.001'],
'Two-engine parity: macOS Gatekeeper bypass', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'macOS Gatekeeper Bypass (DB)');
