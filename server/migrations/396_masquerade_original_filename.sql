-- 332: 未活用テレメトリ(PE OriginalFileName)を使ったマスカレード検知(T1036.005)。
--
-- 2026-07-20 の検知率深掘りで、agent が収集し ingestion/エイリアス層まで完全配線済み
-- (original_file_name → OriginalFileName)なのに、自ルールが OriginalFileName を1つも
-- 使っていないことが判明。攻撃者はツールをリネームして検知を回避するが、PE の
-- VERSIONINFO(OriginalFileName)はリネームしても残るため、SigmaHQ が masquerading 検知に
-- 最も多用するフィールド。高シグナル・低FPで3ルールを追加する。
--
-- すべて process_creation。description にコロン+スペースを含めない。冪等: ON CONFLICT DO NOTHING。

-- ── A. リネームされた攻撃ツール(常時悪性の PE 名) ─────────────────────
-- mimikatz 等の PE OriginalFileName は正規用途では現れない。ディスク上の名前を
-- 変えても発火する(リネーム回避の無効化)。
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

-- ── B. コアシステムバイナリのマスカレード(正規パス外の svchost 等) ─────
-- PE 上は svchost.exe 等を名乗るが System32/SysWOW64/WinSxS の外で実行される
-- =ドロップされた偽システムプロセス。
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

-- ── C. リネームされた dual-use 管理ツール(PsExec/procdump) ────────────
-- PE 名は PsExec/procdump だがディスク上の名前が異なる=リネーム。正規名で実行
-- されている場合(Sysinternals)は除外。
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
