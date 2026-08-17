-- 344: カバレッジ0だった Discovery / Execution テクニックの補完
--   T1124 システム時刻発見 / T1217 ブラウザ情報窃取 / T1010 アプリウィンドウ発見 /
--   T1559.001 COM 経由実行
-- いずれも 2026-07-20 実測でカバレッジ0（builtin/migration いずれにも無し）。
-- process_creation の CommandLine ベースで低FPに絞って補完する。

-- ── T1124 : システム時刻発見（リモート/タイムゾーン照会） ─────────────
-- `net time \\host` / `w32tm /tz` / `tzutil /g` は攻撃者がドメイン時刻同期や
-- Kerberos の時刻差、ログ相関回避のために叩く。単なる `date` は除外（ノイズ）。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'System Time Discovery via net/w32tm/tzutil', 'sigma', ARRAY['windows'], 4,
$SIGMA$
title: System Time Discovery via net/w32tm/tzutil
description: Detects enumeration of system or domain time / timezone via net time, w32tm, or tzutil. Adversaries query time to align with Kerberos skew, schedule actions, or evade log correlation (T1124). Bare `date` is intentionally excluded to avoid noise; these three utilities in a discovery form are far more specific.
status: stable
level: low
tags:
  - attack.t1124
  - attack.discovery
logsource:
  category: process_creation
detection:
  net_time:
    Image|endswith: \net.exe
    CommandLine|contains: ' time'
  w32tm:
    Image|endswith: \w32tm.exe
    CommandLine|contains:
      - ' /tz'
      - ' /monitor'
  tzutil:
    Image|endswith: \tzutil.exe
    CommandLine|contains: ' /g'
  condition: net_time or w32tm or tzutil
falsepositives:
  - Administrative time-sync troubleshooting
$SIGMA$,
'community', ARRAY['T1124'],
'Coverage gap fill: system/domain time discovery (was uncovered)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'System Time Discovery via net/w32tm/tzutil');

-- ── T1217 : ブラウザ情報窃取（履歴/ログイン/クッキーDBアクセス） ────────
-- ブラウザの history / Login Data / cookies SQLite を cat/copy/sqlite3/esentutl 等で
-- 直接読むのは資格情報・トークン窃取の典型。ブラウザ本体プロセスは対象外（別Image）。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Browser Credential and History Store Access', 'sigma', ARRAY['windows','linux','macos'], 6,
$SIGMA$
title: Browser Credential and History Store Access
description: Detects a non-browser process reading Chromium/Firefox credential, cookie, or history stores (Login Data, Cookies, History, places.sqlite, cookies.sqlite, key4.db, logins.json). Copying or querying these files is a common credential- and session-token-theft step and browser-information discovery (T1217 / T1539 / T1555.003).
status: stable
level: medium
tags:
  - attack.t1217
  - attack.discovery
  - attack.credential_access
logsource:
  category: process_creation
detection:
  reader:
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \cat
      - \cp
      - \copy
      - \sqlite3
      - \esentutl.exe
      - \tar
  store:
    CommandLine|contains:
      - '\User Data\'
      - 'Login Data'
      - 'cookies.sqlite'
      - 'places.sqlite'
      - 'key4.db'
      - 'logins.json'
      - '/.mozilla/'
      - '/.config/google-chrome/'
      - 'Library/Application Support/Google/Chrome'
  condition: reader and store
falsepositives:
  - Backup or sync tooling that archives browser profiles (scope by host)
$SIGMA$,
'community', ARRAY['T1217'],
'Coverage gap fill: browser credential/history store access (was uncovered)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Browser Credential and History Store Access');

-- ── T1010 : アプリケーションウィンドウ発見 ──────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Application Window Discovery', 'sigma', ARRAY['windows','linux'], 4,
$SIGMA$
title: Application Window Discovery
description: Detects enumeration of open application window titles — tasklist /v (Windows) or wmctrl/xdotool (Linux). Window titles reveal running apps, RDP/VNC sessions, and sometimes credentials, informing the adversary's next move (T1010).
status: stable
level: low
tags:
  - attack.t1010
  - attack.discovery
logsource:
  category: process_creation
detection:
  tasklist_v:
    Image|endswith: \tasklist.exe
    CommandLine|contains:
      - ' /v'
      - ' -v'
  linux_wm:
    Image|endswith:
      - \wmctrl
      - \xdotool
    CommandLine|contains:
      - ' -l'
      - 'getwindowname'
      - 'getactivewindow'
      - 'search --name'
  condition: tasklist_v or linux_wm
falsepositives:
  - Admin/scripting that inventories windows
$SIGMA$,
'community', ARRAY['T1010'],
'Coverage gap fill: application window discovery (was uncovered)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Application Window Discovery');

-- ── T1559.001 : COM 経由実行（ラテラル/実行代理） ───────────────────
-- スクリプトから COM オブジェクト（MMC20.Application / ShellWindows /
-- ShellBrowserWindow / Excel.Application 等）を生成しての実行代理は、
-- 親子関係を偽装しつつコード実行する常套手段。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Execution via COM Object Instantiation', 'sigma', ARRAY['windows'], 6,
$SIGMA$
title: Execution via COM Object Instantiation
description: Detects script-driven instantiation of COM objects commonly abused for proxied / lateral execution — CreateInstance/GetTypeFromCLSID/GetTypeFromProgID, New-Object -ComObject, GetObject("new:..."), or the classic lateral-movement ProgIDs MMC20.Application, ShellWindows, ShellBrowserWindow, Excel.Application DDE (T1559.001).
status: experimental
level: medium
tags:
  - attack.t1559.001
  - attack.execution
  - attack.lateral_movement
logsource:
  category: process_creation
detection:
  com_api:
    CommandLine|contains:
      - 'GetTypeFromCLSID'
      - 'GetTypeFromProgID'
      - '-ComObject'
      - 'GetObject("new:'
      - "GetObject('new:"
  com_progid:
    CommandLine|contains:
      - 'MMC20.Application'
      - 'ShellWindows'
      - 'ShellBrowserWindow'
      - '9BA05972-F6A8-11CF-A442-00A0C90A8F39'
      - 'C08AFD90-F2A1-11D1-8455-00A0C91F3880'
  condition: com_api or com_progid
falsepositives:
  - Legitimate administrative automation that drives Office/Explorer COM objects
$SIGMA$,
'community', ARRAY['T1559.001'],
'Coverage gap fill: COM object execution / lateral movement (was uncovered)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Execution via COM Object Instantiation');
