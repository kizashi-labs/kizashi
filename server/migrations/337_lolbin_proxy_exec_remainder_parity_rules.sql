-- 337: detection-server (DB RuleEngine) パリティ 第20弾 — LOLBin プロキシ実行(残り T1218 系)。
--
-- mig330(mshta/regsvr32/rundll32)・mig325(InstallUtil/Msiexec/Regsvcs/XSL/CMSTP)で
-- 移植済みのプロキシ実行 LOLBin に続き、api-server ビルトインにあるが DB 未移植の
-- 残り4種を移植する:
--   T1218.002 Control Panel Item — control.exe .cpl / rundll32 Control_RunDLL
--   T1218.008 Odbcconf          — odbcconf regsvr /a .dll
--   T1218.012 Verclsid          — verclsid /S /C(COM オブジェクト検証で実行)
--   T1216.001 Signed Script Proxy — PubPrn.vbs / script: スクリプトレットモニカ
-- ビルトインは Image|contains/endswith を併用するが、DB エンジンでは コマンドライン中の
-- バイナリ名 + 攻撃固有フラグを CommandLine|contains(|all アンカー + フラグ)で捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1218.002 : Control Panel Item 実行(control .cpl / Control_RunDLL)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Control Panel Item Proxy Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Control Panel Item Proxy Execution (DB)
description: Detects control.exe launching a .cpl or rundll32 shell32.dll,Control_RunDLL — proxy execution via Control Panel items.
status: stable
level: medium
tags:
  - attack.t1218.002
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  control_cpl:
    CommandLine|contains|all:
      - "control"
      - ".cpl"
  rundll_control:
    CommandLine|contains: "Control_RunDLL"
  condition: control_cpl or rundll_control
falsepositives:
  - Legitimate Control Panel applets launched from System32
$$,
'builtin-parity', ARRAY['T1218.002'],
'Two-engine parity: Control Panel item proxy execution (control .cpl / Control_RunDLL)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Control Panel Item Proxy Execution (DB)');

-- ── T1218.008 : Odbcconf プロキシ実行(regsvr /a .dll)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Odbcconf Proxy Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Odbcconf Proxy Execution (DB)
description: Detects odbcconf.exe abused to load/execute a DLL via REGSVR (LOLBin proxy execution).
status: stable
level: high
tags:
  - attack.t1218.008
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  odbcconf:
    CommandLine|contains|all:
      - "odbcconf"
    CommandLine|contains:
      - "regsvr"
      - "/a"
      - ".dll"
  condition: odbcconf
falsepositives:
  - Legitimate ODBC driver configuration
$$,
'builtin-parity', ARRAY['T1218.008'],
'Two-engine parity: odbcconf DLL proxy execution via REGSVR', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Odbcconf Proxy Execution (DB)');

-- ── T1218.012 : Verclsid COM オブジェクトプロキシ実行(/S /C)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Verclsid COM Proxy Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Verclsid COM Proxy Execution (DB)
description: Detects verclsid.exe /S /C validating (and thereby executing) a COM/shell object — signed LOLBin proxy execution.
status: stable
level: high
tags:
  - attack.t1218.012
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  verclsid:
    CommandLine|contains|all:
      - "verclsid"
      - "/S"
      - "/C"
  condition: verclsid
falsepositives:
  - Rare legitimate shell extension validation
$$,
'builtin-parity', ARRAY['T1218.012'],
'Two-engine parity: verclsid COM object proxy execution (/S /C)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Verclsid COM Proxy Execution (DB)');

-- ── T1216.001 : 署名スクリプトプロキシ実行(PubPrn.vbs / script: モニカ)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Signed Script Proxy Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Signed Script Proxy Execution (DB)
description: Detects abuse of the signed PubPrn.vbs script or a "script:" scriptlet moniker to proxy remote code past application control.
status: stable
level: high
tags:
  - attack.t1216.001
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  pubprn:
    CommandLine|contains: "pubprn.vbs"
  scriptlet:
    CommandLine|contains:
      - "script:http"
      - "script:https"
  condition: pubprn or scriptlet
falsepositives:
  - Rare legitimate printer-provisioning automation using PubPrn
$$,
'builtin-parity', ARRAY['T1216.001'],
'Two-engine parity: signed script proxy execution (PubPrn / scriptlet moniker)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Signed Script Proxy Execution (DB)');
