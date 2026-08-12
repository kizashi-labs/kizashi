-- 330: detection-server (DB RuleEngine) パリティ 第13弾 — proxy 実行 LOLBin 補完。
--
-- mig325(防御回避 LOLBin)で移植した InstallUtil/Msiexec/Regsvcs/XSL/CMSTP に続き、
-- api-server ビルトインにあるが DB 未移植だった中核の署名済みバイナリ proxy 実行
-- 3種(mshta/regsvr32/rundll32)を移植し、両エンジンで LOLBin proxy 実行を被覆する。
-- ビルトインは Image|contains を併用するが、DB エンジンでは バイナリ名 + 攻撃固有の
-- 指標を CommandLine|contains で捕捉する(死蔵回避)。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1218.005 : Mshta 遠隔/スクリプト proxy 実行 ───────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Mshta Proxy Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Mshta Proxy Execution (DB)
status: stable
level: high
tags:
  - attack.t1218.005
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  mshta:
    CommandLine|contains|all:
      - "mshta"
    CommandLine|contains:
      - "http"
      - "vbscript"
      - "javascript"
      - ".hta"
      - "about:"
  condition: mshta
falsepositives:
  - Legacy HTA-based line-of-business applications
$$,
'builtin-parity', ARRAY['T1218.005'],
'Two-engine parity: mshta remote/scripted proxy execution', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Mshta Proxy Execution (DB)');

-- ── T1218.010 : Regsvr32 Squiblydoo / スクリプトレット proxy 実行 ─
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Regsvr32 Scriptlet Proxy Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Regsvr32 Scriptlet Proxy Execution (DB)
status: stable
level: high
tags:
  - attack.t1218.010
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  regsvr32:
    CommandLine|contains|all:
      - "regsvr32"
    CommandLine|contains:
      - "scrobj.dll"
      - "/i:http"
      - "/i:ftp"
      - ".sct"
  condition: regsvr32
falsepositives:
  - Rare legitimate COM registration of remote scriptlets
$$,
'builtin-parity', ARRAY['T1218.010'],
'Two-engine parity: regsvr32 squiblydoo/scriptlet proxy execution', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Regsvr32 Scriptlet Proxy Execution (DB)');

-- ── T1218.011 : Rundll32 proxy 実行(スクリプト/LOLBin export)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Rundll32 Proxy Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Rundll32 Proxy Execution (DB)
status: stable
level: medium
tags:
  - attack.t1218.011
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  rundll32:
    CommandLine|contains|all:
      - "rundll32"
    CommandLine|contains:
      - "javascript"
      - "vbscript"
      - "mshtml"
      - "url.dll,OpenURL"
      - "url.dll,FileProtocolHandler"
      - "advpack.dll,LaunchINFSection"
      - "pcwutl.dll,LaunchApplication"
      - "zipfldr.dll,RouteTheCall"
      - "shell32.dll,ShellExec_RunDLL"
  condition: rundll32
falsepositives:
  - Rare legitimate rundll32 script or LOLBin export invocation
$$,
'builtin-parity', ARRAY['T1218.011'],
'Two-engine parity: rundll32 script/LOLBin-export proxy execution', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Rundll32 Proxy Execution (DB)');
