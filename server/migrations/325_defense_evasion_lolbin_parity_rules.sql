-- 325: detection-server (DB RuleEngine) パリティ 第8弾 — 防御回避 LOLBin プロキシ実行。
--
-- api-server ビルトインにあるがDB未移植の署名済みシステムバイナリ(LOLBin)悪用を移植し、
-- 両エンジンで被覆する。ビルトインは Image|contains を併用するが、DB エンジンでは
-- LOLBin のバイナリ名+攻撃固有フラグを CommandLine|contains で捕捉する(死蔵回避)。
-- FP多発の MSBuild(T1127.001)は dev/CI で正規多用のため本バッチから除外。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1218.004 : InstallUtil プロキシ実行 ─────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'InstallUtil Proxy Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: InstallUtil Proxy Execution (DB)
description: Detects InstallUtil used to proxy-execute a .NET assembly (via /u uninstall hook or /logfile=/logtoconsole=false), bypassing application control by running through a signed Microsoft binary.
status: stable
level: medium
tags:
  - attack.t1218.004
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  installutil:
    CommandLine|contains|all:
      - "installutil"
    CommandLine|contains:
      - "/logfile="
      - "/logtoconsole=false"
      - "/u"
  condition: installutil
falsepositives:
  - Legitimate .NET installer registration
$$,
'builtin-parity', ARRAY['T1218.004'],
'Two-engine parity: InstallUtil LOLBin proxy execution', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'InstallUtil Proxy Execution (DB)');

-- ── T1218.007 : Msiexec 遠隔MSI実行 ─────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Msiexec Remote MSI Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Msiexec Remote MSI Execution (DB)
description: Detects msiexec installing a package directly from a remote URL, a LOLBin proxy-execution and download technique that fetches and runs an attacker-hosted MSI through a signed Microsoft binary.
status: stable
level: high
tags:
  - attack.t1218.007
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  msiexec_remote:
    CommandLine|contains|all:
      - "msiexec"
    CommandLine|contains:
      - "http://"
      - "https://"
      - "ftp://"
  condition: msiexec_remote
falsepositives:
  - Enterprise software deployment from trusted internal URLs
$$,
'builtin-parity', ARRAY['T1218.007'],
'Two-engine parity: msiexec remote MSI proxy execution', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Msiexec Remote MSI Execution (DB)');

-- ── T1218.009 : Regsvcs/Regasm プロキシ実行 ─────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Regsvcs Regasm Proxy Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Regsvcs Regasm Proxy Execution (DB)
description: Detects regsvcs.exe or regasm.exe used to proxy-execute code in a .NET assembly via its registration hooks, bypassing application control through a signed Microsoft binary.
status: stable
level: medium
tags:
  - attack.t1218.009
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  regsvcs_regasm:
    CommandLine|contains:
      - "regsvcs.exe"
      - "regasm.exe"
  condition: regsvcs_regasm
falsepositives:
  - Legitimate .NET assembly registration by developers or installers
$$,
'builtin-parity', ARRAY['T1218.009'],
'Two-engine parity: Regsvcs/Regasm LOLBin proxy execution', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Regsvcs Regasm Proxy Execution (DB)');

-- ── T1220 : XSL スクリプト処理プロキシ実行 ──────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'XSL Script Processing Proxy Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: XSL Script Processing Proxy Execution (DB)
description: Detects code execution through XSL stylesheets via msxsl.exe or wmic with a /format:*.xsl payload, bypassing application control by running script inside a signed processor.
status: stable
level: medium
tags:
  - attack.t1220
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  msxsl:
    CommandLine|contains: "msxsl"
  wmic_xsl:
    CommandLine|contains|all:
      - "wmic"
      - ".xsl"
  condition: msxsl or wmic_xsl
falsepositives:
  - Rare legitimate XSLT transformation tooling
$$,
'builtin-parity', ARRAY['T1220'],
'Two-engine parity: XSL script processing proxy execution', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'XSL Script Processing Proxy Execution (DB)');

-- ── T1218.003 : CMSTP プロキシ実行 ─────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'CMSTP Proxy Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: CMSTP Proxy Execution (DB)
description: Detects cmstp.exe installing a malicious INF connection-manager profile (/s silent or /ns), abused to proxy-execute code and bypass application control / UAC through a signed Microsoft binary.
status: stable
level: high
tags:
  - attack.t1218.003
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  cmstp:
    CommandLine|contains|all:
      - "cmstp"
    CommandLine|contains:
      - "/s"
      - "/ns"
      - ".inf"
  condition: cmstp
falsepositives:
  - Legitimate connection-manager profile installation
$$,
'builtin-parity', ARRAY['T1218.003'],
'Two-engine parity: CMSTP INF proxy execution', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'CMSTP Proxy Execution (DB)');
