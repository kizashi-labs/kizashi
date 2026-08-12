-- 342: detection-server (DB RuleEngine) パリティ 第25弾 — 間接実行/難読化(防御回避)。
--
-- api-server ビルトインにあるが DB 未移植の防御回避3種を移植する:
--   T1202     Indirect Command Execution — forfiles/pcalua/scriptrunner 経由の実行
--   T1027.004 Compile After Delivery     — gcc/clang 等で temp からソースをコンパイル
--   T1140     Deobfuscate/Decode         — base64 -d 等でのペイロード展開
-- ビルトインは Image を併用するが、DB エンジンでは コマンドライン中のツール名 +
-- 対象(ペイロード拡張子/一時パス/デコード動作)の複合条件で捕捉する。
-- T1027.004 の Windows 一時パス(バックスラッシュ)は YAML エスケープ問題を避けるため
-- 本移植から除外し、Linux 一時パス(/tmp/ 等)で捕捉する(mig331 と同方針)。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1202 : 間接コマンド実行(forfiles/pcalua/scriptrunner)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Indirect Command Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Indirect Command Execution (DB)
description: Detects forfiles/pcalua/scriptrunner launching a shell or executable — indirect execution that breaks the expected parent-child chain.
status: stable
level: medium
tags:
  - attack.t1202
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  tool:
    CommandLine|contains:
      - "forfiles"
      - "pcalua"
      - "scriptrunner"
  payload:
    CommandLine|contains:
      - "cmd"
      - "powershell"
      - ".exe"
      - ".bat"
      - ".vbs"
  condition: tool and payload
falsepositives:
  - Legitimate maintenance scripts using forfiles
$$,
'builtin-parity', ARRAY['T1202'],
'Two-engine parity: indirect command execution (forfiles/pcalua/scriptrunner)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Indirect Command Execution (DB)');

-- ── T1027.004 : 配送後コンパイル(gcc/clang 等 × 一時ディレクトリ)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Compile After Delivery (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Compile After Delivery (DB)
description: Detects on-host compilation by gcc/g++/clang/csc from a temporary directory — building payloads on the victim to evade signature detection.
status: experimental
level: medium
tags:
  - attack.t1027.004
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  compiler:
    CommandLine|contains:
      - "gcc"
      - "g++"
      - "clang"
      - "csc.exe"
  temp_src:
    CommandLine|contains:
      - "/tmp/"
      - "/dev/shm/"
      - "/var/tmp/"
  condition: compiler and temp_src
falsepositives:
  - Build systems that compile in temporary directories
$$,
'builtin-parity', ARRAY['T1027.004'],
'Two-engine parity: compile after delivery (compiler in temp dir)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Compile After Delivery (DB)');

-- ── T1140 : 難読化解除/デコード(base64 -d 等)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Deobfuscate Decode via Base64 (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Deobfuscate Decode via Base64 (DB)
description: Detects base64 decode piped to a shell (base64 -d / --decode / | base64) — command obfuscation and payload expansion.
status: stable
level: medium
tags:
  - attack.t1140
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "base64 -d"
      - "base64 --decode"
      - "| base64"
  condition: selection
falsepositives:
  - Legitimate deployment scripts
$$,
'builtin-parity', ARRAY['T1140'],
'Two-engine parity: deobfuscate/decode via base64', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Deobfuscate Decode via Base64 (DB)');
