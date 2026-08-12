-- 343: detection-server (DB RuleEngine) パリティ 第26弾 — 収集/信頼ストア操作。
--
-- api-server ビルトインにあるが DB 未移植の3種を移植する:
--   T1560.001 Archive Collected Data — rar/7z でのパスワード付きアーカイブ(持ち出し前ステージ)
--   T1113     Screen Capture         — CopyFromScreen API / nircmd savescreenshot
--   T1553.004 Install Root Certificate — certutil -addstore root(AiTM/悪性署名の信頼化)
-- ビルトインは Image を併用するが、DB エンジンでは コマンドライン中のツール名 +
-- 攻撃固有フラグ/キーワードの複合条件で捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1560.001 : パスワード付きアーカイブでのデータステージ(rar/7z)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Data Staged in Password-Protected Archive (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Data Staged in Password-Protected Archive (DB)
description: Detects rar/7z creating password-protected archives — staging data before exfiltration.
status: stable
level: medium
tags:
  - attack.t1560.001
  - attack.collection
logsource:
  category: process_creation
detection:
  tool:
    CommandLine|contains:
      - "rar"
      - "7z"
  protect:
    CommandLine|contains:
      - " -hp"
      - " -p"
      - "-hp"
  condition: tool and protect
falsepositives:
  - Legitimate password-protected backups
$$,
'builtin-parity', ARRAY['T1560.001'],
'Two-engine parity: data staged in password-protected archive (rar/7z)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Data Staged in Password-Protected Archive (DB)');

-- ── T1113 : スクリーンキャプチャ(CopyFromScreen / nircmd savescreenshot)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Screen Capture (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Screen Capture (DB)
description: Detects screen capture via the .NET Graphics.CopyFromScreen API or nircmd savescreenshot LOLBin.
status: stable
level: high
tags:
  - attack.t1113
  - attack.collection
logsource:
  category: process_creation
detection:
  api:
    CommandLine|contains: "CopyFromScreen"
  nircmd:
    CommandLine|contains|all:
      - "nircmd"
      - "savescreenshot"
  condition: api or nircmd
falsepositives:
  - Legitimate screenshot/remote-support tooling
$$,
'builtin-parity', ARRAY['T1113'],
'Two-engine parity: screen capture (CopyFromScreen / nircmd)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Screen Capture (DB)');

-- ── T1553.004 : ルート証明書インストール(certutil -addstore root)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Root Certificate Installation (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Root Certificate Installation (DB)
description: Detects certutil -addstore into the Root/AuthRoot trust store — enabling AiTM interception or trust of malicious code-signing certificates.
status: stable
level: high
tags:
  - attack.t1553.004
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  certutil:
    CommandLine|contains|all:
      - "certutil"
      - "-addstore"
    CommandLine|contains:
      - "root"
      - "authroot"
  condition: certutil
falsepositives:
  - Enterprise PKI deployment of internal root/intermediate certificates
$$,
'builtin-parity', ARRAY['T1553.004'],
'Two-engine parity: root certificate installation via certutil -addstore', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Root Certificate Installation (DB)');
