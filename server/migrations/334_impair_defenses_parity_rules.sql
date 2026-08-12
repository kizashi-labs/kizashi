-- 334: detection-server (DB RuleEngine) パリティ 第17弾 — 防御妨害(Defender/FW)。
--
-- 防御妨害の高信号 2種を移植する。両者とも api-server ビルトインにあるが DB 未移植:
--   T1562.001 Impair Defenses: Disable/Modify Tools — Defender の除外/機能無効化/
--             サービス停止/定義削除(FN堅牢化済みの broad ルールを移植)
--   T1562.004 Disable/Modify System Firewall — netsh advfirewall 全プロファイル無効化
-- ビルトインは Image|contains を併用するが、DB エンジンでは コマンドライン中の
-- 攻撃固有フレーズを CommandLine|contains で捕捉する(死蔵回避)。Defender は
-- ((Set/Add-MpPreference and 除外/無効化) or (サービス名 and 停止動詞) or
-- (MpCmdRun and RemoveDefinitions)) の複合条件で広く捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1562.001 : Windows Defender 改ざん(除外/サービス/MpCmdRun)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Windows Defender Tampering (DB)', 'sigma', ARRAY['linux','windows','macos'], 9,
$$title: Windows Defender Tampering (DB)
status: stable
level: critical
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  setmp:
    CommandLine|contains: "Set-MpPreference"
  addmp:
    CommandLine|contains: "Add-MpPreference"
  mp_evasion:
    CommandLine|contains:
      - "-Disable"
      - "-ExclusionPath"
      - "-ExclusionProcess"
      - "-ExclusionExtension"
      - "-MAPSReporting Disabled"
      - "-SubmitSamplesConsent NeverSend"
  svc_name:
    CommandLine|contains:
      - "windefend"
      - "wdnissvc"
      - " sense"
      - "wdboot"
      - "wscsvc"
  svc_verb:
    CommandLine|contains:
      - "net stop"
      - "sc stop"
      - "sc.exe stop"
      - "Stop-Service"
      - "sc config"
      - "sc.exe config"
  mpcmdrun:
    CommandLine|contains: "MpCmdRun"
  removedef:
    CommandLine|contains: "RemoveDefinitions"
  condition: ((setmp or addmp) and mp_evasion) or (svc_name and svc_verb) or (mpcmdrun and removedef)
falsepositives:
  - Authorised AV administration / security testing
$$,
'builtin-parity', ARRAY['T1562.001'],
'Two-engine parity: Windows Defender tampering (exclusion/service/MpCmdRun)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Windows Defender Tampering (DB)');

-- ── T1562.004 : Windows ファイアウォール無効化(netsh advfirewall)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Windows Firewall Disabled (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Windows Firewall Disabled (DB)
status: stable
level: high
tags:
  - attack.t1562.004
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  netsh_off:
    CommandLine|contains|all:
      - "advfirewall"
      - "allprofiles"
      - "state off"
  condition: netsh_off
falsepositives:
  - Authorised network configuration changes
$$,
'builtin-parity', ARRAY['T1562.004'],
'Two-engine parity: Windows firewall disabled via netsh advfirewall', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Windows Firewall Disabled (DB)');
