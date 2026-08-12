-- 333: detection-server (DB RuleEngine) パリティ 第16弾 — 復旧妨害 / ログ消去。
--
-- ランサム/アンチフォレンジックの高信号 2種を移植する。両者とも api-server
-- ビルトインにあるが DB 未移植だった:
--   T1490     Inhibit System Recovery — シャドウコピー/バックアップ/復旧の破壊
--   T1070.001 Clear Windows Event Logs — 証跡隠滅のためのイベントログ消去
-- ビルトインは Image|contains を併用するが、DB エンジンでは コマンドラインに現れる
-- バイナリ名 + 攻撃固有フレーズを CommandLine|contains で捕捉する(死蔵回避)。
-- wbadmin/wevtutil は汎用語(delete/cl)の誤検知を抑えるため |all でバイナリ名を
-- アンカーする。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1490 : システム復旧妨害(シャドウコピー/バックアップ破壊)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Inhibit System Recovery (DB)', 'sigma', ARRAY['linux','windows','macos'], 9,
$$title: Inhibit System Recovery (DB)
status: stable
level: critical
tags:
  - attack.t1490
  - attack.impact
logsource:
  category: process_creation
detection:
  shadow_delete:
    CommandLine|contains:
      - "delete shadows"
      - "shadowcopy delete"
      - "resize shadowstorage"
  bcdedit_recovery:
    CommandLine|contains:
      - "recoveryenabled no"
      - "bootstatuspolicy ignoreallfailures"
  ps_wmi_obj:
    CommandLine|contains: "Win32_ShadowCopy"
  ps_wmi_del:
    CommandLine|contains:
      - "Remove-WmiObject"
      - "Remove-CimInstance"
      - ".Delete("
      - "Delete()"
  wbadmin_delete:
    CommandLine|contains|all:
      - "wbadmin"
      - "delete"
  condition: shadow_delete or bcdedit_recovery or (ps_wmi_obj and ps_wmi_del) or wbadmin_delete
falsepositives:
  - Legitimate backup software maintenance
$$,
'builtin-parity', ARRAY['T1490'],
'Two-engine parity: inhibit system recovery (shadow/backup/BCD destruction)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Inhibit System Recovery (DB)');

-- ── T1070.001 : Windows イベントログ消去 ─────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Clear Windows Event Logs (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Clear Windows Event Logs (DB)
status: stable
level: high
tags:
  - attack.t1070.001
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  wevtutil_cl:
    CommandLine|contains|all:
      - "wevtutil"
      - "cl"
  ps_clear:
    CommandLine|contains: "Clear-EventLog"
  condition: wevtutil_cl or ps_clear
falsepositives:
  - Legitimate log management automation
$$,
'builtin-parity', ARRAY['T1070.001'],
'Two-engine parity: Windows event log clearing (wevtutil/Clear-EventLog)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Clear Windows Event Logs (DB)');
