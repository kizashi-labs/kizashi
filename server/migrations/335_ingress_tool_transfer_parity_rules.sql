-- 335: detection-server (DB RuleEngine) パリティ 第18弾 — 取り込み(ツール転送)。
--
-- T1105 Ingress Tool Transfer の中核 LOLBin ダウンロード 2ベクタを移植する。
-- api-server ビルトインにあるが DB 未移植:
--   certutil  -urlcache/-split/-decode 等でのファイル取得・復号
--   bitsadmin /transfer での BITS 転送
-- ビルトインは Image|contains を併用するが、DB エンジンでは コマンドライン中の
-- バイナリ名 + 攻撃固有フラグを二段 CommandLine|contains(|all アンカー + フラグ列)で
-- 捕捉する(死蔵回避、mig325 InstallUtil と同型)。
--
-- 備考: UAC バイパス T1548.002 は TargetObject(registry_event)ベースで
-- CommandLine のみの DB エンジンへ忠実移植できないため本バッチから除外。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Ingress Tool Transfer via LOLBin (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Ingress Tool Transfer via LOLBin (DB)
description: Detects certutil or bitsadmin abused to download/stage payloads (LOLBin ingress tool transfer).
status: stable
level: high
tags:
  - attack.t1105
  - attack.command_and_control
logsource:
  category: process_creation
detection:
  certutil:
    CommandLine|contains|all:
      - "certutil"
    CommandLine|contains:
      - "-urlcache"
      - "-verifyctl"
      - "-split"
      - "-decode"
      - "-encode"
      - "-decodehex"
  bitsadmin:
    CommandLine|contains|all:
      - "bitsadmin"
      - "/transfer"
  condition: certutil or bitsadmin
falsepositives:
  - Legitimate certificate management or Windows Update / software distribution
$$,
'builtin-parity', ARRAY['T1105'],
'Two-engine parity: ingress tool transfer (certutil/bitsadmin LOLBin download)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Ingress Tool Transfer via LOLBin (DB)');
