-- 348: 国ベースの外部通信検知(opt-in テンプレート)。
--
-- 前提: detection サーバの EngineConfig.GeoIPEnrichEnabled=true で country_enrich
-- が有効なとき、外部宛先の network イベントに country_code が非同期 populate される。
-- 国の許可/拒否は組織依存のため、本ルールは既定 disabled で seed し、自組織の
-- 高リスク国リストに調整して有効化する運用とする(dual-use テンプレートと同方針)。
--
-- 既定リストは「業務上まず通信しない=通信あれば要調査」の代表例。自組織の実態に
-- 合わせて country_code の値(ISO 3166-1 alpha-2)を編集し、enabled=true にすること。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Outbound Connection to High-Risk Country (opt-in)', 'sigma', ARRAY['windows','linux','macos'], 5,
$SIGMA$
title: Outbound Connection to High-Risk Country (opt-in)
description: Detects an outbound connection whose GeoIP country_code is in the configured high-risk set. Country is not an indicator of compromise by itself, so this ships DISABLED — tune the country_code list to destinations your organization never legitimately talks to, ensure detection GeoIPEnrichEnabled is on (so country_code is populated), then enable. Complements volume/beacon exfil detection with a geographic signal (T1071 / T1041 adjacent).
status: experimental
level: medium
tags:
  - attack.t1071
  - attack.command_and_control
logsource:
  category: network_connection
detection:
  selection:
    country_code:
      - KP
      - IR
      - SY
  filter_dir:
    direction: inbound
  condition: selection and not filter_dir
falsepositives:
  - Legitimate business with the listed regions — tune the list per environment before enabling
$SIGMA$,
'community', ARRAY['T1071'],
'Opt-in GeoIP template: outbound to a high-risk country (requires GeoIPEnrichEnabled; disabled until tuned)', false
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Outbound Connection to High-Risk Country (opt-in)');
