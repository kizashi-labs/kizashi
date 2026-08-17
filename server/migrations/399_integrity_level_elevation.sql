-- 335: 未活用テレメトリ(IntegrityLevel)を使った昇格ペイロード検知(T1134/T1548)。
--
-- 2026-07-20 の深掘り続き。agent が Sysmon ラベル(Untrusted/Low/Medium/High/System)で
-- トークン整合性レベルを収集済み(process_collector.go)・ingestion/エイリアス層で
-- IntegrityLevel として公開済みなのに、自ルールが1つも使っていなかった。
--
-- 最もクリーンな高シグナル・低FPシグナル: SYSTEM 整合性のプロセスがユーザー
-- プロファイルディレクトリ(C:\Users\...)から実行される。正規の SYSTEM プロセスは
-- System32/Program Files/ProgramData から動き、C:\Users 配下では動かない。SYSTEM を
-- ユーザーパスから走らせる=トークン窃取/名前付きパイプ偽装/サービス悪用で SYSTEM を
-- 得た後にドロップ済みペイロードを実行する post-exploitation の強シグナル。
-- process_creation。冪等: ON CONFLICT DO NOTHING。

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0335-0001-0001-000000000001',
  'SYSTEM Integrity Process from User Profile Path',
  'sigma',
  ARRAY['windows'],
  9,
  $SIGMA$title: SYSTEM Integrity Process from User Profile Path
id: f1a0c0de-0335-0001-0001-000000000001
status: stable
description: Detects a process running at SYSTEM integrity from within a user profile directory which is highly abnormal because legitimate SYSTEM processes run from system directories and indicates token theft or service abuse followed by execution of a dropped payload
references:
  - https://attack.mitre.org/techniques/T1134/
  - https://attack.mitre.org/techniques/T1548/002/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    IntegrityLevel: System
  user_path:
    Image|contains: \Users\
  condition: selection and user_path
falsepositives:
  - Rare SYSTEM-context installer custom actions staged under a user profile
level: critical$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1134', 'T1548.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;
