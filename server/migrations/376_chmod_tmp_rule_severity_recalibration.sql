-- 376: "Suspicious chmod of Executable in /tmp" の重大度を 7 → 4 に再校正する。
--
-- このルールは 2026-08-03/04 の FP ソークで一貫して 12 件を出しており、
-- 誤検知の上位常連である。ただし migration 372 の Archive ルールと違い、
-- **セレクタを直す余地が無い。**
--
--   良性: chmod +x /tmp/installer-{{rand}}.sh   (tests/fpsoak/profiles/dev-machine.toml:136)
--   攻撃: ダウンロードしたペイロードに実行権を与える
--
-- 単一の process_creation イベントとして、この 2 つは完全に同一である。
-- 区別する情報がイベント内に存在しない。開発者は日常的にこれを行う。
--
-- 実際の検知はキルチェーン相関が担っている。ダウンロード → chmod → 実行 の
-- 文脈込みで判定する `[BEHAVIORAL] Linux マルウェア投下キルチェーン` が
-- 同じソークで発火しており、そちらが本来の検知器である。単独ルールはその
-- 重複でありながら文脈を持たない。
--
-- ★ 重大度を下げても失われるものが無いことを確認したうえでの変更である:
--
--   自動隔離    engine.go の AutoIsolateSeverityThreshold は既定 9 で、加えて
--               ルール側の auto_isolate=true が要る。本ルールは severity=7 /
--               auto_isolate=false なので、元から対象外。影響なし。
--   相関        killchain.go / ransomware_correlator.go は MITRE タグ (T1222) で
--               入力を選んでおり、重大度を見ていない。影響なし。
--   AI トリアージ AIAnalysisMinSeverity は既定 5。7 → 4 で対象外になる。
--               弁別できない信号に Claude API を 1.67 ホスト日あたり 12 回
--               費やすのは浪費なので、これは損失ではなく削減である。
--
-- 残るのはトリアージ上の優先度だけで、そこが本来直すべき点である。
-- 「high」は、真に高深刻度のアラートと同じ列に並べてよいという主張であり、
-- 良性フリートで 12 件出る信号にその主張は成り立たない。
--
-- セレクションの分割 (chmod_bin / mode_bits / staging_dir) は migration 371 が
-- YAML 重複キーを解消した形をそのまま引き継いでいる。1 つの selection に
-- 戻すと同じキーを 2 回書くことになり、あの欠陥に逆戻りする。
--
-- ⚠️ これは誤検知の「件数」を減らす変更ではない。ソークは重大度に関わらず
-- アラートを数えるので 12 件は残る。変えるのは、その 12 件が何を主張するかである。

UPDATE rules
   SET severity = 4,
       content = $$
title: Suspicious chmod of Executable in /tmp
id: a1b2c3d4-0007-0007-0007-000000000035
status: stable
description: Detects chmod granting execute permission to a file in a world-writable directory (/tmp, /dev/shm) — the step that makes a downloaded payload runnable. Low severity by design; developers do this constantly and a single process_creation event cannot tell the two apart. Its value is as an input to the download→chmod→execute kill chain, which is where the actual detection happens.
level: low
tags:
  - attack.t1222.002
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  chmod_bin:
    Image|contains: '/chmod'
  mode_bits:
    CommandLine|contains:
      - '+x'
      - '755'
      - '777'
  staging_dir:
    CommandLine|contains:
      - '/tmp/'
      - '/dev/shm/'
  condition: chmod_bin and mode_bits and staging_dir
falsepositives:
  - Developers marking downloaded installers or build scripts executable under /tmp — indistinguishable from the technique in a single event
$$
 WHERE name = 'Suspicious chmod of Executable in /tmp';
