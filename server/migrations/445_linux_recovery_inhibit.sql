-- Linux ネイティブな復旧妨害(T1490)の検知。ransomCorr の recovery_inhibit 軸を
-- Linux で埋めるためのルール。
--
-- なぜ必要か。2026-08-17 のランサムウェア模擬(docs/死蔵経路の全数棚卸し_20260810.md §21)で
-- ransomCorr は Linux でも発火することが確認できたが、recovery_inhibit 軸を埋めたのは
-- 既存の `ランサムウェア復旧阻害キルチェーン` であり、その照合語彙は
--
--   stage_1: vssadmin delete shadows, wmic shadowcopy delete, wbadmin delete catalog, ...
--   stage_2: bcdedit /set, cipher /w, fsutil usn deletejournal
--
-- と **すべて Windows のもの**である。sequence ルールは platform ゲートを受けず
-- commandLine の部分一致で判定するため、その文字列を含むコマンドを Linux で実行すれば
-- 当たる——模擬ではまさにそれを意図的に行って軸を埋めた。
--
-- 実際の Linux ランサムウェアは vssadmin も bcdedit も実行しない。LVM/btrfs/ZFS の
-- スナップショット削除や /var/backups の一括削除で復旧手段を潰す。それを拾うルールが
-- 存在しないため、**Linux では strong 軸が埋まらず mass_modify + acl_stage の2軸
-- (severity 9・隔離なし)で止まる**。検知はするが封じ込めない、という状態だった。
--
-- 設計上の判断:
--
-- (1) 2段シーケンスではなく単発(threshold: 1)にする。Windows 版が2段なのは
--     「シャドウコピー削除 → 起動時復旧の無効化」という定型手順があるからで、Linux に
--     対応する第2段は無い。2段を要求すると軸がまた埋まらなくなる。
--
-- (2) 代わりに severity を 3 (低) に抑える。このルールの値打ちは単独のアラートではなく
--     **ransomCorr への入力**である。`Suspicious chmod of Executable in /tmp` が
--     "Its value is as an input to the download→chmod→execute kill chain" として
--     level: low を選んでいるのと同じ設計。単独では騒がず、mass_modify と併発したときに
--     ransomCorr が severity 9/10 で鳴る。
--
-- (3) cooldown を 30m にする。スナップショットのローテーションを定期実行している
--     ホストでは stage_1 相当の操作が日常的に走る。既定のクールダウンに任せず明示する。
--
-- (4) 裸のバイナリ名を語彙にしない。検証EC2 の実測(14日)で `wipefs` は 6 件当たったが、
--     中身は mkinitramfs が `/sbin/wipefs` を **コピーしただけ** だった。破壊を示す
--     引数まで含めた形(`wipefs -a`)にしないと、パス名の言及で誤検知する。
--
-- 誤検知の実測(検証EC2 / 14日 / process イベント): 下記いずれのトークンも自然発生は
-- 0 件だった(検出された数件はすべて、この調査自体が発行した SQL 文が commandLine として
-- 記録されたものと、上記 mkinitramfs のコピー)。ただし1ホストの計測であり、
-- スナップショットのローテーションを実運用しているホストでの FP ソークは別途必要。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'Linux 復旧阻害の疑い(スナップショット/バックアップ破壊)', 'behavioral', ARRAY['linux'], 3,
$$
# Linux でのバックアップ/スナップショット破壊を単発で検知(T1490)。
# 単独では低 severity。ransomCorr の recovery_inhibit 軸への入力として機能し、
# 暗号化バースト(mass_modify)と併発したときに複合アラートへ昇格する。
window: 10m
threshold: 1
cooldown: 30m
event_type: process
field: commandLine
value_any: btrfs subvolume delete, zfs destroy, lvremove, snapper delete, timeshift --delete, restic forget, restic prune, borg delete, borg prune, rm -rf /var/backups, rm -rf /.snapshots, rm -rf /backup, virsh snapshot-delete, rbd snap purge, rbd snap rm, rsnapshot delete, wipefs -a
group_by: agent_id
$$,
'builtin', ARRAY['T1490'], false, false,
'Linux のスナップショット/バックアップ破壊を検知。単独では低 severity で、ランサムウェア相関(ransomCorr)の復旧妨害軸への入力として働く。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux 復旧阻害の疑い(スナップショット/バックアップ破壊)');
