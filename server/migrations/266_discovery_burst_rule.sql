-- 266: 探索コマンドのバースト検知（value_any 振る舞いルール）を既存環境へ前進適用。
--
-- migration 004 は適用済み環境では再実行されないため、004 に追記した
-- 「探索コマンドの短時間バースト」ルールを、本前進 migration で冪等に投入する。
-- rules.name に一意制約が無いので WHERE NOT EXISTS で二重登録を防ぐ。
-- SequenceEngine の value_any ディレクティブ（列挙値のいずれかを含めばマッチ＝OR）を
-- 使い、60秒以内に 4 種以上の異なる探索系コマンドが実行された場合に検知する。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT '探索コマンドの短時間バースト（ディスカバリ）', 'behavioral', ARRAY['windows', 'linux'], 6,
$$
# 60秒以内に同一エージェントから 4 種類以上の異なる探索系コマンドが実行された場合に検知。
# 単発の whoami / tasklist 等はノイズだが、短時間に多種が連続するのは
# 侵入直後の状況把握（ディスカバリ）に典型的なシグナル。
# value_any: 列挙したコマンドのいずれかを processName が含めばマッチ（OR）。
# distinct で「異なる種類のコマンド数」を数え、閾値判定する。
window: 60s
threshold: 4
event_type: process
field: processName
value_any: whoami, tasklist, systeminfo, ipconfig, ifconfig, hostname, net.exe, net1.exe, nltest, quser, qwinsta, arp, route, netstat, wmic, nbtstat, dsquery, sc.exe, reg.exe, findstr, wevtutil
distinct: true
distinct_field: processName
group_by: agent_id
$$,
'community', ARRAY['T1033', 'T1057', 'T1082', 'T1016', 'T1018', 'T1087.002', 'T1518.001'], false, false,
'侵入直後に多用される探索系コマンドが短時間に多種実行される挙動（ディスカバリ・バースト）を相関検知。', true
WHERE NOT EXISTS (
    SELECT 1 FROM rules WHERE name = '探索コマンドの短時間バースト（ディスカバリ）'
);
