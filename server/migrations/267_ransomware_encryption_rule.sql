-- 267: ランサムウェアの一括ファイル暗号化検知（value_any 振る舞いルール）を既存環境へ前進適用。
--
-- migration 004 は適用済み環境では再実行されないため、004 に追記した
-- 「ランサムウェアによる一括ファイル暗号化」ルールを、本前進 migration で冪等に投入する。
-- rules.name に一意制約が無いので WHERE NOT EXISTS で二重登録を防ぐ。
-- SequenceEngine の value_any（列挙拡張子のいずれかを path が含めばマッチ＝OR）と
-- distinct_field=path を併用し、60秒以内に 20 個以上の異なるファイルが
-- ランサムウェア拡張子へ変化した挙動を相関検知する。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'ランサムウェアによる一括ファイル暗号化', 'behavioral', ARRAY['windows', 'linux'], 9,
$$
# 60秒以内に同一エージェントで 20 個以上の異なるファイルが
# ランサムウェア拡張子に変化した場合に検知。
# 単一ファイルの改名はノイズだが、短時間の大量改変はランサムウェアの
# 暗号化進行に典型的なシグナル。
# value_any: パスが列挙した拡張子のいずれかを含めばマッチ（OR）。
# distinct_field=path で「異なる暗号化ファイル数」を数え、閾値判定する。
window: 60s
threshold: 20
event_type: file
field: path
value_any: .locked, .encrypted, .crypt, .crypto, .enc, .crypted, .cry, .cerber, .locky, .zepto, .wncry, .wcry, .ryuk, .conti, .lockbit, .makop, .phobos, .djvu, .stop, .sage, .globe, .vault, .xtbl, .nemesis, .aes256, .rsa
distinct: true
distinct_field: path
group_by: agent_id
$$,
'community', ARRAY['T1486'], false, false,
'短時間に多数のファイルがランサムウェア拡張子へ変化する挙動（一括暗号化）を相関検知。', true
WHERE NOT EXISTS (
    SELECT 1 FROM rules WHERE name = 'ランサムウェアによる一括ファイル暗号化'
);
