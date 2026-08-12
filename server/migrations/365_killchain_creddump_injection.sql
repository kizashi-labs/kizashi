-- 365: LSASSクレデンシャルアクセス → 重要システムプロセスへのスレッド注入の複合キルチェーン。
--
-- PR #542 の棚卸し（docs/検知率向上_20260801_PR542棚卸しとクロスイベント型キルチェーン.md §2）で
-- 「credential_access / create_remote_thread センサーが未着地」として保留したもの。
-- 2026-08-02 に再確認したところ、**両センサーとも main に着地済み**だった:
--
--   agent/internal/collector/credential_access.go   → credential_access（target_image を emit）
--   agent/internal/collector/remote_thread.go       → create_remote_thread（target_image を emit）
--   migration 294 / 314                             → events の CHECK 制約で両 event_type を許可済み
--   internal/detection/field_support.go             → target_image はサポート済みフィールド
--
-- 保留判断が古い前提のまま残っていた。棚卸し時点の情報で書いた「未着地」を鵜呑みにせず、
-- 入力の到達性を4層すべて（センサー emit / CHECK 制約 / フィールドサポート / パイプライン購読）で
-- 再確認してから有効化している。購読については P5-10 を参照。
--
-- 相関の中身:
--   ①lsass.exe への資格情報アクセス（mimikatz/procdump 等の資格情報ダンプの兆候）
--   ②重要システムプロセス（lsass/winlogon/csrss/services/svchost）へのスレッド注入
--
-- がこの順序で15分以内に連鎖するのは、資格情報ダンプの後に検知回避・永続化のため
-- プロセス注入へ移行する、Cobalt Strike/Mimikatz亜種に典型的な侵害後行動。
-- ordered:true — ダンプが先、注入が後（逆順は無関係な事象の可能性が高いため連鎖とみなさない）。
-- target_image をシステムプロセス名に絞ることで、通常のプロセス起動ノイズを排除する。
--
-- stage_N_event_type / stage_N_field は migration 358〜361 と同じクロスイベント型 staged
-- ルール機構（PR #578）。コマンドラインに頼らず、2つの専用センサーを相関させる点が
-- 358〜361（process ベース）との違い。
--
-- rules.name に一意制約が無いので WHERE NOT EXISTS で二重登録を防ぐ（冪等）。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'LSASS資格情報アクセス＋プロセス注入キルチェーン（侵害後の防御回避）', 'behavioral', ARRAY['windows'], 9,
$$
# 15分以内に同一エージェントで「LSASSへの資格情報アクセス」→「重要システムプロセス
# へのスレッド注入」がこの順序で連鎖した場合に検知する、クロスイベント型キルチェーン。
window: 15m
stages: 2
ordered: true
stage_1_event_type: credential_access
stage_1_field: target_image
stage_1: lsass.exe
stage_2_event_type: create_remote_thread
stage_2_field: target_image
stage_2: lsass.exe, winlogon.exe, csrss.exe, services.exe, svchost.exe
group_by: agent_id
$$,
'community', ARRAY['T1003.001', 'T1055.012'], false, false,
'LSASSへの資格情報アクセスの後、重要システムプロセスへのスレッド注入がこの順序で短時間に連鎖する、資格情報ダンプ後の防御回避・永続化行動を複合相関で検知。', true
WHERE NOT EXISTS (
    SELECT 1 FROM rules WHERE name = 'LSASS資格情報アクセス＋プロセス注入キルチェーン（侵害後の防御回避）'
);
