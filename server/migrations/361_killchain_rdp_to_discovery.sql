-- 361: 外部からのRDP接続→即時偵察コマンドの複合キルチェーン。
--
-- migration 318/319と同じクロスイベント型staged機構（stage_N_event_type/
-- stage_N_field）を用いる、3つ目のクロスイベント型キルチェーン。今回はネットワーク
-- イベント(RDP接続受理)とプロセスイベント(偵察コマンド)を相関させる。
--
--   ①RDP(3389)接続の受理
--   ②直後に状況把握コマンド(whoami/net user/net localgroup/systeminfo/tasklist)
--     が実行される
--
-- が5分以内にこの順序で連鎖するのは、外部/未知の経路からRDPで侵入した直後に
-- 攻撃者が状況把握を行う典型パターン。単発のRDP接続はほぼ常に正当な運用のため
-- 低severityの可視化目的の単発Sigmaルールに留めているが、直後の偵察コマンドと
-- 連鎖した場合は不正アクセスの強いシグナルとなる。ordered:true — 接続が先、
-- 偵察が後。
--
-- rules.name に一意制約が無いので WHERE NOT EXISTS で二重登録を防ぐ（冪等）。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'RDP接続＋即時偵察キルチェーン（不正リモートアクセスの直後行動）', 'behavioral', ARRAY['windows'], 7,
$$
# 5分以内に同一エージェントで「RDP(3389)接続の受理」→「偵察コマンド実行」が
# この順序で連鎖した場合に検知する、クロスイベント型キルチェーン。
window: 5m
stages: 2
ordered: true
stage_1_event_type: network
stage_1_field: dst_port
stage_1: 3389
stage_2_event_type: process
stage_2_field: commandline
stage_2: whoami, net user, net localgroup, systeminfo, tasklist
group_by: agent_id
$$,
'community', ARRAY['T1133', 'T1082'], false, false,
'RDP接続の受理直後、同一ホストで状況把握コマンドが短時間に実行される、不正なリモートアクセス直後の行動を複合相関で検知。単発のRDP接続では見えない侵害の兆候を捉える。', true
WHERE NOT EXISTS (
    SELECT 1 FROM rules WHERE name = 'RDP接続＋即時偵察キルチェーン（不正リモートアクセスの直後行動）'
);
