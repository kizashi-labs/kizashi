-- 339: 「量×順序」相関の拡充(per-stage 最小マッチ数の活用)。
--
-- 2026-07-20、SequenceEngine に stage_N_count(per-stage 最小マッチ数)を追加した
-- (migration 338)のを活かし、「先頭段は単発では良性だが VOLUME があると悪性」→
-- 「次段へ順序連鎖」型の相関を2件追加。単発バーストや単発の次段よりも、
-- 「量のある偵察/失敗の直後に決定的アクション」の方が侵入進行の強シグナル。

-- (1) 探索バースト → 横展開(discovery×5 → T1021)。
--     既存 274(偵察→認証情報→横展開)は認証情報ダンプ段を挟むが、本ルールは
--     ダンプせず既存の正規資格情報で横展開する「recon 重→pivot」を捕捉(非重複)。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT '探索バースト→横展開キルチェーン', 'behavioral', ARRAY['windows'], 8,
$$
# 15分以内に「ホスト/ネットワーク探索コマンド 5 回」→「リモート実行(横展開)」が
# この順で発生した場合に検知(Discovery → T1021)。量のある偵察直後の pivot。
window: 15m
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: whoami, net user, net group, net localgroup, net view, nltest, systeminfo, ipconfig /all, netstat -, arp -a, tasklist, quser, dsquery, route print
stage_1_count: 5
stage_2: psexec, wmic /node:, winrs -r:, invoke-command -computername, enter-pssession -computername, sc \\, schtasks /s , wmiexec, /node: process call create
group_by: agent_id
$$,
'community', ARRAY['T1046', 'T1018', 'T1082', 'T1021'], false, false,
'量のあるホスト/ネットワーク探索の直後にリモート実行で横展開する多段攻撃を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = '探索バースト→横展開キルチェーン');

-- (2) 認証失敗多発 → 権限昇格(auth failed×5 → sudo/su 権限取得, T1110/T1548.003)。
--     同一ユーザーの認証失敗が多発した直後に sudo/su で権限を得る=総当たり/推測で
--     資格情報を得た後の昇格。source_ip でなく username で括る(sudo は source_ip 空)。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT '認証失敗多発→権限昇格キルチェーン', 'behavioral', ARRAY['linux'], 8,
$$
# 10分以内に同一ユーザーで「認証失敗 5 回」→「sudo/su 権限取得」が順序で発生した
# 場合に検知(T1110 → T1548.003)。失敗多発の直後の昇格は資格情報奪取後の昇格の疑い。
window: 600s
stages: 2
ordered: true
event_type: auth
field: action
stage_1: failed
stage_1_count: 5
stage_2: privilege
group_by: username
$$,
'community', ARRAY['T1110', 'T1548.003', 'T1078'], false, false,
'同一ユーザーの認証失敗多発の直後に sudo/su で権限昇格する=資格情報奪取後の昇格を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = '認証失敗多発→権限昇格キルチェーン');
