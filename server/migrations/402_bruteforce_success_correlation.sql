-- 338: ブルートフォース成功の相関検知(認証失敗多発 → ログイン成功)。
--
-- 2026-07-20 の auth テレメトリ深掘り。既存の SSH ブルートフォース鑑(288)は
-- 「認証失敗の多発」までしか見ておらず、その直後の「ログイン成功」=実際の資格情報
-- 奪取(侵害成立)を相関できていなかった。SequenceEngine に per-stage の最小マッチ数
-- (stage_N_count)を追加したので、「N 回失敗 → 1 回成功」を1ルールで表現できる。
--
-- 同一送信元 IP(group_by: source_ip)で 10 分以内に失敗 6 回 → 成功 1 回が順序連鎖した
-- 場合に検知(T1110 → T1078/T1021.004)。単発の失敗バーストより「失敗多発の直後に成功」
-- の方が侵害成立の強シグナル。sudo/su の失敗は source_ip が空のため "" バケットに入り、
-- login(SSH, 実 IP 付き)とは別バケット=誤発火しない。冪等: WHERE NOT EXISTS。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'ブルートフォース成功（認証失敗多発→ログイン成功）', 'behavioral', ARRAY['linux', 'windows'], 8,
$$
# 同一送信元から 10 分以内に「認証失敗 6 回」→「ログイン成功」が順序で発生した場合に
# 検知(T1110 → T1078)。失敗バースト単体でなく、直後の成功=侵害成立を捉える。
window: 600s
stages: 2
ordered: true
event_type: auth
field: action
stage_1: failed
stage_1_count: 6
stage_2: login
group_by: source_ip
$$,
'community', ARRAY['T1110', 'T1110.001', 'T1078', 'T1021.004'], false, false,
'同一送信元からの認証失敗多発の直後にログイン成功する=ブルートフォースによる資格情報奪取の成立を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'ブルートフォース成功（認証失敗多発→ログイン成功）');
