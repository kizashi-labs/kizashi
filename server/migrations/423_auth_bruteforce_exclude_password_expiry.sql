-- 372: ブルートフォース系の相関から「パスワード期限切れ」の認証失敗を除外する。
--
-- ── なぜ必要か ────────────────────────────────────────────────────────────
-- 338「ブルートフォース成功（認証失敗多発→ログイン成功）」と 339「認証失敗多発→
-- 権限昇格キルチェーン」は、認証失敗の**回数**だけを見て推測攻撃と判定していた。
-- しかし失敗には推測ではないものが混じる。
--
--   The user's password must be changed before signing in  (STATUS_PASSWORD_MUST_CHANGE)
--   The specified account password has expired             (STATUS_PASSWORD_EXPIRED)
--
-- これらは**提出したパスワードが正しかった**からこそ返る応答で、アカウント状態が
-- ログインを止めているにすぎない。パスワードを推測している攻撃者がこの応答を
-- 受け取ることは原理的にない（正解を当てた時点で推測は終わっている）。
--
-- 実運用では、期限切れが重なる日に失敗が固まって出る。FPソークのプロファイルも
-- それを再現しており（file-server の 'password must be changed'、it-admin の
-- svc_monitor / svc_backup の 'password has expired'）、2026-08-04 の実測で
-- 338 が 9,599.96 /1000ホスト/日（16件・7ホスト）、339 の権限昇格側が
-- 5,399.98（9件・4ホスト）を出していた。どちらもゲート超過の原因。
--
-- ── 何を変えるか ──────────────────────────────────────────────────────────
-- stage_1（認証失敗）に stage_1_exclude / stage_1_exclude_field を足し、
-- failure_reason が期限切れ系のイベントを段の対象から外す。閾値（6回/5回）と
-- 窓（600s）は変えない。**検知能力は落ちない**: 本物のブルートフォースが返す
-- 「ユーザ名かパスワードが違う」系の失敗は従来どおり数える。
--
-- 除外は failure_reason を**持つイベントにのみ**効く。フィールドが無いイベントは
-- 従来どおり数える（無いことを根拠に落とすと、この列を埋めないプロデューサ全部で
-- 段が黙って無効になる）。
--
-- 依存: SequenceEngine の stage_N_exclude / stage_N_exclude_field 対応。

UPDATE rules
SET content = $SEQ$
# 同一送信元から 10 分以内に「認証失敗 6 回」→「ログイン成功」が順序で発生した場合に
# 検知(T1110 → T1078)。失敗バースト単体でなく、直後の成功=侵害成立を捉える。
#
# パスワード期限切れ系の失敗は除外する。これらは提出したパスワードが正しかった
# 場合にのみ返る応答であり、推測攻撃では発生しない。
window: 600s
stages: 2
ordered: true
event_type: auth
field: action
stage_1: failed
stage_1_count: 6
stage_1_exclude_field: failure_reason
stage_1_exclude: password has expired, password must be changed, password expired
stage_2: login
group_by: source_ip
$SEQ$
WHERE name = 'ブルートフォース成功（認証失敗多発→ログイン成功）';

UPDATE rules
SET content = $SEQ$
# 認証失敗の多発から特権昇格へ至る流れ(T1110 → T1548)。同一ユーザで
# 10 分以内に「失敗 5 回」→「権限昇格」が順序で発生した場合に検知。
#
# パスワード期限切れ系の失敗は除外する（338 と同じ理由）。
window: 600s
stages: 2
ordered: true
event_type: auth
field: action
stage_1: failed
stage_1_count: 5
stage_1_exclude_field: failure_reason
stage_1_exclude: password has expired, password must be changed, password expired
stage_2: privilege
group_by: username
$SEQ$
WHERE name = '認証失敗多発→権限昇格キルチェーン';
