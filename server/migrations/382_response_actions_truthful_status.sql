-- Migration 379: response_actions.success を「嘘をつけない」形にする
--
-- 問題:
--   store/response_actions.go の Record は success を
--     success := status != "failure"
--   で決めていた。status は挿入時点では "pending" が普通なので、
--   「まだ何も起きていない」行が success = true として記録されていた。
--   さらに呼び出し側（agents_handler）はコマンドの配送エラーを捨てたうえで
--   status に "success" をハードコードしていた。結果として
--   response_actions.success は常に真で、証拠能力が無かった。
--   「68 件成功」は「API が 68 回呼ばれた」でしかない。
--
-- 方針:
--   status_text を唯一の真実とし、success はそこから導出される生成列にする。
--   これで success と status_text が食い違う余地が構造的に消える
--   （アプリ側がどう書こうと success を直接書き込めない）。
--
-- 状態の語彙（executed_at からの遷移）:
--   pending    受理したがまだ送っていない
--   dispatched エージェントへ送出した（結果は未確認）
--   running    エージェントが実行中と報告した
--   success    完了した
--   failure    失敗した
--   timeout    送ったが期限内に結果が返らなかった
--   warning    完了したが注意すべき結果（スキャンで検出あり等）
--   cancelled  利用者/エージェントが中止した
--
-- timeout を failure と分けるのは、ネットワーク断とエージェントの拒否を
-- 区別できないと復旧手順が選べないため。

BEGIN;

-- 1. status_text が NULL の既存行を、旧 success から埋める。
--    ここを飛ばすと、次の手順で履歴の成否が失われる。
UPDATE response_actions
   SET status_text = CASE WHEN success THEN 'success' ELSE 'failure' END
 WHERE status_text IS NULL;

-- 2. 語彙外の値を正規化する。CHECK を先に張ると既存行で失敗するため順序が重要。
UPDATE response_actions
   SET status_text = CASE WHEN success THEN 'success' ELSE 'failure' END
 WHERE status_text NOT IN ('pending', 'dispatched', 'running', 'success',
                           'failure', 'timeout', 'warning', 'cancelled');

-- 3. status_text を必須にする。既定は「まだ何も起きていない」。
ALTER TABLE response_actions ALTER COLUMN status_text SET DEFAULT 'pending';
ALTER TABLE response_actions ALTER COLUMN status_text SET NOT NULL;

ALTER TABLE response_actions DROP CONSTRAINT IF EXISTS response_actions_status_text_check;
ALTER TABLE response_actions ADD CONSTRAINT response_actions_status_text_check
  CHECK (status_text IN ('pending', 'dispatched', 'running', 'success',
                         'failure', 'timeout', 'warning', 'cancelled'));

-- 4. success を生成列に置き換える。
--    生成列には INSERT/UPDATE できないので、アプリが success を直接書いていた
--    経路はここで必ずエラーになる。壊れたまま気づかれないより、壊れて止まるほうがよい。
ALTER TABLE response_actions DROP COLUMN success;
ALTER TABLE response_actions ADD COLUMN success BOOLEAN
  GENERATED ALWAYS AS (status_text = 'success') STORED;

COMMIT;
