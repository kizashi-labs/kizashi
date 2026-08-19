-- Migration 431: response_actions に 'suppressed' を足す
--
-- 背景:
--   隔離の安全弁（冷却期間・時間あたり上限・ドライラン・AUTO_RESPONSE_ENABLED）が
--   隔離を止めたとき、これまでは slog に一行出るだけだった。ログの grep では
--   「今週この安全弁は何件止めたのか」を集計できない。段階的有効化の判断材料は
--   まさにその件数なので、数えられないものを根拠に本番を有効化することになる。
--
--   そこで抑止も response_actions に行として残す。ただし既存の語彙に当てはまる
--   値が無い:
--     failure   → 失敗していない。実行しないことが正しい動作だった。
--     cancelled → 「利用者/エージェントが中止した」の意味。止めたのは仕組み。
--   どちらを流用しても記録が事実とずれる。success を生成列にしてまで嘘を
--   潰した直後に、別の嘘を語彙の都合で入れるのは筋が通らない。
--
--   'suppressed' = 「実行しないと判断した」。success は生成列なので自動的に
--   false になる（status_text = 'success' ではないため）。
--
-- 参照: server/internal/isolation/isolation.go の Outcome。
--   どの安全弁が止めたのかは details.outcome に入る
--   （dry_run / refused / disabled）。

BEGIN;

ALTER TABLE response_actions DROP CONSTRAINT IF EXISTS response_actions_status_text_check;
ALTER TABLE response_actions ADD CONSTRAINT response_actions_status_text_check
  CHECK (status_text IN ('pending', 'dispatched', 'running', 'success',
                         'failure', 'timeout', 'warning', 'cancelled',
                         'suppressed'));

-- 抑止は放っておくと最も件数が増える行になる（誤検知が続く限り毎回記録される）。
-- 「直近 24 時間に何件止めたか」を安く引けるようにしておく。
CREATE INDEX IF NOT EXISTS response_actions_suppressed_idx
  ON response_actions (executed_at DESC)
  WHERE status_text = 'suppressed';

COMMIT;
