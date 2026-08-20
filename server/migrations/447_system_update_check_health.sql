-- 447_system_update_check_health.sql
--
-- Record the outcome of each update check.
--
-- 背景: 検証環境の updater は GITHUB_TOKEN 失効により 401 を返し続けており、
-- 2026-04-29 を最後に一度も新版を検出できていなかった。それが 40 日以上
-- 誰にも気づかれなかったのは、失敗が WARN ログとカウンタにしか現れず、
-- 画面には出なかったため。
--
-- 「更新はありません」と「更新を確認できていません」は、UI 上まったく同じ姿を
-- していた。前者は正常、後者は**アップデート経路が死んでいる**という意味で、
-- セキュリティ製品としては後者の方が重い。区別できるようにする。
--
-- system_update_settings は id=1 の単一行なので、そこに追記する。

ALTER TABLE system_update_settings
    ADD COLUMN IF NOT EXISTS last_check_at        TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_check_ok        BOOLEAN,
    ADD COLUMN IF NOT EXISTS last_check_error     TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_success_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER     NOT NULL DEFAULT 0;

COMMENT ON COLUMN system_update_settings.last_check_at IS
    '最後にアップデート確認を試みた時刻。NULL は一度も試していないことを表す';
COMMENT ON COLUMN system_update_settings.last_check_ok IS
    '最後の確認が成功したか。false が続いている場合、更新経路が死んでいる';
COMMENT ON COLUMN system_update_settings.last_success_at IS
    '最後に確認が成功した時刻。ここが大きく古い場合は更新を受け取れていない';
COMMENT ON COLUMN system_update_settings.consecutive_failures IS
    '連続失敗回数。成功時に 0 へ戻る';
