-- 022: 初回ログイン時パスワード変更強制フラグ
-- 管理者が作成したユーザーは初回ログイン時にパスワード変更を強制する

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

-- 既存ユーザーはフラグなし（後から作成されるユーザーにのみ適用）
COMMENT ON COLUMN users.must_change_password IS
  '管理者が作成したユーザーは TRUE。初回ログイン後のパスワード変更で FALSE に更新される。';
