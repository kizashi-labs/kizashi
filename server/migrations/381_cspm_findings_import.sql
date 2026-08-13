-- 378: CSPM 所見の取り込みを再実行可能にする
--
-- cspm_findings は first_seen_at / last_seen_at を持っており、再スキャンで
-- 行を増やさず更新する設計だった。ところが「同じ所見」を判定する一意制約が
-- 無いため、そのままでは取り込みのたびに重複していく。
--
-- 同一性の定義: 同じアカウントの、同じチェックが、同じリージョンの、
-- 同じ資源に対して出したもの。これを一意にする。
--
-- account_id は NULL 許容だが、取り込み経路では必ず埋まる。NULL 混在時に
-- 一意制約が効かなくなるのを避けるため、NOT NULL の行だけを対象にする
-- 部分インデックスにしている。

-- 既存の重複を先に畳む (last_seen_at が最も新しいものを残す)。
-- 現時点でこのテーブルに書き込む経路は無く通常は 0 件だが、
-- 手で入れた行がある環境でも失敗しないようにする。
DELETE FROM cspm_findings a
USING cspm_findings b
WHERE a.account_id IS NOT NULL
  AND a.account_id = b.account_id
  AND a.check_id = b.check_id
  AND a.resource_id = b.resource_id
  AND COALESCE(a.region, '') = COALESCE(b.region, '')
  AND (a.last_seen_at, a.id) < (b.last_seen_at, b.id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cspm_findings_identity
    ON cspm_findings (account_id, check_id, resource_id, COALESCE(region, ''))
    WHERE account_id IS NOT NULL;

-- 同じクラウドの同じアカウントを二重登録しない。
-- cspm_accounts.account_id はクラウド側のアカウント識別子 (AWS の 12 桁など)。
CREATE UNIQUE INDEX IF NOT EXISTS uq_cspm_accounts_provider_account
    ON cspm_accounts (cloud_provider, account_id);

-- posture_score は NUMERIC(4,2) だった。これは整数部 2 桁までしか持てず、
-- 満点の 100.00 を入れようとすると numeric field overflow で落ちる
-- (所見が 1 件も無いアカウント = 満点、が保存できない)。
-- これまで書き込む経路が無かったため表面化していなかった。5,2 に広げる。
ALTER TABLE cspm_accounts ALTER COLUMN posture_score TYPE NUMERIC(5,2);
