-- AWS の CSPM スキャナ (internal/cspm/awsscan) が必要とする列。
--
-- 資格情報の持ち方: 顧客の長期アクセスキーは保存しない。顧客アカウント側に
-- 読み取り専用ロールを作ってもらい、その ARN と外部 ID だけを持つ。
-- 実際の認証は実行時の AssumeRole で行い、得られる一時credentialは
-- ディスクに残さない。
--
-- external_id は confused deputy 対策の共有値。ARN だけを知った第三者が
-- ロールを引き受けられないようにするためのもので、推測されない値を
-- アカウントごとに発行する。

-- credentials_arn は migration 149 で既にある (VARCHAR(500))。
-- 外部 ID と対象リージョンを足す。
ALTER TABLE cspm_accounts
    ADD COLUMN IF NOT EXISTS external_id VARCHAR(128);

-- scan_status に 'error' を持たせるため、失敗理由の置き場を作る。
-- 「スキャンした結果 0 件」と「スキャンできなかった」を区別できないと、
-- 権限設定のミスが「問題なし」として表示される。
ALTER TABLE cspm_accounts
    ADD COLUMN IF NOT EXISTS scan_error TEXT;

ALTER TABLE cspm_accounts
    ADD COLUMN IF NOT EXISTS last_scan_started_at TIMESTAMPTZ;

-- 実行中のスキャンを引ける索引。台数が増えても軽い。
CREATE INDEX IF NOT EXISTS idx_cspm_accounts_scan_status
    ON cspm_accounts(scan_status)
    WHERE scan_status = 'scanning';
