-- STIX 2.1 の Indicator.valid_until を保持するため ioc_entries に有効期限列を
-- 追加する。STIX/TAXII 取込でインジケータに失効時刻が付与されている場合に
-- 記録し、将来的な失効 IOC の自動無効化(is_active=FALSE化スイープ)の基盤とする。
-- NULL は「無期限」を意味する。
ALTER TABLE ioc_entries
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- 失効スイープ/失効フィルタ用の部分インデックス(値が入っている行のみ)。
CREATE INDEX IF NOT EXISTS idx_ioc_entries_expires_at
    ON ioc_entries(expires_at)
    WHERE expires_at IS NOT NULL;
