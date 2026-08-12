-- 252: ダークウェブ監視テーブル

-- ランサムウェアグループの .onion URL管理
CREATE TABLE IF NOT EXISTS darkweb_ransomware_sites (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_name    TEXT NOT NULL,
    onion_url     TEXT NOT NULL UNIQUE,
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    fail_count    INT NOT NULL DEFAULT 0,
    last_checked_at TIMESTAMPTZ,
    last_alive_at   TIMESTAMPTZ,
    source        TEXT NOT NULL DEFAULT 'ransomwatch',
    raw_posts     JSONB,          -- ransomwatch の posts キャッシュ（__cache__ 行のみ）
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_darkweb_sites_active ON darkweb_ransomware_sites(is_active);
CREATE INDEX IF NOT EXISTS idx_darkweb_sites_group  ON darkweb_ransomware_sites(group_name);

-- 監視対象キーワード（ドメイン・メール・会社名など）
CREATE TABLE IF NOT EXISTS darkweb_monitors (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    monitor_type TEXT NOT NULL CHECK (monitor_type IN ('domain','email','keyword')),
    value        TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_darkweb_monitors_uniq ON darkweb_monitors(monitor_type, value);

-- 検知結果
CREATE TABLE IF NOT EXISTS darkweb_findings (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source       TEXT NOT NULL, -- 'ransomwatch_posts' | 'tor_scrape'
    group_name   TEXT,
    severity     INT NOT NULL DEFAULT 7,
    title        TEXT NOT NULL,
    description  TEXT,
    raw_data     JSONB,
    monitor_value TEXT,
    alerted      BOOLEAN NOT NULL DEFAULT FALSE,
    found_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_darkweb_findings_alerted  ON darkweb_findings(alerted);
CREATE INDEX IF NOT EXISTS idx_darkweb_findings_found_at ON darkweb_findings(found_at DESC);
