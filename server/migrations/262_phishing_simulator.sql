-- 262: Phishing simulation — templates + campaigns for security awareness.
-- Backs the /admin/phishing-simulator page. Campaign per-user results are stored
-- as JSONB; the analytics endpoint aggregates them at request time so there is
-- no separate rollup table to keep in sync.

CREATE TABLE IF NOT EXISTS phishing_templates (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL,
    name          TEXT NOT NULL,
    category      TEXT NOT NULL DEFAULT 'credential_harvest'
                      CHECK (category IN ('credential_harvest','malware_delivery','pretexting','vishing')),
    difficulty    TEXT NOT NULL DEFAULT 'medium'
                      CHECK (difficulty IN ('easy','medium','hard')),
    industry_tags JSONB NOT NULL DEFAULT '[]',
    from_name     TEXT NOT NULL DEFAULT '',
    from_email    TEXT NOT NULL DEFAULT '',
    subject       TEXT NOT NULL DEFAULT '',
    body          TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_phishing_templates_tenant ON phishing_templates(tenant_id);

CREATE TABLE IF NOT EXISTS phishing_campaigns (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL,
    name           TEXT NOT NULL,
    template_id    UUID,
    template_name  TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'scheduled'
                       CHECK (status IN ('draft','scheduled','running','completed')),
    targets_count  INTEGER NOT NULL DEFAULT 0,
    sent_count     INTEGER NOT NULL DEFAULT 0,
    clicked_count  INTEGER NOT NULL DEFAULT 0,
    reported_count INTEGER NOT NULL DEFAULT 0,
    start_date     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    results        JSONB NOT NULL DEFAULT '[]',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_phishing_campaigns_tenant ON phishing_campaigns(tenant_id, start_date DESC);

-- Seed a couple of starter templates for the default tenant so the page is
-- immediately usable. Idempotent by (tenant_id, name).
INSERT INTO phishing_templates (tenant_id, name, category, difficulty, industry_tags, from_name, from_email, subject, body)
SELECT '00000000-0000-0000-0000-000000000001', 'パスワード有効期限通知', 'credential_harvest', 'medium',
       '["enterprise","it"]'::jsonb, 'IT ヘルプデスク', 'no-reply@it-support.example',
       '【要対応】パスワードの有効期限が72時間後に切れます',
       '<p>お客様各位</p><p>アカウントのパスワード有効期限が近づいています。下記より更新してください。</p><p><a href="#">パスワードを更新する</a></p>'
WHERE NOT EXISTS (SELECT 1 FROM phishing_templates WHERE tenant_id='00000000-0000-0000-0000-000000000001' AND name='パスワード有効期限通知');

INSERT INTO phishing_templates (tenant_id, name, category, difficulty, industry_tags, from_name, from_email, subject, body)
SELECT '00000000-0000-0000-0000-000000000001', '配送荷物の不在通知', 'malware_delivery', 'easy',
       '["logistics"]'::jsonb, '配送センター', 'delivery@parcel-notice.example',
       'お荷物のお届けにあがりましたが不在でした',
       '<p>お荷物のお届けにあがりましたがご不在でした。下記より再配達をご依頼ください。</p><p><a href="#">再配達を依頼する</a></p>'
WHERE NOT EXISTS (SELECT 1 FROM phishing_templates WHERE tenant_id='00000000-0000-0000-0000-000000000001' AND name='配送荷物の不在通知');
