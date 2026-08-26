-- 200_billing.sql
-- Stripe課金連携テーブル

-- ─── 課金顧客 ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS billing_customers (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES tenants(id) ON DELETE CASCADE,
    stripe_customer_id  TEXT NOT NULL UNIQUE,
    email               TEXT NOT NULL,
    name                TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_billing_customers_tenant     ON billing_customers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_billing_customers_stripe_cid ON billing_customers(stripe_customer_id);

-- ─── サブスクリプション ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS billing_subscriptions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id             UUID NOT NULL REFERENCES billing_customers(id) ON DELETE CASCADE,
    tenant_id               UUID REFERENCES tenants(id) ON DELETE SET NULL,
    stripe_subscription_id  TEXT NOT NULL UNIQUE,
    stripe_price_id         TEXT NOT NULL,
    plan                    TEXT NOT NULL,           -- starter | business | enterprise
    status                  TEXT NOT NULL,           -- active | past_due | canceled | trialing
    agent_limit             INT  NOT NULL DEFAULT 0,
    current_period_start    TIMESTAMPTZ,
    current_period_end      TIMESTAMPTZ,
    canceled_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_billing_subs_customer  ON billing_subscriptions(customer_id);
CREATE INDEX IF NOT EXISTS idx_billing_subs_tenant    ON billing_subscriptions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_billing_subs_stripe_id ON billing_subscriptions(stripe_subscription_id);

-- ─── 請求書 ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS billing_invoices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id     UUID NOT NULL REFERENCES billing_subscriptions(id) ON DELETE CASCADE,
    stripe_invoice_id   TEXT NOT NULL UNIQUE,
    amount_jpy          INT  NOT NULL DEFAULT 0,    -- 金額 (円)
    status              TEXT NOT NULL,              -- paid | open | void | uncollectible
    invoice_url         TEXT,                       -- Stripe ホスト請求書 URL
    paid_at             TIMESTAMPTZ,
    due_date            TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_billing_invoices_sub ON billing_invoices(subscription_id);

-- ─── Stripe Webhook 受信ログ ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stripe_event_id TEXT NOT NULL UNIQUE,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL,
    processed       BOOL NOT NULL DEFAULT FALSE,
    error           TEXT,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_stripe_events_type      ON stripe_webhook_events(event_type);
CREATE INDEX IF NOT EXISTS idx_stripe_events_processed ON stripe_webhook_events(processed);
