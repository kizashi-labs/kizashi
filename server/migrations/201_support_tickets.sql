-- 201_support_tickets.sql
-- サポートチケット管理

CREATE TYPE ticket_status AS ENUM ('open', 'in_progress', 'waiting_customer', 'resolved', 'closed');
CREATE TYPE ticket_priority AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE ticket_category AS ENUM (
    'billing', 'technical', 'feature_request', 'bug_report',
    'installation', 'configuration', 'security', 'other'
);

-- ─── チケット ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS support_tickets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id) ON DELETE SET NULL,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_to     UUID REFERENCES users(id) ON DELETE SET NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    category        ticket_category NOT NULL DEFAULT 'other',
    priority        ticket_priority NOT NULL DEFAULT 'medium',
    status          ticket_status NOT NULL DEFAULT 'open',
    resolved_at     TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tickets_tenant    ON support_tickets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tickets_created_by ON support_tickets(created_by);
CREATE INDEX IF NOT EXISTS idx_tickets_status    ON support_tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_priority  ON support_tickets(priority);

-- ─── チケットコメント ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ticket_comments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id   UUID NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
    author_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    body        TEXT NOT NULL,
    is_internal BOOLEAN NOT NULL DEFAULT FALSE,  -- 内部メモ (顧客非表示)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ticket_comments_ticket ON ticket_comments(ticket_id);

-- ─── チケット更新時に updated_at を自動更新 ────────────────────────────────
CREATE OR REPLACE FUNCTION update_ticket_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE support_tickets SET updated_at = NOW() WHERE id = NEW.ticket_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_ticket_comment_updated
    AFTER INSERT ON ticket_comments
    FOR EACH ROW EXECUTE FUNCTION update_ticket_updated_at();
