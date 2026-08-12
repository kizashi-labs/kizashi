-- 260: Endpoint groups — rule-based dynamic grouping of agents.
-- Membership is computed at request time by evaluating `rules` against the
-- agents table (hostname / os / ip_range). `policies` holds lightweight
-- policy references shown in the UI.

CREATE TABLE IF NOT EXISTS endpoint_groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    type        TEXT NOT NULL DEFAULT 'custom' CHECK (type IN ('department','os','location','custom')),
    description TEXT NOT NULL DEFAULT '',
    parent_id   UUID REFERENCES endpoint_groups(id) ON DELETE SET NULL,
    rules       JSONB NOT NULL DEFAULT '[]',
    policies    JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_endpoint_groups_parent ON endpoint_groups(parent_id);

-- Seed two OS-based dynamic groups (idempotent by name).
INSERT INTO endpoint_groups (name, type, description, rules)
SELECT 'Windows 端末', 'os', 'OS が Windows のエンドポイント',
       '[{"id":"r_win","field":"os","operator":"contains","value":"windows"}]'::jsonb
WHERE NOT EXISTS (SELECT 1 FROM endpoint_groups WHERE name = 'Windows 端末');

INSERT INTO endpoint_groups (name, type, description, rules)
SELECT 'Linux サーバー', 'os', 'OS が Linux のエンドポイント',
       '[{"id":"r_lin","field":"os","operator":"contains","value":"linux"}]'::jsonb
WHERE NOT EXISTS (SELECT 1 FROM endpoint_groups WHERE name = 'Linux サーバー');
