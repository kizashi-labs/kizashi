-- Network Segmentation: 管理者が定義するネットワークセグメントと通信ポリシー。
-- セグメント所属デバイスは agents.ip_addresses(INET[]) と CIDR のマッチで動的に算出する
-- ため、ここでは保持しない。

CREATE TABLE IF NOT EXISTS network_segments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    vlan_id     INTEGER NOT NULL DEFAULT 0,
    cidr        TEXT NOT NULL DEFAULT '',
    gateway     TEXT NOT NULL DEFAULT '',
    dns_servers JSONB NOT NULL DEFAULT '[]'::jsonb,
    status      TEXT NOT NULL DEFAULT 'active', -- active, inactive
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_network_segments_name ON network_segments(name);

CREATE TABLE IF NOT EXISTS network_segment_policies (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_segment TEXT NOT NULL DEFAULT '',
    to_segment   TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL DEFAULT 'allow', -- allow, deny, inspect
    protocol     TEXT NOT NULL DEFAULT 'TCP',
    ports        TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_network_policies_from ON network_segment_policies(from_segment);
CREATE INDEX IF NOT EXISTS idx_network_policies_to ON network_segment_policies(to_segment);
