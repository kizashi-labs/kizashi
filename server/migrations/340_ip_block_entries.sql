-- IP block/allow list for the admin IP Blocklist management page

CREATE TABLE ip_block_entries (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_or_cidr  TEXT NOT NULL,
    entry_type  TEXT NOT NULL DEFAULT 'block' CHECK (entry_type IN ('block', 'allow')),
    description TEXT,
    hit_count   INT NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ,
    added_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(ip_or_cidr, entry_type)
);

CREATE INDEX idx_ip_block_type       ON ip_block_entries(entry_type);
CREATE INDEX idx_ip_block_expires_at ON ip_block_entries(expires_at);
