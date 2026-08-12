-- IOC (Indicator of Compromise) management table

CREATE TABLE ioc_entries (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type        TEXT NOT NULL CHECK (type IN ('hash', 'ip', 'domain', 'url', 'email')),
    value       TEXT NOT NULL,
    description TEXT,
    severity    INT NOT NULL DEFAULT 7 CHECK (severity BETWEEN 1 AND 10),
    is_active   BOOLEAN DEFAULT TRUE,
    added_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(type, value)
);

CREATE INDEX idx_ioc_type     ON ioc_entries(type);
CREATE INDEX idx_ioc_value    ON ioc_entries(value);
CREATE INDEX idx_ioc_active   ON ioc_entries(is_active);
CREATE INDEX idx_ioc_severity ON ioc_entries(severity);
