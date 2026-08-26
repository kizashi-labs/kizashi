-- Migration 046: File Integrity Monitoring (FIM) rules table
-- Stores administrator-defined paths to monitor on agents.

CREATE TABLE IF NOT EXISTS fim_rules (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT        NOT NULL,
    path             TEXT        NOT NULL,
    recursive        BOOL        NOT NULL DEFAULT false,
    exclude_patterns TEXT[]      DEFAULT '{}',
    enabled          BOOL        NOT NULL DEFAULT true,
    severity         TEXT        NOT NULL DEFAULT 'high'
                                 CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Default rules covering the most commonly attacked files on Linux/Unix systems.
INSERT INTO fim_rules (name, path, severity) VALUES
    ('Hosts file',    '/etc/hosts',    'critical'),
    ('Password file', '/etc/passwd',   'critical'),
    ('Shadow file',   '/etc/shadow',   'critical'),
    ('Sudoers',       '/etc/sudoers',  'critical'),
    ('SSH daemon config', '/etc/ssh/sshd_config', 'high'),
    ('Crontab',       '/etc/crontab',  'high')
ON CONFLICT DO NOTHING;
