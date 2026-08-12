CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID
);
INSERT INTO system_settings (key, value, description) VALUES
    ('session_timeout_minutes', '60', 'Session timeout in minutes'),
    ('max_login_attempts', '5', 'Max failed login attempts before lockout'),
    ('lockout_duration_minutes', '30', 'Account lockout duration'),
    ('password_min_length', '12', 'Minimum password length'),
    ('password_require_special', 'true', 'Require special characters'),
    ('maintenance_mode', 'false', 'Enable maintenance mode'),
    ('allowed_ip_ranges', '[]', 'JSON array of allowed CIDR ranges'),
    ('mfa_required', 'false', 'Require MFA for all users'),
    ('api_rate_limit_per_minute', '1000', 'API rate limit per minute per IP')
ON CONFLICT (key) DO NOTHING;
