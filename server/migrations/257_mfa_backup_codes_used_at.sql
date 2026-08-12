-- 257: Track when an MFA backup code was consumed (for the usage history UI).
ALTER TABLE mfa_backup_codes ADD COLUMN IF NOT EXISTS used_at TIMESTAMPTZ;
