-- Platform version management: tracks deployed versions, available upgrade packages, and schedule
-- Populated automatically on each startup via PlatformUpgradeHandler.RecordStartup()

CREATE TABLE IF NOT EXISTS platform_versions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version      VARCHAR(100) NOT NULL,
    build_date   VARCHAR(20),
    deployed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deployed_by  VARCHAR(255) NOT NULL DEFAULT 'system',
    status       VARCHAR(20)  NOT NULL DEFAULT 'active'
                     CHECK (status IN ('active', 'rolled_back')),
    notes        TEXT NOT NULL DEFAULT '',
    duration_min INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_platform_versions_deployed_at ON platform_versions (deployed_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_platform_versions_version ON platform_versions (version);

-- Upgrade packages: admins (or CI/CD) insert rows here when a new release is ready
CREATE TABLE IF NOT EXISTS platform_upgrade_packages (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version           VARCHAR(100) NOT NULL UNIQUE,
    release_date      DATE,
    type              VARCHAR(20)  NOT NULL DEFAULT 'patch'
                          CHECK (type IN ('patch', 'minor', 'major')),
    changelog_summary TEXT NOT NULL DEFAULT '',
    changelog_details JSONB NOT NULL DEFAULT '[]',
    size_mb           INTEGER NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_platform_packages_created ON platform_upgrade_packages (created_at DESC);

-- Scheduled upgrades
CREATE TABLE IF NOT EXISTS platform_upgrade_schedule (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version            VARCHAR(100) NOT NULL,
    scheduled_at       TIMESTAMPTZ NOT NULL,
    maintenance_window INTEGER NOT NULL DEFAULT 60,
    notify_users       BOOLEAN NOT NULL DEFAULT TRUE,
    auto_rollback      BOOLEAN NOT NULL DEFAULT TRUE,
    notes              TEXT NOT NULL DEFAULT '',
    status             VARCHAR(20) NOT NULL DEFAULT 'scheduled'
                           CHECK (status IN ('scheduled', 'in_progress', 'completed', 'failed', 'cancelled')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
