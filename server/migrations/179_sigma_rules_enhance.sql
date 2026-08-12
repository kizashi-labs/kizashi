-- Migration 179: Enhance detection_rules table if it exists (add missing columns)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='detection_rules') THEN
        ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS rule_yaml TEXT;
        ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}';
        ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS test_count INTEGER DEFAULT 0;
        ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS last_matched TIMESTAMPTZ;
    ELSE
        CREATE TABLE detection_rules (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            description TEXT,
            rule_yaml TEXT,
            tags TEXT[] DEFAULT '{}',
            severity INTEGER DEFAULT 5,
            enabled BOOLEAN DEFAULT true,
            test_count INTEGER DEFAULT 0,
            match_count INTEGER DEFAULT 0,
            last_matched TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled ON detection_rules(enabled);
        CREATE INDEX IF NOT EXISTS idx_detection_rules_severity ON detection_rules(severity);
    END IF;
END $$;
