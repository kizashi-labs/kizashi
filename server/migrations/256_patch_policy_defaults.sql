-- 256: Seed default patch policies (idempotent by name).
-- The patch-automation UI previously showed hard-coded fake policies; these
-- are the real, editable equivalents.

INSERT INTO patch_policies (name, severity_filter, auto_approve_severity, maintenance_window, enabled)
SELECT 'クリティカルパッチ即時適用', ARRAY['critical'], ARRAY['critical'],
       '{"day":"any","start":"02:00","duration_hours":4}'::jsonb, true
WHERE NOT EXISTS (SELECT 1 FROM patch_policies WHERE name = 'クリティカルパッチ即時適用');

INSERT INTO patch_policies (name, severity_filter, auto_approve_severity, maintenance_window, enabled)
SELECT '週次セキュリティパッチ', ARRAY['critical','high'], ARRAY['critical'],
       '{"day":"sunday","start":"03:00","duration_hours":6}'::jsonb, true
WHERE NOT EXISTS (SELECT 1 FROM patch_policies WHERE name = '週次セキュリティパッチ');

INSERT INTO patch_policies (name, severity_filter, auto_approve_severity, maintenance_window, enabled)
SELECT '月次更新プログラム', ARRAY['critical','high','medium'], ARRAY[]::text[],
       '{"day":"second_sunday","start":"01:00","duration_hours":8}'::jsonb, true
WHERE NOT EXISTS (SELECT 1 FROM patch_policies WHERE name = '月次更新プログラム');
