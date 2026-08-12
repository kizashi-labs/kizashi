-- Capacity Planning: workforce, resources, budget, on-call, tech debt
-- Supports /admin/capacity-planning page (read-only views).

CREATE TABLE IF NOT EXISTS cp_analysts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    role            TEXT NOT NULL,
    skills          JSONB NOT NULL DEFAULT '{}'::jsonb,
    alerts_handled_per_day INT NOT NULL DEFAULT 0,
    hire_date       DATE NOT NULL DEFAULT CURRENT_DATE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cp_tool_licenses (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool_name       TEXT NOT NULL,
    category        TEXT NOT NULL,
    purchased       INT NOT NULL DEFAULT 0,
    used            INT NOT NULL DEFAULT 0,
    price_per_unit  BIGINT NOT NULL DEFAULT 0,
    renewal_date    DATE,
    sort_order      INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cp_storage_metrics (
    id              INT PRIMARY KEY DEFAULT 1,
    used_tb         NUMERIC(10,2) NOT NULL DEFAULT 0,
    total_tb        NUMERIC(10,2) NOT NULL DEFAULT 0,
    projected_6m_tb NUMERIC(10,2) NOT NULL DEFAULT 0,
    projected_12m_tb NUMERIC(10,2) NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT cp_storage_singleton CHECK (id = 1)
);

CREATE TABLE IF NOT EXISTS cp_budget_categories (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    label           TEXT NOT NULL UNIQUE,
    current_year    BIGINT NOT NULL DEFAULT 0,
    next_year       BIGINT NOT NULL DEFAULT 0,
    year3           BIGINT NOT NULL DEFAULT 0,
    sort_order      INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cp_planned_hires (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role                   TEXT NOT NULL,
    planned_quarter        TEXT NOT NULL,
    estimated_annual_cost  BIGINT NOT NULL DEFAULT 0,
    priority               TEXT NOT NULL DEFAULT 'medium'
                              CHECK (priority IN ('high','medium','low')),
    sort_order             INT NOT NULL DEFAULT 0,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cp_tech_debt (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title       TEXT NOT NULL,
    impact      TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT 'medium'
                   CHECK (severity IN ('high','medium','low')),
    sort_order  INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cp_oncall_shifts (
    id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shift   TEXT NOT NULL,
    start_h TEXT NOT NULL DEFAULT '',
    end_h   TEXT NOT NULL DEFAULT '',
    mon     TEXT NOT NULL DEFAULT '—',
    tue     TEXT NOT NULL DEFAULT '—',
    wed     TEXT NOT NULL DEFAULT '—',
    thu     TEXT NOT NULL DEFAULT '—',
    fri     TEXT NOT NULL DEFAULT '—',
    sat     TEXT NOT NULL DEFAULT '—',
    sun     TEXT NOT NULL DEFAULT '—',
    sort_order INT NOT NULL DEFAULT 0
);

-- ── Seed data (idempotent) ────────────────────────────────────────

INSERT INTO cp_analysts (name, role, skills, alerts_handled_per_day, hire_date)
SELECT * FROM (VALUES
    ('田中 太郎',   'L1 Analyst',         '{"DFIR":"partial","Malware":"partial","Network":"full","Cloud":"none","Compliance":"partial"}'::jsonb, 25, DATE '2024-04-01'),
    ('佐藤 花子',   'L2 Analyst',         '{"DFIR":"full","Malware":"full","Network":"full","Cloud":"partial","Compliance":"partial"}'::jsonb,    35, DATE '2023-07-15'),
    ('鈴木 一郎',   'L3 Analyst',         '{"DFIR":"full","Malware":"full","Network":"full","Cloud":"full","Compliance":"full"}'::jsonb,          45, DATE '2022-01-10'),
    ('高橋 美咲',   'Threat Hunter',      '{"DFIR":"full","Malware":"full","Network":"partial","Cloud":"partial","Compliance":"none"}'::jsonb,   20, DATE '2024-01-15'),
    ('山田 健太',   'Incident Responder', '{"DFIR":"full","Malware":"partial","Network":"full","Cloud":"partial","Compliance":"full"}'::jsonb,   15, DATE '2023-03-01'),
    ('伊藤 翔',     'Engineer',           '{"DFIR":"partial","Malware":"none","Network":"full","Cloud":"full","Compliance":"none"}'::jsonb,       10, DATE '2022-09-20'),
    ('渡辺 葵',     'Cloud Analyst',      '{"DFIR":"partial","Malware":"partial","Network":"partial","Cloud":"full","Compliance":"partial"}'::jsonb, 30, DATE '2024-06-01')
) AS v(name, role, skills, alerts_handled_per_day, hire_date)
WHERE NOT EXISTS (SELECT 1 FROM cp_analysts);

INSERT INTO cp_tool_licenses (tool_name, category, purchased, used, price_per_unit, renewal_date, sort_order)
SELECT * FROM (VALUES
    ('Kizashi',         'EDR',       500, 342, 15000,  DATE '2027-03-31', 1),
    ('Splunk Enterprise',     'SIEM',      200, 178, 45000,  DATE '2026-12-31', 2),
    ('VirusTotal Enterprise', 'Threat Intel',50,  42,  8000, DATE '2027-01-15', 3),
    ('Recorded Future',       'Threat Intel',20,  15, 120000, DATE '2026-10-31', 4),
    ('Palo Alto XSOAR',       'SOAR',       30,  22, 60000,  DATE '2027-06-30', 5)
) AS v(tool_name, category, purchased, used, price_per_unit, renewal_date, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM cp_tool_licenses);

INSERT INTO cp_storage_metrics (id, used_tb, total_tb, projected_6m_tb, projected_12m_tb)
VALUES (1, 24.5, 50.0, 32.0, 45.5)
ON CONFLICT (id) DO NOTHING;

INSERT INTO cp_budget_categories (label, current_year, next_year, year3, sort_order)
SELECT * FROM (VALUES
    ('人件費',             120000000::bigint, 150000000::bigint, 180000000::bigint, 1),
    ('ツール・ライセンス', 48000000::bigint,   55000000::bigint,  62000000::bigint, 2),
    ('インフラ',           30000000::bigint,   35000000::bigint,  40000000::bigint, 3),
    ('トレーニング',       8000000::bigint,   10000000::bigint,  12000000::bigint, 4),
    ('外部サービス',       15000000::bigint,   18000000::bigint,  20000000::bigint, 5)
) AS v(label, current_year, next_year, year3, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM cp_budget_categories);

INSERT INTO cp_planned_hires (role, planned_quarter, estimated_annual_cost, priority, sort_order)
SELECT * FROM (VALUES
    ('L2 Analyst',         'FY2026 Q3', 9000000::bigint,  'high',   1),
    ('Threat Hunter',      'FY2026 Q4', 12000000::bigint, 'high',   2),
    ('Cloud Analyst',      'FY2027 Q1', 10000000::bigint, 'medium', 3),
    ('Incident Responder', 'FY2027 Q2', 11000000::bigint, 'medium', 4),
    ('Manager',            'FY2027 Q4', 14000000::bigint, 'low',    5)
) AS v(role, planned_quarter, estimated_annual_cost, priority, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM cp_planned_hires);

INSERT INTO cp_tech_debt (title, impact, severity, sort_order)
SELECT * FROM (VALUES
    ('レガシーSIEMのEOL対応',        '2026年10月にサポート終了。置き換えが必要', 'high',   1),
    ('手動トリアージの高負荷',       'L1アナリストの時間の60%を消費。SOAR自動化で削減可能', 'high', 2),
    ('ログ保持期間の不足',           '現在90日。コンプライアンス要件は180日', 'medium', 3),
    ('エンドポイントエージェント未配布', '未管理端末12台。リスク可視性の欠如',      'medium', 4),
    ('脅威インテル統合の遅延',       '新規フィード3つが未統合',                   'low',    5)
) AS v(title, impact, severity, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM cp_tech_debt);

INSERT INTO cp_oncall_shifts (shift, start_h, end_h, mon, tue, wed, thu, fri, sat, sun, sort_order)
SELECT * FROM (VALUES
    ('平日 日中 (09-18)', '09:00', '18:00', '田中', '田中', '佐藤', '佐藤', '鈴木', '—',      '—',      1),
    ('平日 夜間 (18-09)', '18:00', '09:00', '鈴木', '高橋', '山田', '伊藤', '高橋', '—',      '—',      2),
    ('週末 日中 (09-21)', '09:00', '21:00', '—',    '—',    '—',    '—',    '—',    '渡辺',   '山田',   3),
    ('週末 夜間 (21-09)', '21:00', '09:00', '—',    '—',    '—',    '—',    '—',    '—',      '—',      4)
) AS v(shift, start_h, end_h, mon, tue, wed, thu, fri, sat, sun, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM cp_oncall_shifts);
