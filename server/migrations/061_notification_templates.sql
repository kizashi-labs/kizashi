-- 061_notification_templates.sql
CREATE TABLE IF NOT EXISTS notification_templates (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL,
    channel_type TEXT NOT NULL CHECK (channel_type IN ('webhook_slack','webhook_teams','webhook_generic','email')),
    subject      TEXT,
    body         TEXT NOT NULL,
    variables    TEXT[] NOT NULL DEFAULT '{}',
    is_default   BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert default templates
INSERT INTO notification_templates (name, channel_type, subject, body, variables, is_default) VALUES
('デフォルトSlackテンプレート', 'webhook_slack', NULL,
 '[{{severity}}] {{title}}\nソース: {{source}}\nステータス: {{status}}\n詳細: {{server_url}}/alerts/{{id}}',
 ARRAY['severity','title','source','status','server_url','id'], true),
('デフォルトメールテンプレート', 'email',
 '[EDR {{severity}}] {{title}}',
 'EDR Platformからのアラート通知\n\nタイトル: {{title}}\n重大度: {{severity}}\nソース: {{source}}\nステータス: {{status}}\n\n詳細: {{server_url}}/alerts/{{id}}',
 ARRAY['severity','title','source','status','server_url','id'], true)
ON CONFLICT DO NOTHING;
