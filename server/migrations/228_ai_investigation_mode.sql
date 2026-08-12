-- AI investigation mode settings
INSERT INTO system_settings (key, value, description) VALUES
    ('ai_investigation_mode', '"standard"', 'AI investigation mode: standard or autonomous'),
    ('ai_autonomous_model', '"claude-haiku-4-5-20251001"', 'Model for autonomous investigation agent'),
    ('ai_autonomous_max_tokens', '4096', 'Max tokens for autonomous agent responses'),
    ('ai_auto_investigate_threshold', '7', 'Minimum severity score to trigger auto-investigation'),
    ('ai_autonomous_auto_response', 'false', 'Allow autonomous agent to recommend auto-response actions'),
    ('ai_autonomous_language', '"ja"', 'Language for autonomous agent reports (ja/en)')
ON CONFLICT (key) DO NOTHING;
