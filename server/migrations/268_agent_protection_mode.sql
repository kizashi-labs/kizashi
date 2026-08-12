-- Agent kernel-protection capability tier reported via heartbeat (Ph1 of the
-- Linux prevention roadmap: detect + report, no enforcement yet).
-- Values: 'enforce' | 'observe' | 'poll' | NULL (not yet reported).
-- See docs/design/Linux改ざん防止と実行前防御設計.md.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS protection_mode TEXT;
