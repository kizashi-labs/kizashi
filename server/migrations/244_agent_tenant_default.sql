-- Migration 244: Fix agent tenant_id visibility + os_type correctness
--
-- Two bugs found in agent registration:
--
-- Bug 1 (critical): agents.tenant_id was never set for agents enrolled AFTER
-- migration 027 added multi-tenancy. UpsertAgent and UpdateLastSeen both INSERT
-- without tenant_id, leaving it NULL. PostgreSQL RLS policy requires
-- tenant_id = current_setting('app.tenant_id'), so NULL-tenant agents are
-- invisible to any logged-in API user. Only agents enrolled before migration 027
-- (which backfilled existing rows) were visible.
--
-- Fix: Set a column DEFAULT so all future INSERTs without an explicit tenant_id
-- automatically inherit the default tenant. Backfill all existing NULL rows.
--
-- Bug 2 (cosmetic): UpdateLastSeen's INSERT branch hardcodes os_type='windows'
-- for auto-created agent records (agents that bypass formal enrollment and
-- connect via heartbeat only). The Linux agent 9ed28fec was created this way.
--
-- Fix: Correct the Linux agent's os_type. Future agents auto-created via
-- UpdateLastSeen will still get 'linux' (corrected in code).

-- 1. Set column DEFAULT so all future agent INSERTs auto-get the default tenant.
ALTER TABLE agents
    ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';

-- 2. Backfill all existing agents that have NULL tenant_id.
UPDATE agents
SET tenant_id = '00000000-0000-0000-0000-000000000001'
WHERE tenant_id IS NULL;

-- 3. Fix the Linux endpoint agent's os_type (was 'windows' due to UpdateLastSeen bug).
UPDATE agents
SET os_type = 'linux'
WHERE id = '9ed28fec-3e61-4f7f-8626-d1a782e6ae9c'
  AND os_type = 'windows';
