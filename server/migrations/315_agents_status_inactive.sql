-- Migration 315: allow 'inactive' in agents.status
--
-- DeadAgentCleanup (internal/scheduler/dead_agent_cleanup.go) marks agents that
-- have not reported for 30+ days as status='inactive'. However the original
-- agents_status_check constraint only permitted ('online','offline','isolated',
-- 'error'), so every such UPDATE failed with a CHECK violation (SQLSTATE 23514)
-- and the error was logged-then-swallowed — the long-term-dead inactivation has
-- never actually taken effect (a silent failure caught by the new DB integration
-- test TestDeadAgentCleanup_Integration).
--
-- 'inactive' is a distinct terminal state from transient 'offline': it means the
-- endpoint is presumed decommissioned/gone, not merely temporarily unreachable.
-- Adding it to the allowed set makes the existing cleanup behave as designed.

ALTER TABLE agents
  DROP CONSTRAINT IF EXISTS agents_status_check;

ALTER TABLE agents
  ADD CONSTRAINT agents_status_check
    CHECK (status = ANY (ARRAY[
      'online', 'offline', 'isolated', 'error', 'inactive'
    ]));
