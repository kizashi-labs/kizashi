-- Migration 314: allow 'create_remote_thread' in events.event_type.
--
-- The Windows ETW thread sensor (Kernel-Process provider, THREAD keyword) emits
-- event_type='create_remote_thread' when one process creates a thread in a
-- DIFFERENT process (the ETW event header PID = creator, payload PID = target).
-- This is the CreateRemoteThread / process-hollowing injection primitive
-- (T1055.012) that the enabled "Process Hollowing via Suspicious Executable"
-- SigmaHQ rule (logsource category: create_remote_thread) was waiting on — the
-- rule was structurally inert because no telemetry of this category was emitted.
--
-- The CHECK constraint (last set in migration 294) omits 'create_remote_thread',
-- so every such INSERT would be rejected with SQLSTATE 23514 and the events
-- silently dropped — the same class of wiring bug as #269 / #271 / #294. Extend
-- the constraint. Idempotent.
ALTER TABLE events
  DROP CONSTRAINT IF EXISTS events_event_type_check;

ALTER TABLE events
  ADD CONSTRAINT events_event_type_check
    CHECK (event_type = ANY (ARRAY[
      'process', 'file', 'network', 'dns', 'registry', 'auth', 'process_stats',
      'image_load', 'script', 'process_block', 'memory', 'credential_access',
      'create_remote_thread'
    ]));
