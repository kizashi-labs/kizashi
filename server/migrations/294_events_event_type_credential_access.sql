-- Migration 294: allow 'credential_access' in events.event_type.
--
-- The credential/memory-access sensor emits event_type='credential_access' when
-- one process reads another process's memory (Windows: LSASS-access driver;
-- Linux: eBPF LSM ptrace_access_check — gdb -p, /proc/<pid>/mem, ptrace),
-- covering T1003 (credential dumping) and T1055 (process injection). The CHECK
-- constraint (last set in migration 271) omitted 'credential_access', so every
-- such INSERT was rejected with SQLSTATE 23514 and the events were silently
-- dropped on ALL platforms — the same class of wiring bug as #269 / #271.
-- Confirmed live on the validation EC2 (ingestion log: "violates check
-- constraint events_event_type_check"). Idempotent.
ALTER TABLE events
  DROP CONSTRAINT IF EXISTS events_event_type_check;

ALTER TABLE events
  ADD CONSTRAINT events_event_type_check
    CHECK (event_type = ANY (ARRAY[
      'process', 'file', 'network', 'dns', 'registry', 'auth', 'process_stats',
      'image_load', 'script', 'process_block', 'memory', 'credential_access'
    ]));
