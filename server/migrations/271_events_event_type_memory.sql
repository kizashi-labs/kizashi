-- Migration 271: allow 'memory' in events.event_type.
--
-- The M1 memory/injection scanner (agent memory_scan_linux.go) emits findings as
-- event_type='memory' (RWX / unbacked-executable regions). Without this the
-- CHECK constraint (last set in migration 269) would reject the INSERT and the
-- findings would be silently dropped — the same class of bug as #269. Idempotent.
ALTER TABLE events
  DROP CONSTRAINT IF EXISTS events_event_type_check;

ALTER TABLE events
  ADD CONSTRAINT events_event_type_check
    CHECK (event_type = ANY (ARRAY[
      'process', 'file', 'network', 'dns', 'registry', 'auth', 'process_stats',
      'image_load', 'script', 'process_block', 'memory'
    ]));
