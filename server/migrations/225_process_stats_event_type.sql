-- Migration 225: allow 'process_stats' in events.event_type
-- Per-process CPU/memory snapshots are stored as event_type='process_stats'
-- but the CHECK constraint only allowed the original 6 types.

ALTER TABLE events
  DROP CONSTRAINT IF EXISTS events_event_type_check;

ALTER TABLE events
  ADD CONSTRAINT events_event_type_check
    CHECK (event_type = ANY (ARRAY[
      'process', 'file', 'network', 'dns', 'registry', 'auth', 'process_stats'
    ]));
