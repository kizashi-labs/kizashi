-- Migration 269: allow 'process_block', 'image_load', 'script' in events.event_type
--
-- The events_event_type_check constraint (migration 225) only allowed the 6
-- original types + process_stats. Three event types the ingestion layer actually
-- produces were missing, so their INSERTs failed silently (SQLSTATE 23514) and
-- the events were dropped:
--   - process_block : agent block decisions (polling kill + eBPF LSM prevention/audit)
--   - image_load    : DLL/.so load telemetry (added with EVENT_TYPE_IMAGE_LOAD)
--   - script        : script-content telemetry (added with EVENT_TYPE_SCRIPT)
-- Discovered 2026-06-19 verifying Ph2 server-side process_block ingestion.

ALTER TABLE events
  DROP CONSTRAINT IF EXISTS events_event_type_check;

ALTER TABLE events
  ADD CONSTRAINT events_event_type_check
    CHECK (event_type = ANY (ARRAY[
      'process', 'file', 'network', 'dns', 'registry', 'auth', 'process_stats',
      'image_load', 'script', 'process_block'
    ]));
