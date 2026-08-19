-- 442: allow the six remaining collector event types in events.event_type.
--
-- ingestion's promoteEventType (server/internal/ingestion/handler.go) deliberately
-- promotes 21 event types. events_event_type_check permits 15. The six it does not
-- permit are rejected at INSERT with 23514, measured against the migrated schema:
--
--     tls_handshake      REJECTED  violates check constraint events_event_type_check
--     ps_module          REJECTED
--     pipe_created       REJECTED
--     eventlog_cleared   REJECTED
--     service_installed  REJECTED
--     device_event       REJECTED
--
-- So every TLS handshake, PowerShell module-logging record (4103), named-pipe
-- creation, cleared event log (1102), installed service (7045) and USB device
-- event the agent has ever sent has been dropped at the door. Each has a
-- collector, each is promoted on purpose, and five of the six are declared in
-- detection's eventTypeCategories — which means the AlertPipeline subscribes to
-- them on NATS and evaluates Sigma against them. The NATS half works; only the
-- durable copy is lost, so the events are un-huntable, absent from the timeline,
-- and invisible to server-detect (which reads the DB).
--
-- eventlog_cleared and service_installed are the two that hurt most: 1102 and
-- 7045 are the canonical anti-forensics and persistence signals, and both are
-- exactly the records an investigator goes looking for after the fact.
--
-- insertEvents falls back to per-row inserts when a chunk fails, so the other
-- events in a batch survive — but a batch carrying one of these six costs a
-- failed multi-row INSERT plus up to 500 individual round-trips, which is the
-- pathology the chunked insert exists to avoid.
--
-- This is the same defect migration 370 fixed for wmi_activity, and 314, 322,
-- 269 and 225 fixed before it: the constraint was extended once per collector
-- and six were missed. A contract test now derives the required set from
-- promoteEventType itself, so the list cannot fall behind again.
--
-- Rewrite preserves whatever the constraint currently allows rather than
-- restating a fixed list, because several migrations have extended it
-- independently and a restatement would silently drop the ones added since this
-- file was written.

DO $migration$
DECLARE
  cur_def  text;
  arr_body text;
  want     text[] := ARRAY[
    'tls_handshake', 'ps_module', 'pipe_created',
    'eventlog_cleared', 'service_installed', 'device_event'
  ];
  missing  text[] := '{}';
  t        text;
BEGIN
  SELECT pg_get_constraintdef(c.oid) INTO cur_def
    FROM pg_constraint c
   WHERE c.conname = 'events_event_type_check'
     AND c.conrelid = 'events'::regclass
   LIMIT 1;

  -- No constraint at all: create one covering everything promoteEventType emits.
  IF cur_def IS NULL THEN
    ALTER TABLE events
      ADD CONSTRAINT events_event_type_check
        CHECK (event_type = ANY (ARRAY[
          'process', 'file', 'network', 'dns', 'registry', 'auth', 'process_stats',
          'image_load', 'script', 'process_block', 'memory', 'credential_access',
          'create_remote_thread', 'host_integrity', 'wmi_activity',
          'tls_handshake', 'ps_module', 'pipe_created',
          'eventlog_cleared', 'service_installed', 'device_event'
        ]));
    RETURN;
  END IF;

  FOREACH t IN ARRAY want LOOP
    IF position('''' || t || '''' in cur_def) = 0 THEN
      missing := missing || t;
    END IF;
  END LOOP;

  -- Already permitted (re-run, or a later migration added them): nothing to do.
  IF cardinality(missing) = 0 THEN
    RETURN;
  END IF;

  arr_body := substring(cur_def from 'ARRAY\[(.*)\]');
  IF arr_body IS NULL THEN
    RAISE EXCEPTION 'events_event_type_check has an unexpected shape, refusing to rewrite: %', cur_def;
  END IF;

  FOREACH t IN ARRAY missing LOOP
    arr_body := arr_body || format(', %L::text', t);
  END LOOP;

  ALTER TABLE events DROP CONSTRAINT events_event_type_check;
  EXECUTE format(
    'ALTER TABLE events ADD CONSTRAINT events_event_type_check CHECK (event_type = ANY (ARRAY[%s]))',
    arr_body);
END
$migration$;
