-- Migration 329: Correct agents.os_type that was pinned by the heartbeat fallback
--
-- Symptom: EC2AMAZ-QCQVG82 shows os_type='linux' in the endpoint list while its
-- os_version reads "Windows Server 2022 (Build 20348)".
--
-- Root cause (three defects that compound):
--   1. The agent never reported os_type on the heartbeat path — neither the gRPC
--      metadata (x-os-type, which the server has always read) nor the HTTP JSON
--      body carried it, so the server saw an empty value on every beat.
--   2. UpdateLastSeen turned that empty value into a hardcoded 'linux'.
--   3. Its ON CONFLICT branch never updated os_type, so the fallback written when
--      the row was auto-created outlived every later (correct) report. os_version
--      *was* updated on conflict, which is why the two fields disagree.
--
-- Migration 244 patched the same class of bug for a single Linux agent back when
-- the hardcoded fallback was 'windows'. All three defects are fixed in code now
-- (agent reports runtime.GOOS; the fallback applies to the INSERT branch only;
-- os_type is refreshed on conflict), so this backfill is a one-off repair of rows
-- already carrying the wrong value.
--
-- Repair strategy: os_version is agent-reported free text that was kept current,
-- so it is the trustworthy signal. Only rows where it plainly contradicts os_type
-- are touched; rows with a NULL/ambiguous os_version are left for the agent's next
-- heartbeat to correct on its own.

UPDATE agents
SET os_type    = 'windows',
    updated_at = NOW()
WHERE os_type != 'windows'
  AND os_version ILIKE '%windows%';

UPDATE agents
SET os_type    = 'darwin',
    updated_at = NOW()
WHERE os_type != 'darwin'
  AND (os_version ILIKE '%macos%' OR os_version ILIKE '%mac os%' OR os_version ILIKE '%darwin%');

UPDATE agents
SET os_type    = 'linux',
    updated_at = NOW()
WHERE os_type != 'linux'
  AND (os_version ILIKE '%linux%'
       OR os_version ILIKE '%ubuntu%'
       OR os_version ILIKE '%debian%'
       OR os_version ILIKE '%amazon linux%'
       OR os_version ILIKE '%centos%'
       OR os_version ILIKE '%rhel%'
       OR os_version ILIKE '%red hat%'
       OR os_version ILIKE '%alpine%');
