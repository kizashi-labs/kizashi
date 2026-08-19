-- Migration 322: allow 'host_integrity' in events.event_type, and add the Sigma
-- rules + a CommandLine gap-fill that ride on it.
--
-- New syscall-level Linux sensor (agent/ebpf/hostintegrity_monitor.bpf.c):
-- init_module/finit_module (T1547.006 kernel module load), unshare/setns
-- (T1611 namespace manipulation / container-host escape), capset (T1548.001
-- capability change). Existing coverage for these three techniques
-- (sigma_builtins.go "Kernel Module Loading (Linux)" / "Container Escape to
-- Host", migration 309's setuid-via-chmod rule) all key on CommandLine text
-- (insmod/modprobe/nsenter/chmod +s) — a custom or renamed binary calling the
-- syscall directly bypasses every one of them. The new events close that gap
-- at the syscall layer, independent of what the calling binary is named.
--
-- Same class of wiring bug as #269/#271/#294/314: without extending the CHECK
-- constraint, every host_integrity event INSERT is rejected (SQLSTATE 23514)
-- and silently dropped before any rule ever sees it.
--
-- The constraint is extended ADDITIVELY rather than by restating a hardcoded
-- list. Every prior migration in this family (294/314/…) rewrote the full
-- ARRAY literal, which makes the end state depend on migration ORDER: a
-- database that already allows event types added by migrations this file does
-- not know about (deployments have run migrations from branches not yet in
-- main — production at 2026-07-20 allowed named_pipe/wmi_activity/ps_classic/
-- device_event/resource_usage from such a branch) would SILENTLY LOSE them
-- when this file's hardcoded list replaced the constraint, rejecting those
-- events from then on. Reading the current definition and appending keeps the
-- result correct no matter which migrations ran before, and makes re-running
-- a no-op.
DO $migration$
DECLARE
  cur_def  text;
  arr_body text;
BEGIN
  SELECT pg_get_constraintdef(c.oid) INTO cur_def
    FROM pg_constraint c
   WHERE c.conname = 'events_event_type_check'
     AND c.conrelid = 'events'::regclass
   LIMIT 1;

  -- Already permitted (re-run, or a later migration added it): nothing to do.
  IF cur_def IS NOT NULL AND position('''host_integrity''' in cur_def) > 0 THEN
    RETURN;
  END IF;

  -- NOT VALID on both paths below (added 2026-08-03). A VALIDATED constraint makes
  -- PostgreSQL check every existing row, so ONE legacy row carrying a type this
  -- migration does not list aborts it — and because the API runs migrations at
  -- startup and exits on failure, that is a restart loop plus every later migration
  -- silently unapplied. Migration 353 did exactly this in production. Rows like that
  -- exist wherever a deployment was upgraded across branches. Widening what is
  -- accepted going forward must not depend on assertions about the past; new INSERTs
  -- are still checked under NOT VALID, so nothing is lost defensively.
  --
  -- No constraint at all: create one from the known base set.
  IF cur_def IS NULL THEN
    ALTER TABLE events
      ADD CONSTRAINT events_event_type_check
        CHECK (event_type = ANY (ARRAY[
          'process', 'file', 'network', 'dns', 'registry', 'auth', 'process_stats',
          'image_load', 'script', 'process_block', 'memory', 'credential_access',
          'create_remote_thread', 'host_integrity'
        ])) NOT VALID;
    RETURN;
  END IF;

  -- Preserve every value the current constraint allows, then append ours.
  arr_body := substring(cur_def from 'ARRAY\[(.*)\]');
  IF arr_body IS NULL THEN
    RAISE EXCEPTION 'events_event_type_check has an unexpected shape, refusing to rewrite: %', cur_def;
  END IF;

  ALTER TABLE events DROP CONSTRAINT events_event_type_check;
  EXECUTE format(
    'ALTER TABLE events ADD CONSTRAINT events_event_type_check CHECK (event_type = ANY (ARRAY[%s, %L::text])) NOT VALID',
    arr_body, 'host_integrity');
END
$migration$;

-- ── T1547.006 : カーネルモジュールロード(syscallレベル) ──────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux Kernel Module Load (syscall-level)', 'sigma', ARRAY['linux'], 8,
$$
title: Linux Kernel Module Load (syscall-level)
description: Detects a process calling init_module/finit_module directly (eBPF tracepoint), independent of which binary made the call. Complements "Kernel Module Loading (Linux)" (CommandLine match on insmod/modprobe), which a custom or renamed binary calling the syscall directly bypasses (T1547.006).
status: stable
level: high
tags:
  - attack.t1547.006
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: linux
  category: host_integrity
detection:
  selection:
    action: kernel_module_load
  condition: selection
falsepositives:
  - Legitimate driver/module installation by package managers or administrators
$$,
'community', ARRAY['T1547.006'],
'Linux syscall-level gap-fill: kernel module load bypassing insmod/modprobe CommandLine rules', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux Kernel Module Load (syscall-level)');

-- ── T1611 : namespace操作/コンテナ・ホストエスケープ(syscallレベル) ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux Namespace Manipulation (syscall-level)', 'sigma', ARRAY['linux'], 7,
$$
title: Linux Namespace Manipulation (syscall-level)
description: Detects a process calling unshare/setns directly (eBPF tracepoint), independent of which binary made the call. Complements "Container Escape to Host" (CommandLine match on nsenter/--privileged), which a custom or renamed binary calling the syscall directly bypasses (T1611). Container-runtime processes (runc/containerd-shim/crun/conmon) are filtered at the agent source — every alert here is from a non-runtime process.
status: stable
level: high
tags:
  - attack.t1611
  - attack.privilege_escalation
logsource:
  product: linux
  category: host_integrity
detection:
  selection:
    action: namespace_manipulation
  condition: selection
falsepositives:
  - Container tooling not on the source-side runtime allowlist (review and extend the allowlist rather than this rule)
$$,
'community', ARRAY['T1611'],
'Linux syscall-level gap-fill: namespace manipulation bypassing nsenter CommandLine rules', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux Namespace Manipulation (syscall-level)');

-- ── T1548.001 : capability変更(syscallレベル) ──────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux Capability Set (syscall-level)', 'sigma', ARRAY['linux'], 6,
$$
title: Linux Capability Set (syscall-level)
description: Detects a process calling capset directly (eBPF tracepoint) to change its own or a target thread's capability set, independent of which binary made the call. Complements the chmod-+s setuid rule (migration 309), which only covers persistent file-based privilege escalation, not in-process capability grants (T1548.001). Both dropping and raising capabilities go through this syscall; severity is kept below auto-isolate since container runtimes legitimately drop capabilities outside the source-side runtime allowlist in some configurations.
status: stable
level: medium
tags:
  - attack.t1548.001
  - attack.privilege_escalation
logsource:
  product: linux
  category: host_integrity
detection:
  selection:
    action: capability_set
  condition: selection
falsepositives:
  - Container/sandbox tooling dropping capabilities at startup outside the source-side runtime allowlist
$$,
'community', ARRAY['T1548.001'],
'Linux syscall-level gap-fill: capability changes bypassing chmod +s CommandLine rule', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux Capability Set (syscall-level)');

-- ── T1548.001 : setcap によるファイルcapability付与(CLIレベル、既存の
--   chmod +s ルール(migration 309)は setuid ビットのみでファイルcapabilityは
--   未検知だったギャップを埋める) ──────────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux File Capability Grant (setcap)', 'sigma', ARRAY['linux'], 6,
$$
title: Linux File Capability Grant (setcap)
description: Detects granting a file capability via setcap (e.g. cap_setuid, cap_net_raw, cap_sys_admin) — a persistence/privilege-escalation setup equivalent to a setuid binary but implemented via file capabilities instead of the setuid bit, and not covered by the existing chmod-+s setuid rule (T1548.001).
status: stable
level: high
tags:
  - attack.t1548.001
  - attack.privilege_escalation
  - attack.persistence
logsource:
  product: linux
  category: process_creation
detection:
  setcap:
    CommandLine|contains: setcap
  grant:
    CommandLine|contains:
      - cap_setuid
      - cap_setgid
      - cap_net_raw
      - cap_net_admin
      - cap_sys_admin
      - cap_sys_ptrace
      - cap_dac_override
      - '+ep'
      - '=ep'
  condition: setcap and grant
falsepositives:
  - Package installation scripts granting capabilities to legitimate helpers (e.g. ping, tcpdump)
$$,
'community', ARRAY['T1548.001'],
'Linux measurement gap-fill: setcap file-capability grant (chmod +s counterpart)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux File Capability Grant (setcap)');
