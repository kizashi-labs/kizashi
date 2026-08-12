-- 235_agent_config_profiles_seed.sql
--
-- Seed default agent configuration profiles (Windows / Linux / macOS).
--
-- Background: migration 178 created the agent_config_profiles table but did
-- not seed defaults. Without rows, the admin UI fell back to the in-memory
-- DefaultProfiles() helper whose IDs are string literals ("default-windows-
-- profile" etc.), not UUIDs — so UPDATE / DELETE from the UI failed because
-- the WHERE clause could not cast the id to UUID.
--
-- This migration inserts three real rows with stable UUIDs so CRUD operations
-- from /admin/agent-profiles route through the DB as expected. The UUIDs are
-- namespaced under 00000000-0000-0000-0000-0000000001xx so they are easy to
-- recognize in logs.
--
-- Idempotent: ON CONFLICT DO NOTHING — re-applies cleanly.

INSERT INTO agent_config_profiles (id, name, description, os_type, config, is_default, created_at, updated_at)
VALUES
  (
    '00000000-0000-0000-0000-000000000101'::uuid,
    'Windows Default',
    'Standard configuration for Windows endpoints',
    'windows',
    '{
      "collection_interval_sec": 60,
      "enable_process_monitor": true,
      "enable_network_monitor": true,
      "enable_file_monitor": true,
      "enable_registry_monitor": true,
      "file_monitor_paths": [
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
        "C:\\Users\\*\\AppData\\Roaming",
        "C:\\ProgramData"
      ],
      "excluded_processes": ["svchost.exe", "System", "Registry", "smss.exe"],
      "max_events_per_min": 1000,
      "log_level": "info",
      "heartbeat_interval_sec": 30
    }'::jsonb,
    true,
    NOW(),
    NOW()
  ),
  (
    '00000000-0000-0000-0000-000000000102'::uuid,
    'Linux Default',
    'Standard configuration for Linux endpoints',
    'linux',
    '{
      "collection_interval_sec": 60,
      "enable_process_monitor": true,
      "enable_network_monitor": true,
      "enable_file_monitor": true,
      "enable_registry_monitor": false,
      "file_monitor_paths": ["/etc", "/usr/bin", "/usr/sbin", "/tmp", "/var/tmp"],
      "excluded_processes": ["kworker", "ksoftirqd", "kthreadd"],
      "max_events_per_min": 1000,
      "log_level": "info",
      "heartbeat_interval_sec": 30
    }'::jsonb,
    true,
    NOW(),
    NOW()
  ),
  (
    '00000000-0000-0000-0000-000000000103'::uuid,
    'macOS Default',
    'Standard configuration for macOS endpoints',
    'macos',
    '{
      "collection_interval_sec": 60,
      "enable_process_monitor": true,
      "enable_network_monitor": true,
      "enable_file_monitor": true,
      "enable_registry_monitor": false,
      "file_monitor_paths": [
        "/Applications",
        "/Library",
        "/Users/*/Library/LaunchAgents",
        "/tmp"
      ],
      "excluded_processes": ["kernel_task", "launchd", "mds_stores"],
      "max_events_per_min": 1000,
      "log_level": "info",
      "heartbeat_interval_sec": 30
    }'::jsonb,
    true,
    NOW(),
    NOW()
  )
ON CONFLICT (id) DO NOTHING;
