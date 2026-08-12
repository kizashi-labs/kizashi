-- 281: allow the 'app_inventory' MDM command type (iOS InstalledApplicationList).
--
-- MTD roadmap #2 / step (A): bridge MDM into MTD. iOS reports installed apps only
-- via the Apple MDM InstalledApplicationList command — there is no on-device app
-- enumeration in the sandbox. We add an 'app_inventory' command_type whose iOS body
-- is InstalledApplicationList; the device's Acknowledged response carries the app
-- array, which the command-reconcile path parses into mobile_app_inventory and runs
-- through the same risky-app detection as the JSON ingest. The CHECK constraint
-- (inline in migration 231) did not list it, so queueing one would 23514-fail.

ALTER TABLE mdm_commands DROP CONSTRAINT IF EXISTS mdm_commands_command_type_check;
ALTER TABLE mdm_commands ADD CONSTRAINT mdm_commands_command_type_check
    CHECK (command_type IN (
        'device_lock','erase_device','clear_passcode','restart_device','shutdown',
        'install_profile','remove_profile','install_app','remove_app',
        'refresh_inventory','app_inventory','enable_lost_mode','disable_lost_mode','play_sound'
    ));
