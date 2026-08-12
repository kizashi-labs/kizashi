-- 344: detection-server (DB RuleEngine) パリティ 第27弾 — Linux 権限昇格。
--
-- api-server ビルトインにあるが DB 未移植の Linux 権限昇格3種を移植する:
--   T1548.003 Sudo Shell Escape (GTFOBins) — sudo 許可バイナリからの特権シェル奪取
--   T1548.001 Setuid/Setgid Abuse         — find -perm -4000 / getcap による SUID 偵察
--   T1068     Exploitation for Priv Esc    — pkexec PwnKit (CVE-2021-4034)
-- いずれもコマンドライン主体の検知で、pkexec のみ Image アンカーを
-- CommandLine|contains(|all) の pkexec 語に置換する。sudo/SUID はそのまま移植。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1548.003 : sudo シェルエスケープ(GTFOBins)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Sudo Shell Escape GTFOBins (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Sudo Shell Escape GTFOBins (DB)
description: Detects abuse of sudo-permitted binaries to spawn a privileged shell (GTFOBins) — editors, find -exec, interpreters, or preserve-privilege shells.
status: stable
level: high
tags:
  - attack.t1548.003
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "sudo vim -c"
      - "sudo vi -c"
      - "sudo nmap --interactive"
      - "sudo find / -exec"
      - "sudo find . -exec"
      - "sudo awk 'BEGIN"
      - "sudo python -c"
      - "sudo perl -e"
      - "/bin/sh -p"
      - "/bin/bash -p"
      - "sudo env "
      - "sudo gdb"
      - "sudo less "
      - "sudo more "
      - "sudo man "
      - "sudo ftp"
      - "sudo ed "
      - "sudo vim.tiny"
      - "--checkpoint-action=exec"
  condition: selection
falsepositives:
  - Rare legitimate administrative one-liners
$$,
'builtin-parity', ARRAY['T1548.003'],
'Two-engine parity: sudo shell escape via GTFOBins', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Sudo Shell Escape GTFOBins (DB)');

-- ── T1548.001 : SUID/ケーパビリティ偵察(find -perm / getcap)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'SUID and Capability Enumeration (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: SUID and Capability Enumeration (DB)
description: Detects enumeration of setuid/setgid binaries or file capabilities (find -perm -4000, getcap -r) — standard recon before Linux privilege escalation.
status: stable
level: medium
tags:
  - attack.t1548.001
  - attack.privilege_escalation
logsource:
  category: process_creation
detection:
  find_suid:
    CommandLine|contains:
      - "-perm -4000"
      - "-perm -2000"
      - "-perm -6000"
      - "-perm -u=s"
      - "-perm -g=s"
      - "-perm /4000"
      - "-perm /6000"
  getcap:
    CommandLine|contains:
      - "getcap -r"
      - "getcap -a"
  condition: find_suid or getcap
falsepositives:
  - Security auditing / hardening scans
$$,
'builtin-parity', ARRAY['T1548.001'],
'Two-engine parity: SUID/capability enumeration (find -perm / getcap)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'SUID and Capability Enumeration (DB)');

-- ── T1068 : pkexec 権限昇格エクスプロイト(PwnKit CVE-2021-4034)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Pkexec Exploitation PwnKit (DB)', 'sigma', ARRAY['linux','windows','macos'], 9,
$$title: Pkexec Exploitation PwnKit (DB)
description: Detects pkexec privilege-escalation exploitation patterns (PwnKit CVE-2021-4034) via GCONV_PATH/CHARSET/GIO_USE_VFS.
status: stable
level: critical
tags:
  - attack.t1068
  - attack.privilege_escalation
logsource:
  category: process_creation
detection:
  pkexec:
    CommandLine|contains|all:
      - "pkexec"
    CommandLine|contains:
      - "GCONV_PATH"
      - "CHARSET"
      - "GIO_USE_VFS"
  condition: pkexec
falsepositives:
  - Unlikely in production; high-confidence indicator
$$,
'builtin-parity', ARRAY['T1068'],
'Two-engine parity: pkexec PwnKit exploitation (CVE-2021-4034)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Pkexec Exploitation PwnKit (DB)');
