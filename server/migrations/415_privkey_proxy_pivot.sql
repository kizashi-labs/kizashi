-- 351: 秘密鍵窃取(T1552.004、既存は僅少)の強化と、内部プロキシ/ポートフォワード
-- ピボット(T1090.001、0カバレッジ)の補完。いずれも process_creation の CommandLine。

-- ── T1552.004 : 秘密鍵の窃取・探索 ────────────────────────────────────
-- SSH/TLS の秘密鍵(id_rsa, .pem, .ppk, .pfx, .key)をシェル/アーカイバ/検索で
-- 読む・集める・探すのは資格情報窃取の典型。鍵を「使う」正規プロセス(ssh 等)は
-- Image で除外し、「集める/探す」動作に絞る。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Private Key Harvesting or Search', 'sigma', ARRAY['windows','linux','macos'], 6,
$SIGMA$
title: Private Key Harvesting or Search
description: Detects a shell, archiver, or search utility reading, copying, or hunting for SSH/TLS private keys (id_rsa, id_ed25519, .pem, .ppk, .pfx, .p12, .key, the .ssh directory). Unlike ssh/openssl which legitimately consume a specific key, a shell tarring the .ssh dir or a find/grep sweep for key material is credential theft (T1552.004).
status: stable
level: medium
tags:
  - attack.t1552.004
  - attack.credential_access
logsource:
  category: process_creation
detection:
  collector:
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - /tar
      - /cat
      - /cp
      - /scp
      - \7z.exe
      - \xcopy.exe
  key_target:
    CommandLine|contains:
      - 'id_rsa'
      - 'id_ed25519'
      - 'id_dsa'
      - '.ppk'
      - '.pfx'
      - '.p12'
      - '/.ssh/'
      - '\.ssh\'
  searcher:
    Image|endswith:
      - /find
      - /grep
      - \findstr.exe
    CommandLine|contains:
      - 'id_rsa'
      - '-----BEGIN'
      - '.pem'
      - 'PRIVATE KEY'
  condition: (collector and key_target) or searcher
falsepositives:
  - Backup/config-management tooling that packages key material (scope by host)
$SIGMA$,
'community', ARRAY['T1552.004'],
'Coverage strengthen: SSH/TLS private-key harvesting and search', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Private Key Harvesting or Search');

-- ── T1090.001 : 内部プロキシ / ポートフォワードによるピボット ─────────────
-- netsh portproxy / chisel / socat TCP-LISTEN...fork / ssh -R,-L のバインドは、
-- 侵害ホストを踏み台に内部ネットワークへピボットする典型手口(T1090.001)。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Internal Proxy or Port-Forward Pivot', 'sigma', ARRAY['windows','linux'], 6,
$SIGMA$
title: Internal Proxy or Port-Forward Pivot
description: Detects setup of an internal proxy or port-forward used to pivot through a compromised host — netsh interface portproxy add, chisel client/server, socat TCP-LISTEN...fork, or ssh -R/-L remote/local forwards. These relay traffic deeper into the network to reach otherwise-unreachable internal systems (T1090.001).
status: stable
level: medium
tags:
  - attack.t1090.001
  - attack.command_and_control
  - attack.lateral_movement
logsource:
  category: process_creation
detection:
  portproxy:
    CommandLine|contains: 'interface portproxy add'
  chisel:
    CommandLine|contains:
      - 'chisel client'
      - 'chisel server'
      - ' --reverse'
  socat:
    Image|endswith: /socat
    CommandLine|contains: 'TCP-LISTEN'
  ssh_forward:
    Image|endswith:
      - /ssh
      - \ssh.exe
      - \plink.exe
    CommandLine|contains:
      - ' -R '
      - ' -L '
      - ' -D '
  condition: portproxy or chisel or socat or ssh_forward
falsepositives:
  - Administrators using SSH port-forwarding or socat for legitimate access (scope by host/account)
$SIGMA$,
'community', ARRAY['T1090.001'],
'Coverage gap fill: internal proxy / port-forward pivot (was uncovered)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Internal Proxy or Port-Forward Pivot');
