-- Migration 296: 回避(defense evasion)敵対テスト v5 で発見した検知ギャップを埋める
-- カスタム Linux Sigma ルール(4件)。
--
-- 2026-07-02 の回避中心 adversarial テスト(docs/results/live-20260702-linux-evasion-adversarial.md)で
-- 実質未検知だった手口に、テスト固有文字列ではなく**一般的な手口**へマッチする技術固有ルールを追加。
-- CommandLine 部分文字列照合(agent は image 空)、platform=linux(#356)、level low〜medium、冪等。
--
-- ★据え置き(意図的に追加しない): T1071.004 DNS トンネリング / T1132.001 エンコード C2 は
--   プロセス文字列では低品質・高FP。DNS の高エントロピー/多量サブドメインはサーバ側 DNS
--   テレメトリ解析で扱うのが本筋(process_creation ルールでゲームしない)。

INSERT INTO rules (id, name, type, platform, severity, content, enabled, source, mitre_tags, curate_state, created_at)
VALUES
-- ── T1105 Ingress Tool Transfer(curl/wget を回避しインタプリタ/組込で DL)──
('ed6e0003-0000-0000-0000-000000001105',
 'Ingress Tool Transfer via Interpreter or /dev/tcp (Linux)', 'sigma', ARRAY['linux'], 5,
$$title: Ingress Tool Transfer via Interpreter or /dev/tcp (Linux)
status: stable
description: Detects file download via language interpreters (python/perl/ruby) or bash /dev/tcp, a LOLBin technique that evades curl/wget-based rules.
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'urllib.request'
      - 'urlretrieve'
      - 'urlopen('
      - 'requests.get('
      - 'LWP::Simple'
      - 'Net::HTTP'
      - 'open-uri'
      - 'URI.open'
      - '/dev/tcp/'
  condition: selection
falsepositives:
  - Legitimate scripts that fetch resources via language HTTP clients
level: low$$,
 true, 'custom', ARRAY['T1105'], 'enabled', NOW()),

-- ── T1548.001 Setuid/Setgid Abuse(権限昇格の探索: setuid バイナリ列挙)──
('ed6e0003-0000-0000-0000-001548001000',
 'Setuid/Setgid Binary Enumeration (Linux)', 'sigma', ARRAY['linux'], 4,
$$title: Setuid/Setgid Binary Enumeration (Linux)
status: stable
description: Detects enumeration of setuid/setgid binaries (find -perm), a privilege-escalation reconnaissance step (GTFOBins).
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - '-perm -4000'
      - '-perm -04000'
      - '-perm /4000'
      - '-perm -2000'
      - '-perm -u+s'
      - '-perm -g+s'
      - '-perm -6000'
  condition: selection
falsepositives:
  - Security/compliance scanners auditing setuid inventory
level: medium$$,
 true, 'custom', ARRAY['T1548.001'], 'enabled', NOW()),

-- ── T1562.003 Impair Defenses: Impair Command History Logging ──
('ed6e0003-0000-0000-0000-001562003000',
 'Command History Logging Tampering (Linux)', 'sigma', ARRAY['linux'], 5,
$$title: Command History Logging Tampering (Linux)
status: stable
description: Detects disabling of shell command history (HISTFILE/HISTSIZE/HISTCONTROL manipulation, set +o history), an anti-forensics technique.
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'set +o history'
      - 'unset HISTFILE'
      - 'HISTFILE=/dev/null'
      - 'HISTSIZE=0'
      - 'HISTFILESIZE=0'
      - 'HISTCONTROL=ignoreboth'
      - 'HISTCONTROL=ignorespace'
  condition: selection
falsepositives:
  - Some dotfile frameworks tune HISTCONTROL/HISTSIZE for convenience
level: medium$$,
 true, 'custom', ARRAY['T1562.003'], 'enabled', NOW()),

-- ── T1564.001 Hidden Files and Directories(world-writable 下の隠しファイル実行)──
('ed6e0003-0000-0000-0000-001564001000',
 'Hidden File Execution from World-Writable Directory (Linux)', 'sigma', ARRAY['linux'], 4,
$$title: Hidden File Execution from World-Writable Directory (Linux)
status: stable
description: Detects execution of a hidden (dot-prefixed) file or from a hidden directory under a world-writable path, used to conceal payloads.
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - '/tmp/.'
      - '/dev/shm/.'
      - '/var/tmp/.'
      - '/.cache/.'
  condition: selection
falsepositives:
  - Some tools stage dot-prefixed temp/cache files under /tmp
level: low$$,
 true, 'custom', ARRAY['T1564.001'], 'enabled', NOW())

ON CONFLICT (id) DO NOTHING;
