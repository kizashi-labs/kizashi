-- Migration 297: プロセス系譜 / LOLBin 濫用の文脈検知(カスタム Linux Sigma ルール)。
--
-- 個別コマンドは良性に見えても「誰が誰を起動したか」で悪性度が決まる。サーバ/cron が
-- シェルを spawn する、ダウンロードをシェルにパイプする、等の系譜/LOLBin パターンを検知。
-- ParentImage は parentResolver が ppid から解決(alert_pipeline)。command_line ベースの
-- 規則は agent の実出力(image 空・command_line のみ)でも確実に発火。platform=linux(#356)、冪等。

INSERT INTO rules (id, name, type, platform, severity, content, enabled, source, mitre_tags, curate_state, created_at)
VALUES
-- ── T1505.003 Web Shell: Web/DB サーバがシェルを spawn ──
('ed6e0004-0000-0000-0000-001505003000',
 'Web/DB Server Spawning Shell (Linux)', 'sigma', ARRAY['linux'], 8,
$$title: Web/DB Server Spawning Shell (Linux)
status: stable
description: Detects a web or database server process spawning an interactive shell — a hallmark of web-shell / RCE exploitation.
logsource:
  category: process_creation
  product: linux
detection:
  parent:
    ParentImage|endswith:
      - '/nginx'
      - '/apache2'
      - '/httpd'
      - '/php-fpm'
      - '/php'
      - '/mysqld'
      - '/postgres'
      - '/tomcat'
      - '/java'
  child:
    Image|endswith:
      - '/sh'
      - '/bash'
      - '/dash'
      - '/zsh'
  condition: parent and child
falsepositives:
  - Legitimate CGI or admin scripts that shell out
level: high$$,
 true, 'custom', ARRAY['T1505.003'], 'enabled', NOW()),

-- ── T1059 Scheduled task spawning network/interpreter tools ──
('ed6e0004-0000-0000-0000-000000001059',
 'Cron/at Spawning Network or Interpreter Tools (Linux)', 'sigma', ARRAY['linux'], 6,
$$title: Cron/at Spawning Network or Interpreter Tools (Linux)
status: stable
description: Detects a scheduled-task daemon (cron/at) spawning download/network tools or interpreters, a common persistence-plus-execution pattern.
logsource:
  category: process_creation
  product: linux
detection:
  parent:
    ParentImage|endswith:
      - '/cron'
      - '/crond'
      - '/atd'
      - '/anacron'
  child:
    Image|endswith:
      - '/curl'
      - '/wget'
      - '/nc'
      - '/ncat'
      - '/socat'
      - '/python3'
      - '/perl'
      - '/bash'
  condition: parent and child
falsepositives:
  - Legitimate scheduled maintenance jobs
level: medium$$,
 true, 'custom', ARRAY['T1059'], 'enabled', NOW()),

-- ── T1059.004 Download piped to shell(command_line ベース=確実に発火)──
('ed6e0004-0000-0000-0000-001059004000',
 'Download Piped to Shell (Linux)', 'sigma', ARRAY['linux'], 7,
$$title: Download Piped to Shell (Linux)
status: stable
description: Detects the curl|sh / wget|bash one-liner that downloads and directly executes a remote script (ingress tool transfer + execution).
logsource:
  category: process_creation
  product: linux
detection:
  tool:
    CommandLine|contains:
      - 'curl'
      - 'wget'
      - 'fetch'
  pipe:
    CommandLine|contains:
      - '| sh'
      - '|sh'
      - '| bash'
      - '|bash'
      - '| python'
      - '|python'
  condition: tool and pipe
falsepositives:
  - Some installers use curl | sh (rustup, nvm) — soak before enforce
level: high$$,
 true, 'custom', ARRAY['T1059.004'], 'enabled', NOW())

ON CONFLICT (id) DO NOTHING;
