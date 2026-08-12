-- 327: detection-server (DB RuleEngine) パリティ 第10弾 — C2/持ち出しチャネル。
--
-- api-server ビルトインにあるがDB未移植の C2/持ち出しチャネル(RMM遠隔操作、正規Webサービス
-- 経由のデッドドロップ、FTP/TFTP・メール経由の持ち出し)を移植し、両エンジンで被覆する。
-- ビルトインは Image|contains/endswith を併用するが、DB エンジンでは RMM ツール名・正規サービス
-- のURL・転送ツール構文を CommandLine|contains で捕捉する(死蔵回避、ツール非依存でより汎用)。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1219 : 遠隔操作ソフト(RMM 悪用) ──────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Remote Access Software Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Remote Access Software Execution (DB)
description: Detects execution of remote-access/RMM tools frequently abused for hands-on-keyboard access and ransomware staging (AnyDesk, TeamViewer, ScreenConnect, Atera, Splashtop, Ammyy, AnyViewer).
status: stable
level: medium
tags:
  - attack.t1219
  - attack.command_and_control
logsource:
  category: process_creation
detection:
  rmm:
    CommandLine|contains:
      - "anydesk"
      - "teamviewer"
      - "screenconnect"
      - "ateragent"
      - "splashtop"
      - "ammyy"
      - "anyviewer"
  condition: rmm
falsepositives:
  - Organisations that legitimately use these tools for IT support
$$,
'builtin-parity', ARRAY['T1219'],
'Two-engine parity: remote access / RMM software execution', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Remote Access Software Execution (DB)');

-- ── T1102 : 正規Webサービス経由C2(デッドドロップ) ───────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'C2 over Legitimate Web Service (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: C2 over Legitimate Web Service (DB)
description: Detects command-and-control or data staging through legitimate web services used as dead-drop resolvers (pastebin raw, raw/gist githubusercontent, Telegram bot API, Discord/Slack webhooks, transfer.sh, anonfiles), which blend with normal HTTPS traffic.
status: stable
level: high
tags:
  - attack.t1102
  - attack.command_and_control
logsource:
  category: process_creation
detection:
  service:
    CommandLine|contains:
      - "pastebin.com/raw"
      - "raw.githubusercontent.com"
      - "gist.githubusercontent.com"
      - "api.telegram.org/bot"
      - "discord.com/api/webhooks"
      - "discordapp.com/api/webhooks"
      - "hooks.slack.com/services"
      - "transfer.sh"
      - "anonfiles"
  condition: service
falsepositives:
  - CI/CD or automation legitimately fetching from raw GitHub / pastebin
$$,
'builtin-parity', ARRAY['T1102'],
'Two-engine parity: C2 over legitimate web service (dead-drop)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'C2 over Legitimate Web Service (DB)');

-- ── T1071.002 : FTP/TFTP 持ち出しチャネル ───────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'FTP TFTP Exfiltration Channel (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: FTP TFTP Exfiltration Channel (DB)
description: Detects scripted FTP/TFTP uploads used as an exfiltration channel (ftp with an -s script file, tftp put, curl -T to an ftp URL, WinSCP/pscp scripted transfer).
status: stable
level: medium
tags:
  - attack.t1071.002
  - attack.exfiltration
logsource:
  category: process_creation
detection:
  ftp_scripted:
    CommandLine|contains:
      - "ftp -s:"
      - "ftp -n -s"
  tftp_put:
    CommandLine|contains|all:
      - "tftp"
      - " put "
  curl_ftp_upload:
    CommandLine|contains|all:
      - "ftp://"
      - "-T "
  winscp_pscp:
    CommandLine|contains:
      - "winscp.com /command"
      - "winscp.exe /command"
      - "pscp -"
  condition: ftp_scripted or tftp_put or curl_ftp_upload or winscp_pscp
falsepositives:
  - Legitimate scripted FTP/SFTP backups or deployments
$$,
'builtin-parity', ARRAY['T1071.002'],
'Two-engine parity: FTP/TFTP exfiltration channel', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'FTP TFTP Exfiltration Channel (DB)');

-- ── T1071.003 : メールプロトコル持ち出し ────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Mail Protocol Exfiltration (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Mail Protocol Exfiltration (DB)
description: Detects sending data out as email attachments via command-line mailers (PowerShell Send-MailMessage with an attachment, swaks --attach, sendemail -a, or curl to an smtp/smtps server), used to exfiltrate over a mail protocol.
status: stable
level: medium
tags:
  - attack.t1071.003
  - attack.exfiltration
logsource:
  category: process_creation
detection:
  ps_sendmail:
    CommandLine|contains|all:
      - "Send-MailMessage"
      - "-Attachment"
  swaks:
    CommandLine|contains|all:
      - "swaks"
      - "--attach"
  sendemail:
    CommandLine|contains|all:
      - "sendemail"
      - " -a "
  curl_smtp:
    CommandLine|contains:
      - "curl smtp://"
      - "curl smtps://"
      - "--mail-from"
  condition: ps_sendmail or swaks or sendemail or curl_smtp
falsepositives:
  - Monitoring or backup scripts emailing reports with attachments
$$,
'builtin-parity', ARRAY['T1071.003'],
'Two-engine parity: mail protocol exfiltration', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Mail Protocol Exfiltration (DB)');
