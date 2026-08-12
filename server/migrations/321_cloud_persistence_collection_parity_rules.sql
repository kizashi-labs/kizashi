-- 321: detection-server (DB RuleEngine) パリティ 第4弾 — クラウド永続化/収集/認証情報。
--
-- api-server ビルトインの高価値技法(クラウド計算基盤改ざん・クラウドアカウント作成・
-- インスタンスメタデータ窃取・メール転送ルール)を detection-server DB RuleEngine へ移植。
-- T1552.005 はビルトインが Image|endswith(curl/wget)を併用するが、DB エンジンでは
-- 高シグナルなメタデータエンドポイント文字列(169.254.169.254 等)を CommandLine|contains
-- で捕捉する(field mapping で解決=死蔵回避、ツール非依存でより汎用)。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)が固定する。

-- ── T1578 : クラウド計算基盤の改ざん(スナップショット持ち出し等) ─
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Cloud Compute Infrastructure Modification (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Cloud Compute Infrastructure Modification (DB)
description: Detects abuse of cloud compute APIs for data theft or persistence — creating and sharing disk snapshots to an attacker-controlled account (aws ec2 create-snapshot / modify-snapshot-attribute, az snapshot create, gcloud compute disks snapshot) or modifying instance attributes.
status: stable
level: high
tags:
  - attack.t1578
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  aws_snapshot_share:
    CommandLine|contains:
      - "modify-snapshot-attribute"
      - "modify-image-attribute"
  aws_snapshot_create:
    CommandLine|contains: "ec2 create-snapshot"
  aws_instance_modify:
    CommandLine|contains: "modify-instance-attribute"
  az_snapshot:
    CommandLine|contains|all:
      - "az snapshot"
      - "create"
  gcloud_snapshot:
    CommandLine|contains|all:
      - "compute disks snapshot"
  condition: aws_snapshot_share or aws_snapshot_create or aws_instance_modify or az_snapshot or gcloud_snapshot
falsepositives:
  - Backup automation creating snapshots (sharing snapshots externally is the higher-signal case)
$$,
'builtin-parity', ARRAY['T1578'],
'Two-engine parity: cloud compute infrastructure modification / snapshot exfil', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Cloud Compute Infrastructure Modification (DB)');

-- ── T1136.003 : クラウドアカウント作成(永続化) ───────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Cloud Account Creation (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Cloud Account Creation (DB)
description: Detects creation of cloud identities for persistence — aws iam create-user / create-login-profile, az ad user|sp|app create, gcloud iam service-accounts create — establishing durable attacker-controlled access after cloud compromise.
status: stable
level: high
tags:
  - attack.t1136.003
  - attack.persistence
logsource:
  category: process_creation
detection:
  aws_create:
    CommandLine|contains:
      - "iam create-user"
      - "iam create-login-profile"
  az_create:
    CommandLine|contains|all:
      - "az ad"
      - "create"
    CommandLine|contains:
      - "user"
      - "sp"
      - "app"
  gcloud_create:
    CommandLine|contains: "iam service-accounts create"
  condition: aws_create or az_create or gcloud_create
falsepositives:
  - Cloud administrators or IaC provisioning new identities
$$,
'builtin-parity', ARRAY['T1136.003'],
'Two-engine parity: cloud account creation for persistence', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Cloud Account Creation (DB)');

-- ── T1552.005 : クラウドインスタンスメタデータ窃取 ────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Cloud Instance Metadata Service Access (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Cloud Instance Metadata Service Access (DB)
description: Detects a process querying the cloud instance metadata service (169.254.169.254 / metadata.google.internal / computeMetadata / Metadata-Flavor header), commonly abused to steal instance credentials and role tokens via SSRF or on-host access.
status: stable
level: high
tags:
  - attack.t1552.005
  - attack.credential_access
logsource:
  category: process_creation
detection:
  metadata_endpoint:
    CommandLine|contains:
      - "169.254.169.254"
      - "metadata.google.internal"
      - "100.100.100.200"
      - "/latest/meta-data"
      - "/computeMetadata/"
      - "Metadata-Flavor"
  condition: metadata_endpoint
falsepositives:
  - Legitimate cloud-init / instance bootstrap tooling
$$,
'builtin-parity', ARRAY['T1552.005'],
'Two-engine parity: cloud instance metadata credential theft', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Cloud Instance Metadata Service Access (DB)');

-- ── T1114.003 : メール転送ルール(収集/持ち出し) ─────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Email Forwarding Rule (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Email Forwarding Rule (DB)
description: Detects creation of mail forwarding/redirection rules used to silently exfiltrate a victim mailbox — Exchange/M365 New-InboxRule with ForwardTo/RedirectTo, Set-Mailbox ForwardingSMTPAddress, or New-TransportRule with BlindCopyTo.
status: stable
level: high
tags:
  - attack.t1114.003
  - attack.collection
  - attack.exfiltration
logsource:
  category: process_creation
detection:
  inbox_rule:
    CommandLine|contains|all:
      - "New-InboxRule"
    CommandLine|contains:
      - "-ForwardTo"
      - "-ForwardAsAttachmentTo"
      - "-RedirectTo"
  mailbox_fwd:
    CommandLine|contains:
      - "ForwardingSMTPAddress"
      - "DeliverToMailboxAndForward"
  transport_rule:
    CommandLine|contains|all:
      - "New-TransportRule"
    CommandLine|contains:
      - "BlindCopyTo"
      - "RedirectMessageTo"
  condition: inbox_rule or mailbox_fwd or transport_rule
falsepositives:
  - Users legitimately configuring mail forwarding (review destination domain)
$$,
'builtin-parity', ARRAY['T1114.003'],
'Two-engine parity: email forwarding rule for silent exfiltration', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Email Forwarding Rule (DB)');
