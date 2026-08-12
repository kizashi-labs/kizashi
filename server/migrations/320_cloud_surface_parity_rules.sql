-- 320: detection-server (DB RuleEngine) パリティ 第3弾 — クラウド攻撃面。
--
-- api-server ビルトインの高価値クラウド技法(偵察・永続化・権限昇格・防御回避)を
-- detection-server DB RuleEngine へ移植し、クラウド侵害チェーンを両エンジンで被覆する。
-- ビルトイン側も元々 CommandLine|contains のみ(クラウド CLI 起点)なので等価に移植できる。
--
-- platform は linux/windows/macos を明示(aws/az/gcloud CLI はクロスプラットフォーム)。
-- 冪等化は WHERE NOT EXISTS。回帰は migration_rules_test.go 群 +
-- migration_parity_test.go(発火)が固定する。

-- ── T1580 : クラウドインフラ探索 ──────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Cloud Infrastructure Discovery (DB)', 'sigma', ARRAY['linux','windows','macos'], 4,
$$title: Cloud Infrastructure Discovery (DB)
description: Detects enumeration of cloud compute and network infrastructure via cloud CLIs (aws ec2 describe-instances/security-groups/vpcs, az vm/network list, gcloud compute list), used to map lateral-movement and pivot targets after cloud access.
status: stable
level: low
tags:
  - attack.t1580
  - attack.discovery
logsource:
  category: process_creation
detection:
  aws_infra:
    CommandLine|contains:
      - "ec2 describe-instances"
      - "ec2 describe-security-groups"
      - "ec2 describe-vpcs"
      - "ec2 describe-subnets"
      - "rds describe-db-instances"
  az_infra:
    CommandLine|contains|all:
      - "az "
    CommandLine|contains:
      - "vm list"
      - "network nic list"
      - "network vnet list"
  gcloud_infra:
    CommandLine|contains|all:
      - "gcloud compute"
      - "list"
  condition: aws_infra or az_infra or gcloud_infra
falsepositives:
  - DevOps / IaC tooling inventorying cloud resources
$$,
'builtin-parity', ARRAY['T1580'],
'Two-engine parity: cloud infrastructure discovery via cloud CLIs', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Cloud Infrastructure Discovery (DB)');

-- ── T1619 : クラウドストレージオブジェクト探索 ────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Cloud Storage Object Discovery (DB)', 'sigma', ARRAY['linux','windows','macos'], 4,
$$title: Cloud Storage Object Discovery (DB)
description: Detects enumeration of cloud object storage buckets and objects (aws s3 ls / s3api list-buckets / list-objects, az storage container/blob list, gsutil ls, gcloud storage ls), used to locate data for collection and exfiltration.
status: stable
level: low
tags:
  - attack.t1619
  - attack.discovery
logsource:
  category: process_creation
detection:
  aws_s3:
    CommandLine|contains:
      - "s3 ls"
      - "s3api list-buckets"
      - "s3api list-objects"
  az_storage:
    CommandLine|contains|all:
      - "az storage"
      - "list"
  gcp_storage:
    CommandLine|contains:
      - "gsutil ls"
      - "gcloud storage ls"
  condition: aws_s3 or az_storage or gcp_storage
falsepositives:
  - Backup / data-pipeline jobs listing buckets
$$,
'builtin-parity', ARRAY['T1619'],
'Two-engine parity: cloud storage object discovery', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Cloud Storage Object Discovery (DB)');

-- ── T1098.001 : クラウド認証情報の追加(永続化) ──────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Additional Cloud Credentials (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Additional Cloud Credentials (DB)
description: Detects attaching new long-lived credentials to a cloud identity for persistence (aws iam create-access-key / create-login-profile, az ad app|sp credential reset, gcloud iam service-accounts keys create), so the attacker retains access even if the initial credential is revoked.
status: stable
level: high
tags:
  - attack.t1098.001
  - attack.persistence
logsource:
  category: process_creation
detection:
  aws_key:
    CommandLine|contains:
      - "iam create-access-key"
      - "iam create-login-profile"
  az_cred:
    CommandLine|contains|all:
      - "az ad"
      - "credential"
    CommandLine|contains: "reset"
  gcloud_key:
    CommandLine|contains: "service-accounts keys create"
  condition: aws_key or az_cred or gcloud_key
falsepositives:
  - Legitimate key rotation by cloud administrators or IaC
$$,
'builtin-parity', ARRAY['T1098.001'],
'Two-engine parity: additional cloud credentials for persistence', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Additional Cloud Credentials (DB)');

-- ── T1098.003 : クラウドロールの追加(権限昇格/永続化) ───────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Additional Cloud Roles (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Additional Cloud Roles (DB)
description: Detects granting elevated permissions to a cloud identity (aws iam attach-user-policy / attach-role-policy / put-user-policy / add-user-to-group, az role assignment create, gcloud add-iam-policy-binding), used for privilege escalation and persistence.
status: stable
level: high
tags:
  - attack.t1098.003
  - attack.privilege_escalation
  - attack.persistence
logsource:
  category: process_creation
detection:
  aws_grant:
    CommandLine|contains:
      - "iam attach-user-policy"
      - "iam attach-role-policy"
      - "iam put-user-policy"
      - "iam add-user-to-group"
  az_grant:
    CommandLine|contains: "role assignment create"
  gcloud_grant:
    CommandLine|contains: "add-iam-policy-binding"
  condition: aws_grant or az_grant or gcloud_grant
falsepositives:
  - Cloud administrators or IaC assigning roles
$$,
'builtin-parity', ARRAY['T1098.003'],
'Two-engine parity: additional cloud roles for privilege escalation', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Additional Cloud Roles (DB)');

-- ── T1562.007 : クラウドファイアウォールの開放(防御回避) ─────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Cloud Firewall Opening (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Cloud Firewall Opening (DB)
description: Detects opening cloud network controls to the internet for attacker access or persistence (aws ec2 authorize-security-group-ingress with 0.0.0.0/0, az network nsg rule create allow-any, gcloud compute firewall-rules create allowing 0.0.0.0/0).
status: stable
level: high
tags:
  - attack.t1562.007
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  aws_sg:
    CommandLine|contains|all:
      - "ec2 authorize-security-group-ingress"
      - "0.0.0.0/0"
  az_nsg:
    CommandLine|contains|all:
      - "network nsg rule create"
      - "0.0.0.0/0"
  gcloud_fw:
    CommandLine|contains|all:
      - "compute firewall-rules create"
      - "0.0.0.0/0"
  condition: aws_sg or az_nsg or gcloud_fw
falsepositives:
  - Administrators intentionally exposing a service (should be reviewed)
$$,
'builtin-parity', ARRAY['T1562.007'],
'Two-engine parity: cloud firewall opening to the internet', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Cloud Firewall Opening (DB)');
