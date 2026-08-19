'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Search, Plus, Play, Edit2, Trash2, ToggleLeft, ToggleRight,
  ChevronDown, ChevronRight, X, Clock, AlertTriangle, CheckCircle,
  Activity, Shield, Cpu, Globe, Folder, Database, Zap,
  RefreshCw, Filter, Calendar, Tag, TrendingUp,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

import { USE_MOCK, m } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

type HuntType = 'ioc_sweep' | 'behavioral' | 'anomaly' | 'yara' | 'sigma' | 'custom'
type DataSource = 'events' | 'processes' | 'network' | 'registry' | 'files'
type Severity = 'critical' | 'high' | 'medium' | 'any'
type RuleStatus = 'running' | 'idle' | 'error' | 'disabled'
type ExecStatus = 'completed' | 'running' | 'failed' | 'cancelled'

interface HuntRule {
  id: string
  name: string
  description: string
  hunt_type: HuntType
  data_source: DataSource
  query: string
  schedule: string
  severity_threshold: Severity
  auto_escalate: boolean
  auto_escalate_threshold: number
  mitre_techniques: string[]
  last_run: string | null
  last_findings_count: number
  enabled: boolean
  total_runs: number
  total_findings: number
}

interface Execution {
  id: string
  rule_id: string
  rule_name: string
  started_at: string
  completed_at: string | null
  duration_sec: number | null
  status: ExecStatus
  findings_count: number
  escalated: boolean
  findings: Finding[]
}

interface Finding {
  id: string
  endpoint: string
  indicator: string
  process_or_file: string
  severity: Severity
  details: string
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_RULES: HuntRule[] = [
  {
    id: 'r-001', name: 'Lateral Movement Detection', description: 'Pass-the-hash / pass-the-ticket パターンを検出',
    hunt_type: 'behavioral', data_source: 'events',
    query: "SELECT * FROM events WHERE event_type='authentication' AND failure_reason='wrong_password' GROUP BY source_ip HAVING count(*) > 10",
    schedule: '0 */1 * * *', severity_threshold: 'high', auto_escalate: true, auto_escalate_threshold: 3,
    mitre_techniques: ['T1550', 'T1550.002'], last_run: '2026-03-18T08:00:00Z', last_findings_count: 5,
    enabled: true, total_runs: 142, total_findings: 27,
  },
  {
    id: 'r-002', name: 'YARA Malware Scan', description: '既知マルウェアシグネチャをファイルシステムでスキャン',
    hunt_type: 'yara', data_source: 'files',
    query: 'rule Ransomware_Generic {\n  meta:\n    description = "Generic ransomware detection"\n  strings:\n    $a = {6A 40 68 00 30 00 00}\n  condition:\n    $a\n}',
    schedule: '0 6 * * *', severity_threshold: 'critical', auto_escalate: true, auto_escalate_threshold: 1,
    mitre_techniques: ['T1486', 'T1204'], last_run: '2026-03-18T06:00:00Z', last_findings_count: 0,
    enabled: true, total_runs: 88, total_findings: 3,
  },
  {
    id: 'r-003', name: 'Suspicious Process Creation', description: '異常なプロセス生成チェーンを検知',
    hunt_type: 'sigma', data_source: 'processes',
    query: "title: Suspicious Process\nstatus: experimental\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    ParentImage|endswith: '\\\\winword.exe'\n    Image|endswith:\n      - '\\\\cmd.exe'\n      - '\\\\powershell.exe'\n  condition: selection",
    schedule: '*/30 * * * *', severity_threshold: 'high', auto_escalate: true, auto_escalate_threshold: 2,
    mitre_techniques: ['T1059', 'T1059.001', 'T1566'], last_run: '2026-03-18T09:30:00Z', last_findings_count: 2,
    enabled: true, total_runs: 512, total_findings: 44,
  },
  {
    id: 'r-004', name: 'Anomalous Network Traffic', description: 'ベースラインを超えたネットワークトラフィック異常検知',
    hunt_type: 'anomaly', data_source: 'network',
    query: 'SELECT src_ip, dst_ip, bytes_sent, connection_count FROM network_flows WHERE bytes_sent > baseline_threshold * 3 ORDER BY bytes_sent DESC',
    schedule: '0 */6 * * *', severity_threshold: 'medium', auto_escalate: false, auto_escalate_threshold: 5,
    mitre_techniques: ['T1048', 'T1041'], last_run: '2026-03-18T06:00:00Z', last_findings_count: 8,
    enabled: true, total_runs: 66, total_findings: 19,
  },
  {
    id: 'r-005', name: 'Registry Persistence Hunt', description: 'レジストリ永続化メカニズムの検索',
    hunt_type: 'ioc_sweep', data_source: 'registry',
    query: 'SELECT * FROM registry_events WHERE key_path LIKE "%\\\\Run%" OR key_path LIKE "%\\\\RunOnce%" AND modified_by != "SYSTEM"',
    schedule: '0 */12 * * *', severity_threshold: 'high', auto_escalate: true, auto_escalate_threshold: 1,
    mitre_techniques: ['T1547', 'T1547.001'], last_run: '2026-03-17T18:00:00Z', last_findings_count: 1,
    enabled: true, total_runs: 45, total_findings: 8,
  },
  {
    id: 'r-006', name: 'Credential Dumping Detection', description: 'LSASSアクセスおよびクレデンシャルダンプ試行を検出',
    hunt_type: 'behavioral', data_source: 'processes',
    query: "SELECT * FROM process_events WHERE target_process='lsass.exe' AND access_rights LIKE '%0x1010%'",
    schedule: '0 * * * *', severity_threshold: 'critical', auto_escalate: true, auto_escalate_threshold: 1,
    mitre_techniques: ['T1003', 'T1003.001'], last_run: '2026-03-18T09:00:00Z', last_findings_count: 0,
    enabled: true, total_runs: 210, total_findings: 5,
  },
  {
    id: 'r-007', name: 'DNS Tunneling Hunt', description: 'DNSトンネリングパターンを検知',
    hunt_type: 'anomaly', data_source: 'network',
    query: 'SELECT query_name, COUNT(*) as query_count, AVG(query_length) as avg_len FROM dns_queries GROUP BY query_name HAVING query_count > 100 AND avg_len > 50',
    schedule: '0 */4 * * *', severity_threshold: 'medium', auto_escalate: false, auto_escalate_threshold: 10,
    mitre_techniques: ['T1071.004'], last_run: '2026-03-18T08:00:00Z', last_findings_count: 3,
    enabled: false, total_runs: 30, total_findings: 2,
  },
  {
    id: 'r-008', name: 'Scheduled Task Abuse', description: 'スケジュールタスクを悪用した永続化を検出',
    hunt_type: 'sigma', data_source: 'events',
    query: "title: Suspicious Scheduled Task\ndetection:\n  selection:\n    EventID: 4698\n    TaskContent|contains:\n      - 'cmd.exe'\n      - 'powershell'\n  condition: selection",
    schedule: '0 */2 * * *', severity_threshold: 'high', auto_escalate: false, auto_escalate_threshold: 5,
    mitre_techniques: ['T1053', 'T1053.005'], last_run: '2026-03-18T08:00:00Z', last_findings_count: 0,
    enabled: true, total_runs: 94, total_findings: 7,
  },
  {
    id: 'r-009', name: 'Custom IOC Sweep', description: 'カスタムIOCリストによる一括スキャン',
    hunt_type: 'custom', data_source: 'events',
    query: 'SELECT * FROM events WHERE hash IN (SELECT hash FROM ioc_list WHERE type="sha256") OR ip_address IN (SELECT ip FROM ioc_list WHERE type="ip")',
    schedule: '0 0 * * *', severity_threshold: 'any', auto_escalate: false, auto_escalate_threshold: 20,
    mitre_techniques: [], last_run: '2026-03-18T00:00:00Z', last_findings_count: 0,
    enabled: true, total_runs: 55, total_findings: 4,
  },
  {
    id: 'r-010', name: 'Privilege Escalation Hunt', description: '権限昇格の試みを検出するハンティングルール',
    hunt_type: 'behavioral', data_source: 'processes',
    query: "SELECT * FROM process_events WHERE integrity_level_change='medium_to_high' OR parent_process='cmd.exe' AND child_process_integrity='high'",
    schedule: '0 */3 * * *', severity_threshold: 'critical', auto_escalate: true, auto_escalate_threshold: 1,
    mitre_techniques: ['T1068', 'T1078'], last_run: '2026-03-18T09:00:00Z', last_findings_count: 4,
    enabled: true, total_runs: 78, total_findings: 12,
  },
]

const MOCK_EXECUTIONS: Execution[] = [
  {
    id: 'e-001', rule_id: 'r-001', rule_name: 'Lateral Movement Detection',
    started_at: '2026-03-18T08:00:00Z', completed_at: '2026-03-18T08:02:15Z',
    duration_sec: 135, status: 'completed', findings_count: 5, escalated: true,
    findings: [
      { id: 'f-001', endpoint: 'WIN-PC-042', indicator: '10.0.1.55', process_or_file: 'lsass.exe', severity: 'high', details: 'Pass-the-hash attempt from 10.0.1.55' },
      { id: 'f-002', endpoint: 'WIN-SRV-001', indicator: '10.0.1.55', process_or_file: 'cmd.exe', severity: 'high', details: 'Lateral movement to domain controller' },
      { id: 'f-003', endpoint: 'WIN-PC-019', indicator: '10.0.1.33', process_or_file: 'winlogon.exe', severity: 'medium', details: 'Failed authentication spike' },
      { id: 'f-004', endpoint: 'WIN-PC-031', indicator: '10.0.1.77', process_or_file: 'svchost.exe', severity: 'medium', details: 'Unusual SMB connection pattern' },
      { id: 'f-005', endpoint: 'WIN-SRV-003', indicator: '10.0.1.55', process_or_file: 'msv1_0.dll', severity: 'critical', details: 'NTLM hash dumped' },
    ],
  },
  {
    id: 'e-002', rule_id: 'r-003', rule_name: 'Suspicious Process Creation',
    started_at: '2026-03-18T09:30:00Z', completed_at: '2026-03-18T09:30:22Z',
    duration_sec: 22, status: 'completed', findings_count: 2, escalated: false,
    findings: [
      { id: 'f-006', endpoint: 'WIN-PC-077', indicator: 'winword.exe -> cmd.exe', process_or_file: 'cmd.exe', severity: 'high', details: 'Word spawned command prompt' },
      { id: 'f-007', endpoint: 'WIN-PC-091', indicator: 'winword.exe -> powershell.exe', process_or_file: 'powershell.exe', severity: 'high', details: 'Word spawned PowerShell' },
    ],
  },
  {
    id: 'e-003', rule_id: 'r-002', rule_name: 'YARA Malware Scan',
    started_at: '2026-03-18T06:00:00Z', completed_at: '2026-03-18T06:18:45Z',
    duration_sec: 1125, status: 'completed', findings_count: 0, escalated: false, findings: [],
  },
  {
    id: 'e-004', rule_id: 'r-004', rule_name: 'Anomalous Network Traffic',
    started_at: '2026-03-18T06:00:00Z', completed_at: '2026-03-18T06:03:40Z',
    duration_sec: 220, status: 'completed', findings_count: 8, escalated: false,
    findings: [
      { id: 'f-008', endpoint: 'WIN-PC-052', indicator: '185.220.101.45', process_or_file: 'chrome.exe', severity: 'medium', details: 'High volume upload to unknown IP' },
      { id: 'f-009', endpoint: 'WIN-PC-003', indicator: '45.142.212.100', process_or_file: 'svchost.exe', severity: 'medium', details: 'Unusual outbound connection' },
    ],
  },
  {
    id: 'e-005', rule_id: 'r-010', rule_name: 'Privilege Escalation Hunt',
    started_at: '2026-03-18T09:00:00Z', completed_at: '2026-03-18T09:01:05Z',
    duration_sec: 65, status: 'completed', findings_count: 4, escalated: true,
    findings: [
      { id: 'f-010', endpoint: 'WIN-PC-015', indicator: 'juicypotato.exe', process_or_file: 'juicypotato.exe', severity: 'critical', details: 'Token impersonation exploit' },
    ],
  },
  {
    id: 'e-006', rule_id: 'r-005', rule_name: 'Registry Persistence Hunt',
    started_at: '2026-03-17T18:00:00Z', completed_at: '2026-03-17T18:00:48Z',
    duration_sec: 48, status: 'completed', findings_count: 1, escalated: false,
    findings: [
      { id: 'f-011', endpoint: 'WIN-PC-028', indicator: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', process_or_file: 'updater.exe', severity: 'high', details: 'Suspicious run key added' },
    ],
  },
  {
    id: 'e-007', rule_id: 'r-006', rule_name: 'Credential Dumping Detection',
    started_at: '2026-03-18T09:00:00Z', completed_at: '2026-03-18T09:00:18Z',
    duration_sec: 18, status: 'completed', findings_count: 0, escalated: false, findings: [],
  },
  {
    id: 'e-008', rule_id: 'r-008', rule_name: 'Scheduled Task Abuse',
    started_at: '2026-03-18T08:00:00Z', completed_at: null,
    duration_sec: null, status: 'running', findings_count: 0, escalated: false, findings: [],
  },
  {
    id: 'e-009', rule_id: 'r-001', rule_name: 'Lateral Movement Detection',
    started_at: '2026-03-18T07:00:00Z', completed_at: '2026-03-18T07:02:05Z',
    duration_sec: 125, status: 'completed', findings_count: 3, escalated: false,
    findings: [
      { id: 'f-012', endpoint: 'WIN-PC-042', indicator: '10.0.1.88', process_or_file: 'cmd.exe', severity: 'high', details: 'Brute force attempt' },
    ],
  },
  {
    id: 'e-010', rule_id: 'r-009', rule_name: 'Custom IOC Sweep',
    started_at: '2026-03-18T00:00:00Z', completed_at: null,
    duration_sec: null, status: 'failed', findings_count: 0, escalated: false, findings: [],
  },
  {
    id: 'e-011', rule_id: 'r-003', rule_name: 'Suspicious Process Creation',
    started_at: '2026-03-18T09:00:00Z', completed_at: '2026-03-18T09:00:19Z',
    duration_sec: 19, status: 'completed', findings_count: 0, escalated: false, findings: [],
  },
  {
    id: 'e-012', rule_id: 'r-007', rule_name: 'DNS Tunneling Hunt',
    started_at: '2026-03-18T08:00:00Z', completed_at: '2026-03-18T08:02:30Z',
    duration_sec: 150, status: 'completed', findings_count: 3, escalated: false,
    findings: [
      { id: 'f-013', endpoint: 'WIN-PC-060', indicator: 'a1b2c3d4e5f6.evildomain.com', process_or_file: 'chrome.exe', severity: 'medium', details: 'High-entropy DNS subdomains' },
    ],
  },
  {
    id: 'e-013', rule_id: 'r-010', rule_name: 'Privilege Escalation Hunt',
    started_at: '2026-03-18T06:00:00Z', completed_at: '2026-03-18T06:01:02Z',
    duration_sec: 62, status: 'completed', findings_count: 1, escalated: false,
    findings: [],
  },
  {
    id: 'e-014', rule_id: 'r-004', rule_name: 'Anomalous Network Traffic',
    started_at: '2026-03-18T00:00:00Z', completed_at: '2026-03-18T00:03:50Z',
    duration_sec: 230, status: 'completed', findings_count: 4, escalated: false, findings: [],
  },
  {
    id: 'e-015', rule_id: 'r-002', rule_name: 'YARA Malware Scan',
    started_at: '2026-03-17T06:00:00Z', completed_at: '2026-03-17T06:20:00Z',
    duration_sec: 1200, status: 'completed', findings_count: 0, escalated: false, findings: [],
  },
  {
    id: 'e-016', rule_id: 'r-001', rule_name: 'Lateral Movement Detection',
    started_at: '2026-03-17T08:00:00Z', completed_at: '2026-03-17T08:01:50Z',
    duration_sec: 110, status: 'completed', findings_count: 2, escalated: false, findings: [],
  },
  {
    id: 'e-017', rule_id: 'r-006', rule_name: 'Credential Dumping Detection',
    started_at: '2026-03-17T09:00:00Z', completed_at: null,
    duration_sec: null, status: 'failed', findings_count: 0, escalated: false, findings: [],
  },
  {
    id: 'e-018', rule_id: 'r-005', rule_name: 'Registry Persistence Hunt',
    started_at: '2026-03-17T06:00:00Z', completed_at: '2026-03-17T06:00:55Z',
    duration_sec: 55, status: 'completed', findings_count: 0, escalated: false, findings: [],
  },
  {
    id: 'e-019', rule_id: 'r-003', rule_name: 'Suspicious Process Creation',
    started_at: '2026-03-17T21:30:00Z', completed_at: '2026-03-17T21:30:21Z',
    duration_sec: 21, status: 'completed', findings_count: 1, escalated: false,
    findings: [
      { id: 'f-014', endpoint: 'WIN-PC-044', indicator: 'excel.exe -> wscript.exe', process_or_file: 'wscript.exe', severity: 'high', details: 'Excel spawned wscript' },
    ],
  },
  {
    id: 'e-020', rule_id: 'r-008', rule_name: 'Scheduled Task Abuse',
    started_at: '2026-03-17T20:00:00Z', completed_at: '2026-03-17T20:00:12Z',
    duration_sec: 12, status: 'completed', findings_count: 0, escalated: false, findings: [],
  },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

function humanizeCron(cron: string): string {
  const map: Record<string, string> = {
    '0 */1 * * *': '1時間ごと',
    '*/30 * * * *': '30分ごと',
    '0 */2 * * *': '2時間ごと',
    '0 */3 * * *': '3時間ごと',
    '0 */4 * * *': '4時間ごと',
    '0 */6 * * *': '6時間ごと',
    '0 */12 * * *': '12時間ごと',
    '0 * * * *': '毎時',
    '0 0 * * *': '毎日',
    '0 6 * * *': '毎日06:00',
    '0 0 * * 0': '毎週',
  }
  return map[cron] ?? cron
}

function formatDuration(sec: number | null): string {
  if (sec === null) return '-'
  if (sec < 60) return `${sec}秒`
  return `${Math.floor(sec / 60)}分${sec % 60}秒`
}

function fmtTime(iso: string | null): string {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

const HUNT_TYPE_COLORS: Record<HuntType, string> = {
  ioc_sweep: 'bg-purple-900/50 text-purple-300 border-purple-700/50',
  behavioral: 'bg-blue-900/50 text-blue-300 border-blue-700/50',
  anomaly: 'bg-yellow-900/50 text-yellow-300 border-yellow-700/50',
  yara: 'bg-green-900/50 text-green-300 border-green-700/50',
  sigma: 'bg-orange-900/50 text-orange-300 border-orange-700/50',
  custom: 'bg-[#1e2d42] text-[#7d92b0] border-[#1e2d42]',
}

const DS_COLORS: Record<DataSource, string> = {
  events: 'bg-blue-900/40 text-blue-400',
  processes: 'bg-orange-900/40 text-orange-400',
  network: 'bg-teal-900/40 text-teal-400',
  registry: 'bg-yellow-900/40 text-yellow-400',
  files: 'bg-green-900/40 text-green-400',
}

const DS_ICONS: Record<DataSource, React.ReactNode> = {
  events: <Database className="w-3 h-3" />,
  processes: <Cpu className="w-3 h-3" />,
  network: <Globe className="w-3 h-3" />,
  registry: <Shield className="w-3 h-3" />,
  files: <Folder className="w-3 h-3" />,
}

const SEV_COLORS: Record<Severity, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  any: 'text-[#7d92b0]',
}

const EXEC_STATUS_BADGE: Record<ExecStatus, string> = {
  completed: 'bg-green-900/40 text-green-400',
  running: 'bg-blue-900/40 text-blue-300 animate-pulse',
  failed: 'bg-red-900/40 text-red-400',
  cancelled: 'bg-[#1e2d42] text-[#7d92b0]',
}

const QUERY_PLACEHOLDERS: Record<HuntType, string> = {
  behavioral: 'SELECT * FROM events WHERE event_type = \'authentication\' AND ...',
  yara: '#YARA rule\nrule SuspiciousFile {\n  strings:\n    $a = "suspicious_string"\n  condition:\n    $a\n}',
  sigma: 'title: Suspicious Activity\nstatus: experimental\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    ...\n  condition: selection',
  ioc_sweep: 'SELECT * FROM events WHERE hash IN (SELECT hash FROM ioc_list) ...',
  anomaly: 'SELECT src_ip, COUNT(*) FROM events GROUP BY src_ip HAVING ...',
  custom: '-- カスタムクエリを入力してください',
}

const SCHEDULE_PRESETS = [
  { label: '毎時', cron: '0 * * * *' },
  { label: '6時間ごと', cron: '0 */6 * * *' },
  { label: '12時間ごと', cron: '0 */12 * * *' },
  { label: '毎日', cron: '0 0 * * *' },
  { label: '毎週', cron: '0 0 * * 0' },
  { label: 'カスタム', cron: '' },
]

// ─── Toast ────────────────────────────────────────────────────────────────────

function Toast({ msg, type }: { msg: string; type: 'info' | 'success' | 'error' }) {
  const colors = { info: 'bg-blue-900/80 border-blue-700 text-blue-200', success: 'bg-green-900/80 border-green-700 text-green-200', error: 'bg-red-900/80 border-red-700 text-red-300' }
  return (
    <div className={`fixed bottom-6 right-6 z-50 px-4 py-3 rounded-lg border text-sm font-medium shadow-2xl transition-all ${colors[type]}`}>
      {msg}
    </div>
  )
}

// ─── RuleModal ────────────────────────────────────────────────────────────────

interface RuleModalProps {
  rule?: HuntRule | null
  onClose: () => void
  onSave: (data: Partial<HuntRule>) => void
}

function RuleModal({ rule, onClose, onSave }: RuleModalProps) {
  const [form, setForm] = useState<Partial<HuntRule>>({
    name: rule?.name ?? '',
    description: rule?.description ?? '',
    hunt_type: rule?.hunt_type ?? 'behavioral',
    data_source: rule?.data_source ?? 'events',
    query: rule?.query ?? '',
    schedule: rule?.schedule ?? '0 */6 * * *',
    severity_threshold: rule?.severity_threshold ?? 'high',
    auto_escalate: rule?.auto_escalate ?? false,
    auto_escalate_threshold: rule?.auto_escalate_threshold ?? 3,
    mitre_techniques: rule?.mitre_techniques ?? [],
    enabled: rule?.enabled ?? true,
  })
  const [scheduleMode, setScheduleMode] = useState<'preset' | 'custom'>('preset')
  const [mitreInput, setMitreInput] = useState('')

  const set = (k: keyof HuntRule, v: unknown) => setForm(p => ({ ...p, [k]: v }))

  const addMitre = () => {
    if (mitreInput.trim() && !form.mitre_techniques?.includes(mitreInput.trim())) {
      set('mitre_techniques', [...(form.mitre_techniques ?? []), mitreInput.trim().toUpperCase()])
      setMitreInput('')
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-base">{rule ? 'ルール編集' : '新規ハンティングルール'}</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-5 space-y-4">
          {/* Name */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">ルール名 *</label>
            <input value={form.name} onChange={e => set('name', e.target.value)}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/50" placeholder="例: Lateral Movement Detection" />
          </div>
          {/* Description */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">説明</label>
            <textarea value={form.description} onChange={e => set('description', e.target.value)} rows={2}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/50 resize-none" />
          </div>
          {/* Type & Source */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">ハントタイプ</label>
              <select value={form.hunt_type} onChange={e => set('hunt_type', e.target.value as HuntType)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden">
                {(['ioc_sweep', 'behavioral', 'anomaly', 'yara', 'sigma', 'custom'] as HuntType[]).map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">データソース</label>
              <select value={form.data_source} onChange={e => set('data_source', e.target.value as DataSource)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden">
                {(['events', 'processes', 'network', 'registry', 'files'] as DataSource[]).map(d => (
                  <option key={d} value={d}>{d}</option>
                ))}
              </select>
            </div>
          </div>
          {/* Query */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">クエリ / パターン</label>
            <textarea value={form.query} onChange={e => set('query', e.target.value)} rows={5}
              placeholder={QUERY_PLACEHOLDERS[form.hunt_type ?? 'behavioral']}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-xs text-[#e2e8f4] font-mono focus:outline-hidden focus:border-[#e8002d]/50 resize-none" />
          </div>
          {/* Schedule */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">スケジュール</label>
            <div className="flex gap-2 flex-wrap mb-2">
              {SCHEDULE_PRESETS.map(p => (
                <button key={p.label} onClick={() => { if (p.cron) { set('schedule', p.cron); setScheduleMode('preset') } else setScheduleMode('custom') }}
                  className={`px-3 py-1 rounded-lg text-xs border transition-colors ${
                    (p.cron && form.schedule === p.cron) || (p.label === 'カスタム' && scheduleMode === 'custom')
                      ? 'bg-[#e8002d]/20 border-[#e8002d]/50 text-white'
                      : 'bg-[#0a1020] border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/40'
                  }`}>{p.label}</button>
              ))}
            </div>
            {scheduleMode === 'custom' && (
              <input value={form.schedule} onChange={e => set('schedule', e.target.value)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-hidden" placeholder="0 */6 * * *" />
            )}
          </div>
          {/* Severity & Auto-escalate */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">重大度しきい値</label>
              <select value={form.severity_threshold} onChange={e => set('severity_threshold', e.target.value as Severity)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden">
                {(['critical', 'high', 'medium', 'any'] as Severity[]).map(s => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">自動エスカレーション</label>
              <div className="flex items-center gap-3 mt-1">
                <button onClick={() => set('auto_escalate', !form.auto_escalate)}
                  className={`w-10 h-5 rounded-full relative transition-colors ${form.auto_escalate ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'}`}>
                  <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-[#e2e8f4] transition-transform shadow-sm ${form.auto_escalate ? 'translate-x-5' : 'translate-x-0.5'}`} />
                </button>
                {form.auto_escalate && (
                  <div className="flex items-center gap-1 text-xs text-[#7d92b0]">
                    <span>所見</span>
                    <input type="number" min={1} max={100} value={form.auto_escalate_threshold}
                      onChange={e => set('auto_escalate_threshold', +e.target.value)}
                      className="w-12 bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-0.5 text-white text-xs text-center focus:outline-hidden" />
                    <span>件以上で作成</span>
                  </div>
                )}
              </div>
            </div>
          </div>
          {/* MITRE */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">MITREテクニック</label>
            <div className="flex gap-2 mb-2">
              <input value={mitreInput} onChange={e => setMitreInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && (e.preventDefault(), addMitre())}
                className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden" placeholder="T1059.001" />
              <button onClick={addMitre} className="px-3 py-2 bg-[#1e2d42] hover:bg-[#253650] rounded-lg text-sm text-[#7d92b0]"><Plus className="w-4 h-4" /></button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {(form.mitre_techniques ?? []).map(t => (
                <span key={t} className="inline-flex items-center gap-1 px-2 py-0.5 bg-purple-900/30 border border-purple-700/40 rounded-sm text-xs text-purple-300">
                  {t}
                  <button onClick={() => set('mitre_techniques', form.mitre_techniques?.filter(x => x !== t))}><X className="w-3 h-3" /></button>
                </span>
              ))}
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#7d92b0]/40">キャンセル</button>
          <button onClick={() => onSave(form)} className="px-4 py-2 rounded-lg text-sm bg-[#e8002d] hover:bg-[#c8001e] text-white font-medium">
            {rule ? '更新' : '作成'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── FindingRow ───────────────────────────────────────────────────────────────

function FindingRow({ f }: { f: Finding }) {
  return (
    <div className="flex items-center gap-3 px-3 py-2 bg-[#070d19] rounded-lg border border-[#1e2d42] text-xs">
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${f.severity === 'critical' ? 'bg-red-500' : f.severity === 'high' ? 'bg-orange-400' : 'bg-yellow-400'}`} />
      <span className="text-[#7d92b0] w-28 truncate shrink-0">{f.endpoint}</span>
      <span className="text-white flex-1 truncate">{f.indicator}</span>
      <span className="text-[#7d92b0] w-32 truncate">{f.process_or_file}</span>
      <button className="ml-auto px-2 py-0.5 bg-[#1e2d42] hover:bg-[#253650] rounded-sm text-[#7d92b0] whitespace-nowrap">アラート作成</button>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function AutomatedHuntingPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'rules' | 'history'>('rules')
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [showModal, setShowModal] = useState(false)
  const [editRule, setEditRule] = useState<HuntRule | null>(null)
  const [expandedExec, setExpandedExec] = useState<string | null>(null)
  const [execRuleFilter, setExecRuleFilter] = useState<string>('all')
  const [execStatusFilter, setExecStatusFilter] = useState<string>('all')
  const [toast, setToast] = useState<{ msg: string; type: 'info' | 'success' | 'error' } | null>(null)

  const showToast = (msg: string, type: 'info' | 'success' | 'error' = 'info') => {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 4000)
  }

  // ── Queries ─────────────────────────────────────────────────────────────────

  const rulesQ = useQuery<HuntRule[]>({
    queryKey: ['hunt-rules'],
    queryFn: () => apiFetch('/api/v1/threat-hunting/rules'),
    ...(USE_MOCK ? { initialData: MOCK_RULES } : {}),
    retry: 1,
  })

  const execQ = useQuery<Execution[]>({
    queryKey: ['hunt-executions'],
    queryFn: () => apiFetch('/api/v1/threat-hunting/executions'),
    ...(USE_MOCK ? { initialData: MOCK_EXECUTIONS } : {}),
    retry: 1,
  })

  const rules = rulesQ.data ?? m(MOCK_RULES)
  const executions = execQ.data ?? m(MOCK_EXECUTIONS)

  // ── Mutations ────────────────────────────────────────────────────────────────

  const runMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/threat-hunting/rules/${id}/run`, { method: 'POST' }),
    onMutate: () => showToast('実行中...', 'info'),
    onSuccess: (data: unknown) => {
      const d = data as { findings_count?: number }
      showToast(`${d?.findings_count ?? 0}件の所見を発見`, 'success')
      qc.invalidateQueries({ queryKey: ['hunt-executions'] })
    },
    onError: () => showToast('実行に失敗しました', 'error'),
  })

  const saveMutation = useMutation({
    mutationFn: (payload: { id?: string; data: Partial<HuntRule> }) =>
      payload.id
        ? apiFetch(`/api/v1/threat-hunting/rules/${payload.id}`, { method: 'PUT', body: JSON.stringify(payload.data) })
        : apiFetch('/api/v1/threat-hunting/rules', { method: 'POST', body: JSON.stringify(payload.data) }),
    onSuccess: () => { showToast('保存しました', 'success'); setShowModal(false); setEditRule(null) },
    onError: () => showToast('保存に失敗しました', 'error'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/threat-hunting/rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => showToast('削除しました', 'success'),
    onError: () => showToast('削除に失敗しました', 'error'),
  })

  // ── Derived ──────────────────────────────────────────────────────────────────

  const filteredRules = useMemo(() =>
    rules.filter(r =>
      (r.name.toLowerCase().includes(search.toLowerCase()) || r.description.toLowerCase().includes(search.toLowerCase())) &&
      (typeFilter === 'all' || r.hunt_type === typeFilter)
    ), [rules, search, typeFilter])

  const filteredExecs = useMemo(() =>
    executions.filter(e =>
      (execRuleFilter === 'all' || e.rule_id === execRuleFilter) &&
      (execStatusFilter === 'all' || e.status === execStatusFilter)
    ), [executions, execRuleFilter, execStatusFilter])

  const today = new Date().toISOString().slice(0, 10)
  const activeHunts = rules.filter(r => r.enabled).length
  const todayExecs = executions.filter(e => e.started_at.startsWith(today)).length
  const weekFindings = executions.reduce((s, e) => s + e.findings_count, 0)
  const autoEscalated = executions.filter(e => e.escalated).length

  const effectivenessTop5 = useMemo(() => {
    return [...rules]
      .filter(r => r.total_runs > 0)
      .map(r => ({ ...r, ratio: r.total_findings / r.total_runs }))
      .sort((a, b) => b.ratio - a.ratio)
      .slice(0, 5)
  }, [rules])

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {toast && <Toast msg={toast.msg} type={toast.type} />}
      {(showModal || editRule) && (
        <RuleModal
          rule={editRule}
          onClose={() => { setShowModal(false); setEditRule(null) }}
          onSave={data => saveMutation.mutate({ id: editRule?.id, data })}
        />
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-linear-to-br from-[#e8002d]/20 to-[#e8002d]/5 border border-[#e8002d]/30 flex items-center justify-center">
            <Search className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">自動脅威ハンティング</h1>
            <p className="text-[#7d92b0] text-sm">スケジュールベースのハンティングルールと実行管理</p>
          </div>
        </div>
        <button onClick={() => { setEditRule(null); setShowModal(true) }}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c8001e] text-white rounded-lg text-sm font-medium transition-colors">
          <Plus className="w-4 h-4" />
          新規ルール作成
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'アクティブハント', value: activeHunts, icon: <Activity className="w-5 h-5" />, color: 'text-blue-400' },
          { label: '今日の実行数', value: todayExecs, icon: <Clock className="w-5 h-5" />, color: 'text-green-400' },
          { label: '今週の所見', value: weekFindings, icon: <AlertTriangle className="w-5 h-5" />, color: 'text-yellow-400' },
          { label: '自動エスカレーション', value: autoEscalated, icon: <Zap className="w-5 h-5" />, color: 'text-[#e8002d]' },
        ].map(c => (
          <div key={c.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className={`${c.color} mb-2`}>{c.icon}</div>
            <p className="text-white text-2xl font-bold">{c.value}</p>
            <p className="text-[#7d92b0] text-xs mt-0.5">{c.label}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-1 w-fit">
        {([['rules', 'ハンティングルール'], ['history', '実行履歴']] as const).map(([key, label]) => (
          <button key={key} onClick={() => setTab(key)}
            className={`px-5 py-2 rounded-lg text-sm font-medium transition-colors ${tab === key ? 'bg-[#e8002d] text-white' : 'text-[#7d92b0] hover:text-white'}`}>
            {label}
          </button>
        ))}
      </div>

      {/* ── Rules Tab ────────────────────────────────────────────────────────── */}
      {tab === 'rules' && (
        <div className="space-y-5">
          {/* Filters */}
          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#7d92b0]" />
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="ルール名・説明を検索..."
                className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/50" />
            </div>
            <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
              className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#7d92b0] focus:outline-hidden">
              <option value="all">全タイプ</option>
              {(['ioc_sweep', 'behavioral', 'anomaly', 'yara', 'sigma', 'custom'] as HuntType[]).map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
            <span className="text-[#7d92b0] text-sm">{filteredRules.length}件</span>
          </div>

          {/* Rules Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['ルール名', 'タイプ', 'データソース', 'スケジュール', '最終実行', '所見', '有効', '操作'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredRules.length === 0 && (
                  <tr>
                    <td colSpan={8} className="px-4 py-12 text-center">
                      <Zap className="w-8 h-8 text-[#1e2d42] mx-auto mb-3" />
                      <p className="text-[#7d92b0] text-sm font-medium">
                        {search || typeFilter !== 'all' ? '条件に一致するルールが見つかりません' : 'ハンティングルールがまだありません'}
                      </p>
                      <p className="text-[#3d5068] text-xs mt-1">
                        {search || typeFilter !== 'all' ? 'フィルターを変更してください' : '「ルール追加」ボタンから最初のルールを作成できます'}
                      </p>
                    </td>
                  </tr>
                )}
                {filteredRules.map(r => (
                  <tr key={r.id} className="border-b border-[#1e2d42] hover:bg-[#0a1320] transition-colors">
                    <td className="px-4 py-3">
                      <div>
                        <p className="text-white font-medium">{r.name}</p>
                        <p className="text-[#7d92b0] text-xs mt-0.5 truncate max-w-[200px]">{r.description}</p>
                        {r.mitre_techniques.length > 0 && (
                          <div className="flex gap-1 mt-1 flex-wrap">
                            {r.mitre_techniques.slice(0, 3).map(t => (
                              <span key={t} className="text-[10px] px-1.5 py-0.5 bg-purple-900/30 text-purple-400 rounded-sm">{t}</span>
                            ))}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded-sm border text-xs font-medium ${HUNT_TYPE_COLORS[r.hunt_type]}`}>{r.hunt_type}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs ${DS_COLORS[r.data_source]}`}>
                        {DS_ICONS[r.data_source]}{r.data_source}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div>
                        <p className="text-white text-xs">{humanizeCron(r.schedule)}</p>
                        <p className="text-[#3d5068] text-[10px] font-mono">{r.schedule}</p>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-[#7d92b0] text-xs">{fmtTime(r.last_run)}</td>
                    <td className="px-4 py-3">
                      <span className={`font-bold text-sm ${r.last_findings_count > 0 ? 'text-red-400' : 'text-[#7d92b0]'}`}>
                        {r.last_findings_count}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <button onClick={() => {/* toggle */ }}
                        className={`w-9 h-5 rounded-full relative transition-colors ${r.enabled ? 'bg-green-600' : 'bg-[#1e2d42]'}`}>
                        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-[#e2e8f4] transition-transform shadow-sm ${r.enabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
                      </button>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        <button onClick={() => runMutation.mutate(r.id)} title="今すぐ実行"
                          className="p-1.5 hover:bg-green-900/30 rounded-sm text-green-400 transition-colors">
                          <Play className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => setEditRule(r)} title="編集"
                          className="p-1.5 hover:bg-[#1e2d42] rounded-sm text-[#7d92b0] transition-colors">
                          <Edit2 className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => deleteMutation.mutate(r.id)} title="削除"
                          className="p-1.5 hover:bg-red-900/30 rounded-sm text-red-400/70 transition-colors">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Effectiveness */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <TrendingUp className="w-4 h-4 text-[#e8002d]" />
              <h2 className="text-white font-semibold text-sm">ルール有効性 Top 5 (所見/実行比率)</h2>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['ルール名', 'タイプ', '総実行', '総所見', '比率'].map(h => (
                    <th key={h} className="text-left px-3 py-2 text-xs text-[#7d92b0]">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {effectivenessTop5.map((r, i) => (
                  <tr key={r.id} className="border-b border-[#1e2d42]/50">
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-2">
                        <span className="text-[#3d5068] text-xs w-4">{i + 1}</span>
                        <span className="text-white">{r.name}</span>
                      </div>
                    </td>
                    <td className="px-3 py-2"><span className={`px-2 py-0.5 rounded-sm border text-xs ${HUNT_TYPE_COLORS[r.hunt_type]}`}>{r.hunt_type}</span></td>
                    <td className="px-3 py-2 text-[#7d92b0]">{r.total_runs}</td>
                    <td className="px-3 py-2 text-[#7d92b0]">{r.total_findings}</td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-2">
                        <div className="w-20 bg-[#1e2d42] rounded-full h-1.5">
                          <div className="bg-[#e8002d] h-1.5 rounded-full" style={{ width: `${Math.min(r.ratio * 100, 100)}%` }} />
                        </div>
                        <span className="text-white text-xs">{(r.ratio * 100).toFixed(1)}%</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── History Tab ──────────────────────────────────────────────────────── */}
      {tab === 'history' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <select value={execRuleFilter} onChange={e => setExecRuleFilter(e.target.value)}
              className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#7d92b0] focus:outline-hidden">
              <option value="all">全ルール</option>
              {rules.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
            <select value={execStatusFilter} onChange={e => setExecStatusFilter(e.target.value)}
              className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#7d92b0] focus:outline-hidden">
              <option value="all">全ステータス</option>
              {(['completed', 'running', 'failed', 'cancelled'] as ExecStatus[]).map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <span className="text-[#7d92b0] text-sm ml-auto">{filteredExecs.length}件</span>
          </div>

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['', 'ルール名', '開始時刻', '完了時刻', '所要時間', 'ステータス', '所見', 'エスカレーション'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredExecs.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center">
                      <Clock className="w-8 h-8 text-[#1e2d42] mx-auto mb-3" />
                      <p className="text-[#7d92b0] text-sm">実行履歴がありません</p>
                      <p className="text-[#3d5068] text-xs mt-1">ハンティングルールを実行すると、ここに履歴が表示されます</p>
                    </td>
                  </tr>
                )}
                {filteredExecs.map(e => (
                  <>
                    <tr key={e.id} className="border-b border-[#1e2d42] hover:bg-[#0a1320] transition-colors cursor-pointer"
                      onClick={() => setExpandedExec(expandedExec === e.id ? null : e.id)}>
                      <td className="px-4 py-3">
                        {e.findings.length > 0
                          ? expandedExec === e.id ? <ChevronDown className="w-4 h-4 text-[#7d92b0]" /> : <ChevronRight className="w-4 h-4 text-[#7d92b0]" />
                          : <span className="w-4 h-4 block" />}
                      </td>
                      <td className="px-4 py-3 text-white">{e.rule_name}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">{fmtTime(e.started_at)}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">{fmtTime(e.completed_at)}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">{formatDuration(e.duration_sec)}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${EXEC_STATUS_BADGE[e.status]}`}>{e.status}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`font-semibold ${e.findings_count > 0 ? 'text-red-400' : 'text-[#7d92b0]'}`}>{e.findings_count}</span>
                      </td>
                      <td className="px-4 py-3">
                        {e.escalated && (
                          <span className="px-2 py-0.5 rounded-sm text-xs bg-orange-900/40 text-orange-400 border border-orange-700/40">エスカレーション</span>
                        )}
                      </td>
                    </tr>
                    {expandedExec === e.id && e.findings.length > 0 && (
                      <tr key={`${e.id}-details`} className="border-b border-[#1e2d42] bg-[#070d19]">
                        <td colSpan={8} className="px-6 py-3">
                          <p className="text-xs text-[#7d92b0] mb-2 font-medium">所見の詳細 ({e.findings.length}件)</p>
                          <div className="space-y-1.5">
                            {e.findings.map(f => <FindingRow key={f.id} f={f} />)}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
